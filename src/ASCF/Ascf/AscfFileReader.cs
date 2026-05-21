using ASCF.Lz4;
using ASCF.Util;
using System.Buffers;
using System.Security.Cryptography;

namespace ASCF;

public static class AscfFileReader
{
    public readonly record struct DecodeResult(string Hash, long RawSize);
    public readonly record struct StoredStreamResult(string Hash, long RawSize, long StoredSize);

    private readonly record struct DecodedChunkResult(long RawSize, long EncodedOffset, List<AscfChunkIndexEntry> Entries);

    public static bool LooksLikeAscf(ReadOnlySpan<byte> buffer)
        => LooksLikeAscf(buffer, AscfReaderOptions.Default);

    public static bool LooksLikeAscf(ReadOnlySpan<byte> buffer, AscfReaderOptions options)
    {
        options.Validate();
        if (buffer.Length < AscfFileFormat.HeaderSize)
        {
            return false;
        }

        return AscfFileHeaderCodec.TryRead(buffer, options.MaxRawFileBytes, out _);
    }

    public static async Task<bool> FileLooksLikeAscfAsync(string path, CancellationToken token)
        => await FileLooksLikeAscfAsync(path, AscfReaderOptions.Default, token).ConfigureAwait(false);

    public static async Task<bool> FileLooksLikeAscfAsync(string path, AscfReaderOptions options, CancellationToken token)
    {
        options.Validate();
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete,
            bufferSize: options.BufferSize,
            FileOptions.Asynchronous | FileOptions.SequentialScan);

        if (stream.Length < AscfFileFormat.HeaderSize)
        {
            return false;
        }

        var header = new byte[AscfFileFormat.HeaderSize];
        await FileFormatStreamReader.ReadExactlyAsync(stream, header.AsMemory(0, header.Length), token).ConfigureAwait(false);
        return LooksLikeAscf(header, options);
    }

    /// <summary> reads the chunk index from a complete file </summary>
    public static AscfChunkIndex ReadChunkIndex(string path)
        => ReadChunkIndex(path, AscfReaderOptions.Default);

    /// <summary> reads the chunk index from a complete file </summary>
    public static AscfChunkIndex ReadChunkIndex(string path, AscfReaderOptions options)
    {
        options.Validate();
        using var input = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: options.BufferSize,
            FileOptions.SequentialScan);

        var header = new byte[AscfFileFormat.HeaderSize];
        FileFormatStreamReader.ReadExactly(input, header);
        var fileHeader = ValidateHeader(header, options);
        return ReadChunkIndexFromEnd(input, fileHeader);
    }

    /// <summary> reads the chunk index from a complete file </summary>
    public static async Task<AscfChunkIndex> ReadChunkIndexAsync(string path, CancellationToken token)
        => await ReadChunkIndexAsync(path, AscfReaderOptions.Default, token).ConfigureAwait(false);

    /// <summary> reads the chunk index from a complete file </summary>
    public static async Task<AscfChunkIndex> ReadChunkIndexAsync(string path, AscfReaderOptions options, CancellationToken token)
    {
        options.Validate();
        var input = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: options.BufferSize,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        await using (input.ConfigureAwait(false))
        {
            var header = new byte[AscfFileFormat.HeaderSize];
            await FileFormatStreamReader.ReadExactlyAsync(input, header.AsMemory(0, header.Length), token).ConfigureAwait(false);
            var fileHeader = ValidateHeader(header, options);
            return await ReadChunkIndexFromEndAsync(input, fileHeader, token).ConfigureAwait(false);
        }
    }

    /// <summary> validates a partial file for chunk aligned resume </summary>
    public static async Task<AscfPartialValidationResult> ValidatePartialFileAsync(string path, CancellationToken token)
        => await ValidatePartialFileAsync(path, AscfReaderOptions.Default, token).ConfigureAwait(false);

    /// <summary> validates a partial file for chunk aligned resume </summary>
    public static async Task<AscfPartialValidationResult> ValidatePartialFileAsync(string path, AscfReaderOptions options, CancellationToken token)
    {
        options.Validate();
        var input = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete,
            bufferSize: options.BufferSize,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        await using (input.ConfigureAwait(false))
        {
            if (input.Length < AscfFileFormat.HeaderSize)
            {
                return new AscfPartialValidationResult(false, false, false, 0, 0, 0);
            }

            var header = new byte[AscfFileFormat.HeaderSize];
            await FileFormatStreamReader.ReadExactlyAsync(input, header.AsMemory(0, header.Length), token).ConfigureAwait(false);
            if (!AscfFileHeaderCodec.TryRead(header, options.MaxRawFileBytes, out var fileHeader))
            {
                return new AscfPartialValidationResult(false, false, true, 0, 0, 0);
            }

            return await ValidatePartialChunksAsync(input, fileHeader, token).ConfigureAwait(false);
        }
    }

    public static byte[] DecodeToArray(ReadOnlySpan<byte> encoded)
        => DecodeToArray(encoded.ToArray(), AscfReaderOptions.Default);

    public static byte[] DecodeToArray(ReadOnlySpan<byte> encoded, AscfReaderOptions options)
        => DecodeToArray(encoded.ToArray(), options);

    public static byte[] DecodeToArray(byte[] encoded)
        => DecodeToArray(encoded, AscfReaderOptions.Default);

    public static byte[] DecodeToArray(byte[] encoded, AscfReaderOptions options)
    {
        options.Validate();
        if (!LooksLikeAscf(encoded, options))
        {
            throw new InvalidDataException(".ascf header is invalid.");
        }

        var fileHeader = AscfFileHeaderCodec.Read(encoded.AsSpan(0, AscfFileFormat.HeaderSize), options.MaxRawFileBytes);
        if (fileHeader.RawSize > options.MaxInMemoryDecodeBytes || fileHeader.RawSize > int.MaxValue)
        {
            throw new InvalidDataException($".ascf raw size is too large for an in-memory decode ({fileHeader.RawSize} bytes).");
        }

        using var input = new MemoryStream(encoded, writable: false);
        using var output = new MemoryStream(checked((int)fileHeader.RawSize));
        DecodeStreamToStream(input, output, options);
        return output.ToArray();
    }

    public static DecodeResult ComputeFileHash(string inputPath)
        => ComputeFileHash(inputPath, AscfReaderOptions.Default);

    public static DecodeResult ComputeFileHash(string inputPath, AscfReaderOptions options)
    {
        options.Validate();
        using var input = new FileStream(
            inputPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: options.BufferSize,
            FileOptions.SequentialScan);
        using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);

        var header = new byte[AscfFileFormat.HeaderSize];
        FileFormatStreamReader.ReadExactly(input, header);
        var fileHeader = ValidateHeader(header, options);

        var chunkHeader = new byte[AscfFileFormat.ChunkHeaderSize];
        var maxCompressedSize = Lz4BlockCodec.MaxCompressedLength(fileHeader.RawChunkSize);
        var compressedBuffer = ArrayPool<byte>.Shared.Rent(maxCompressedSize);
        var rawBuffer = ArrayPool<byte>.Shared.Rent(fileHeader.RawChunkSize);
        var entries = new List<AscfChunkIndexEntry>(fileHeader.ChunkCount);
        try
        {
            long rawSize = 0;
            long encodedOffset = AscfFileFormat.HeaderSize;
            for (var chunkIndex = 0; chunkIndex < fileHeader.ChunkCount; chunkIndex++)
            {
                FileFormatStreamReader.ReadExactly(input, chunkHeader);
                var chunk = AscfChunkHeaderCodec.Read(chunkHeader, fileHeader, chunkIndex, rawSize, maxCompressedSize);

                FileFormatStreamReader.ReadExactly(input, compressedBuffer.AsSpan(0, chunk.StoredLength));
                ValidateStoredChecksum(chunk, compressedBuffer.AsSpan(0, chunk.StoredLength));
                if (chunk.StoresRaw)
                {
                    ValidateRawChecksum(chunk, compressedBuffer.AsSpan(0, chunk.RawLength));
                    hasher.AppendData(compressedBuffer.AsSpan(0, chunk.RawLength));
                }
                else
                {
                    Lz4BlockCodec.Decode(compressedBuffer.AsSpan(0, chunk.StoredLength), rawBuffer.AsSpan(0, chunk.RawLength), chunk.RawLength);
                    ValidateRawChecksum(chunk, rawBuffer.AsSpan(0, chunk.RawLength));
                    hasher.AppendData(rawBuffer.AsSpan(0, chunk.RawLength));
                }

                entries.Add(ToIndexEntry(chunk, encodedOffset));
                rawSize += chunk.RawLength;
                encodedOffset += AscfFileFormat.ChunkHeaderSize + chunk.StoredLength;
            }

            if (rawSize != fileHeader.RawSize)
            {
                throw new InvalidDataException(".ascf decoded raw size did not match the header.");
            }

            ReadAndValidateIndex(input, entries, rawSize, encodedOffset);
            if (input.Position != input.Length)
            {
                throw new InvalidDataException(".ascf file contained trailing bytes.");
            }

            return new DecodeResult(Convert.ToHexString(hasher.GetHashAndReset()), rawSize);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rawBuffer);
            ArrayPool<byte>.Shared.Return(compressedBuffer);
        }
    }

    public static async Task<StoredStreamResult> CopyEncodedStreamToFileAsync(
        Stream encodedStream,
        string outputPath,
        CancellationToken token)
        => await CopyEncodedStreamToFileAsync(encodedStream, outputPath, transform: null, AscfReaderOptions.Default, token).ConfigureAwait(false);

    public static async Task<StoredStreamResult> CopyEncodedStreamToFileAsync(
        Stream encodedStream,
        string outputPath,
        AscfBufferTransform? transform,
        CancellationToken token)
        => await CopyEncodedStreamToFileAsync(encodedStream, outputPath, transform, AscfReaderOptions.Default, token).ConfigureAwait(false);

    public static async Task<StoredStreamResult> CopyEncodedStreamToFileAsync(
        Stream encodedStream,
        string outputPath,
        AscfBufferTransform? transform,
        AscfReaderOptions options,
        CancellationToken token)
    {
        options.Validate();
        FileFormatPaths.EnsureOutputDirectory(outputPath);

        var output = new FileStream(
            outputPath,
            FileMode.Create,
            FileAccess.Write,
            FileShare.None,
            bufferSize: options.BufferSize,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        await using (output.ConfigureAwait(false))
        {
            using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);

            var header = new byte[AscfFileFormat.HeaderSize];
            await ReadTransformedBytesAsync(encodedStream, header.AsMemory(0, header.Length), transform, token).ConfigureAwait(false);
            var fileHeader = ValidateHeader(header, options);
            await output.WriteAsync(header.AsMemory(0, header.Length), token).ConfigureAwait(false);

            var chunkHeader = new byte[AscfFileFormat.ChunkHeaderSize];
            var maxCompressedSize = Lz4BlockCodec.MaxCompressedLength(fileHeader.RawChunkSize);
            var compressedBuffer = ArrayPool<byte>.Shared.Rent(maxCompressedSize);
            var rawBuffer = ArrayPool<byte>.Shared.Rent(fileHeader.RawChunkSize);
            try
            {
                var decoded = await DecodeChunksAsync(
                        encodedStream,
                        output,
                        hasher,
                        fileHeader,
                        chunkHeader,
                        compressedBuffer,
                        rawBuffer,
                        maxCompressedSize,
                        transform,
                        token,
                        writeWirePayload: true)
                    .ConfigureAwait(false);
                await ReadAndValidateIndexAsync(encodedStream, output, decoded.Entries, decoded.RawSize, decoded.EncodedOffset, transform, token, writeWirePayload: true)
                    .ConfigureAwait(false);

                if (await HasTrailingByteAsync(encodedStream, transform, token).ConfigureAwait(false))
                {
                    throw new InvalidDataException(".ascf stream contained trailing bytes.");
                }

                await output.FlushAsync(token).ConfigureAwait(false);
                return new StoredStreamResult(Convert.ToHexString(hasher.GetHashAndReset()), decoded.RawSize, output.Length);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(rawBuffer);
                ArrayPool<byte>.Shared.Return(compressedBuffer);
            }
        }
    }

    public static async Task<DecodeResult> DecodeFileToRawFileAsync(
        string inputPath,
        string outputPath,
        CancellationToken token)
        => await DecodeFileToRawFileAsync(inputPath, outputPath, AscfReaderOptions.Default, token).ConfigureAwait(false);

    public static async Task<DecodeResult> DecodeFileToRawFileAsync(
        string inputPath,
        string outputPath,
        AscfReaderOptions options,
        CancellationToken token)
    {
        options.Validate();
        var input = new FileStream(
            inputPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: options.BufferSize,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        await using (input.ConfigureAwait(false))
        {
            return await DecodeStreamToRawFileAsync(input, outputPath, transform: null, options, token).ConfigureAwait(false);
        }
    }

    public static async Task<long> DecodeFileToFileAsync(
        string inputPath,
        string outputPath,
        CancellationToken token)
        => await DecodeFileToFileAsync(inputPath, outputPath, AscfReaderOptions.Default, token).ConfigureAwait(false);

    public static async Task<long> DecodeFileToFileAsync(
        string inputPath,
        string outputPath,
        AscfReaderOptions options,
        CancellationToken token)
    {
        var result = await DecodeFileToRawFileAsync(inputPath, outputPath, options, token).ConfigureAwait(false);
        return result.RawSize;
    }

    public static async Task<WrappedLz4FileFormat.WriteResult?> TryWriteStoredRawWrappedLz4Async(
        string inputPath,
        string outputPath,
        CancellationToken token)
        => await TryWriteStoredRawWrappedLz4Async(inputPath, outputPath, AscfReaderOptions.Default, token).ConfigureAwait(false);

    public static async Task<WrappedLz4FileFormat.WriteResult?> TryWriteStoredRawWrappedLz4Async(
        string inputPath,
        string outputPath,
        AscfReaderOptions options,
        CancellationToken token)
    {
        options.Validate();
        FileFormatPaths.EnsureOutputDirectory(outputPath);

        var success = false;
        try
        {
            var input = new FileStream(
                inputPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: options.BufferSize,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            await using (input.ConfigureAwait(false))
            {
                var fileHeader = await ReadHeaderAsync(input, options, token).ConfigureAwait(false);
                if (fileHeader.RawSize > int.MaxValue)
                {
                    return null;
                }

                if (!await AllChunksStoredRawAsync(input, fileHeader, token).ConfigureAwait(false))
                {
                    return null;
                }

                input.Position = AscfFileFormat.HeaderSize;
                var wrappedRawSize = (int)fileHeader.RawSize;

                var output = new FileStream(
                    outputPath,
                    FileMode.Create,
                    FileAccess.Write,
                    FileShare.None,
                    bufferSize: options.BufferSize,
                    FileOptions.Asynchronous | FileOptions.SequentialScan);
                await using (output.ConfigureAwait(false))
                {
                    await WriteWrappedRawHeaderAsync(output, wrappedRawSize, token).ConfigureAwait(false);
                    await CopyStoredRawChunksAsync(input, output, fileHeader, token).ConfigureAwait(false);
                    await output.FlushAsync(token).ConfigureAwait(false);
                    success = true;
                    return new WrappedLz4FileFormat.WriteResult(fileHeader.RawSize, WrappedLz4FileFormat.HeaderSize + fileHeader.RawSize);
                }
            }
        }
        finally
        {
            if (!success)
            {
                TryDeleteFile(outputPath);
            }
        }
    }

    private static async Task<AscfFileHeader> ReadHeaderAsync(Stream input, AscfReaderOptions options, CancellationToken token)
    {
        var header = new byte[AscfFileFormat.HeaderSize];
        await FileFormatStreamReader.ReadExactlyAsync(input, header.AsMemory(0, header.Length), token).ConfigureAwait(false);
        return ValidateHeader(header, options);
    }

    private static async Task WriteWrappedRawHeaderAsync(Stream output, int rawSize, CancellationToken token)
    {
        var wrappedHeader = new byte[WrappedLz4FileFormat.HeaderSize];
        WrappedLz4FileFormat.WriteHeader(wrappedHeader, rawSize, rawSize);
        await output.WriteAsync(wrappedHeader.AsMemory(0, wrappedHeader.Length), token).ConfigureAwait(false);
    }

    private static async Task<bool> AllChunksStoredRawAsync(FileStream input, AscfFileHeader fileHeader, CancellationToken token)
    {
        var chunkHeader = new byte[AscfFileFormat.ChunkHeaderSize];
        var maxCompressedSize = Lz4BlockCodec.MaxCompressedLength(fileHeader.RawChunkSize);
        var entries = new List<AscfChunkIndexEntry>(fileHeader.ChunkCount);
        long rawSize = 0;
        long encodedOffset = AscfFileFormat.HeaderSize;
        for (var chunkIndex = 0; chunkIndex < fileHeader.ChunkCount; chunkIndex++)
        {
            await FileFormatStreamReader.ReadExactlyAsync(input, chunkHeader.AsMemory(0, chunkHeader.Length), token).ConfigureAwait(false);
            var chunk = AscfChunkHeaderCodec.Read(chunkHeader, fileHeader, chunkIndex, rawSize, maxCompressedSize);

            if (!chunk.StoresRaw)
            {
                return false;
            }

            entries.Add(ToIndexEntry(chunk, encodedOffset));
            SeekForward(input, chunk.StoredLength);
            rawSize += chunk.RawLength;
            encodedOffset += AscfFileFormat.ChunkHeaderSize + chunk.StoredLength;
        }

        if (rawSize != fileHeader.RawSize)
        {
            throw new InvalidDataException(".ascf decoded raw size did not match the header.");
        }

        await ReadAndValidateIndexAsync(input, output: null, entries, rawSize, encodedOffset, transform: null, token, writeWirePayload: false)
            .ConfigureAwait(false);
        if (input.Position != input.Length)
        {
            throw new InvalidDataException(".ascf file contained trailing bytes.");
        }

        return true;
    }

    private static async Task CopyStoredRawChunksAsync(Stream input, Stream output, AscfFileHeader fileHeader, CancellationToken token)
    {
        var chunkHeader = new byte[AscfFileFormat.ChunkHeaderSize];
        var maxCompressedSize = Lz4BlockCodec.MaxCompressedLength(fileHeader.RawChunkSize);
        var copyBuffer = ArrayPool<byte>.Shared.Rent(fileHeader.RawChunkSize);
        long rawSize = 0;
        try
        {
            for (var chunkIndex = 0; chunkIndex < fileHeader.ChunkCount; chunkIndex++)
            {
                await FileFormatStreamReader.ReadExactlyAsync(input, chunkHeader.AsMemory(0, chunkHeader.Length), token).ConfigureAwait(false);
                var chunk = AscfChunkHeaderCodec.Read(chunkHeader, fileHeader, chunkIndex, rawSize, maxCompressedSize);

                if (!chunk.StoresRaw)
                {
                    throw new InvalidDataException(".ascf file changed while converting stored raw chunks.");
                }

                await FileFormatStreamReader.ReadExactlyAsync(input, copyBuffer.AsMemory(0, chunk.StoredLength), token).ConfigureAwait(false);
                ValidateStoredChecksum(chunk, copyBuffer.AsSpan(0, chunk.StoredLength));
                ValidateRawChecksum(chunk, copyBuffer.AsSpan(0, chunk.RawLength));
                await output.WriteAsync(copyBuffer.AsMemory(0, chunk.StoredLength), token).ConfigureAwait(false);
                rawSize += chunk.RawLength;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(copyBuffer);
        }
    }

    public static async Task<DecodeResult> DecodeStreamToRawFileAsync(
        Stream encodedStream,
        string outputPath,
        CancellationToken token)
        => await DecodeStreamToRawFileAsync(encodedStream, outputPath, transform: null, AscfReaderOptions.Default, token).ConfigureAwait(false);

    public static async Task<DecodeResult> DecodeStreamToRawFileAsync(
        Stream encodedStream,
        string outputPath,
        AscfBufferTransform? transform,
        CancellationToken token)
        => await DecodeStreamToRawFileAsync(encodedStream, outputPath, transform, AscfReaderOptions.Default, token).ConfigureAwait(false);

    public static async Task<DecodeResult> DecodeStreamToRawFileAsync(
        Stream encodedStream,
        string outputPath,
        AscfBufferTransform? transform,
        AscfReaderOptions options,
        CancellationToken token)
    {
        options.Validate();
        FileFormatPaths.EnsureOutputDirectory(outputPath);

        var output = new FileStream(
            outputPath,
            FileMode.Create,
            FileAccess.Write,
            FileShare.None,
            bufferSize: options.BufferSize,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        await using (output.ConfigureAwait(false))
        {
            using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);

            var header = new byte[AscfFileFormat.HeaderSize];
            await ReadTransformedBytesAsync(encodedStream, header.AsMemory(0, header.Length), transform, token).ConfigureAwait(false);
            var fileHeader = ValidateHeader(header, options);

            var chunkHeader = new byte[AscfFileFormat.ChunkHeaderSize];
            var maxCompressedSize = Lz4BlockCodec.MaxCompressedLength(fileHeader.RawChunkSize);
            var compressedBuffer = ArrayPool<byte>.Shared.Rent(maxCompressedSize);
            var rawBuffer = ArrayPool<byte>.Shared.Rent(fileHeader.RawChunkSize);
            try
            {
                var decoded = await DecodeChunksAsync(
                        encodedStream,
                        output,
                        hasher,
                        fileHeader,
                        chunkHeader,
                        compressedBuffer,
                        rawBuffer,
                        maxCompressedSize,
                        transform,
                        token,
                        writeWirePayload: false)
                    .ConfigureAwait(false);
                await ReadAndValidateIndexAsync(encodedStream, output: null, decoded.Entries, decoded.RawSize, decoded.EncodedOffset, transform, token, writeWirePayload: false)
                    .ConfigureAwait(false);

                if (await HasTrailingByteAsync(encodedStream, transform, token).ConfigureAwait(false))
                {
                    throw new InvalidDataException(".ascf stream contained trailing bytes.");
                }

                await output.FlushAsync(token).ConfigureAwait(false);
                return new DecodeResult(Convert.ToHexString(hasher.GetHashAndReset()), decoded.RawSize);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(rawBuffer);
                ArrayPool<byte>.Shared.Return(compressedBuffer);
            }
        }
    }

    private static async Task<DecodedChunkResult> DecodeChunksAsync(
        Stream encodedStream,
        Stream output,
        IncrementalHash? hasher,
        AscfFileHeader fileHeader,
        byte[] chunkHeader,
        byte[] compressedBuffer,
        byte[] rawBuffer,
        int maxCompressedSize,
        AscfBufferTransform? transform,
        CancellationToken token,
        bool writeWirePayload)
    {
        long rawSize = 0;
        long encodedOffset = AscfFileFormat.HeaderSize;
        var entries = new List<AscfChunkIndexEntry>(fileHeader.ChunkCount);
        for (var chunkIndex = 0; chunkIndex < fileHeader.ChunkCount; chunkIndex++)
        {
            await ReadTransformedBytesAsync(encodedStream, chunkHeader.AsMemory(0, chunkHeader.Length), transform, token).ConfigureAwait(false);
            var chunk = AscfChunkHeaderCodec.Read(chunkHeader, fileHeader, chunkIndex, rawSize, maxCompressedSize);

            await ReadTransformedBytesAsync(encodedStream, compressedBuffer.AsMemory(0, chunk.StoredLength), transform, token).ConfigureAwait(false);
            ValidateStoredChecksum(chunk, compressedBuffer.AsSpan(0, chunk.StoredLength));
            if (writeWirePayload)
            {
                await output.WriteAsync(chunkHeader.AsMemory(0, chunkHeader.Length), token).ConfigureAwait(false);
                await output.WriteAsync(compressedBuffer.AsMemory(0, chunk.StoredLength), token).ConfigureAwait(false);
            }

            if (chunk.StoresRaw)
            {
                ValidateRawChecksum(chunk, compressedBuffer.AsSpan(0, chunk.RawLength));
                hasher?.AppendData(compressedBuffer.AsSpan(0, chunk.RawLength));
                if (!writeWirePayload)
                {
                    await output.WriteAsync(compressedBuffer.AsMemory(0, chunk.RawLength), token).ConfigureAwait(false);
                }
            }
            else
            {
                Lz4BlockCodec.Decode(compressedBuffer.AsSpan(0, chunk.StoredLength), rawBuffer.AsSpan(0, chunk.RawLength), chunk.RawLength);
                ValidateRawChecksum(chunk, rawBuffer.AsSpan(0, chunk.RawLength));
                hasher?.AppendData(rawBuffer.AsSpan(0, chunk.RawLength));
                if (!writeWirePayload)
                {
                    await output.WriteAsync(rawBuffer.AsMemory(0, chunk.RawLength), token).ConfigureAwait(false);
                }
            }

            entries.Add(ToIndexEntry(chunk, encodedOffset));
            rawSize += chunk.RawLength;
            encodedOffset += AscfFileFormat.ChunkHeaderSize + chunk.StoredLength;
        }

        if (rawSize != fileHeader.RawSize)
        {
            throw new InvalidDataException(".ascf decoded raw size did not match the header.");
        }

        return new DecodedChunkResult(rawSize, encodedOffset, entries);
    }

    private static long DecodeStreamToStream(Stream input, Stream output, AscfReaderOptions options)
    {
        var header = new byte[AscfFileFormat.HeaderSize];
        FileFormatStreamReader.ReadExactly(input, header);
        var fileHeader = ValidateHeader(header, options);

        var chunkHeader = new byte[AscfFileFormat.ChunkHeaderSize];
        var maxCompressedSize = Lz4BlockCodec.MaxCompressedLength(fileHeader.RawChunkSize);
        var compressedBuffer = ArrayPool<byte>.Shared.Rent(maxCompressedSize);
        var rawBuffer = ArrayPool<byte>.Shared.Rent(fileHeader.RawChunkSize);
        var entries = new List<AscfChunkIndexEntry>(fileHeader.ChunkCount);
        try
        {
            long rawSize = 0;
            long encodedOffset = AscfFileFormat.HeaderSize;
            for (var chunkIndex = 0; chunkIndex < fileHeader.ChunkCount; chunkIndex++)
            {
                FileFormatStreamReader.ReadExactly(input, chunkHeader);
                var chunk = AscfChunkHeaderCodec.Read(chunkHeader, fileHeader, chunkIndex, rawSize, maxCompressedSize);

                FileFormatStreamReader.ReadExactly(input, compressedBuffer.AsSpan(0, chunk.StoredLength));
                ValidateStoredChecksum(chunk, compressedBuffer.AsSpan(0, chunk.StoredLength));
                if (chunk.StoresRaw)
                {
                    ValidateRawChecksum(chunk, compressedBuffer.AsSpan(0, chunk.RawLength));
                    output.Write(compressedBuffer.AsSpan(0, chunk.RawLength));
                }
                else
                {
                    Lz4BlockCodec.Decode(compressedBuffer.AsSpan(0, chunk.StoredLength), rawBuffer.AsSpan(0, chunk.RawLength), chunk.RawLength);
                    ValidateRawChecksum(chunk, rawBuffer.AsSpan(0, chunk.RawLength));
                    output.Write(rawBuffer.AsSpan(0, chunk.RawLength));
                }

                entries.Add(ToIndexEntry(chunk, encodedOffset));
                rawSize += chunk.RawLength;
                encodedOffset += AscfFileFormat.ChunkHeaderSize + chunk.StoredLength;
            }

            if (rawSize != fileHeader.RawSize)
            {
                throw new InvalidDataException(".ascf decoded raw size did not match the header.");
            }

            ReadAndValidateIndex(input, entries, rawSize, encodedOffset);
            if (input.Position != input.Length)
            {
                throw new InvalidDataException(".ascf stream contained trailing bytes.");
            }

            return rawSize;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rawBuffer);
            ArrayPool<byte>.Shared.Return(compressedBuffer);
        }
    }

    private static AscfFileHeader ValidateHeader(ReadOnlySpan<byte> header, AscfReaderOptions options)
        => AscfFileHeaderCodec.Read(header, options.MaxRawFileBytes);

    private static AscfChunkIndexEntry ToIndexEntry(AscfChunkHeader chunk, long chunkOffset)
        => new(
            chunk.ChunkIndex,
            chunk.Method,
            chunk.RawOffset,
            chunkOffset,
            chunk.RawLength,
            chunk.StoredLength,
            chunk.RawChecksum,
            chunk.StoredChecksum);

    private static void ReadAndValidateIndex(
        Stream input,
        List<AscfChunkIndexEntry> entries,
        long rawSize,
        long indexOffset)
    {
        var indexLength = checked(entries.Count * AscfFileFormat.IndexEntrySize);
        var index = FileFormatStreamReader.ReadExactlyToArray(input, indexLength);
        var footerBytes = FileFormatStreamReader.ReadExactlyToArray(input, AscfFileFormat.IndexFooterSize);
        var footer = AscfChunkIndexCodec.ReadFooter(footerBytes, indexOffset + indexLength + AscfFileFormat.IndexFooterSize);
        ValidateIndexFooter(footer, entries, rawSize, indexOffset);
        ValidateIndexEntries(AscfChunkIndexCodec.ReadIndex(index, footer), entries);
    }

    private static async Task ReadAndValidateIndexAsync(
        Stream input,
        Stream? output,
        List<AscfChunkIndexEntry> entries,
        long rawSize,
        long indexOffset,
        AscfBufferTransform? transform,
        CancellationToken token,
        bool writeWirePayload)
    {
        var indexLength = checked(entries.Count * AscfFileFormat.IndexEntrySize);
        var index = new byte[indexLength];
        await ReadTransformedBytesAsync(input, index.AsMemory(0, index.Length), transform, token).ConfigureAwait(false);

        var footerBytes = new byte[AscfFileFormat.IndexFooterSize];
        await ReadTransformedBytesAsync(input, footerBytes.AsMemory(0, footerBytes.Length), transform, token).ConfigureAwait(false);

        var footer = AscfChunkIndexCodec.ReadFooter(footerBytes, indexOffset + indexLength + AscfFileFormat.IndexFooterSize);
        ValidateIndexFooter(footer, entries, rawSize, indexOffset);
        ValidateIndexEntries(AscfChunkIndexCodec.ReadIndex(index, footer), entries);

        if (writeWirePayload)
        {
            if (output == null)
            {
                throw new ArgumentNullException(nameof(output));
            }

            await output.WriteAsync(index.AsMemory(0, index.Length), token).ConfigureAwait(false);
            await output.WriteAsync(footerBytes.AsMemory(0, footerBytes.Length), token).ConfigureAwait(false);
        }
    }

    private static AscfChunkIndex ReadChunkIndexFromEnd(FileStream input, AscfFileHeader fileHeader)
    {
        if (input.Length < AscfFileFormat.HeaderSize + AscfFileFormat.IndexFooterSize)
        {
            throw new InvalidDataException(".ascf file is too short to contain an index footer.");
        }

        input.Position = input.Length - AscfFileFormat.IndexFooterSize;
        var footerBytes = FileFormatStreamReader.ReadExactlyToArray(input, AscfFileFormat.IndexFooterSize);
        var footer = AscfChunkIndexCodec.ReadFooter(footerBytes, input.Length);
        ValidateFooterAgainstHeader(footer, fileHeader);

        input.Position = footer.IndexOffset;
        var index = FileFormatStreamReader.ReadExactlyToArray(input, checked((int)footer.IndexLength));
        var chunkIndex = AscfChunkIndexCodec.ReadIndex(index, footer);
        ValidateIndexRawSize(chunkIndex, fileHeader.RawSize);
        return chunkIndex;
    }

    private static async Task<AscfChunkIndex> ReadChunkIndexFromEndAsync(FileStream input, AscfFileHeader fileHeader, CancellationToken token)
    {
        if (input.Length < AscfFileFormat.HeaderSize + AscfFileFormat.IndexFooterSize)
        {
            throw new InvalidDataException(".ascf file is too short to contain an index footer.");
        }

        input.Position = input.Length - AscfFileFormat.IndexFooterSize;
        var footerBytes = await FileFormatStreamReader.ReadExactlyToArrayAsync(input, AscfFileFormat.IndexFooterSize, token).ConfigureAwait(false);
        var footer = AscfChunkIndexCodec.ReadFooter(footerBytes, input.Length);
        ValidateFooterAgainstHeader(footer, fileHeader);

        input.Position = footer.IndexOffset;
        var index = await FileFormatStreamReader.ReadExactlyToArrayAsync(input, checked((int)footer.IndexLength), token).ConfigureAwait(false);
        var chunkIndex = AscfChunkIndexCodec.ReadIndex(index, footer);
        ValidateIndexRawSize(chunkIndex, fileHeader.RawSize);
        return chunkIndex;
    }

    private static async Task<AscfPartialValidationResult> ValidatePartialChunksAsync(
        FileStream input,
        AscfFileHeader fileHeader,
        CancellationToken token)
    {
        var chunkHeader = new byte[AscfFileFormat.ChunkHeaderSize];
        var maxCompressedSize = Lz4BlockCodec.MaxCompressedLength(fileHeader.RawChunkSize);
        var compressedBuffer = ArrayPool<byte>.Shared.Rent(maxCompressedSize);
        var rawBuffer = ArrayPool<byte>.Shared.Rent(fileHeader.RawChunkSize);
        var entries = new List<AscfChunkIndexEntry>(fileHeader.ChunkCount);
        try
        {
            long rawSize = 0;
            long encodedOffset = AscfFileFormat.HeaderSize;
            for (var chunkIndex = 0; chunkIndex < fileHeader.ChunkCount; chunkIndex++)
            {
                if (input.Length - input.Position < AscfFileFormat.ChunkHeaderSize)
                {
                    return new AscfPartialValidationResult(true, false, false, chunkIndex, rawSize, encodedOffset);
                }

                await FileFormatStreamReader.ReadExactlyAsync(input, chunkHeader.AsMemory(0, chunkHeader.Length), token).ConfigureAwait(false);
                AscfChunkHeader chunk;
                try
                {
                    chunk = AscfChunkHeaderCodec.Read(chunkHeader, fileHeader, chunkIndex, rawSize, maxCompressedSize);
                }
                catch (InvalidDataException)
                {
                    return new AscfPartialValidationResult(true, false, true, chunkIndex, rawSize, encodedOffset);
                }

                if (input.Length - input.Position < chunk.StoredLength)
                {
                    return new AscfPartialValidationResult(true, false, false, chunkIndex, rawSize, encodedOffset);
                }

                await FileFormatStreamReader.ReadExactlyAsync(input, compressedBuffer.AsMemory(0, chunk.StoredLength), token).ConfigureAwait(false);
                if (!TryValidateChunkPayload(chunk, compressedBuffer.AsSpan(0, chunk.StoredLength), rawBuffer))
                {
                    return new AscfPartialValidationResult(true, false, true, chunkIndex, rawSize, encodedOffset);
                }

                entries.Add(ToIndexEntry(chunk, encodedOffset));
                rawSize += chunk.RawLength;
                encodedOffset += AscfFileFormat.ChunkHeaderSize + chunk.StoredLength;
            }

            if (rawSize != fileHeader.RawSize)
            {
                return new AscfPartialValidationResult(true, false, true, entries.Count, rawSize, encodedOffset);
            }

            var remainingIndexBytes = checked((long)entries.Count * AscfFileFormat.IndexEntrySize) + AscfFileFormat.IndexFooterSize;
            if (input.Length - input.Position < remainingIndexBytes)
            {
                return new AscfPartialValidationResult(true, false, false, entries.Count, rawSize, encodedOffset);
            }

            try
            {
                await ReadAndValidateIndexAsync(input, output: null, entries, rawSize, encodedOffset, transform: null, token, writeWirePayload: false)
                    .ConfigureAwait(false);
            }
            catch (InvalidDataException)
            {
                return new AscfPartialValidationResult(true, false, true, entries.Count, rawSize, encodedOffset);
            }

            var isCorrupt = input.Position != input.Length;
            return new AscfPartialValidationResult(true, !isCorrupt, isCorrupt, entries.Count, rawSize, input.Position);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rawBuffer);
            ArrayPool<byte>.Shared.Return(compressedBuffer);
        }
    }

    private static bool TryValidateChunkPayload(AscfChunkHeader chunk, ReadOnlySpan<byte> stored, byte[] rawBuffer)
    {
        try
        {
            ValidateStoredChecksum(chunk, stored);
            if (chunk.StoresRaw)
            {
                ValidateRawChecksum(chunk, stored[..chunk.RawLength]);
                return true;
            }

            Lz4BlockCodec.Decode(stored, rawBuffer.AsSpan(0, chunk.RawLength), chunk.RawLength);
            ValidateRawChecksum(chunk, rawBuffer.AsSpan(0, chunk.RawLength));
            return true;
        }
        catch (InvalidDataException)
        {
            return false;
        }
    }

    private static void ValidateFooterAgainstHeader(AscfIndexFooter footer, AscfFileHeader fileHeader)
    {
        if (footer.ChunkCount != fileHeader.ChunkCount || footer.RawSize != fileHeader.RawSize)
        {
            throw new InvalidDataException(".ascf index footer does not match the file header.");
        }
    }

    private static void ValidateIndexFooter(
        AscfIndexFooter footer,
        IReadOnlyList<AscfChunkIndexEntry> entries,
        long rawSize,
        long indexOffset)
    {
        if (footer.ChunkCount != entries.Count
            || footer.RawSize != rawSize
            || footer.IndexOffset != indexOffset)
        {
            throw new InvalidDataException(".ascf index footer does not match the chunk stream.");
        }
    }

    private static void ValidateIndexEntries(AscfChunkIndex index, IReadOnlyList<AscfChunkIndexEntry> expected)
    {
        if (index.Entries.Count != expected.Count)
        {
            throw new InvalidDataException(".ascf index entry count mismatch.");
        }

        for (var i = 0; i < expected.Count; i++)
        {
            if (!index.Entries[i].Equals(expected[i]))
            {
                throw new InvalidDataException(".ascf index entry mismatch.");
            }
        }
    }

    private static void ValidateIndexRawSize(AscfChunkIndex index, long rawSize)
    {
        var computedRawSize = index.Entries.Count == 0
            ? 0
            : index.Entries[^1].RawOffset + index.Entries[^1].RawLength;
        if (computedRawSize != rawSize)
        {
            throw new InvalidDataException(".ascf index raw size mismatch.");
        }
    }

    private static void ValidateStoredChecksum(AscfChunkHeader chunk, ReadOnlySpan<byte> stored)
    {
        var checksum = AscfChecksum.ComputeXxHash3(stored);
        if (checksum != chunk.StoredChecksum)
        {
            throw new InvalidDataException(".ascf stored chunk checksum mismatch.");
        }
    }

    private static void ValidateRawChecksum(AscfChunkHeader chunk, ReadOnlySpan<byte> raw)
    {
        var checksum = AscfChecksum.ComputeXxHash3(raw);
        if (checksum != chunk.RawChecksum)
        {
            throw new InvalidDataException(".ascf raw chunk checksum mismatch.");
        }
    }

    private static async Task ReadTransformedBytesAsync(Stream stream, Memory<byte> buffer, AscfBufferTransform? transform, CancellationToken token)
    {
        await FileFormatStreamReader.ReadExactlyAsync(stream, buffer, token).ConfigureAwait(false);

        transform?.Invoke(buffer.Span);
    }

    private static async Task<bool> HasTrailingByteAsync(Stream stream, AscfBufferTransform? transform, CancellationToken token)
    {
        var buffer = new byte[1];
        var read = await stream.ReadAsync(buffer.AsMemory(0, 1), token).ConfigureAwait(false);
        if (read <= 0)
        {
            return false;
        }

        transform?.Invoke(buffer);

        return true;
    }

    private static void SeekForward(FileStream input, int length)
    {
        if (length > input.Length - input.Position)
        {
            throw new EndOfStreamException();
        }

        input.Position += length;
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch
        {
            // best effort cleanup after a failed conversion
        }
    }
}
