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

    public static Task<bool> FileLooksLikeAscfAsync(string path, CancellationToken token)
        => FileLooksLikeAscfAsync(path, AscfReaderOptions.Default, token);

    public static async Task<bool> FileLooksLikeAscfAsync(string path, AscfReaderOptions options, CancellationToken token)
    {
        options.Validate();
        var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete,
            bufferSize: options.BufferSize,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        await using (stream.ConfigureAwait(false))
        {
            if (stream.Length < AscfFileFormat.HeaderSize)
            {
                return false;
            }

            var header = new byte[AscfFileFormat.HeaderSize];
            await stream.ReadExactlyAsync(header.AsMemory(0, header.Length), token).ConfigureAwait(false);
            return LooksLikeAscf(header, options);
        }
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
        input.ReadExactly(header);
        var fileHeader = ValidateHeader(header, options);
        return ReadChunkIndexFromEnd(input, fileHeader);
    }

    /// <summary> reads the chunk index from a complete file </summary>
    public static Task<AscfChunkIndex> ReadChunkIndexAsync(string path, CancellationToken token)
        => ReadChunkIndexAsync(path, AscfReaderOptions.Default, token);

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
            await input.ReadExactlyAsync(header.AsMemory(0, header.Length), token).ConfigureAwait(false);
            var fileHeader = ValidateHeader(header, options);
            return await ReadChunkIndexFromEndAsync(input, fileHeader, token).ConfigureAwait(false);
        }
    }

    /// <summary> validates a partial file for chunk aligned resume </summary>
    public static Task<AscfPartialValidationResult> ValidatePartialFileAsync(string path, CancellationToken token)
        => ValidatePartialFileAsync(path, AscfReaderOptions.Default, token);

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
            await input.ReadExactlyAsync(header.AsMemory(0, header.Length), token).ConfigureAwait(false);
            if (!AscfFileHeaderCodec.TryRead(header, options.MaxRawFileBytes, out var fileHeader))
            {
                return new AscfPartialValidationResult(false, false, true, 0, 0, 0);
            }

            return await ValidatePartialChunksAsync(input, fileHeader, token).ConfigureAwait(false);
        }
    }

    public static byte[] DecodeToArray(ReadOnlySpan<byte> encoded)
        => DecodeToArray(encoded, AscfReaderOptions.Default);

    public static byte[] DecodeToArray(ReadOnlySpan<byte> encoded, AscfReaderOptions options)
    {
        options.Validate();
        var fileHeader = ValidateHeader(encoded, options);
        if (fileHeader.RawSize > options.MaxInMemoryDecodeBytes || fileHeader.RawSize > int.MaxValue)
        {
            throw new InvalidDataException($".ascf raw size is too large for an in-memory decode ({fileHeader.RawSize} bytes).");
        }

        var raw = fileHeader.RawSize == 0
            ? []
            : GC.AllocateUninitializedArray<byte>(checked((int)fileHeader.RawSize));
        DecodeToArray(encoded, raw, fileHeader);
        return raw;
    }

    public static byte[] DecodeToArray(byte[] encoded)
        => DecodeToArray(encoded.AsSpan(), AscfReaderOptions.Default);

    public static byte[] DecodeToArray(byte[] encoded, AscfReaderOptions options)
        => DecodeToArray(encoded.AsSpan(), options);

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
        input.ReadExactly(header);
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
                input.ReadExactly(chunkHeader);
                var chunk = AscfChunkHeaderCodec.Read(chunkHeader, fileHeader, chunkIndex, rawSize);

                input.ReadExactly(compressedBuffer.AsSpan(0, chunk.StoredLength));
                ValidateStoredChecksumAndRawIfStoredRaw(chunk, compressedBuffer.AsSpan(0, chunk.StoredLength));
                if (chunk.StoresRaw)
                {
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

    public static Task<StoredStreamResult> CopyEncodedStreamToFileAsync(
        Stream encodedStream,
        string outputPath,
        CancellationToken token)
        => CopyEncodedStreamToFileAsync(encodedStream, outputPath, transform: null, AscfReaderOptions.Default, token);

    public static Task<StoredStreamResult> CopyEncodedStreamToFileAsync(
        Stream encodedStream,
        string outputPath,
        AscfBufferTransform? transform,
        CancellationToken token)
        => CopyEncodedStreamToFileAsync(encodedStream, outputPath, transform, AscfReaderOptions.Default, token);

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
                        transform,
                        writeWirePayload: true,
                        token: token)
                    .ConfigureAwait(false);
                await ReadAndValidateIndexAsync(encodedStream, output, decoded.Entries, decoded.RawSize, decoded.EncodedOffset, transform, writeWirePayload: true, token: token)
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

    public static Task<DecodeResult> DecodeFileToRawFileAsync(
        string inputPath,
        string outputPath,
        CancellationToken token)
        => DecodeFileToRawFileAsync(inputPath, outputPath, AscfReaderOptions.Default, token);

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

    public static Task<long> DecodeFileToFileAsync(
        string inputPath,
        string outputPath,
        CancellationToken token)
        => DecodeFileToFileAsync(inputPath, outputPath, AscfReaderOptions.Default, token);

    public static async Task<long> DecodeFileToFileAsync(
        string inputPath,
        string outputPath,
        AscfReaderOptions options,
        CancellationToken token)
    {
        var result = await DecodeFileToRawFileAsync(inputPath, outputPath, options, token).ConfigureAwait(false);
        return result.RawSize;
    }

    public static Task<WrappedLz4FileFormat.WriteResult?> TryWriteStoredRawWrappedLz4Async(
        string inputPath,
        string outputPath,
        CancellationToken token)
        => TryWriteStoredRawWrappedLz4Async(inputPath, outputPath, AscfReaderOptions.Default, token);

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
                    if (!await TryCopyStoredRawChunksAsWrappedLz4Async(input, output, fileHeader, token).ConfigureAwait(false))
                    {
                        return null;
                    }

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
        await input.ReadExactlyAsync(header.AsMemory(0, header.Length), token).ConfigureAwait(false);
        return ValidateHeader(header, options);
    }

    private static async Task WriteWrappedRawHeaderAsync(Stream output, int rawSize, CancellationToken token)
    {
        var wrappedHeader = new byte[WrappedLz4FileFormat.HeaderSize];
        WrappedLz4FileFormat.WriteHeader(wrappedHeader, rawSize, rawSize);
        await output.WriteAsync(wrappedHeader.AsMemory(0, wrappedHeader.Length), token).ConfigureAwait(false);
    }

    private static async Task<bool> TryCopyStoredRawChunksAsWrappedLz4Async(FileStream input, Stream output, AscfFileHeader fileHeader, CancellationToken token)
    {
        var chunkHeader = new byte[AscfFileFormat.ChunkHeaderSize];
        var copyBuffer = ArrayPool<byte>.Shared.Rent(fileHeader.RawChunkSize);
        var entries = new List<AscfChunkIndexEntry>(fileHeader.ChunkCount);
        long rawSize = 0;
        long encodedOffset = AscfFileFormat.HeaderSize;
        try
        {
            for (var chunkIndex = 0; chunkIndex < fileHeader.ChunkCount; chunkIndex++)
            {
                await input.ReadExactlyAsync(chunkHeader.AsMemory(0, chunkHeader.Length), token).ConfigureAwait(false);
                var chunk = AscfChunkHeaderCodec.Read(chunkHeader, fileHeader, chunkIndex, rawSize);

                if (!chunk.StoresRaw)
                {
                    return false;
                }

                await input.ReadExactlyAsync(copyBuffer.AsMemory(0, chunk.StoredLength), token).ConfigureAwait(false);
                ValidateStoredChecksumAndRawIfStoredRaw(chunk, copyBuffer.AsSpan(0, chunk.StoredLength));
                await output.WriteAsync(copyBuffer.AsMemory(0, chunk.StoredLength), token).ConfigureAwait(false);

                entries.Add(ToIndexEntry(chunk, encodedOffset));
                rawSize += chunk.RawLength;
                encodedOffset += AscfFileFormat.ChunkHeaderSize + chunk.StoredLength;
            }

            if (rawSize != fileHeader.RawSize)
            {
                throw new InvalidDataException(".ascf decoded raw size did not match the header.");
            }

            await ReadAndValidateIndexAsync(input, output: null, entries, rawSize, encodedOffset, transform: null, writeWirePayload: false, token: token)
                .ConfigureAwait(false);
            if (input.Position != input.Length)
            {
                throw new InvalidDataException(".ascf file contained trailing bytes.");
            }

            return true;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(copyBuffer);
        }
    }

    public static Task<DecodeResult> DecodeStreamToRawFileAsync(
        Stream encodedStream,
        string outputPath,
        CancellationToken token)
        => DecodeStreamToRawFileAsync(encodedStream, outputPath, transform: null, AscfReaderOptions.Default, token);

    public static Task<DecodeResult> DecodeStreamToRawFileAsync(
        Stream encodedStream,
        string outputPath,
        AscfBufferTransform? transform,
        CancellationToken token)
        => DecodeStreamToRawFileAsync(encodedStream, outputPath, transform, AscfReaderOptions.Default, token);

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
                        transform,
                        writeWirePayload: false,
                        token: token)
                    .ConfigureAwait(false);
                await ReadAndValidateIndexAsync(encodedStream, output: null, decoded.Entries, decoded.RawSize, decoded.EncodedOffset, transform, writeWirePayload: false, token: token)
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
        AscfBufferTransform? transform,
        bool writeWirePayload,
        CancellationToken token)
    {
        long rawSize = 0;
        long encodedOffset = AscfFileFormat.HeaderSize;
        var entries = new List<AscfChunkIndexEntry>(fileHeader.ChunkCount);
        for (var chunkIndex = 0; chunkIndex < fileHeader.ChunkCount; chunkIndex++)
        {
            await ReadTransformedBytesAsync(encodedStream, chunkHeader.AsMemory(0, chunkHeader.Length), transform, token).ConfigureAwait(false);
            var chunk = AscfChunkHeaderCodec.Read(chunkHeader, fileHeader, chunkIndex, rawSize);

            await ReadTransformedBytesAsync(encodedStream, compressedBuffer.AsMemory(0, chunk.StoredLength), transform, token).ConfigureAwait(false);
            ValidateStoredChecksumAndRawIfStoredRaw(chunk, compressedBuffer.AsSpan(0, chunk.StoredLength));
            if (writeWirePayload)
            {
                await output.WriteAsync(chunkHeader.AsMemory(0, chunkHeader.Length), token).ConfigureAwait(false);
                await output.WriteAsync(compressedBuffer.AsMemory(0, chunk.StoredLength), token).ConfigureAwait(false);
            }

            if (chunk.StoresRaw)
            {
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

    private static void DecodeToArray(ReadOnlySpan<byte> encoded, byte[] raw, AscfFileHeader fileHeader)
    {
        var entries = new List<AscfChunkIndexEntry>(fileHeader.ChunkCount);
        long rawSize = 0;
        long encodedOffset = AscfFileFormat.HeaderSize;
        var position = AscfFileFormat.HeaderSize;
        for (var chunkIndex = 0; chunkIndex < fileHeader.ChunkCount; chunkIndex++)
        {
            var chunkHeader = ReadSlice(encoded, ref position, AscfFileFormat.ChunkHeaderSize);
            var chunk = AscfChunkHeaderCodec.Read(chunkHeader, fileHeader, chunkIndex, rawSize);
            var stored = ReadSlice(encoded, ref position, chunk.StoredLength);

            ValidateStoredChecksumAndRawIfStoredRaw(chunk, stored);
            var destination = raw.AsSpan(checked((int)rawSize), chunk.RawLength);
            if (chunk.StoresRaw)
            {
                stored.CopyTo(destination);
            }
            else
            {
                Lz4BlockCodec.Decode(stored, destination, chunk.RawLength);
                ValidateRawChecksum(chunk, destination);
            }

            entries.Add(ToIndexEntry(chunk, encodedOffset));
            rawSize += chunk.RawLength;
            encodedOffset += AscfFileFormat.ChunkHeaderSize + chunk.StoredLength;
        }

        if (rawSize != fileHeader.RawSize)
        {
            throw new InvalidDataException(".ascf decoded raw size did not match the header.");
        }

        ReadAndValidateIndex(encoded, ref position, entries, rawSize, encodedOffset);
        if (position != encoded.Length)
        {
            throw new InvalidDataException(".ascf stream contained trailing bytes.");
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
        var index = new byte[indexLength];
        input.ReadExactly(index);
        var footerBytes = new byte[AscfFileFormat.IndexFooterSize];
        input.ReadExactly(footerBytes);
        var footer = AscfChunkIndexCodec.ReadFooter(footerBytes, indexOffset + indexLength + AscfFileFormat.IndexFooterSize);
        ValidateIndexFooter(footer, entries, rawSize, indexOffset);
        ValidateIndexEntries(AscfChunkIndexCodec.ReadIndex(index, footer), entries);
    }

    private static void ReadAndValidateIndex(
        ReadOnlySpan<byte> encoded,
        ref int position,
        List<AscfChunkIndexEntry> entries,
        long rawSize,
        long indexOffset)
    {
        var indexLength = checked(entries.Count * AscfFileFormat.IndexEntrySize);
        var index = ReadSlice(encoded, ref position, indexLength);
        var footerBytes = ReadSlice(encoded, ref position, AscfFileFormat.IndexFooterSize);
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
        bool writeWirePayload,
        CancellationToken token)
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
            ArgumentNullException.ThrowIfNull(output);
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
        var footerBytes = new byte[AscfFileFormat.IndexFooterSize];
        input.ReadExactly(footerBytes);
        var footer = AscfChunkIndexCodec.ReadFooter(footerBytes, input.Length);
        ValidateFooterAgainstHeader(footer, fileHeader);

        input.Position = footer.IndexOffset;
        var index = new byte[checked((int)footer.IndexLength)];
        input.ReadExactly(index);
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
        var footerBytes = new byte[AscfFileFormat.IndexFooterSize];
        await input.ReadExactlyAsync(footerBytes.AsMemory(0, footerBytes.Length), token).ConfigureAwait(false);
        var footer = AscfChunkIndexCodec.ReadFooter(footerBytes, input.Length);
        ValidateFooterAgainstHeader(footer, fileHeader);

        input.Position = footer.IndexOffset;
        var index = new byte[checked((int)footer.IndexLength)];
        await input.ReadExactlyAsync(index.AsMemory(0, index.Length), token).ConfigureAwait(false);
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

                await input.ReadExactlyAsync(chunkHeader.AsMemory(0, chunkHeader.Length), token).ConfigureAwait(false);
                AscfChunkHeader chunk;
                try
                {
                    chunk = AscfChunkHeaderCodec.Read(chunkHeader, fileHeader, chunkIndex, rawSize);
                }
                catch (InvalidDataException)
                {
                    return new AscfPartialValidationResult(true, false, true, chunkIndex, rawSize, encodedOffset);
                }

                if (input.Length - input.Position < chunk.StoredLength)
                {
                    return new AscfPartialValidationResult(true, false, false, chunkIndex, rawSize, encodedOffset);
                }

                await input.ReadExactlyAsync(compressedBuffer.AsMemory(0, chunk.StoredLength), token).ConfigureAwait(false);
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
                await ReadAndValidateIndexAsync(input, output: null, entries, rawSize, encodedOffset, transform: null, writeWirePayload: false, token: token)
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
            ValidateStoredChecksumAndRawIfStoredRaw(chunk, stored);
            if (chunk.StoresRaw)
            {
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
        List<AscfChunkIndexEntry> entries,
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

    private static void ValidateIndexEntries(AscfChunkIndex index, List<AscfChunkIndexEntry> expected)
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

    private static void ValidateStoredChecksumAndRawIfStoredRaw(AscfChunkHeader chunk, ReadOnlySpan<byte> stored)
    {
        var checksum = AscfChecksum.ComputeXxHash3(stored);
        if (checksum != chunk.StoredChecksum)
        {
            throw new InvalidDataException(".ascf stored chunk checksum mismatch.");
        }

        if (chunk.StoresRaw && checksum != chunk.RawChecksum)
        {
            throw new InvalidDataException(".ascf raw chunk checksum mismatch.");
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

    private static ReadOnlySpan<byte> ReadSlice(ReadOnlySpan<byte> source, ref int position, int length)
    {
        if ((uint)position > (uint)source.Length || source.Length - position < length)
        {
            throw new EndOfStreamException();
        }

        var slice = source.Slice(position, length);
        position = checked(position + length);
        return slice;
    }

    private static async Task ReadTransformedBytesAsync(Stream stream, Memory<byte> buffer, AscfBufferTransform? transform, CancellationToken token)
    {
        await stream.ReadExactlyAsync(buffer, token).ConfigureAwait(false);

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
