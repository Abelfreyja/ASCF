using ASCF.Lz4;
using ASCF.Util;
using Microsoft.Win32.SafeHandles;
using System.Buffers;
using System.Security.Cryptography;

namespace ASCF;

public static class AscfFileReader
{
    public readonly record struct DecodeResult(AscfRawHashes Hashes, long RawSize);
    public readonly record struct StoredStreamResult(AscfRawHashes Hashes, long RawSize, long StoredSize);

    private readonly record struct DecodeFileResult(AscfRawHashes Hashes, long RawSize, bool HasHashes);
    private readonly record struct DecodedChunkResult(long RawSize, long EncodedOffset, List<AscfChunkIndexEntry> Entries);

    private sealed class DecodedRawChunk(PooledBufferOwner raw) : IDisposable
    {
        public ReadOnlyMemory<byte> Raw => raw.ReadOnlyMemory;

        public void Dispose()
            => raw.Dispose();
    }

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

    public static AscfRawHashes ReadRawHashes(string path)
        => ReadRawHashes(path, AscfReaderOptions.Default);

    public static AscfRawHashes ReadRawHashes(string path, AscfReaderOptions options)
    {
        options.Validate();
        using var input = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: options.BufferSize,
            FileOptions.SequentialScan);

        return ReadHeader(input, options).RawHashes.ToPublic();
    }

    public static Task<AscfRawHashes> ReadRawHashesAsync(string path, CancellationToken token)
        => ReadRawHashesAsync(path, AscfReaderOptions.Default, token);

    public static async Task<AscfRawHashes> ReadRawHashesAsync(string path, AscfReaderOptions options, CancellationToken token)
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
            var fileHeader = await ReadHeaderAsync(input, options, token).ConfigureAwait(false);
            return fileHeader.RawHashes.ToPublic();
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

        var fileHeader = ReadHeader(input, options);
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
            var fileHeader = await ReadHeaderAsync(input, options, token).ConfigureAwait(false);
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

            if (PartialEncodedSizeExceeded(fileHeader, input.Length))
            {
                return new AscfPartialValidationResult(true, false, true, 0, 0, input.Length);
            }

            return await ValidatePartialChunksAsync(input, fileHeader, token).ConfigureAwait(false);
        }
    }

    public static byte[] DecodeToArray(ReadOnlySpan<byte> encoded)
        => DecodeToArray(encoded, AscfReaderOptions.Default);

    public static byte[] DecodeToArray(ReadOnlySpan<byte> encoded, AscfReaderOptions options)
    {
        options.Validate();
        var fileHeader = ValidateHeader(encoded, options, encoded.Length);
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
        ValidateHashResultOptions(options);
        using var input = new FileStream(
            inputPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: options.BufferSize,
            FileOptions.SequentialScan);
        var fileHeader = ReadHeader(input, options);
        using var hasher = CreateRawHasher(GetHashAlgorithms(fileHeader, options));

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

            return new DecodeResult(GetResultHashes(FinalizeHashes(fileHeader, hasher), options), rawSize);
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
        ValidateHashResultOptions(options);
        using var stagedFile = FileFormatPaths.CreateStagedFile(outputPath);
        StoredStreamResult storedResult;

        var output = FileFormatPaths.OpenSequentialStagingWrite(stagedFile.StagingPath, options.BufferSize);
        await using (output.ConfigureAwait(false))
        {
            var header = new byte[AscfFileFormat.HeaderSize];
            var encodedStartPosition = encodedStream.CanSeek ? encodedStream.Position : 0;
            await ReadTransformedBytesAsync(encodedStream, header.AsMemory(0, header.Length), transform, token).ConfigureAwait(false);
            var fileHeader = ValidateHeader(
                header,
                options,
                encodedStream.CanSeek ? encodedStream.Length - encodedStartPosition : null);
            using var hasher = CreateRawHasher(GetHashAlgorithms(fileHeader, options));
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

                var hashes = FinalizeHashes(fileHeader, hasher);
                await RewriteStoredHeaderAsync(
                        output,
                        fileHeader,
                        output.Length,
                        fileHeader.RawHashes.Merge(hashes),
                        token)
                    .ConfigureAwait(false);
                await output.FlushAsync(token).ConfigureAwait(false);
                storedResult = new StoredStreamResult(GetResultHashes(hashes, options), decoded.RawSize, output.Length);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(rawBuffer);
                ArrayPool<byte>.Shared.Return(compressedBuffer);
            }
        }

        stagedFile.Commit();
        return storedResult;
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
        ValidateHashResultOptions(options);
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
            return await DecodeStreamToFileAsync(input, outputPath, transform: null, options, token).ConfigureAwait(false);
        }
    }

    public static Task<DecodeResult> DecodeFileToRawFileParallelAsync(
        string inputPath,
        string outputPath,
        CancellationToken token)
        => DecodeFileToRawFileParallelAsync(inputPath, outputPath, AscfReaderOptions.Default, token);

    public static Task<DecodeResult> DecodeFileToRawFileParallelAsync(
        string inputPath,
        string outputPath,
        AscfReaderOptions options,
        CancellationToken token)
        => DecodeFileToRawFileParallelWithHashAsync(inputPath, outputPath, options, token);

    public static Task<DecodeResult> DecodeFileToRawFileParallelOrderedAsync(
        string inputPath,
        string outputPath,
        CancellationToken token)
        => DecodeFileToRawFileParallelOrderedAsync(inputPath, outputPath, AscfReaderOptions.Default, token);

    public static Task<DecodeResult> DecodeFileToRawFileParallelOrderedAsync(
        string inputPath,
        string outputPath,
        AscfReaderOptions options,
        CancellationToken token)
        => DecodeFileToRawFileParallelWithHashAsync(inputPath, outputPath, options with
        {
            ParallelDecodeMode = AscfParallelDecodeMode.OrderedWrite
        }, token);

    private static async Task<DecodeFileResult> DecodeFileToRawFileParallelCoreAsync(
        string inputPath,
        string outputPath,
        AscfReaderOptions options,
        bool computeHash,
        CancellationToken token)
    {
        options.Validate();
        using var stagedFile = FileFormatPaths.CreateStagedFile(outputPath);

        var input = new FileStream(
            inputPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: options.BufferSize,
            FileOptions.Asynchronous | FileOptions.RandomAccess);
        await using (input.ConfigureAwait(false))
        {
            var fileHeader = await ReadHeaderAsync(input, options, token).ConfigureAwait(false);
            var chunkIndex = await ReadChunkIndexFromEndAsync(input, fileHeader, token).ConfigureAwait(false);

            var decodeMode = options.ResolveParallelDecodeMode(computeHash);
            var result = decodeMode switch
            {
                AscfParallelDecodeMode.OrderedWrite => await DecodeCompleteFileParallelOrderedAsync(input, stagedFile.StagingPath, fileHeader, chunkIndex, options, computeHash, token).ConfigureAwait(false),
                AscfParallelDecodeMode.RandomWrite => await DecodeCompleteFileParallelRandomWriteAsync(input, stagedFile.StagingPath, fileHeader, chunkIndex, options, computeHash, token).ConfigureAwait(false),
                _ => throw new ArgumentOutOfRangeException(nameof(options), decodeMode, "Parallel decode mode is not supported.")
            };
            stagedFile.Commit();
            return result;
        }
    }

    private static async Task<DecodeResult> DecodeFileToRawFileParallelWithHashAsync(
        string inputPath,
        string outputPath,
        AscfReaderOptions options,
        CancellationToken token)
    {
        ValidateHashResultOptions(options);
        var result = await DecodeFileToRawFileParallelCoreAsync(inputPath, outputPath, options, computeHash: true, token)
            .ConfigureAwait(false);
        return RequireHash(result);
    }

    public static Task<long> DecodeFileToFileParallelAsync(
        string inputPath,
        string outputPath,
        CancellationToken token)
        => DecodeFileToFileParallelAsync(inputPath, outputPath, AscfReaderOptions.Default, token);

    public static async Task<long> DecodeFileToFileParallelAsync(
        string inputPath,
        string outputPath,
        AscfReaderOptions options,
        CancellationToken token)
    {
        var result = await DecodeFileToRawFileParallelCoreAsync(inputPath, outputPath, options, computeHash: false, token)
            .ConfigureAwait(false);
        return result.RawSize;
    }

    private static async Task<DecodeFileResult> DecodeCompleteFileParallelRandomWriteAsync(
        FileStream input,
        string outputPath,
        AscfFileHeader fileHeader,
        AscfChunkIndex chunkIndex,
        AscfReaderOptions options,
        bool computeHash,
        CancellationToken token)
    {
        var output = FileFormatPaths.OpenRandomStagingReadWrite(outputPath, options.BufferSize);
        await using (output.ConfigureAwait(false))
        {
            output.SetLength(fileHeader.RawSize);
            await DecodeChunksParallelRandomWriteAsync(
                    input.SafeFileHandle,
                    output.SafeFileHandle,
                    fileHeader,
                    chunkIndex,
                    options.GetParallelDecodeWorkerCount(),
                    token)
                .ConfigureAwait(false);

            await output.FlushAsync(token).ConfigureAwait(false);
            var hashes = AscfRawHashBytes.Empty;
            if (computeHash)
            {
                output.Position = 0;
                hashes = await ComputeHashesAsync(output, GetHashAlgorithms(fileHeader, options), options.BufferSize, token).ConfigureAwait(false);
                ValidateStoredHashes(fileHeader, hashes);
            }

            return new DecodeFileResult(GetResultHashes(hashes, options), fileHeader.RawSize, computeHash);
        }
    }

    private static async Task<DecodeFileResult> DecodeCompleteFileParallelOrderedAsync(
        FileStream input,
        string outputPath,
        AscfFileHeader fileHeader,
        AscfChunkIndex chunkIndex,
        AscfReaderOptions options,
        bool computeHash,
        CancellationToken token)
    {
        var output = FileFormatPaths.OpenSequentialStagingWrite(outputPath, options.BufferSize);
        await using (output.ConfigureAwait(false))
        {
            output.SetLength(fileHeader.RawSize);
            output.Position = 0;
            using var hasher = computeHash ? CreateRawHasher(GetHashAlgorithms(fileHeader, options)) : null;
            await DecodeChunksParallelOrderedAsync(
                    input.SafeFileHandle,
                    output,
                    hasher,
                    fileHeader,
                    chunkIndex,
                    options.GetParallelDecodeWorkerCount(),
                    token)
                .ConfigureAwait(false);

            await output.FlushAsync(token).ConfigureAwait(false);
            return hasher is null
                ? new DecodeFileResult(default, fileHeader.RawSize, HasHashes: false)
                : new DecodeFileResult(GetResultHashes(FinalizeHashes(fileHeader, hasher), options), fileHeader.RawSize, HasHashes: true);
        }
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
        using var stagedFile = FileFormatPaths.CreateStagedFile(outputPath);

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

            var output = FileFormatPaths.OpenSequentialStagingWrite(stagedFile.StagingPath, options.BufferSize);
            await using (output.ConfigureAwait(false))
            {
                await WriteWrappedRawHeaderAsync(output, wrappedRawSize, token).ConfigureAwait(false);
                if (!await TryCopyStoredRawChunksAsWrappedLz4Async(input, output, fileHeader, token).ConfigureAwait(false))
                {
                    return null;
                }

                await output.FlushAsync(token).ConfigureAwait(false);
            }

            stagedFile.Commit();
            return new WrappedLz4FileFormat.WriteResult(fileHeader.RawSize, WrappedLz4FileFormat.HeaderSize + fileHeader.RawSize);
        }
    }

    private static async Task<AscfFileHeader> ReadHeaderAsync(Stream input, AscfReaderOptions options, CancellationToken token)
    {
        var header = new byte[AscfFileFormat.HeaderSize];
        var encodedStartPosition = input.CanSeek ? input.Position : 0;
        await input.ReadExactlyAsync(header.AsMemory(0, header.Length), token).ConfigureAwait(false);
        return ValidateHeader(
            header,
            options,
            input.CanSeek ? input.Length - encodedStartPosition : null);
    }

    private static AscfFileHeader ReadHeader(Stream input, AscfReaderOptions options)
    {
        var header = new byte[AscfFileFormat.HeaderSize];
        var encodedStartPosition = input.CanSeek ? input.Position : 0;
        input.ReadExactly(header);
        return ValidateHeader(
            header,
            options,
            input.CanSeek ? input.Length - encodedStartPosition : null);
    }

    private static async Task WriteWrappedRawHeaderAsync(Stream output, int rawSize, CancellationToken token)
    {
        var wrappedHeader = new byte[WrappedLz4FileFormat.HeaderSize];
        WrappedLz4FileFormat.WriteHeader(wrappedHeader, rawSize, rawSize);
        await output.WriteAsync(wrappedHeader.AsMemory(0, wrappedHeader.Length), token).ConfigureAwait(false);
    }

    private static async Task RewriteStoredHeaderAsync(
        FileStream output,
        AscfFileHeader fileHeader,
        long encodedSize,
        AscfRawHashBytes rawHashes,
        CancellationToken token)
    {
        var header = new byte[AscfFileFormat.HeaderSize];
        AscfFileHeaderCodec.Write(
            header,
            fileHeader.RawSize,
            fileHeader.RawChunkSize,
            fileHeader.ChunkCount,
            fileHeader.StreamId,
            encodedSize,
            rawHashes);

        output.Position = 0;
        await output.WriteAsync(header.AsMemory(0, header.Length), token).ConfigureAwait(false);
        output.Position = output.Length;
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
        ValidateHashResultOptions(options);
        var result = await DecodeStreamToFileCoreAsync(encodedStream, outputPath, transform, options, computeHash: true, token)
            .ConfigureAwait(false);
        return RequireHash(result);
    }

    public static Task<long> DecodeStreamToFileAsync(
        Stream encodedStream,
        string outputPath,
        CancellationToken token)
        => DecodeStreamToFileAsync(encodedStream, outputPath, transform: null, AscfReaderOptions.Default, token);

    public static Task<long> DecodeStreamToFileAsync(
        Stream encodedStream,
        string outputPath,
        AscfBufferTransform? transform,
        CancellationToken token)
        => DecodeStreamToFileAsync(encodedStream, outputPath, transform, AscfReaderOptions.Default, token);

    public static async Task<long> DecodeStreamToFileAsync(
        Stream encodedStream,
        string outputPath,
        AscfBufferTransform? transform,
        AscfReaderOptions options,
        CancellationToken token)
    {
        var result = await DecodeStreamToFileCoreAsync(encodedStream, outputPath, transform, options, computeHash: false, token)
            .ConfigureAwait(false);
        return result.RawSize;
    }

    private static async Task<DecodeFileResult> DecodeStreamToFileCoreAsync(
        Stream encodedStream,
        string outputPath,
        AscfBufferTransform? transform,
        AscfReaderOptions options,
        bool computeHash,
        CancellationToken token)
    {
        options.Validate();
        using var stagedFile = FileFormatPaths.CreateStagedFile(outputPath);
        DecodeFileResult decodedResult;

        var output = FileFormatPaths.OpenSequentialStagingWrite(stagedFile.StagingPath, options.BufferSize);
        await using (output.ConfigureAwait(false))
        {
            var header = new byte[AscfFileFormat.HeaderSize];
            var encodedStartPosition = encodedStream.CanSeek ? encodedStream.Position : 0;
            await ReadTransformedBytesAsync(encodedStream, header.AsMemory(0, header.Length), transform, token).ConfigureAwait(false);
            var fileHeader = ValidateHeader(
                header,
                options,
                encodedStream.CanSeek ? encodedStream.Length - encodedStartPosition : null);
            using var hasher = computeHash ? CreateRawHasher(GetHashAlgorithms(fileHeader, options)) : null;

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
                decodedResult = hasher is null
                    ? new DecodeFileResult(default, decoded.RawSize, HasHashes: false)
                    : new DecodeFileResult(GetResultHashes(FinalizeHashes(fileHeader, hasher), options), decoded.RawSize, HasHashes: true);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(rawBuffer);
                ArrayPool<byte>.Shared.Return(compressedBuffer);
            }
        }

        stagedFile.Commit();
        return decodedResult;
    }

    private static async Task<DecodedChunkResult> DecodeChunksAsync(
        Stream encodedStream,
        Stream output,
        AscfRawContentHasher? hasher,
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

    private static AscfFileHeader ValidateHeader(ReadOnlySpan<byte> header, AscfReaderOptions options, long? encodedLength)
    {
        var fileHeader = AscfFileHeaderCodec.Read(header, options.MaxRawFileBytes);
        if (encodedLength.HasValue)
        {
            ValidateEncodedSize(fileHeader, encodedLength.Value);
        }

        return fileHeader;
    }

    private static void ValidateEncodedSize(AscfFileHeader header, long actualLength)
    {
        if (header.EncodedSize != 0 && header.EncodedSize != actualLength)
        {
            throw new InvalidDataException(".ascf encoded size does not match file length.");
        }
    }

    private static bool PartialEncodedSizeExceeded(AscfFileHeader header, long partialLength)
        => header.EncodedSize != 0 && partialLength > header.EncodedSize;

    private static DecodeResult RequireHash(DecodeFileResult result)
        => result.HasHashes
            ? new DecodeResult(result.Hashes, result.RawSize)
            : throw new InvalidOperationException(".ascf decode did not produce a hash.");

    private static void ValidateHashResultOptions(AscfReaderOptions options)
    {
        options.Validate();
        if (options.GetResultHashAlgorithms() == AscfRawHashAlgorithms.None)
        {
            throw new ArgumentException("At least one result hash algorithm must be selected.", nameof(options));
        }
    }

    private static AscfRawContentHasher CreateRawHasher(AscfRawHashAlgorithms algorithms)
    {
        AscfRawHashAlgorithmFlags.ValidateSupported(algorithms, nameof(algorithms));
        return AscfRawContentHasher.Create(algorithms)
            ?? throw new InvalidOperationException(".ascf hash algorithm is invalid.");
    }

    private static AscfRawHashAlgorithms GetHashAlgorithms(AscfFileHeader fileHeader, AscfReaderOptions options)
        => options.GetResultHashAlgorithms() | fileHeader.RawHashes.Algorithms;

    private static AscfRawHashes GetResultHashes(AscfRawHashBytes hashes, AscfReaderOptions options)
        => hashes.Filter(options.GetResultHashAlgorithms()).ToPublic();

    private static AscfRawHashBytes FinalizeHashes(AscfFileHeader fileHeader, AscfRawContentHasher hasher)
    {
        var rawHashes = hasher.FinalizeHashes();
        ValidateStoredHashes(fileHeader, rawHashes);
        return rawHashes;
    }

    private static void ValidateStoredHashes(AscfFileHeader fileHeader, AscfRawHashBytes computed)
    {
        ValidateStoredHash(fileHeader.RawHashes.Sha1, computed.Sha1, AscfRawHashAlgorithms.Sha1);
        ValidateStoredHash(fileHeader.RawHashes.Blake3, computed.Blake3, AscfRawHashAlgorithms.Blake3);
    }

    private static void ValidateStoredHash(byte[]? stored, byte[]? computed, AscfRawHashAlgorithms algorithm)
    {
        if (stored != null
            && computed != null
            && !CryptographicOperations.FixedTimeEquals(stored, computed))
        {
            throw new InvalidDataException($".ascf raw {AscfRawHashAlgorithmFlags.GetDisplayName(algorithm)} hash does not match decoded content.");
        }
    }

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
        var indexLength = checked((long)entries.Count * AscfFileFormat.IndexEntrySize);
        Span<byte> entryBytes = stackalloc byte[AscfFileFormat.IndexEntrySize];
        var indexChecksum = AscfChecksum.CreateIncrementalXxHash3();
        for (var i = 0; i < entries.Count; i++)
        {
            input.ReadExactly(entryBytes);
            indexChecksum.Append(entryBytes);
            ValidateIndexEntry(AscfChunkIndexCodec.ReadEntry(entryBytes), entries[i]);
        }

        var footerBytes = new byte[AscfFileFormat.IndexFooterSize];
        input.ReadExactly(footerBytes);
        var footer = AscfChunkIndexCodec.ReadFooter(footerBytes, indexOffset + indexLength + AscfFileFormat.IndexFooterSize);
        ValidateIndexFooter(footer, entries, rawSize, indexOffset);
        ValidateIndexChecksum(footer, indexChecksum.GetCurrentHashAsUInt64());
    }

    private static void ReadAndValidateIndex(
        ReadOnlySpan<byte> encoded,
        ref int position,
        List<AscfChunkIndexEntry> entries,
        long rawSize,
        long indexOffset)
    {
        var indexLength = checked((long)entries.Count * AscfFileFormat.IndexEntrySize);
        var indexChecksum = AscfChecksum.CreateIncrementalXxHash3();
        for (var i = 0; i < entries.Count; i++)
        {
            var entryBytes = ReadSlice(encoded, ref position, AscfFileFormat.IndexEntrySize);
            indexChecksum.Append(entryBytes);
            ValidateIndexEntry(AscfChunkIndexCodec.ReadEntry(entryBytes), entries[i]);
        }

        var footerBytes = ReadSlice(encoded, ref position, AscfFileFormat.IndexFooterSize);
        var footer = AscfChunkIndexCodec.ReadFooter(footerBytes, indexOffset + indexLength + AscfFileFormat.IndexFooterSize);
        ValidateIndexFooter(footer, entries, rawSize, indexOffset);
        ValidateIndexChecksum(footer, indexChecksum.GetCurrentHashAsUInt64());
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
        if (writeWirePayload)
        {
            ArgumentNullException.ThrowIfNull(output);
        }

        var indexLength = checked((long)entries.Count * AscfFileFormat.IndexEntrySize);
        var entryBytes = new byte[AscfFileFormat.IndexEntrySize];
        var indexChecksum = AscfChecksum.CreateIncrementalXxHash3();
        for (var i = 0; i < entries.Count; i++)
        {
            await ReadTransformedBytesAsync(input, entryBytes.AsMemory(0, entryBytes.Length), transform, token).ConfigureAwait(false);
            indexChecksum.Append(entryBytes);
            ValidateIndexEntry(AscfChunkIndexCodec.ReadEntry(entryBytes), entries[i]);

            if (writeWirePayload)
            {
                await output!.WriteAsync(entryBytes.AsMemory(0, entryBytes.Length), token).ConfigureAwait(false);
            }
        }

        var footerBytes = new byte[AscfFileFormat.IndexFooterSize];
        await ReadTransformedBytesAsync(input, footerBytes.AsMemory(0, footerBytes.Length), transform, token).ConfigureAwait(false);

        var footer = AscfChunkIndexCodec.ReadFooter(footerBytes, indexOffset + indexLength + AscfFileFormat.IndexFooterSize);
        ValidateIndexFooter(footer, entries, rawSize, indexOffset);
        ValidateIndexChecksum(footer, indexChecksum.GetCurrentHashAsUInt64());

        if (writeWirePayload)
        {
            await output!.WriteAsync(footerBytes.AsMemory(0, footerBytes.Length), token).ConfigureAwait(false);
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
        var chunkIndex = ReadChunkIndexEntries(input, footer);
        chunkIndex.ValidateForRandomAccess(fileHeader, footer.IndexOffset);
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
        var chunkIndex = await ReadChunkIndexEntriesAsync(input, footer, token).ConfigureAwait(false);
        chunkIndex.ValidateForRandomAccess(fileHeader, footer.IndexOffset);
        return chunkIndex;
    }

    private static AscfChunkIndex ReadChunkIndexEntries(Stream input, AscfIndexFooter footer)
    {
        var entries = new AscfChunkIndexEntry[footer.ChunkCount];
        Span<byte> entryBytes = stackalloc byte[AscfFileFormat.IndexEntrySize];
        var indexChecksum = AscfChecksum.CreateIncrementalXxHash3();
        for (var i = 0; i < entries.Length; i++)
        {
            input.ReadExactly(entryBytes);
            indexChecksum.Append(entryBytes);
            entries[i] = AscfChunkIndexCodec.ReadEntry(entryBytes);
        }

        ValidateIndexChecksum(footer, indexChecksum.GetCurrentHashAsUInt64());
        return new AscfChunkIndex(entries);
    }

    private static async Task<AscfChunkIndex> ReadChunkIndexEntriesAsync(FileStream input, AscfIndexFooter footer, CancellationToken token)
    {
        var entries = new AscfChunkIndexEntry[footer.ChunkCount];
        var entryBytes = new byte[AscfFileFormat.IndexEntrySize];
        var indexChecksum = AscfChecksum.CreateIncrementalXxHash3();
        for (var i = 0; i < entries.Length; i++)
        {
            await input.ReadExactlyAsync(entryBytes.AsMemory(0, entryBytes.Length), token).ConfigureAwait(false);
            indexChecksum.Append(entryBytes);
            entries[i] = AscfChunkIndexCodec.ReadEntry(entryBytes);
        }

        ValidateIndexChecksum(footer, indexChecksum.GetCurrentHashAsUInt64());
        return new AscfChunkIndex(entries);
    }

    private static async Task DecodeChunksParallelRandomWriteAsync(
        SafeFileHandle inputHandle,
        SafeFileHandle outputHandle,
        AscfFileHeader fileHeader,
        AscfChunkIndex chunkIndex,
        int workerCount,
        CancellationToken token)
    {
        var parallelOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = workerCount,
            CancellationToken = token
        };

        await Parallel.ForEachAsync(
                chunkIndex.Entries,
                parallelOptions,
                async (entry, cancellationToken) =>
                {
                    using var decoded = await DecodeChunkToBufferAsync(inputHandle, fileHeader, entry, cancellationToken).ConfigureAwait(false);
                    await RandomAccess.WriteAsync(outputHandle, decoded.Raw, entry.RawOffset, cancellationToken).ConfigureAwait(false);
                })
            .ConfigureAwait(false);
    }

    private static async Task DecodeChunksParallelOrderedAsync(
        SafeFileHandle inputHandle,
        Stream output,
        AscfRawContentHasher? hasher,
        AscfFileHeader fileHeader,
        AscfChunkIndex chunkIndex,
        int workerCount,
        CancellationToken token)
    {
        var entries = chunkIndex.Entries;
        var pending = new Queue<Task<DecodedRawChunk>>(Math.Min(workerCount, entries.Count));
        var nextEntry = 0;
        try
        {
            while (nextEntry < entries.Count && pending.Count < workerCount)
            {
                pending.Enqueue(DecodeChunkToBufferAsync(inputHandle, fileHeader, entries[nextEntry++], token));
            }

            while (pending.Count > 0)
            {
                using var decoded = await pending.Dequeue().ConfigureAwait(false);
                hasher?.AppendData(decoded.Raw.Span);
                await output.WriteAsync(decoded.Raw, token).ConfigureAwait(false);

                if (nextEntry < entries.Count)
                {
                    pending.Enqueue(DecodeChunkToBufferAsync(inputHandle, fileHeader, entries[nextEntry++], token));
                }
            }
        }
        catch
        {
            await ReturnPendingDecodedChunksAsync(pending).ConfigureAwait(false);
            throw;
        }
    }

    private static async Task ReturnPendingDecodedChunksAsync(Queue<Task<DecodedRawChunk>> pending)
    {
        while (pending.Count > 0)
        {
            try
            {
                using var decoded = await pending.Dequeue().ConfigureAwait(false);
            }
            catch
            {
                // best effort cleanup after a failed parallel decode
            }
        }
    }

    private static async Task<DecodedRawChunk> DecodeChunkToBufferAsync(
        SafeFileHandle inputHandle,
        AscfFileHeader fileHeader,
        AscfChunkIndexEntry entry,
        CancellationToken token)
    {
        var recordLength = checked(AscfFileFormat.ChunkHeaderSize + entry.StoredLength);
        byte[]? recordBuffer = ArrayPool<byte>.Shared.Rent(recordLength);
        byte[]? rawBuffer = null;
        try
        {
            await ReadExactlyAtAsync(inputHandle, recordBuffer.AsMemory(0, recordLength), entry.ChunkOffset, token).ConfigureAwait(false);

            var header = recordBuffer.AsSpan(0, AscfFileFormat.ChunkHeaderSize);
            var chunk = AscfChunkHeaderCodec.Read(header, fileHeader, entry.ChunkIndex, entry.RawOffset);
            ValidateIndexEntry(ToIndexEntry(chunk, entry.ChunkOffset), entry);

            var stored = recordBuffer.AsSpan(AscfFileFormat.ChunkHeaderSize, chunk.StoredLength);
            ValidateStoredChecksumAndRawIfStoredRaw(chunk, stored);
            if (chunk.StoresRaw)
            {
                var decoded = new DecodedRawChunk(new PooledBufferOwner(recordBuffer, chunk.RawLength, AscfFileFormat.ChunkHeaderSize));
                recordBuffer = null;
                return decoded;
            }

            rawBuffer = ArrayPool<byte>.Shared.Rent(chunk.RawLength);
            Lz4BlockCodec.Decode(stored, rawBuffer.AsSpan(0, chunk.RawLength), chunk.RawLength);
            ValidateRawChecksum(chunk, rawBuffer.AsSpan(0, chunk.RawLength));
            var raw = new DecodedRawChunk(new PooledBufferOwner(rawBuffer, chunk.RawLength));
            rawBuffer = null;
            return raw;
        }
        finally
        {
            if (recordBuffer != null)
            {
                ArrayPool<byte>.Shared.Return(recordBuffer);
            }

            if (rawBuffer != null)
            {
                ArrayPool<byte>.Shared.Return(rawBuffer);
            }
        }
    }

    private static async ValueTask ReadExactlyAtAsync(SafeFileHandle handle, Memory<byte> buffer, long fileOffset, CancellationToken token)
    {
        var readTotal = 0;
        while (readTotal < buffer.Length)
        {
            var read = await RandomAccess.ReadAsync(handle, buffer.Slice(readTotal), fileOffset + readTotal, token).ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException();
            }

            readTotal += read;
        }
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
            var isMissingDeclaredBytes = fileHeader.EncodedSize != 0 && input.Length < fileHeader.EncodedSize;
            return new AscfPartialValidationResult(true, !isCorrupt && !isMissingDeclaredBytes, isCorrupt, entries.Count, rawSize, input.Position);
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

    private static void ValidateIndexEntry(AscfChunkIndexEntry actual, AscfChunkIndexEntry expected)
    {
        if (!actual.Equals(expected))
        {
            throw new InvalidDataException(".ascf index entry mismatch.");
        }
    }

    private static void ValidateIndexChecksum(AscfIndexFooter footer, ulong indexChecksum)
    {
        if (footer.IndexChecksum != indexChecksum)
        {
            throw new InvalidDataException(".ascf index checksum mismatch.");
        }
    }

    private static async Task<AscfRawHashBytes> ComputeHashesAsync(Stream input, AscfRawHashAlgorithms algorithms, int bufferSize, CancellationToken token)
    {
        FileFormatBuffers.ValidateBufferSize(bufferSize, nameof(bufferSize));

        using var hasher = CreateRawHasher(algorithms);
        var buffer = ArrayPool<byte>.Shared.Rent(bufferSize);
        try
        {
            while (true)
            {
                var read = await input.ReadAsync(buffer.AsMemory(0, buffer.Length), token).ConfigureAwait(false);
                if (read == 0)
                {
                    return hasher.FinalizeHashes();
                }

                hasher.AppendData(buffer.AsSpan(0, read));
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
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

}
