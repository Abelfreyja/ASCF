using System.Buffers;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using ASCF.Lz4;
using ASCF.Util;

namespace ASCF;

public static class AscfFileWriter
{
    [StructLayout(LayoutKind.Auto)]
    public readonly record struct WriteResult(long RawSize, long StoredSize);

    [StructLayout(LayoutKind.Auto)]
    public readonly record struct HashedWriteResult(string Hash, long RawSize, long StoredSize);

    [StructLayout(LayoutKind.Auto)]
    private readonly record struct WriteOptions(
        AscfWriterOptions Format,
        Func<int, CancellationToken, ValueTask>? WaitForBytes,
        IProgress<long>? Progress,
        AscfBufferTransform? Transform);

    [StructLayout(LayoutKind.Auto)]
    private readonly record struct CompressedWriteResult(long RawSize, int ChunkCount, long EncodedOffset, List<AscfChunkIndexEntry> Entries);

    [StructLayout(LayoutKind.Auto)]
    private readonly record struct ChunkWriteResult(int RawLength, long EncodedLength);

    public static async Task<long> WriteFileAsync(string sourcePath, string outputPath, CancellationToken token)
        => await WriteFileAsync(sourcePath, outputPath, AscfWriterOptions.Default, token).ConfigureAwait(false);

    public static async Task<long> WriteFileAsync(string sourcePath, string outputPath, AscfWriterOptions options, CancellationToken token)
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
            await WriteFileAsync(sourcePath, output, options, token).ConfigureAwait(false);
            await output.FlushAsync(token).ConfigureAwait(false);
            return output.Length;
        }
    }

    public static async Task<HashedWriteResult> WriteFileWithHashAsync(string sourcePath, string outputPath, CancellationToken token)
        => await WriteFileWithHashAsync(sourcePath, outputPath, AscfWriterOptions.Default, token).ConfigureAwait(false);

    public static async Task<HashedWriteResult> WriteFileWithHashAsync(string sourcePath, string outputPath, AscfWriterOptions options, CancellationToken token)
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
            var result = await WriteFileToStreamWithHashAsync(sourcePath, output, options, token).ConfigureAwait(false);
            await output.FlushAsync(token).ConfigureAwait(false);
            return new HashedWriteResult(result.Hash, result.RawSize, output.Length);
        }
    }

    public static async Task WriteFileAsync(string sourcePath, Stream destination, CancellationToken token)
        => await WriteFileAsync(sourcePath, destination, AscfWriterOptions.Default, token).ConfigureAwait(false);

    public static async Task WriteFileAsync(string sourcePath, Stream destination, AscfWriterOptions options, CancellationToken token)
    {
        options.Validate();
        await WriteFileInternalAsync(sourcePath, destination, hasher: null, new WriteOptions(options, null, null, null), token).ConfigureAwait(false);
    }

    public static async Task WriteFileAsync(
        string sourcePath,
        Stream destination,
        Func<int, CancellationToken, ValueTask>? waitForBytes,
        IProgress<long>? progress,
        AscfBufferTransform? transform,
        CancellationToken token)
        => await WriteFileAsync(sourcePath, destination, AscfWriterOptions.Default, waitForBytes, progress, transform, token).ConfigureAwait(false);

    public static async Task WriteFileAsync(
        string sourcePath,
        Stream destination,
        AscfWriterOptions formatOptions,
        Func<int, CancellationToken, ValueTask>? waitForBytes,
        IProgress<long>? progress,
        AscfBufferTransform? transform,
        CancellationToken token)
    {
        formatOptions.Validate();
        var options = new WriteOptions(formatOptions, waitForBytes, progress, transform);
        await WriteFileInternalAsync(sourcePath, destination, hasher: null, options, token).ConfigureAwait(false);
    }

    private static async Task<(string Hash, long RawSize)> WriteFileToStreamWithHashAsync(
        string sourcePath,
        Stream destination,
        AscfWriterOptions options,
        CancellationToken token)
    {
        using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
        var rawSize = await WriteFileInternalAsync(sourcePath, destination, hasher, new WriteOptions(options, null, null, null), token).ConfigureAwait(false);
        return (Convert.ToHexString(hasher.GetHashAndReset()), rawSize);
    }

    private static async Task<long> WriteFileInternalAsync(
        string sourcePath,
        Stream destination,
        IncrementalHash? hasher,
        WriteOptions options,
        CancellationToken token)
    {
        var sourceInfo = new FileInfo(sourcePath);
        ValidateRawSize(sourceInfo.Length, options.Format.MaxRawFileBytes);

        var source = new FileStream(
            sourcePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: options.Format.BufferSize,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        await using (source.ConfigureAwait(false))
        {
            var chunkCount = AscfFileFormat.GetChunkCount(sourceInfo.Length, options.Format.RawChunkSize);
            var streamId = Guid.NewGuid();
            await WriteHeaderAsync(destination, sourceInfo.Length, options.Format.RawChunkSize, chunkCount, streamId, 0, options, token)
                .ConfigureAwait(false);
            var result = await WriteCompressedChunksAsync(source, destination, hasher, knownChunkCount: chunkCount, options, token)
                .ConfigureAwait(false);
            if (result.RawSize != sourceInfo.Length)
            {
                throw new InvalidDataException($".ascf source size changed while writing (expected {sourceInfo.Length}, got {result.RawSize}).");
            }

            await WriteIndexAsync(destination, result.Entries, result.RawSize, result.EncodedOffset, options, token)
                .ConfigureAwait(false);
            await TryRewriteHeaderAsync(destination, result.RawSize, result.ChunkCount, streamId, options, token).ConfigureAwait(false);
            return result.RawSize;
        }
    }

    public static async Task<WriteResult> WriteStreamToFileAsync(Stream source, string outputPath, CancellationToken token)
        => await WriteStreamToFileAsync(source, outputPath, AscfWriterOptions.Default, token).ConfigureAwait(false);

    public static async Task<WriteResult> WriteStreamToFileAsync(Stream source, string outputPath, AscfWriterOptions options, CancellationToken token)
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
            var streamId = Guid.NewGuid();
            var writeOptions = new WriteOptions(options, null, null, null);
            await WriteHeaderAsync(output, 0, options.RawChunkSize, 0, streamId, 0, writeOptions, token).ConfigureAwait(false);
            var result = await WriteCompressedChunksAsync(source, output, hasher: null, knownChunkCount: null, writeOptions, token).ConfigureAwait(false);
            ValidateRawSize(result.RawSize, options.MaxRawFileBytes);
            await WriteIndexAsync(output, result.Entries, result.RawSize, result.EncodedOffset, writeOptions, token).ConfigureAwait(false);
            await RewriteHeaderAsync(output, result.RawSize, options.RawChunkSize, result.ChunkCount, streamId, output.Length, token).ConfigureAwait(false);
            await output.FlushAsync(token).ConfigureAwait(false);
            return new WriteResult(result.RawSize, output.Length);
        }
    }

    public static async Task<HashedWriteResult> WriteStreamToFileWithHashAsync(Stream source, string outputPath, CancellationToken token)
        => await WriteStreamToFileWithHashAsync(source, outputPath, AscfWriterOptions.Default, token).ConfigureAwait(false);

    public static async Task<HashedWriteResult> WriteStreamToFileWithHashAsync(Stream source, string outputPath, AscfWriterOptions options, CancellationToken token)
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
        using (var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA1))
        {
            var streamId = Guid.NewGuid();
            var writeOptions = new WriteOptions(options, null, null, null);
            await WriteHeaderAsync(output, 0, options.RawChunkSize, 0, streamId, 0, writeOptions, token).ConfigureAwait(false);
            var result = await WriteCompressedChunksAsync(source, output, hasher, knownChunkCount: null, writeOptions, token).ConfigureAwait(false);
            ValidateRawSize(result.RawSize, options.MaxRawFileBytes);
            await WriteIndexAsync(output, result.Entries, result.RawSize, result.EncodedOffset, writeOptions, token).ConfigureAwait(false);
            await RewriteHeaderAsync(output, result.RawSize, options.RawChunkSize, result.ChunkCount, streamId, output.Length, token).ConfigureAwait(false);
            await output.FlushAsync(token).ConfigureAwait(false);
            return new HashedWriteResult(Convert.ToHexString(hasher.GetHashAndReset()), result.RawSize, output.Length);
        }
    }

    public static async Task<long> WriteStoredRawFileAsync(
        string sourcePath,
        long sourceOffset,
        long rawLength,
        string outputPath,
        CancellationToken token)
        => await WriteStoredRawFileAsync(sourcePath, sourceOffset, rawLength, outputPath, AscfWriterOptions.Default, token).ConfigureAwait(false);

    public static async Task<long> WriteStoredRawFileAsync(
        string sourcePath,
        long sourceOffset,
        long rawLength,
        string outputPath,
        AscfWriterOptions options,
        CancellationToken token)
    {
        options.Validate();
        var result = await WriteStoredRawFileInternalAsync(sourcePath, sourceOffset, rawLength, outputPath, options, hasher: null, token)
            .ConfigureAwait(false);
        return result.StoredSize;
    }

    public static async Task<HashedWriteResult> WriteStoredRawFileWithHashAsync(
        string sourcePath,
        long sourceOffset,
        long rawLength,
        string outputPath,
        CancellationToken token)
        => await WriteStoredRawFileWithHashAsync(sourcePath, sourceOffset, rawLength, outputPath, AscfWriterOptions.Default, token).ConfigureAwait(false);

    public static async Task<HashedWriteResult> WriteStoredRawFileWithHashAsync(
        string sourcePath,
        long sourceOffset,
        long rawLength,
        string outputPath,
        AscfWriterOptions options,
        CancellationToken token)
    {
        options.Validate();
        using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
        var result = await WriteStoredRawFileInternalAsync(sourcePath, sourceOffset, rawLength, outputPath, options, hasher, token)
            .ConfigureAwait(false);
        return new HashedWriteResult(Convert.ToHexString(hasher.GetHashAndReset()), result.RawSize, result.StoredSize);
    }

    private static async Task<WriteResult> WriteStoredRawFileInternalAsync(
        string sourcePath,
        long sourceOffset,
        long rawLength,
        string outputPath,
        AscfWriterOptions options,
        IncrementalHash? hasher,
        CancellationToken token)
    {
        ValidateRawSize(rawLength, options.MaxRawFileBytes);
        FileFormatPaths.EnsureOutputDirectory(outputPath);

        var sourceInfo = new FileInfo(sourcePath);
        if (!sourceInfo.Exists)
        {
            throw new FileNotFoundException($"No raw source found at {sourcePath}.", sourcePath);
        }

        ValidateSourceRange(sourceOffset, rawLength, sourceInfo.Length);

        var source = new FileStream(
            sourcePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: options.BufferSize,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        await using (source.ConfigureAwait(false))
        {
            source.Position = sourceOffset;

            var output = new FileStream(
                outputPath,
                FileMode.Create,
                FileAccess.Write,
                FileShare.None,
                bufferSize: options.BufferSize,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            await using (output.ConfigureAwait(false))
            {
                var chunkCount = AscfFileFormat.GetChunkCount(rawLength, options.RawChunkSize);
                var streamId = Guid.NewGuid();
                var writeOptions = new WriteOptions(options, null, null, null);
                await WriteHeaderAsync(output, rawLength, options.RawChunkSize, chunkCount, streamId, 0, writeOptions, token).ConfigureAwait(false);
                var entries = await WriteStoredRawChunksAsync(source, output, rawLength, chunkCount, options.RawChunkSize, hasher, token).ConfigureAwait(false);
                var indexOffset = GetEncodedOffset(entries);
                await WriteIndexAsync(output, entries, rawLength, indexOffset, writeOptions, token).ConfigureAwait(false);
                await RewriteHeaderAsync(output, rawLength, options.RawChunkSize, chunkCount, streamId, output.Length, token).ConfigureAwait(false);

                await output.FlushAsync(token).ConfigureAwait(false);
                return new WriteResult(rawLength, output.Length);
            }
        }
    }

    private static async Task<List<AscfChunkIndexEntry>> WriteStoredRawChunksAsync(
        Stream source,
        Stream output,
        long rawLength,
        int chunkCount,
        int rawChunkSize,
        IncrementalHash? hasher,
        CancellationToken token)
    {
        var remaining = rawLength;
        var chunkHeader = new byte[AscfFileFormat.ChunkHeaderSize];
        var chunkBuffer = ArrayPool<byte>.Shared.Rent(rawChunkSize);
        var chunkIndex = 0;
        long rawOffset = 0;
        long chunkOffset = AscfFileFormat.HeaderSize;
        var entries = new List<AscfChunkIndexEntry>(chunkCount);
        try
        {
            while (remaining > 0)
            {
                var chunkLength = checked((int)Math.Min(rawChunkSize, remaining));
                var entry = await WriteStoredRawChunkAsync(source, output, chunkBuffer, chunkHeader, chunkIndex, chunkCount, rawOffset, chunkOffset, chunkLength, hasher, token)
                    .ConfigureAwait(false);

                entries.Add(entry);
                remaining -= chunkLength;
                rawOffset += chunkLength;
                chunkOffset += AscfFileFormat.ChunkHeaderSize + chunkLength;
                chunkIndex++;
            }

            return entries;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(chunkBuffer);
        }
    }

    private static async Task<AscfChunkIndexEntry> WriteStoredRawChunkAsync(
        Stream source,
        Stream output,
        byte[] chunkBuffer,
        byte[] chunkHeader,
        int chunkIndex,
        int chunkCount,
        long rawOffset,
        long chunkOffset,
        int chunkLength,
        IncrementalHash? hasher,
        CancellationToken token)
    {
        await FileFormatStreamReader.ReadExactlyAsync(source, chunkBuffer.AsMemory(0, chunkLength), token).ConfigureAwait(false);
        var checksum = AscfChecksum.ComputeXxHash3(chunkBuffer.AsSpan(0, chunkLength));
        AscfChunkHeaderCodec.Write(
            chunkHeader,
            new AscfChunkHeader(
                chunkIndex,
                AscfFileFormat.MethodRaw,
                rawOffset,
                chunkLength,
                chunkLength,
                checksum,
                checksum,
                AscfChunkHeaderCodec.GetFlags(chunkIndex == chunkCount - 1)));

        await output.WriteAsync(chunkHeader.AsMemory(0, chunkHeader.Length), token).ConfigureAwait(false);
        hasher?.AppendData(chunkBuffer.AsSpan(0, chunkLength));
        await output.WriteAsync(chunkBuffer.AsMemory(0, chunkLength), token).ConfigureAwait(false);
        return new AscfChunkIndexEntry(
            chunkIndex,
            AscfFileFormat.MethodRaw,
            rawOffset,
            chunkOffset,
            chunkLength,
            chunkLength,
            checksum,
            checksum);
    }

    private static async Task<CompressedWriteResult> WriteCompressedChunksAsync(
        Stream source,
        Stream destination,
        IncrementalHash? hasher,
        int? knownChunkCount,
        WriteOptions options,
        CancellationToken token)
    {
        var maxCompressedSize = Lz4BlockCodec.MaxCompressedLength(options.Format.RawChunkSize);
        var pendingChunks = new Queue<Task<AscfChunkCompressor.EncodedChunk>>(options.Format.CompressionWorkerCount);
        var chunkHeader = new byte[AscfFileFormat.ChunkHeaderSize];
        var entries = new List<AscfChunkIndexEntry>();
        using var workerSlots = new SemaphoreSlim(options.Format.CompressionWorkerCount, options.Format.CompressionWorkerCount);
        try
        {
            long rawSize = 0;
            long writtenRawSize = 0;
            long encodedOffset = AscfFileFormat.HeaderSize;
            var chunkIndex = 0;
            while (true)
            {
                var read = await QueueNextCompressedChunkAsync(source, pendingChunks, workerSlots, hasher, rawSize, maxCompressedSize, options, token)
                    .ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                rawSize += read;

                if (pendingChunks.Count >= options.Format.CompressionWorkerCount)
                {
                    var canWriteBeforeEnd = pendingChunks.Count > 1;
                    if (canWriteBeforeEnd)
                    {
                        var isFinalChunk = knownChunkCount.HasValue && chunkIndex == knownChunkCount.Value - 1;
                        var written = await WriteNextChunkAsync(destination, chunkHeader, pendingChunks, chunkIndex++, writtenRawSize, encodedOffset, isFinalChunk, entries, options, token)
                            .ConfigureAwait(false);
                        writtenRawSize += written.RawLength;
                        encodedOffset += written.EncodedLength;
                        options.Progress?.Report(writtenRawSize);
                    }
                }
            }

            while (pendingChunks.Count > 0)
            {
                var isFinalChunk = pendingChunks.Count == 1;
                var written = await WriteNextChunkAsync(destination, chunkHeader, pendingChunks, chunkIndex++, writtenRawSize, encodedOffset, isFinalChunk, entries, options, token)
                    .ConfigureAwait(false);
                writtenRawSize += written.RawLength;
                encodedOffset += written.EncodedLength;
                options.Progress?.Report(writtenRawSize);
            }

            return new CompressedWriteResult(rawSize, chunkIndex, encodedOffset, entries);
        }
        catch
        {
            await ReturnPendingChunksAsync(pendingChunks).ConfigureAwait(false);
            throw;
        }
    }

    private static async Task<int> QueueNextCompressedChunkAsync(
        Stream source,
        Queue<Task<AscfChunkCompressor.EncodedChunk>> pendingChunks,
        SemaphoreSlim workerSlots,
        IncrementalHash? hasher,
        long currentRawSize,
        int maxCompressedSize,
        WriteOptions options,
        CancellationToken token)
    {
        var rawBuffer = ArrayPool<byte>.Shared.Rent(options.Format.RawChunkSize);
        var queued = false;
        try
        {
            var read = await FileFormatStreamReader
                .ReadUpToAsync(source, rawBuffer.AsMemory(0, options.Format.RawChunkSize), token)
                .ConfigureAwait(false);
            if (read == 0)
            {
                return 0;
            }

            ValidateRawSize(currentRawSize + read, options.Format.MaxRawFileBytes);
            hasher?.AppendData(rawBuffer.AsSpan(0, read));
            pendingChunks.Enqueue(await AscfChunkCompressor
                .StartAsync(rawBuffer, read, maxCompressedSize, workerSlots, token)
                .ConfigureAwait(false));
            queued = true;
            return read;
        }
        finally
        {
            if (!queued)
            {
                ArrayPool<byte>.Shared.Return(rawBuffer);
            }
        }
    }

    private static async Task<ChunkWriteResult> WriteNextChunkAsync(
        Stream destination,
        byte[] chunkHeader,
        Queue<Task<AscfChunkCompressor.EncodedChunk>> pendingChunks,
        int chunkIndex,
        long rawOffset,
        long chunkOffset,
        bool isFinalChunk,
        List<AscfChunkIndexEntry> entries,
        WriteOptions options,
        CancellationToken token)
    {
        using var chunk = await pendingChunks.Dequeue().ConfigureAwait(false);

        AscfChunkHeaderCodec.Write(
            chunkHeader,
            new AscfChunkHeader(
                chunkIndex,
                chunk.Method,
                rawOffset,
                chunk.RawLength,
                chunk.StoredLength,
                chunk.RawChecksum,
                chunk.StoredChecksum,
                AscfChunkHeaderCodec.GetFlags(isFinalChunk)));
        entries.Add(new AscfChunkIndexEntry(
            chunkIndex,
            chunk.Method,
            rawOffset,
            chunkOffset,
            chunk.RawLength,
            chunk.StoredLength,
            chunk.RawChecksum,
            chunk.StoredChecksum));
        await WriteBytesAsync(destination, chunkHeader.AsMemory(0, chunkHeader.Length), options, token).ConfigureAwait(false);
        await WriteBytesAsync(destination, chunk.Payload, options, token).ConfigureAwait(false);
        return new ChunkWriteResult(chunk.RawLength, AscfFileFormat.ChunkHeaderSize + chunk.StoredLength);
    }

    private static async Task ReturnPendingChunksAsync(Queue<Task<AscfChunkCompressor.EncodedChunk>> pendingChunks)
    {
        while (pendingChunks.Count > 0)
        {
            try
            {
                using var chunk = await pendingChunks.Dequeue().ConfigureAwait(false);
            }
            catch
            {
                // best effort cleanup after a failed write
            }
        }
    }

    private static async Task WriteHeaderAsync(
        Stream destination,
        long rawSize,
        int rawChunkSize,
        int chunkCount,
        Guid streamId,
        long encodedSize,
        CancellationToken token)
        => await WriteHeaderAsync(
                destination,
                rawSize,
                rawChunkSize,
                chunkCount,
                streamId,
                encodedSize,
                new WriteOptions(AscfWriterOptions.Default, null, null, null),
                token)
            .ConfigureAwait(false);

    private static async Task WriteHeaderAsync(
        Stream destination,
        long rawSize,
        int rawChunkSize,
        int chunkCount,
        Guid streamId,
        long encodedSize,
        WriteOptions options,
        CancellationToken token)
    {
        var fileHeader = new byte[AscfFileFormat.HeaderSize];
        AscfFileHeaderCodec.Write(fileHeader, rawSize, rawChunkSize, chunkCount, streamId, encodedSize);
        await WriteBytesAsync(destination, fileHeader.AsMemory(0, fileHeader.Length), options, token).ConfigureAwait(false);
    }

    private static async Task RewriteHeaderAsync(
        Stream destination,
        long rawSize,
        int rawChunkSize,
        int chunkCount,
        Guid streamId,
        long encodedSize,
        CancellationToken token)
    {
        destination.Position = 0;
        await WriteHeaderAsync(destination, rawSize, rawChunkSize, chunkCount, streamId, encodedSize, token).ConfigureAwait(false);
        destination.Position = destination.Length;
    }

    private static async Task TryRewriteHeaderAsync(
        Stream destination,
        long rawSize,
        int chunkCount,
        Guid streamId,
        WriteOptions options,
        CancellationToken token)
    {
        if (!destination.CanSeek || options.Transform != null)
        {
            return;
        }

        await RewriteHeaderAsync(destination, rawSize, options.Format.RawChunkSize, chunkCount, streamId, destination.Length, token).ConfigureAwait(false);
    }

    private static async Task WriteIndexAsync(
        Stream destination,
        IReadOnlyList<AscfChunkIndexEntry> entries,
        long rawSize,
        long indexOffset,
        WriteOptions options,
        CancellationToken token)
    {
        var index = AscfChunkIndexCodec.WriteIndex(entries);
        var footer = AscfChunkIndexCodec.WriteFooter(entries.Count, rawSize, indexOffset, index);
        await WriteBytesAsync(destination, index, options, token).ConfigureAwait(false);
        await WriteBytesAsync(destination, footer, options, token).ConfigureAwait(false);
    }

    private static long GetEncodedOffset(IEnumerable<AscfChunkIndexEntry> entries)
    {
        long encodedOffset = AscfFileFormat.HeaderSize;
        foreach (var entry in entries)
        {
            encodedOffset += AscfFileFormat.ChunkHeaderSize + entry.StoredLength;
        }

        return encodedOffset;
    }

    private static async ValueTask WriteBytesAsync(Stream destination, ReadOnlyMemory<byte> buffer, WriteOptions options, CancellationToken token)
    {
        if (buffer.Length == 0)
        {
            return;
        }

        if (options.WaitForBytes != null)
        {
            await options.WaitForBytes(buffer.Length, token).ConfigureAwait(false);
        }

        if (options.Transform != null)
        {
            if (!MemoryMarshal.TryGetArray(buffer, out var segment) || segment.Array == null)
            {
                throw new InvalidOperationException(".ascf output transform requires array-backed buffers.");
            }

            options.Transform(segment.Array.AsSpan(segment.Offset, buffer.Length));
        }

        await destination.WriteAsync(buffer, token).ConfigureAwait(false);
    }

    private static void ValidateRawSize(long rawSize, long maxRawFileBytes)
    {
        if (rawSize < 0 || rawSize > maxRawFileBytes)
        {
            throw new InvalidDataException($".ascf raw size too large ({rawSize} bytes).");
        }
    }

    private static void ValidateSourceRange(long sourceOffset, long rawLength, long sourceLength)
    {
        if (sourceOffset < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(sourceOffset), sourceOffset, "Source offset must be non-negative.");
        }

        if (rawLength < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(rawLength), rawLength, "Raw length must be non-negative.");
        }

        if (sourceOffset > sourceLength)
        {
            throw new ArgumentOutOfRangeException(nameof(sourceOffset), sourceOffset, "Source offset exceeds source file length.");
        }

        if (rawLength > sourceLength - sourceOffset)
        {
            throw new ArgumentOutOfRangeException(nameof(rawLength), rawLength, "Source range exceeds source file length.");
        }
    }
}
