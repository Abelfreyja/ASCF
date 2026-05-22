using System.Buffers;
using System.Runtime.InteropServices;
using System.Threading.Channels;
using ASCF.Lz4;
using ASCF.Util;

namespace ASCF;

public static class AscfFileWriter
{
    [StructLayout(LayoutKind.Auto)]
    public readonly record struct WriteResult(long RawSize, long StoredSize);

    [StructLayout(LayoutKind.Auto)]
    public readonly record struct HashedWriteResult(AscfRawHashes Hashes, long RawSize, long StoredSize);

    [StructLayout(LayoutKind.Auto)]
    private readonly record struct WriteOptions(
        AscfWriterOptions Format,
        Func<int, CancellationToken, ValueTask>? WaitForBytes,
        IProgress<long>? Progress,
        AscfBufferTransform? Transform);

    [StructLayout(LayoutKind.Auto)]
    private readonly record struct CompressedWriteResult(long RawSize, int ChunkCount, long EncodedOffset, List<AscfChunkIndexEntry> Entries, AscfRawHashBytes RawHashes);

    [StructLayout(LayoutKind.Auto)]
    private readonly record struct CompressedReadResult(long RawSize, int ChunkCount);

    [StructLayout(LayoutKind.Auto)]
    private readonly record struct EncodedChunkResult(int ChunkIndex, AscfChunkCompressor.EncodedChunk Chunk);

    [StructLayout(LayoutKind.Auto)]
    private readonly record struct ChunkWriteResult(int RawLength, long EncodedLength);

    [StructLayout(LayoutKind.Auto)]
    private readonly record struct CompressedWriteState(int NextChunkIndex, long WrittenRawSize, long EncodedOffset);

    private sealed class RawChunk(int chunkIndex, PooledBufferOwner raw) : IDisposable
    {
        public int ChunkIndex { get; } = chunkIndex;
        public int RawLength => raw.Length;

        public byte[] TakeBuffer()
            => raw.TakeBuffer();

        public void Dispose()
            => raw.Dispose();
    }

    public static Task<long> WriteFileAsync(string sourcePath, string outputPath, CancellationToken token)
        => WriteFileAsync(sourcePath, outputPath, AscfWriterOptions.Default, token);

    public static async Task<long> WriteFileAsync(string sourcePath, string outputPath, AscfWriterOptions options, CancellationToken token)
    {
        options.Validate();
        using var stagedFile = FileFormatPaths.CreateStagedFile(outputPath);

        long storedSize;
        var output = FileFormatPaths.OpenSequentialStagingWrite(stagedFile.StagingPath, options.BufferSize);
        await using (output.ConfigureAwait(false))
        {
            await WriteFileAsync(sourcePath, output, options, token).ConfigureAwait(false);
            await output.FlushAsync(token).ConfigureAwait(false);
            storedSize = output.Length;
        }

        stagedFile.Commit();
        return storedSize;
    }

    public static async Task<HashedWriteResult> WriteFileWithHashAsync(string sourcePath, string outputPath, AscfWriterOptions options, CancellationToken token)
    {
        ValidateHashOptions(options);
        using var stagedFile = FileFormatPaths.CreateStagedFile(outputPath);

        HashedWriteResult writeResult;
        var output = FileFormatPaths.OpenSequentialStagingWrite(stagedFile.StagingPath, options.BufferSize);
        await using (output.ConfigureAwait(false))
        {
            var result = await WriteFileToStreamWithHashAsync(sourcePath, output, options, token).ConfigureAwait(false);
            await output.FlushAsync(token).ConfigureAwait(false);
            writeResult = new HashedWriteResult(result.Hashes, result.RawSize, output.Length);
        }

        stagedFile.Commit();
        return writeResult;
    }

    public static Task WriteFileAsync(string sourcePath, Stream destination, CancellationToken token)
        => WriteFileAsync(sourcePath, destination, AscfWriterOptions.Default, token);

    public static async Task WriteFileAsync(string sourcePath, Stream destination, AscfWriterOptions options, CancellationToken token)
    {
        options.Validate();
        await WriteFileInternalAsync(sourcePath, destination, new WriteOptions(options, null, null, null), requiredHashAlgorithms: AscfRawHashAlgorithms.None, token)
            .ConfigureAwait(false);
    }

    public static Task WriteFileAsync(
        string sourcePath,
        Stream destination,
        Func<int, CancellationToken, ValueTask>? waitForBytes,
        IProgress<long>? progress,
        AscfBufferTransform? transform,
        CancellationToken token)
        => WriteFileAsync(sourcePath, destination, AscfWriterOptions.Default, waitForBytes, progress, transform, token);

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
        await WriteFileInternalAsync(sourcePath, destination, options, requiredHashAlgorithms: AscfRawHashAlgorithms.None, token)
            .ConfigureAwait(false);
    }

    private static async Task<(AscfRawHashes Hashes, long RawSize)> WriteFileToStreamWithHashAsync(
        string sourcePath,
        Stream destination,
        AscfWriterOptions options,
        CancellationToken token)
    {
        var result = await WriteFileInternalAsync(
                sourcePath,
                destination,
                new WriteOptions(options, null, null, null),
                options.GetResultHashAlgorithms(),
                token)
            .ConfigureAwait(false);
        return (GetResultHashes(result.RawHashes, options.GetResultHashAlgorithms()), result.RawSize);
    }

    private static async Task<(long RawSize, AscfRawHashBytes RawHashes)> WriteFileInternalAsync(
        string sourcePath,
        Stream destination,
        WriteOptions options,
        AscfRawHashAlgorithms requiredHashAlgorithms,
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
            using var hasher = CreateRawHasher(options.Format.RawHashAlgorithms | requiredHashAlgorithms);
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
            await TryRewriteHeaderAsync(
                    destination,
                    result.RawSize,
                    result.ChunkCount,
                    streamId,
                    GetHeaderRawHashes(result.RawHashes, options.Format),
                    options,
                    token)
                .ConfigureAwait(false);
            return (result.RawSize, result.RawHashes);
        }
    }

    public static Task<WriteResult> WriteStreamToFileAsync(Stream source, string outputPath, CancellationToken token)
        => WriteStreamToFileAsync(source, outputPath, AscfWriterOptions.Default, token);

    public static async Task<WriteResult> WriteStreamToFileAsync(Stream source, string outputPath, AscfWriterOptions options, CancellationToken token)
    {
        options.Validate();
        var result = await WriteStreamToFileInternalAsync(source, outputPath, options, AscfRawHashAlgorithms.None, token)
            .ConfigureAwait(false);
        return new WriteResult(result.RawSize, result.StoredSize);
    }

    public static async Task<HashedWriteResult> WriteStreamToFileWithHashAsync(Stream source, string outputPath, AscfWriterOptions options, CancellationToken token)
    {
        ValidateHashOptions(options);
        var result = await WriteStreamToFileInternalAsync(source, outputPath, options, options.GetResultHashAlgorithms(), token)
            .ConfigureAwait(false);
        return new HashedWriteResult(GetResultHashes(result.RawHashes, options.GetResultHashAlgorithms()), result.RawSize, result.StoredSize);
    }

    private static async Task<(long RawSize, long StoredSize, AscfRawHashBytes RawHashes)> WriteStreamToFileInternalAsync(
        Stream source,
        string outputPath,
        AscfWriterOptions options,
        AscfRawHashAlgorithms requiredHashAlgorithms,
        CancellationToken token)
    {
        using var stagedFile = FileFormatPaths.CreateStagedFile(outputPath);

        (long RawSize, long StoredSize, AscfRawHashBytes RawHashes) result;
        var output = FileFormatPaths.OpenSequentialStagingWrite(stagedFile.StagingPath, options.BufferSize);
        await using (output.ConfigureAwait(false))
        using (var hasher = CreateRawHasher(options.RawHashAlgorithms | requiredHashAlgorithms))
        {
            var streamId = Guid.NewGuid();
            var writeOptions = new WriteOptions(options, null, null, null);
            await WriteHeaderAsync(output, 0, options.RawChunkSize, 0, streamId, 0, writeOptions, token).ConfigureAwait(false);
            var written = await WriteCompressedChunksAsync(source, output, hasher, knownChunkCount: null, writeOptions, token).ConfigureAwait(false);
            ValidateRawSize(written.RawSize, options.MaxRawFileBytes);
            await WriteIndexAsync(output, written.Entries, written.RawSize, written.EncodedOffset, writeOptions, token).ConfigureAwait(false);
            await RewriteHeaderAsync(
                    output,
                    written.RawSize,
                    options.RawChunkSize,
                    written.ChunkCount,
                    streamId,
                    output.Length,
                    GetHeaderRawHashes(written.RawHashes, options),
                    token)
                .ConfigureAwait(false);
            await output.FlushAsync(token).ConfigureAwait(false);
            result = (written.RawSize, output.Length, written.RawHashes);
        }

        stagedFile.Commit();
        return result;
    }

    public static Task<long> WriteStoredRawFileAsync(
        string sourcePath,
        long sourceOffset,
        long rawLength,
        string outputPath,
        CancellationToken token)
        => WriteStoredRawFileAsync(sourcePath, sourceOffset, rawLength, outputPath, AscfWriterOptions.Default, token);

    public static async Task<long> WriteStoredRawFileAsync(
        string sourcePath,
        long sourceOffset,
        long rawLength,
        string outputPath,
        AscfWriterOptions options,
        CancellationToken token)
    {
        options.Validate();
        var result = await WriteStoredRawFileInternalAsync(sourcePath, sourceOffset, rawLength, outputPath, options, AscfRawHashAlgorithms.None, token)
            .ConfigureAwait(false);
        return result.StoredSize;
    }

    public static async Task<HashedWriteResult> WriteStoredRawFileWithHashAsync(
        string sourcePath,
        long sourceOffset,
        long rawLength,
        string outputPath,
        AscfWriterOptions options,
        CancellationToken token)
    {
        ValidateHashOptions(options);
        var result = await WriteStoredRawFileInternalAsync(sourcePath, sourceOffset, rawLength, outputPath, options, options.GetResultHashAlgorithms(), token)
            .ConfigureAwait(false);
        return new HashedWriteResult(GetResultHashes(result.RawHashes, options.GetResultHashAlgorithms()), result.RawSize, result.StoredSize);
    }

    private static async Task<(long RawSize, long StoredSize, AscfRawHashBytes RawHashes)> WriteStoredRawFileInternalAsync(
        string sourcePath,
        long sourceOffset,
        long rawLength,
        string outputPath,
        AscfWriterOptions options,
        AscfRawHashAlgorithms requiredHashAlgorithms,
        CancellationToken token)
    {
        ValidateRawSize(rawLength, options.MaxRawFileBytes);
        using var stagedFile = FileFormatPaths.CreateStagedFile(outputPath);

        var sourceInfo = new FileInfo(sourcePath);
        if (!sourceInfo.Exists)
        {
            throw new FileNotFoundException($"No raw source found at {sourcePath}.", sourcePath);
        }

        ValidateSourceRange(sourceOffset, rawLength, sourceInfo.Length);

        (long RawSize, long StoredSize, AscfRawHashBytes RawHashes) result;
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

            var output = FileFormatPaths.OpenSequentialStagingWrite(stagedFile.StagingPath, options.BufferSize);
            await using (output.ConfigureAwait(false))
            {
                using var hasher = CreateRawHasher(options.RawHashAlgorithms | requiredHashAlgorithms);
                var chunkCount = AscfFileFormat.GetChunkCount(rawLength, options.RawChunkSize);
                var streamId = Guid.NewGuid();
                var writeOptions = new WriteOptions(options, null, null, null);
                await WriteHeaderAsync(output, rawLength, options.RawChunkSize, chunkCount, streamId, 0, writeOptions, token).ConfigureAwait(false);
                var entries = await WriteStoredRawChunksAsync(source, output, rawLength, chunkCount, options.RawChunkSize, hasher, token).ConfigureAwait(false);
                var indexOffset = GetEncodedOffset(entries);
                await WriteIndexAsync(output, entries, rawLength, indexOffset, writeOptions, token).ConfigureAwait(false);
                var rawHashes = hasher?.FinalizeHashes() ?? AscfRawHashBytes.Empty;
                await RewriteHeaderAsync(
                        output,
                        rawLength,
                        options.RawChunkSize,
                        chunkCount,
                        streamId,
                        output.Length,
                        GetHeaderRawHashes(rawHashes, options),
                        token)
                    .ConfigureAwait(false);

                await output.FlushAsync(token).ConfigureAwait(false);
                result = (rawLength, output.Length, rawHashes);
            }
        }

        stagedFile.Commit();
        return result;
    }

    private static async Task<List<AscfChunkIndexEntry>> WriteStoredRawChunksAsync(
        Stream source,
        Stream output,
        long rawLength,
        int chunkCount,
        int rawChunkSize,
        AscfRawContentHasher? hasher,
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
        AscfRawContentHasher? hasher,
        CancellationToken token)
    {
        await source.ReadExactlyAsync(chunkBuffer.AsMemory(0, chunkLength), token).ConfigureAwait(false);
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
        AscfRawContentHasher? hasher,
        int? knownChunkCount,
        WriteOptions options,
        CancellationToken token)
    {
        var workerCount = options.Format.GetCompressionWorkerCount();
        if (workerCount == 1)
        {
            var inlineResult = await WriteCompressedChunksInlineAsync(source, destination, hasher, knownChunkCount, options, token).ConfigureAwait(false);
            var inlineHashes = hasher?.FinalizeHashes() ?? AscfRawHashBytes.Empty;
            return inlineResult with
            {
                RawHashes = inlineHashes
            };
        }

        var maxUsefulCompressedLength = Lz4BlockCodec.MaxUsefulCompressedLength(options.Format.RawChunkSize);
        var pipelineChunkLimit = options.Format.GetCompressionPipelineChunkLimit();
        var chunkHeader = new byte[AscfFileFormat.ChunkHeaderSize];
        var entries = knownChunkCount.HasValue
            ? new List<AscfChunkIndexEntry>(knownChunkCount.Value)
            : [];
        var rawChunks = Channel.CreateBounded<RawChunk>(
            new BoundedChannelOptions(pipelineChunkLimit)
            {
                SingleReader = false,
                SingleWriter = true,
                FullMode = BoundedChannelFullMode.Wait
            });
        var encodedChunks = Channel.CreateBounded<EncodedChunkResult>(
            new BoundedChannelOptions(pipelineChunkLimit)
            {
                SingleReader = true,
                SingleWriter = false,
                FullMode = BoundedChannelFullMode.Wait
            });
        using var pipelineSlots = new SemaphoreSlim(pipelineChunkLimit);
        using var pipelineCancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
        var pipelineToken = pipelineCancellation.Token;
        var producerTask = ReadRawChunksForCompressionAsync(source, rawChunks.Writer, pipelineSlots, hasher, options, pipelineToken);
        var workerTasks = StartCompressionWorkers(rawChunks.Reader, encodedChunks.Writer, pipelineSlots, workerCount, maxUsefulCompressedLength, pipelineToken);
        var completionTask = CompleteEncodedChunksWhenWorkersFinishAsync(rawChunks.Writer, encodedChunks.Writer, workerTasks);
        try
        {
            var result = await WriteCompressedResultsAsync(
                    destination,
                    chunkHeader,
                    encodedChunks.Reader,
                    producerTask,
                    knownChunkCount,
                    pipelineSlots,
                    entries,
                    options,
                    pipelineToken)
                .ConfigureAwait(false);
            await completionTask.ConfigureAwait(false);
            var rawHashes = hasher?.FinalizeHashes() ?? AscfRawHashBytes.Empty;
            return result with
            {
                RawHashes = rawHashes
            };
        }
        catch
        {
            await pipelineCancellation.CancelAsync().ConfigureAwait(false);
            rawChunks.Writer.TryComplete();
            encodedChunks.Writer.TryComplete();
            await ObservePipelineAsync(producerTask, completionTask).ConfigureAwait(false);
            DrainRawChunks(rawChunks.Reader, pipelineSlots);
            throw;
        }
    }

    private static async Task<CompressedWriteResult> WriteCompressedChunksInlineAsync(
        Stream source,
        Stream destination,
        AscfRawContentHasher? hasher,
        int? knownChunkCount,
        WriteOptions options,
        CancellationToken token)
    {
        var maxUsefulCompressedLength = Lz4BlockCodec.MaxUsefulCompressedLength(options.Format.RawChunkSize);
        var chunkHeader = new byte[AscfFileFormat.ChunkHeaderSize];
        var entries = knownChunkCount.HasValue
            ? new List<AscfChunkIndexEntry>(knownChunkCount.Value)
            : [];
        AscfChunkCompressor.EncodedChunk? pendingChunk = null;
        try
        {
            long rawSize = 0;
            long writtenRawSize = 0;
            long encodedOffset = AscfFileFormat.HeaderSize;
            while (true)
            {
                var nextChunk = await ReadCompressedChunkInlineAsync(source, hasher, rawSize, maxUsefulCompressedLength, options, token).ConfigureAwait(false);
                if (nextChunk == null)
                {
                    break;
                }

                rawSize += nextChunk.RawLength;
                if (pendingChunk != null)
                {
                    var written = await WriteEncodedChunkAsync(destination, chunkHeader, pendingChunk, entries.Count, writtenRawSize, encodedOffset, isFinalChunk: false, entries, options, token)
                        .ConfigureAwait(false);
                    pendingChunk.Dispose();
                    pendingChunk = null;
                    writtenRawSize += written.RawLength;
                    encodedOffset += written.EncodedLength;
                    options.Progress?.Report(writtenRawSize);
                }

                pendingChunk = nextChunk;
            }

            if (pendingChunk != null)
            {
                var written = await WriteEncodedChunkAsync(destination, chunkHeader, pendingChunk, entries.Count, writtenRawSize, encodedOffset, isFinalChunk: true, entries, options, token)
                    .ConfigureAwait(false);
                pendingChunk.Dispose();
                pendingChunk = null;
                writtenRawSize += written.RawLength;
                encodedOffset += written.EncodedLength;
                options.Progress?.Report(writtenRawSize);
            }

            return new CompressedWriteResult(rawSize, entries.Count, encodedOffset, entries, AscfRawHashBytes.Empty);
        }
        catch
        {
            pendingChunk?.Dispose();
            throw;
        }
    }

    private static async Task<AscfChunkCompressor.EncodedChunk?> ReadCompressedChunkInlineAsync(
        Stream source,
        AscfRawContentHasher? hasher,
        long currentRawSize,
        int maxUsefulCompressedLength,
        WriteOptions options,
        CancellationToken token)
    {
        using var rawChunk = await ReadNextRawChunkAsync(source, chunkIndex: 0, currentRawSize, hasher, options, token)
            .ConfigureAwait(false);
        if (rawChunk == null)
        {
            return null;
        }

        return AscfChunkCompressor.Encode(rawChunk.TakeBuffer(), rawChunk.RawLength, maxUsefulCompressedLength);
    }

    private static async Task<CompressedReadResult> ReadRawChunksForCompressionAsync(
        Stream source,
        ChannelWriter<RawChunk> rawChunks,
        SemaphoreSlim pipelineSlots,
        AscfRawContentHasher? hasher,
        WriteOptions options,
        CancellationToken token)
    {
        long rawSize = 0;
        var chunkIndex = 0;
        try
        {
            while (true)
            {
                var rawChunk = await ReadNextRawChunkAsync(source, chunkIndex, rawSize, hasher, options, token)
                    .ConfigureAwait(false);
                if (rawChunk == null)
                {
                    rawChunks.TryComplete();
                    return new CompressedReadResult(rawSize, chunkIndex);
                }

                var queued = false;
                var slotAcquired = false;
                try
                {
                    await pipelineSlots.WaitAsync(token).ConfigureAwait(false);
                    slotAcquired = true;
                    await rawChunks.WriteAsync(rawChunk, token).ConfigureAwait(false);
                    queued = true;
                    slotAcquired = false;
                    rawSize += rawChunk.RawLength;
                    chunkIndex++;
                }
                finally
                {
                    if (!queued)
                    {
                        rawChunk.Dispose();
                    }

                    if (slotAcquired)
                    {
                        pipelineSlots.Release();
                    }
                }
            }
        }
        catch (Exception ex)
        {
            rawChunks.TryComplete(ex);
            throw;
        }
    }

    private static async Task<RawChunk?> ReadNextRawChunkAsync(
        Stream source,
        int chunkIndex,
        long currentRawSize,
        AscfRawContentHasher? hasher,
        WriteOptions options,
        CancellationToken token)
    {
        byte[]? rawBuffer = ArrayPool<byte>.Shared.Rent(options.Format.RawChunkSize);
        try
        {
            var read = await FileFormatStreamReader
                .ReadUpToAsync(source, rawBuffer.AsMemory(0, options.Format.RawChunkSize), token)
                .ConfigureAwait(false);
            if (read == 0)
            {
                return null;
            }

            ValidateRawSize(currentRawSize + read, options.Format.MaxRawFileBytes);
            hasher?.AppendData(rawBuffer.AsSpan(0, read));
            var raw = new PooledBufferOwner(rawBuffer, read);
            rawBuffer = null;
            return new RawChunk(chunkIndex, raw);
        }
        finally
        {
            if (rawBuffer != null)
            {
                ArrayPool<byte>.Shared.Return(rawBuffer);
            }
        }
    }

    private static Task[] StartCompressionWorkers(
        ChannelReader<RawChunk> rawChunks,
        ChannelWriter<EncodedChunkResult> encodedChunks,
        SemaphoreSlim pipelineSlots,
        int workerCount,
        int maxUsefulCompressedLength,
        CancellationToken token)
    {
        var workers = new Task[workerCount];
        for (var i = 0; i < workers.Length; i++)
        {
            workers[i] = Task.Run(
                () => RunCompressionWorkerAsync(rawChunks, encodedChunks, pipelineSlots, maxUsefulCompressedLength, token),
                CancellationToken.None);
        }

        return workers;
    }

    private static async Task RunCompressionWorkerAsync(
        ChannelReader<RawChunk> rawChunks,
        ChannelWriter<EncodedChunkResult> encodedChunks,
        SemaphoreSlim pipelineSlots,
        int maxUsefulCompressedLength,
        CancellationToken token)
    {
        await foreach (var rawChunk in rawChunks.ReadAllAsync(token).ConfigureAwait(false))
        {
            AscfChunkCompressor.EncodedChunk? encodedChunk = null;
            var delivered = false;
            try
            {
                encodedChunk = AscfChunkCompressor.Encode(rawChunk.TakeBuffer(), rawChunk.RawLength, maxUsefulCompressedLength);
                await encodedChunks.WriteAsync(new EncodedChunkResult(rawChunk.ChunkIndex, encodedChunk), token).ConfigureAwait(false);
                delivered = true;
                encodedChunk = null;
            }
            finally
            {
                rawChunk.Dispose();
                encodedChunk?.Dispose();
                if (!delivered)
                {
                    pipelineSlots.Release();
                }
            }
        }
    }

    private static async Task CompleteEncodedChunksWhenWorkersFinishAsync(
        ChannelWriter<RawChunk> rawChunks,
        ChannelWriter<EncodedChunkResult> encodedChunks,
        Task[] workerTasks)
    {
        try
        {
            await Task.WhenAll(workerTasks).ConfigureAwait(false);
            encodedChunks.TryComplete();
        }
        catch (Exception ex)
        {
            rawChunks.TryComplete(ex);
            encodedChunks.TryComplete(ex);
            throw;
        }
    }

    private static async Task<CompressedWriteResult> WriteCompressedResultsAsync(
        Stream destination,
        byte[] chunkHeader,
        ChannelReader<EncodedChunkResult> encodedChunks,
        Task<CompressedReadResult> producerTask,
        int? knownChunkCount,
        SemaphoreSlim pipelineSlots,
        List<AscfChunkIndexEntry> entries,
        WriteOptions options,
        CancellationToken token)
    {
        var pendingChunks = new Dictionary<int, AscfChunkCompressor.EncodedChunk>();
        var readResult = default(CompressedReadResult?);
        var highestCompletedChunkIndex = -1;
        long writtenRawSize = 0;
        long encodedOffset = AscfFileFormat.HeaderSize;
        var nextChunkIndex = 0;
        try
        {
            await foreach (var result in encodedChunks.ReadAllAsync(token).ConfigureAwait(false))
            {
                highestCompletedChunkIndex = Math.Max(highestCompletedChunkIndex, result.ChunkIndex);
                try
                {
                    pendingChunks.Add(result.ChunkIndex, result.Chunk);
                }
                catch
                {
                    result.Chunk.Dispose();
                    pipelineSlots.Release();
                    throw;
                }

                if (producerTask.IsCompletedSuccessfully)
                {
                    readResult = producerTask.Result;
                }

                var state = await WriteReadyCompressedChunksAsync(
                        destination,
                        chunkHeader,
                        pendingChunks,
                        knownChunkCount,
                        readResult,
                        highestCompletedChunkIndex,
                        nextChunkIndex,
                        pipelineSlots,
                        writtenRawSize,
                        encodedOffset,
                        entries,
                        options,
                        token)
                    .ConfigureAwait(false);
                nextChunkIndex = state.NextChunkIndex;
                writtenRawSize = state.WrittenRawSize;
                encodedOffset = state.EncodedOffset;
            }

            readResult = await producerTask.ConfigureAwait(false);
            var finalState = await WriteReadyCompressedChunksAsync(
                    destination,
                    chunkHeader,
                    pendingChunks,
                    knownChunkCount,
                    readResult,
                    highestCompletedChunkIndex,
                    nextChunkIndex,
                    pipelineSlots,
                    writtenRawSize,
                    encodedOffset,
                    entries,
                    options,
                    token)
                .ConfigureAwait(false);

            if (pendingChunks.Count != 0 || finalState.NextChunkIndex != readResult.Value.ChunkCount)
            {
                throw new InvalidDataException(".ascf compression pipeline ended with missing chunks.");
            }

            return new CompressedWriteResult(readResult.Value.RawSize, readResult.Value.ChunkCount, finalState.EncodedOffset, entries, AscfRawHashBytes.Empty);
        }
        catch
        {
            foreach (var chunk in pendingChunks.Values)
            {
                chunk.Dispose();
                pipelineSlots.Release();
            }

            while (encodedChunks.TryRead(out var result))
            {
                result.Chunk.Dispose();
                pipelineSlots.Release();
            }

            throw;
        }
    }

    private static async Task<CompressedWriteState> WriteReadyCompressedChunksAsync(
        Stream destination,
        byte[] chunkHeader,
        Dictionary<int, AscfChunkCompressor.EncodedChunk> pendingChunks,
        int? knownChunkCount,
        CompressedReadResult? readResult,
        int highestCompletedChunkIndex,
        int nextChunkIndex,
        SemaphoreSlim pipelineSlots,
        long writtenRawSize,
        long encodedOffset,
        List<AscfChunkIndexEntry> entries,
        WriteOptions options,
        CancellationToken token)
    {
        while (pendingChunks.Remove(nextChunkIndex, out var chunk))
        {
            var totalChunkCount = knownChunkCount ?? readResult?.ChunkCount;
            if (!totalChunkCount.HasValue && highestCompletedChunkIndex <= nextChunkIndex)
            {
                pendingChunks.Add(nextChunkIndex, chunk);
                return new CompressedWriteState(nextChunkIndex, writtenRawSize, encodedOffset);
            }

            var isFinalChunk = totalChunkCount.HasValue && nextChunkIndex == totalChunkCount.Value - 1;
            try
            {
                using (chunk)
                {
                    var written = await WriteEncodedChunkAsync(
                            destination,
                            chunkHeader,
                            chunk,
                            nextChunkIndex,
                            writtenRawSize,
                            encodedOffset,
                            isFinalChunk,
                            entries,
                            options,
                            token)
                        .ConfigureAwait(false);
                    writtenRawSize += written.RawLength;
                    encodedOffset += written.EncodedLength;
                    options.Progress?.Report(writtenRawSize);
                }
            }
            finally
            {
                pipelineSlots.Release();
            }

            nextChunkIndex++;
        }

        return new CompressedWriteState(nextChunkIndex, writtenRawSize, encodedOffset);
    }

    private static async Task<ChunkWriteResult> WriteEncodedChunkAsync(
        Stream destination,
        byte[] chunkHeader,
        AscfChunkCompressor.EncodedChunk chunk,
        int chunkIndex,
        long rawOffset,
        long chunkOffset,
        bool isFinalChunk,
        List<AscfChunkIndexEntry> entries,
        WriteOptions options,
        CancellationToken token)
    {
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

    private static async Task ObservePipelineAsync(Task producerTask, Task completionTask)
    {
        await ObservePipelineTaskAsync(producerTask).ConfigureAwait(false);
        await ObservePipelineTaskAsync(completionTask).ConfigureAwait(false);
    }

    private static void DrainRawChunks(ChannelReader<RawChunk> rawChunks, SemaphoreSlim pipelineSlots)
    {
        while (rawChunks.TryRead(out var rawChunk))
        {
            rawChunk.Dispose();
            pipelineSlots.Release();
        }
    }

    private static async Task ObservePipelineTaskAsync(Task task)
    {
        try
        {
            await task.ConfigureAwait(false);
        }
        catch
        {
            // best effort cleanup after a failed write
        }
    }

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
        AscfFileHeaderCodec.Write(fileHeader, rawSize, rawChunkSize, chunkCount, streamId, encodedSize, AscfRawHashBytes.Empty);
        await WriteBytesAsync(destination, fileHeader.AsMemory(0, fileHeader.Length), options, token).ConfigureAwait(false);
    }

    private static async Task RewriteHeaderAsync(
        Stream destination,
        long rawSize,
        int rawChunkSize,
        int chunkCount,
        Guid streamId,
        long encodedSize,
        AscfRawHashBytes rawHashes,
        CancellationToken token)
    {
        destination.Position = 0;
        var fileHeader = new byte[AscfFileFormat.HeaderSize];
        AscfFileHeaderCodec.Write(fileHeader, rawSize, rawChunkSize, chunkCount, streamId, encodedSize, rawHashes);
        await destination.WriteAsync(fileHeader.AsMemory(0, fileHeader.Length), token).ConfigureAwait(false);
        destination.Position = destination.Length;
    }

    private static async Task TryRewriteHeaderAsync(
        Stream destination,
        long rawSize,
        int chunkCount,
        Guid streamId,
        AscfRawHashBytes rawHashes,
        WriteOptions options,
        CancellationToken token)
    {
        if (!destination.CanSeek || options.Transform != null)
        {
            return;
        }

        await RewriteHeaderAsync(destination, rawSize, options.Format.RawChunkSize, chunkCount, streamId, destination.Length, rawHashes, token).ConfigureAwait(false);
    }

    private static async Task WriteIndexAsync(
        Stream destination,
        List<AscfChunkIndexEntry> entries,
        long rawSize,
        long indexOffset,
        WriteOptions options,
        CancellationToken token)
    {
        var pageSize = checked(AscfFileFormat.IndexEntrySize * FileFormatBuffers.IndexEntriesPerPage);
        var page = ArrayPool<byte>.Shared.Rent(pageSize);
        var indexChecksum = AscfChecksum.CreateIncrementalXxHash3();
        try
        {
            var used = 0;
            foreach (var entry in entries)
            {
                var slot = page.AsSpan(used, AscfFileFormat.IndexEntrySize);
                AscfChunkIndexCodec.WriteEntry(slot, entry);
                indexChecksum.Append(slot);
                used += AscfFileFormat.IndexEntrySize;

                if (used == pageSize)
                {
                    await WriteBytesAsync(destination, page.AsMemory(0, used), options, token).ConfigureAwait(false);
                    used = 0;
                }
            }

            if (used > 0)
            {
                await WriteBytesAsync(destination, page.AsMemory(0, used), options, token).ConfigureAwait(false);
            }

            var indexLength = checked((long)entries.Count * AscfFileFormat.IndexEntrySize);
            var footer = AscfChunkIndexCodec.WriteFooter(entries.Count, rawSize, indexOffset, indexLength, indexChecksum.GetCurrentHashAsUInt64());
            await WriteBytesAsync(destination, footer, options, token).ConfigureAwait(false);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(page);
        }
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

    private static AscfRawContentHasher? CreateRawHasher(AscfRawHashAlgorithms algorithms)
    {
        AscfRawHashAlgorithmFlags.ValidateSupported(algorithms, nameof(algorithms));
        return AscfRawContentHasher.Create(algorithms);
    }

    private static void ValidateHashOptions(AscfWriterOptions options)
    {
        options.Validate();
        if (options.GetResultHashAlgorithms() == AscfRawHashAlgorithms.None)
        {
            throw new ArgumentException("At least one result hash algorithm must be selected.", nameof(options));
        }
    }

    private static AscfRawHashBytes GetHeaderRawHashes(AscfRawHashBytes rawHashes, AscfWriterOptions options)
        => rawHashes.Filter(options.RawHashAlgorithms);

    private static AscfRawHashes GetResultHashes(AscfRawHashBytes rawHashes, AscfRawHashAlgorithms algorithms)
        => rawHashes.Filter(algorithms).ToPublic();

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
