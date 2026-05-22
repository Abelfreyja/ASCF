using ASCF.Lz4;
using ASCF.Util;

namespace ASCF;

/// <summary> options for writing .ascf files </summary>
public sealed record AscfWriterOptions
{
    public static AscfWriterOptions Default { get; } = new();

    public long MaxRawFileBytes { get; init; } = AscfFileFormat.DefaultMaxRawFileBytes;
    public int RawChunkSize { get; init; } = AscfFileFormat.DefaultRawChunkBytes;
    public int BufferSize { get; init; } = AscfFileFormat.DefaultBufferSize;
    public int CompressionWorkerCount { get; init; } = AscfFileFormat.AutoWorkerCount;
    public int MaxCompressionWorkerCount { get; init; } = AscfFileFormat.DefaultMaxCompressionWorkerCount;
    public long MaxCompressionPipelineBytes { get; init; } = AscfFileFormat.DefaultMaxCompressionPipelineBytes;
    public AscfRawHashAlgorithms RawHashAlgorithms { get; init; } = AscfRawHashAlgorithms.None;
    public AscfRawHashAlgorithms ResultHashAlgorithms { get; init; } = AscfRawHashAlgorithms.None;

    internal int GetCompressionWorkerCount()
        => FileFormatWorkerCounts.Resolve(
            CompressionWorkerCount,
            MaxCompressionWorkerCount,
            nameof(CompressionWorkerCount),
            nameof(MaxCompressionWorkerCount));

    internal int GetCompressionPipelineChunkLimit()
    {
        if (MaxCompressionPipelineBytes <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxCompressionPipelineBytes), MaxCompressionPipelineBytes, "Compression pipeline byte limit must be positive.");
        }

        var workerCount = GetCompressionWorkerCount();
        if (workerCount == 1)
        {
            return 1;
        }

        var bytesPerChunk = checked((long)RawChunkSize + Lz4BlockCodec.MaxCompressedLength(RawChunkSize));
        return FileFormatWorkerCounts.ResolveByteWindow(
            bytesPerChunk,
            MaxCompressionPipelineBytes,
            minItemCount: 2,
            maxItemCount: checked((long)workerCount * 2),
            nameof(MaxCompressionPipelineBytes));
    }

    internal void Validate()
    {
        if (MaxRawFileBytes < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxRawFileBytes), MaxRawFileBytes, "Maximum raw file size must be non-negative.");
        }

        if (RawChunkSize < AscfFileFormat.MinRawChunkBytes || RawChunkSize > AscfFileFormat.MaxRawChunkBytes)
        {
            throw new ArgumentOutOfRangeException(
                nameof(RawChunkSize),
                RawChunkSize,
                $"Raw chunk size must be between {AscfFileFormat.MinRawChunkBytes} and {AscfFileFormat.MaxRawChunkBytes} bytes.");
        }

        FileFormatBuffers.ValidateBufferSize(BufferSize, nameof(BufferSize));
        ValidateRawHashAlgorithms(RawHashAlgorithms);
        ValidateResultHashAlgorithms(ResultHashAlgorithms);
        GetCompressionPipelineChunkLimit();
    }

    internal AscfRawHashAlgorithms GetResultHashAlgorithms()
        => ResultHashAlgorithms;

    private static void ValidateRawHashAlgorithms(AscfRawHashAlgorithms algorithms)
        => AscfRawHashAlgorithmFlags.ValidateSupported(algorithms, nameof(RawHashAlgorithms));

    private static void ValidateResultHashAlgorithms(AscfRawHashAlgorithms algorithms)
        => AscfRawHashAlgorithmFlags.ValidateSupported(algorithms, nameof(ResultHashAlgorithms));
}
