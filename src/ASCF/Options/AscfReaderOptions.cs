using ASCF.Util;

namespace ASCF;

/// <summary> options for reading .ascf files </summary>
public sealed record AscfReaderOptions
{
    public static AscfReaderOptions Default { get; } = new();

    public long MaxRawFileBytes { get; init; } = AscfFileFormat.DefaultMaxRawFileBytes;
    public int MaxInMemoryDecodeBytes { get; init; } = AscfFileFormat.DefaultMaxInMemoryDecodeBytes;
    public int BufferSize { get; init; } = AscfFileFormat.DefaultBufferSize;
    public int ParallelDecodeWorkerCount { get; init; } = AscfFileFormat.AutoWorkerCount;
    public int MaxParallelDecodeWorkerCount { get; init; } = AscfFileFormat.DefaultMaxParallelDecodeWorkerCount;
    public AscfParallelDecodeMode ParallelDecodeMode { get; init; } = AscfParallelDecodeMode.Auto;
    public AscfRawHashAlgorithms ResultHashAlgorithms { get; init; } = AscfRawHashAlgorithms.Sha1;

    internal int GetParallelDecodeWorkerCount()
        => FileFormatWorkerCounts.Resolve(
            ParallelDecodeWorkerCount,
            MaxParallelDecodeWorkerCount,
            nameof(ParallelDecodeWorkerCount),
            nameof(MaxParallelDecodeWorkerCount));

    internal void Validate()
    {
        if (MaxRawFileBytes < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxRawFileBytes), MaxRawFileBytes, "Maximum raw file size must be non-negative.");
        }

        if (MaxInMemoryDecodeBytes < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxInMemoryDecodeBytes), MaxInMemoryDecodeBytes, "Maximum in-memory decode size must be non-negative.");
        }

        FileFormatBuffers.ValidateBufferSize(BufferSize, nameof(BufferSize));
        ValidateParallelDecodeMode(ParallelDecodeMode);
        ValidateResultHashAlgorithms(ResultHashAlgorithms);
        GetParallelDecodeWorkerCount();
    }

    internal AscfParallelDecodeMode ResolveParallelDecodeMode(bool computeHash)
    {
        if (ParallelDecodeMode == AscfParallelDecodeMode.Auto)
        {
            return computeHash ? AscfParallelDecodeMode.OrderedWrite : AscfParallelDecodeMode.RandomWrite;
        }

        return ParallelDecodeMode;
    }

    internal AscfRawHashAlgorithms GetResultHashAlgorithms()
        => ResultHashAlgorithms;

    private static void ValidateParallelDecodeMode(AscfParallelDecodeMode mode)
    {
        if (mode is not AscfParallelDecodeMode.Auto and not AscfParallelDecodeMode.OrderedWrite and not AscfParallelDecodeMode.RandomWrite)
        {
            throw new ArgumentOutOfRangeException(nameof(mode), mode, "Parallel decode mode is not supported.");
        }
    }

    private static void ValidateResultHashAlgorithms(AscfRawHashAlgorithms algorithms)
        => AscfRawHashAlgorithmFlags.ValidateSupported(algorithms, nameof(ResultHashAlgorithms));
}
