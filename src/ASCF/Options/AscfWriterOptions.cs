using ASCF.Util;
namespace ASCF;

/// <summary> options for writing .ascf files </summary>
public sealed record AscfWriterOptions
{
    public static AscfWriterOptions Default { get; } = new();

    public long MaxRawFileBytes { get; init; } = AscfFileFormat.DefaultMaxRawFileBytes;
    public int RawChunkSize { get; init; } = AscfFileFormat.DefaultRawChunkBytes;
    public int BufferSize { get; init; } = AscfFileFormat.DefaultBufferSize;
    public int CompressionWorkerCount { get; init; } = AscfFileFormat.DefaultCompressionWorkerCount;

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

        if (CompressionWorkerCount <= 0 || CompressionWorkerCount > AscfFileFormat.MaxCompressionWorkerCount)
        {
            throw new ArgumentOutOfRangeException(
                nameof(CompressionWorkerCount),
                CompressionWorkerCount,
                $"Compression worker count must be between 1 and {AscfFileFormat.MaxCompressionWorkerCount}.");
        }
    }
}
