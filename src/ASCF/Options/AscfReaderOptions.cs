using ASCF.Util;

namespace ASCF;

/// <summary> options for reading .ascf files </summary>
public sealed record AscfReaderOptions
{
    public static AscfReaderOptions Default { get; } = new();

    public long MaxRawFileBytes { get; init; } = AscfFileFormat.DefaultMaxRawFileBytes;
    public int MaxInMemoryDecodeBytes { get; init; } = AscfFileFormat.DefaultMaxInMemoryDecodeBytes;
    public int BufferSize { get; init; } = AscfFileFormat.DefaultBufferSize;

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
    }
}
