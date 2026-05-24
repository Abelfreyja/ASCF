using ASCF.Util;

namespace ASCF.Lz4;

/// <summary> options for wrapped lz4 helpers </summary>
public sealed record Lz4FormatOptions
{
    public static Lz4FormatOptions Default { get; } = new();

    public long MaxRawFileBytes { get; init; } = AscfFileFormat.DefaultMaxRawFileBytes;
    public int MaxInMemoryDecodeBytes { get; init; } = AscfFileFormat.DefaultMaxInMemoryDecodeBytes;
    public int BufferSize { get; init; } = AscfFileFormat.DefaultBufferSize;
    public int CopyBufferSize { get; init; } = AscfFileFormat.DefaultBufferSize;
    public int MemoryMappedCompressionThreshold { get; init; } = 8 * 1024 * 1024;
    public int MemoryMappedDecodeThreshold { get; init; } = 128 * 1024 * 1024;

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
        FileFormatBuffers.ValidateBufferSize(CopyBufferSize, nameof(CopyBufferSize));

        if (MemoryMappedCompressionThreshold < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(MemoryMappedCompressionThreshold),
                MemoryMappedCompressionThreshold,
                "Memory mapped compression threshold must be non-negative.");
        }

        if (MemoryMappedDecodeThreshold < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(MemoryMappedDecodeThreshold),
                MemoryMappedDecodeThreshold,
                "Memory mapped decode threshold must be non-negative.");
        }
    }
}
