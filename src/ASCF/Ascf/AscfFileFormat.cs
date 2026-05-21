namespace ASCF;

public static class AscfFileFormat
{
    //
    //  ASCF container
    //
    //       +0x0000 +--------------------------------+
    //               | file header          ASCF      |
    //               | 80 bytes                       |
    //               +--------------------------------+
    //               | chunk header         ASCH      |
    //               | 64 bytes                       |
    //               +--------------------------------+
    //               | chunk payload                  |
    //               +--------------------------------+
    //               | ... more chunk records ...     |
    //               +--------------------------------+
    //               | chunk index entries            |
    //               | 64 bytes each                  |
    //      eof - 64 +--------------------------------+
    //               | index footer         ASIX      |
    //               | 64 bytes                       |
    //               +--------------------------------+
    //
    //  header flags
    //
    //      0000 0000 0000 00FI
    //                       ^^
    //                       ||
    //                       |+-- bit 0: chunk index present
    //                       +--- bit 1: fixed raw chunking
    //

    public const int Magic = 0x46435341; // ASCF
    public const int ChunkMagic = 0x48435341; // ASCH
    public const int Version = 1;
    public const int HeaderSize = 80;
    public const int ChunkHeaderSize = 64;
    public const int IndexEntrySize = 64;
    public const int IndexFooterSize = 64;
    public const int DefaultRawChunkBytes = 1024 * 1024;
    public const int MinRawChunkBytes = 16 * 1024;
    public const int MaxRawChunkBytes = 16 * 1024 * 1024;
    public const int DefaultBufferSize = 81920;
    public const int DefaultMaxInMemoryDecodeBytes = 512 * 1024 * 1024;
    public const long DefaultMaxRawFileBytes = 32L * 1024 * 1024 * 1024;
    public const int MaxCompressionWorkerCount = 64;
    public static int DefaultCompressionWorkerCount { get; } = Math.Clamp(Math.Max(1, Environment.ProcessorCount) / 2, 1, 16);

    public const int HeaderFlagChunkIndexPresent = 1;
    public const int HeaderFlagFixedRawChunkingRequired = 1 << 1;

    public const int IndexMagic = 0x58495341; // ASIX

    public const int ChunkFlagRawChecksumPresent = 1;
    public const int ChunkFlagStoredChecksumPresent = 1 << 1;
    public const int ChunkFlagFinalChunk = 1 << 2;

    public const int ChecksumKindXxHash3 = 1;

    public const int MethodRaw = 0;
    public const int MethodLz4Fast = 1;
    public const int MethodLz4HighCompression = 2;

    public const int RequiredChunkChecksumFlags = ChunkFlagRawChecksumPresent | ChunkFlagStoredChecksumPresent;
    public const int SupportedMethodMask = (1 << MethodRaw) | (1 << MethodLz4Fast) | (1 << MethodLz4HighCompression);
    public const int RequiredHeaderFlags = HeaderFlagChunkIndexPresent | HeaderFlagFixedRawChunkingRequired;

    public static int GetChunkCount(long rawSize)
        => GetChunkCount(rawSize, DefaultRawChunkBytes);

    public static int GetChunkCount(long rawSize, int rawChunkSize)
    {
        if (rawSize < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(rawSize), rawSize, "Raw size must be non-negative.");
        }

        if (rawChunkSize < MinRawChunkBytes || rawChunkSize > MaxRawChunkBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(rawChunkSize), rawChunkSize, "Raw chunk size is outside the supported range.");
        }

        return rawSize == 0
            ? 0
            : checked((int)((rawSize + rawChunkSize - 1) / rawChunkSize));
    }
}
