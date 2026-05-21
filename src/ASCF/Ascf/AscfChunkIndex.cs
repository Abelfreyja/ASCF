namespace ASCF;

/// <summary> chunk index read from an .ascf footer. </summary>
public sealed class AscfChunkIndex
{
    private readonly AscfChunkIndexEntry[] _entries;

    public AscfChunkIndex(IEnumerable<AscfChunkIndexEntry> entries)
    {
        _entries = entries.ToArray();
        ValidateOrderedEntries(_entries);
    }

    /// <summary> The entries in file order. </summary>
    public IReadOnlyList<AscfChunkIndexEntry> Entries => _entries;

    /// <summary> Get the entry for a chunk index. </summary>
    public AscfChunkIndexEntry this[int chunkIndex] => _entries[chunkIndex];

    /// <summary> Find an entry by chunk index. </summary>
    public bool TryGetChunk(int chunkIndex, out AscfChunkIndexEntry entry)
    {
        if ((uint)chunkIndex >= (uint)_entries.Length)
        {
            entry = default;
            return false;
        }

        entry = _entries[chunkIndex];
        return true;
    }

    /// <summary> Find the entry containing a raw byte ofset. </summary>
    public bool TryGetChunkForRawOffset(long rawOffset, out AscfChunkIndexEntry entry)
    {
        if (rawOffset < 0 || _entries.Length == 0)
        {
            entry = default;
            return false;
        }

        var left = 0;
        var right = _entries.Length - 1;
        while (left <= right)
        {
            var index = left + ((right - left) / 2);
            var candidate = _entries[index];
            if (rawOffset < candidate.RawOffset)
            {
                right = index - 1;
                continue;
            }

            if (rawOffset >= candidate.RawOffset + candidate.RawLength)
            {
                left = index + 1;
                continue;
            }

            entry = candidate;
            return true;
        }

        entry = default;
        return false;
    }

    private static void ValidateOrderedEntries(ReadOnlySpan<AscfChunkIndexEntry> entries)
    {
        long expectedRawOffset = 0;
        long expectedChunkOffset = AscfFileFormat.HeaderSize;
        for (var i = 0; i < entries.Length; i++)
        {
            var entry = entries[i];
            if (entry.ChunkIndex != i
                || entry.Method < 0
                || entry.Method > AscfFileFormat.MethodLz4HighCompression
                || entry.RawLength <= 0
                || entry.RawLength > AscfFileFormat.MaxRawChunkBytes
                || entry.StoredLength <= 0
                || entry.RawOffset != expectedRawOffset
                || entry.ChunkOffset != expectedChunkOffset)
            {
                throw new InvalidDataException(".ascf index entries are invalid.");
            }

            expectedRawOffset = checked(expectedRawOffset + entry.RawLength);
            expectedChunkOffset = checked(expectedChunkOffset + AscfFileFormat.ChunkHeaderSize + entry.StoredLength);
        }
    }
}

/// <summary> One entry in the .ascf chunk index. </summary>
public readonly record struct AscfChunkIndexEntry(
    int ChunkIndex,
    int Method,
    long RawOffset,
    long ChunkOffset,
    int RawLength,
    int StoredLength,
    ulong RawChecksum,
    ulong StoredChecksum)
{
    /// <summary> The encoded offset of the payload bytes. </summary>
    public long PayloadOffset => ChunkOffset + AscfFileFormat.ChunkHeaderSize;
}
