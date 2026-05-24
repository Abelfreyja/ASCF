using System.Runtime.InteropServices;

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

    internal AscfChunkIndex(AscfChunkIndexEntry[] entries)
    {
        _entries = entries;
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

    /// <summary> Find the entry containing a raw byte offset. </summary>
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

    /// <summary> snap the encoded byte count to the last complete chunk boundary. </summary>
    public AscfResumePosition GetResumePosition(long encodedBytes, AscfFileMetadata metadata)
    {
        if (encodedBytes < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(encodedBytes), encodedBytes, "Encoded byte count must be non-negative.");
        }

        if (_entries.Length != metadata.ChunkCount)
        {
            throw new InvalidDataException(".ascf index entries do not match the file metadata.");
        }

        if (metadata.EncodedSize > 0 && encodedBytes >= metadata.EncodedSize)
        {
            return new AscfResumePosition(metadata.ChunkCount, metadata.EncodedSize, metadata.RawSize, IsComplete: true);
        }

        if (encodedBytes < AscfFileFormat.HeaderSize)
        {
            return new AscfResumePosition(0, 0, 0, IsComplete: false);
        }

        if (_entries.Length == 0)
        {
            return new AscfResumePosition(0, AscfFileFormat.HeaderSize, 0, IsComplete: false);
        }

        for (var i = 0; i < _entries.Length; i++)
        {
            var entry = _entries[i];
            if (encodedBytes < entry.NextEncodedOffset)
            {
                return new AscfResumePosition(entry.ChunkIndex, entry.ChunkOffset, entry.RawOffset, IsComplete: false);
            }
        }

        var lastEntry = _entries[^1];
        return new AscfResumePosition(metadata.ChunkCount, lastEntry.NextEncodedOffset, metadata.RawSize, IsComplete: false);
    }

    internal void ValidateForRandomAccess(AscfFileHeader fileHeader, long indexOffset)
    {
        if (_entries.Length != fileHeader.ChunkCount)
        {
            throw new InvalidDataException(".ascf index entries do not match the file header.");
        }

        long expectedRawOffset = 0;
        long expectedChunkOffset = AscfFileFormat.HeaderSize;
        for (var i = 0; i < _entries.Length; i++)
        {
            var entry = _entries[i];
            AscfChunkIndexValidation.ValidateEntryAgainstHeader(entry, fileHeader, indexOffset, i);
            AscfChunkIndexValidation.ValidateChunkOffset(entry, expectedChunkOffset);
            expectedRawOffset = AscfChunkIndexValidation.AddOffset(expectedRawOffset, entry.RawLength);
            expectedChunkOffset = AscfChunkIndexValidation.GetNextEncodedOffset(entry);
        }

        if (expectedRawOffset != fileHeader.RawSize || expectedChunkOffset != indexOffset)
        {
            throw new InvalidDataException(".ascf index entries do not match the file layout.");
        }
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
                || entry.RawOffset != expectedRawOffset
                || entry.ChunkOffset != expectedChunkOffset)
            {
                throw new InvalidDataException(".ascf index entries are invalid.");
            }

            AscfChunkIndexValidation.ValidateEntryStorage(entry);
            expectedRawOffset = AscfChunkIndexValidation.AddOffset(expectedRawOffset, entry.RawLength);
            expectedChunkOffset = AscfChunkIndexValidation.GetNextEncodedOffset(entry);
        }
    }
}

/// <summary> One entry in the .ascf chunk index. </summary>
[StructLayout(LayoutKind.Auto)]
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
    public long PayloadOffset => checked(ChunkOffset + AscfFileFormat.ChunkHeaderSize);

    /// <summary> the encoded offset after this chunk record. </summary>
    public long NextEncodedOffset => checked(PayloadOffset + StoredLength);
}
