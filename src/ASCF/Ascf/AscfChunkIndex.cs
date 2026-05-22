using ASCF.Lz4;
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
            var expectedRawLength = i == _entries.Length - 1
                ? checked((int)(fileHeader.RawSize - expectedRawOffset))
                : fileHeader.RawChunkSize;

            if (entry.ChunkIndex != i
                || entry.RawOffset != expectedRawOffset
                || entry.ChunkOffset != expectedChunkOffset
                || entry.RawLength != expectedRawLength)
            {
                throw new InvalidDataException(".ascf index entries do not match the file header.");
            }

            ValidateMethodForRandomAccess(entry);

            var payloadOffset = CheckedAdd(entry.ChunkOffset, AscfFileFormat.ChunkHeaderSize);
            var payloadEnd = CheckedAdd(payloadOffset, entry.StoredLength);
            if (payloadEnd > indexOffset)
            {
                throw new InvalidDataException(".ascf index payload range overlaps the index.");
            }

            expectedRawOffset = CheckedAdd(expectedRawOffset, entry.RawLength);
            expectedChunkOffset = CheckedAdd(expectedChunkOffset, (long)AscfFileFormat.ChunkHeaderSize + entry.StoredLength);
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

    private static void ValidateMethodForRandomAccess(AscfChunkIndexEntry entry)
    {
        if (entry.Method == AscfFileFormat.MethodRaw)
        {
            if (entry.StoredLength != entry.RawLength)
            {
                throw new InvalidDataException(".ascf raw index entry has mismatched stored length.");
            }

            return;
        }

        if (entry.Method < AscfFileFormat.MethodRaw
            || entry.Method > AscfFileFormat.MethodLz4HighCompression
            || (AscfFileFormat.SupportedMethodMask & (1 << entry.Method)) == 0)
        {
            throw new InvalidDataException($".ascf index entry uses unsupported method {entry.Method}.");
        }

        var maxStoredLength = Lz4BlockCodec.MaxUsefulCompressedLength(entry.RawLength);
        if (entry.StoredLength <= 0 || entry.StoredLength > maxStoredLength)
        {
            throw new InvalidDataException($".ascf compressed index entry length {entry.StoredLength} is invalid.");
        }
    }

    private static long CheckedAdd(long left, long right)
    {
        try
        {
            return checked(left + right);
        }
        catch (OverflowException exception)
        {
            throw new InvalidDataException(".ascf index offsets overflow.", exception);
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
}
