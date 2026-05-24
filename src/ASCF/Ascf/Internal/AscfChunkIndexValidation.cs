using ASCF.Lz4;

namespace ASCF;

internal static class AscfChunkIndexValidation
{
    public static void ValidateEntryStorage(AscfChunkIndexEntry entry)
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

    public static void ValidateEntryAgainstHeader(
        AscfChunkIndexEntry entry,
        AscfFileHeader fileHeader,
        long indexOffset,
        int expectedIndex)
    {
        var nextEncodedOffset = GetNextEncodedOffset(entry);
        var expectedRawOffset = checked((long)expectedIndex * fileHeader.RawChunkSize);
        var expectedRawLength = expectedIndex == fileHeader.ChunkCount - 1
            ? checked((int)(fileHeader.RawSize - expectedRawOffset))
            : fileHeader.RawChunkSize;
        if (entry.ChunkIndex != expectedIndex
            || entry.RawOffset != expectedRawOffset
            || entry.RawLength != expectedRawLength
            || entry.ChunkOffset < AscfFileFormat.HeaderSize
            || nextEncodedOffset > indexOffset)
        {
            throw new InvalidDataException(".ascf index entries do not match the file header.");
        }

        ValidateEntryStorage(entry);
    }

    public static void ValidateChunkOffset(AscfChunkIndexEntry entry, long expectedChunkOffset)
    {
        if (entry.ChunkOffset != expectedChunkOffset)
        {
            throw new InvalidDataException(".ascf index entries do not match the file layout.");
        }
    }

    public static long GetNextEncodedOffset(AscfChunkIndexEntry entry)
    {
        try
        {
            return entry.NextEncodedOffset;
        }
        catch (OverflowException exception)
        {
            throw new InvalidDataException(".ascf index offsets overflow.", exception);
        }
    }

    public static long AddOffset(long left, long right)
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
