using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace ASCF;

[StructLayout(LayoutKind.Auto)]
internal readonly record struct AscfIndexFooter(
    int ChunkCount,
    long RawSize,
    long IndexOffset,
    long IndexLength,
    ulong IndexChecksum);

internal static class AscfChunkIndexCodec
{
    //
    //  index entry, 64 bytes each
    //
    //      +0x00  +------------------------------+
    //             | chunk index                  | i32
    //      +0x04  +------------------------------+
    //             | method                       | u16
    //      +0x06  +------------------------------+
    //             | checksum flags               | u16
    //      +0x08  +------------------------------+
    //             | raw offset                   | i64
    //      +0x10  +------------------------------+
    //             | chunk offset                 | i64
    //      +0x18  +------------------------------+
    //             | raw length                   | i32
    //      +0x1c  +------------------------------+
    //             | stored length                | i32
    //      +0x20  +------------------------------+
    //             | raw checksum                 | u64
    //      +0x28  +------------------------------+
    //             | stored checksum              | u64
    //      +0x30  +------------------------------+
    //             | entry checksum               | u64
    //      +0x38  +------------------------------+
    //             | reserved                     | u64
    //      +0x40  +------------------------------+
    //
    //  index footer, 64 bytes
    //
    //      +0x00  +------------------------------+
    //             | magic               ASIX     | u32
    //      +0x04  +------------------------------+
    //             | version                      | u32
    //      +0x08  +------------------------------+
    //             | footer size                  | u32
    //      +0x0c  +------------------------------+
    //             | index entry size             | u32
    //      +0x10  +------------------------------+
    //             | chunk count                  | i32
    //      +0x14  +------------------------------+
    //             | reserved                     | u32
    //      +0x18  +------------------------------+
    //             | raw size                     | i64
    //      +0x20  +------------------------------+
    //             | index offset                 | i64
    //      +0x28  +------------------------------+
    //             | index length                 | i64
    //      +0x30  +------------------------------+
    //             | index checksum               | u64
    //      +0x38  +------------------------------+
    //             | footer checksum              | u64
    //      +0x40  +------------------------------+
    //

    public static AscfChunkIndex ReadIndex(ReadOnlySpan<byte> index, AscfIndexFooter footer)
    {
        if (index.Length != footer.IndexLength || index.Length % AscfFileFormat.IndexEntrySize != 0)
        {
            throw new InvalidDataException(".ascf index length is invalid.");
        }

        var checksum = AscfChecksum.ComputeXxHash3(index);
        if (checksum != footer.IndexChecksum)
        {
            throw new InvalidDataException(".ascf index checksum mismatch.");
        }

        var entries = new AscfChunkIndexEntry[footer.ChunkCount];
        for (var i = 0; i < entries.Length; i++)
        {
            entries[i] = ReadEntry(index.Slice(i * AscfFileFormat.IndexEntrySize, AscfFileFormat.IndexEntrySize));
        }

        return new AscfChunkIndex(entries);
    }

    public static byte[] WriteFooter(int chunkCount, long rawSize, long indexOffset, long indexLength, ulong indexChecksum)
    {
        var footer = new byte[AscfFileFormat.IndexFooterSize];
        footer.AsSpan().Clear();
        BinaryPrimitives.WriteInt32LittleEndian(footer.AsSpan(0x00), AscfFileFormat.IndexMagic);
        BinaryPrimitives.WriteInt32LittleEndian(footer.AsSpan(0x04), AscfFileFormat.Version);
        BinaryPrimitives.WriteInt32LittleEndian(footer.AsSpan(0x08), AscfFileFormat.IndexFooterSize);
        BinaryPrimitives.WriteInt32LittleEndian(footer.AsSpan(0x0C), AscfFileFormat.IndexEntrySize);
        BinaryPrimitives.WriteInt32LittleEndian(footer.AsSpan(0x10), chunkCount);
        BinaryPrimitives.WriteInt64LittleEndian(footer.AsSpan(0x18), rawSize);
        BinaryPrimitives.WriteInt64LittleEndian(footer.AsSpan(0x20), indexOffset);
        BinaryPrimitives.WriteInt64LittleEndian(footer.AsSpan(0x28), indexLength);
        BinaryPrimitives.WriteUInt64LittleEndian(footer.AsSpan(0x30), indexChecksum);
        BinaryPrimitives.WriteUInt64LittleEndian(footer.AsSpan(0x38), ComputeFooterChecksum(footer));
        return footer;
    }

    public static AscfIndexFooter ReadFooter(ReadOnlySpan<byte> footer, long fileLength)
    {
        if (footer.Length < AscfFileFormat.IndexFooterSize
            || BinaryPrimitives.ReadInt32LittleEndian(footer[0x00..]) != AscfFileFormat.IndexMagic
            || BinaryPrimitives.ReadInt32LittleEndian(footer[0x04..]) != AscfFileFormat.Version
            || BinaryPrimitives.ReadInt32LittleEndian(footer[0x08..]) != AscfFileFormat.IndexFooterSize
            || BinaryPrimitives.ReadInt32LittleEndian(footer[0x0C..]) != AscfFileFormat.IndexEntrySize
            || BinaryPrimitives.ReadInt32LittleEndian(footer[0x14..]) != 0
            || !FooterChecksumMatches(footer))
        {
            throw new InvalidDataException(".ascf index footer is invalid.");
        }

        var chunkCount = BinaryPrimitives.ReadInt32LittleEndian(footer[0x10..]);
        var rawSize = BinaryPrimitives.ReadInt64LittleEndian(footer[0x18..]);
        var indexOffset = BinaryPrimitives.ReadInt64LittleEndian(footer[0x20..]);
        var indexLength = BinaryPrimitives.ReadInt64LittleEndian(footer[0x28..]);
        var indexChecksum = BinaryPrimitives.ReadUInt64LittleEndian(footer[0x30..]);
        if (chunkCount < 0
            || rawSize < 0
            || indexOffset < AscfFileFormat.HeaderSize
            || indexLength != checked((long)chunkCount * AscfFileFormat.IndexEntrySize)
            || indexOffset + indexLength + AscfFileFormat.IndexFooterSize != fileLength)
        {
            throw new InvalidDataException(".ascf index footer length fields are invalid.");
        }

        return new AscfIndexFooter(chunkCount, rawSize, indexOffset, indexLength, indexChecksum);
    }

    public static void WriteEntry(Span<byte> destination, AscfChunkIndexEntry entry)
    {
        destination.Clear();
        BinaryPrimitives.WriteInt32LittleEndian(destination[0x00..], entry.ChunkIndex);
        BinaryPrimitives.WriteUInt16LittleEndian(destination[0x04..], (ushort)entry.Method);
        BinaryPrimitives.WriteUInt16LittleEndian(destination[0x06..], AscfFileFormat.RequiredChunkChecksumFlags);
        BinaryPrimitives.WriteInt64LittleEndian(destination[0x08..], entry.RawOffset);
        BinaryPrimitives.WriteInt64LittleEndian(destination[0x10..], entry.ChunkOffset);
        BinaryPrimitives.WriteInt32LittleEndian(destination[0x18..], entry.RawLength);
        BinaryPrimitives.WriteInt32LittleEndian(destination[0x1C..], entry.StoredLength);
        BinaryPrimitives.WriteUInt64LittleEndian(destination[0x20..], entry.RawChecksum);
        BinaryPrimitives.WriteUInt64LittleEndian(destination[0x28..], entry.StoredChecksum);
        BinaryPrimitives.WriteUInt64LittleEndian(destination[0x30..], ComputeEntryChecksum(destination));
    }

    internal static AscfChunkIndexEntry ReadEntry(ReadOnlySpan<byte> source)
    {
        if (source.Length < AscfFileFormat.IndexEntrySize
            || BinaryPrimitives.ReadUInt16LittleEndian(source[0x06..]) != AscfFileFormat.RequiredChunkChecksumFlags
            || BinaryPrimitives.ReadInt64LittleEndian(source[0x38..]) != 0
            || !EntryChecksumMatches(source))
        {
            throw new InvalidDataException(".ascf index entry is invalid.");
        }

        return new AscfChunkIndexEntry(
            BinaryPrimitives.ReadInt32LittleEndian(source[0x00..]),
            BinaryPrimitives.ReadUInt16LittleEndian(source[0x04..]),
            BinaryPrimitives.ReadInt64LittleEndian(source[0x08..]),
            BinaryPrimitives.ReadInt64LittleEndian(source[0x10..]),
            BinaryPrimitives.ReadInt32LittleEndian(source[0x18..]),
            BinaryPrimitives.ReadInt32LittleEndian(source[0x1C..]),
            BinaryPrimitives.ReadUInt64LittleEndian(source[0x20..]),
            BinaryPrimitives.ReadUInt64LittleEndian(source[0x28..]));
    }

    private static bool EntryChecksumMatches(ReadOnlySpan<byte> source)
    {
        Span<byte> entry = stackalloc byte[AscfFileFormat.IndexEntrySize];
        source[..AscfFileFormat.IndexEntrySize].CopyTo(entry);
        var expected = BinaryPrimitives.ReadUInt64LittleEndian(entry[0x30..]);
        return AscfChecksum.ComputeXxHash3WithZeroedField(entry, 0x30) == expected;
    }

    private static ulong ComputeEntryChecksum(Span<byte> entry)
        => AscfChecksum.ComputeXxHash3WithZeroedField(entry, 0x30);

    private static bool FooterChecksumMatches(ReadOnlySpan<byte> source)
    {
        Span<byte> footer = stackalloc byte[AscfFileFormat.IndexFooterSize];
        source[..AscfFileFormat.IndexFooterSize].CopyTo(footer);
        var expected = BinaryPrimitives.ReadUInt64LittleEndian(footer[0x38..]);
        return AscfChecksum.ComputeXxHash3WithZeroedField(footer, 0x38) == expected;
    }

    private static ulong ComputeFooterChecksum(Span<byte> footer)
        => AscfChecksum.ComputeXxHash3WithZeroedField(footer, 0x38);
}
