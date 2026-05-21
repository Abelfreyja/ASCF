using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace ASCF;

[StructLayout(LayoutKind.Auto)]
internal readonly record struct AscfFileHeader(
    long RawSize,
    int Flags,
    int RawChunkSize,
    int ChunkCount,
    Guid StreamId,
    long EncodedSize);

internal static class AscfFileHeaderCodec
{
    private const int HeaderChecksumOffset = 0x48;
    private const int KnownFlags = AscfFileFormat.RequiredHeaderFlags;

    //
    //  file header, 80 bytes
    //
    //      +0x00  +------------------------------+
    //             | magic               ASCF     | u32
    //      +0x04  +------------------------------+
    //             | version                      | u32
    //      +0x08  +------------------------------+
    //             | raw size                     | i64
    //      +0x10  +------------------------------+
    //             | header size                  | u32
    //      +0x14  +------------------------------+
    //             | flags                        | u32
    //      +0x18  +------------------------------+
    //             | raw chunk size               | i32
    //      +0x1c  +------------------------------+
    //             | chunk count                  | i32
    //      +0x20  +------------------------------+
    //             | chunk header size            | u16
    //      +0x22  +------------------------------+
    //             | index entry size             | u16
    //      +0x24  +------------------------------+
    //             | checksum kind                | u16
    //      +0x26  +------------------------------+
    //             | chunk checksum flags         | u16
    //      +0x28  +------------------------------+
    //             | supported method mask        | u32
    //      +0x2c  +------------------------------+
    //             | reserved                     | u32
    //      +0x30  +------------------------------+
    //             | stream id                    | 16 bytes
    //      +0x40  +------------------------------+
    //             | encoded size                 | i64
    //      +0x48  +------------------------------+
    //             | header checksum              | u64
    //      +0x50  +------------------------------+
    //

    public static void Write(Span<byte> destination, long rawSize, int rawChunkSize, int chunkCount, Guid streamId, long encodedSize)
    {
        destination.Clear();
        BinaryPrimitives.WriteInt32LittleEndian(destination[0x00..], AscfFileFormat.Magic);
        BinaryPrimitives.WriteInt32LittleEndian(destination[0x04..], AscfFileFormat.Version);
        BinaryPrimitives.WriteInt64LittleEndian(destination[0x08..], rawSize);
        BinaryPrimitives.WriteInt32LittleEndian(destination[0x10..], AscfFileFormat.HeaderSize);
        BinaryPrimitives.WriteInt32LittleEndian(destination[0x14..], AscfFileFormat.RequiredHeaderFlags);
        BinaryPrimitives.WriteInt32LittleEndian(destination[0x18..], rawChunkSize);
        BinaryPrimitives.WriteInt32LittleEndian(destination[0x1C..], chunkCount);
        BinaryPrimitives.WriteUInt16LittleEndian(destination[0x20..], AscfFileFormat.ChunkHeaderSize);
        BinaryPrimitives.WriteUInt16LittleEndian(destination[0x22..], AscfFileFormat.IndexEntrySize);
        BinaryPrimitives.WriteUInt16LittleEndian(destination[0x24..], AscfFileFormat.ChecksumKindXxHash3);
        BinaryPrimitives.WriteUInt16LittleEndian(destination[0x26..], AscfFileFormat.RequiredChunkChecksumFlags);
        BinaryPrimitives.WriteInt32LittleEndian(destination[0x28..], AscfFileFormat.SupportedMethodMask);
        _ = streamId.TryWriteBytes(destination.Slice(0x30, 16));
        BinaryPrimitives.WriteInt64LittleEndian(destination[0x40..], encodedSize);
        BinaryPrimitives.WriteUInt64LittleEndian(destination[HeaderChecksumOffset..], ComputeHeaderChecksum(destination));
    }

    public static bool TryRead(ReadOnlySpan<byte> source, long maxRawSize, out AscfFileHeader header)
    {
        header = default;
        if (source.Length < AscfFileFormat.HeaderSize)
        {
            return false;
        }

        if (BinaryPrimitives.ReadInt32LittleEndian(source[0x00..]) != AscfFileFormat.Magic
            || BinaryPrimitives.ReadInt32LittleEndian(source[0x04..]) != AscfFileFormat.Version)
        {
            return false;
        }

        if (BinaryPrimitives.ReadInt32LittleEndian(source[0x10..]) != AscfFileFormat.HeaderSize
            || BinaryPrimitives.ReadUInt16LittleEndian(source[0x20..]) != AscfFileFormat.ChunkHeaderSize
            || BinaryPrimitives.ReadUInt16LittleEndian(source[0x22..]) != AscfFileFormat.IndexEntrySize
            || BinaryPrimitives.ReadUInt16LittleEndian(source[0x24..]) != AscfFileFormat.ChecksumKindXxHash3
            || BinaryPrimitives.ReadUInt16LittleEndian(source[0x26..]) != AscfFileFormat.RequiredChunkChecksumFlags
            || BinaryPrimitives.ReadInt32LittleEndian(source[0x28..]) != AscfFileFormat.SupportedMethodMask)
        {
            return false;
        }

        var rawChunkSize = BinaryPrimitives.ReadInt32LittleEndian(source[0x18..]);
        if (rawChunkSize < AscfFileFormat.MinRawChunkBytes || rawChunkSize > AscfFileFormat.MaxRawChunkBytes)
        {
            return false;
        }

        var flags = BinaryPrimitives.ReadInt32LittleEndian(source[0x14..]);
        if ((flags & ~KnownFlags) != 0
            || (flags & AscfFileFormat.RequiredHeaderFlags) != AscfFileFormat.RequiredHeaderFlags)
        {
            return false;
        }

        var rawSize = BinaryPrimitives.ReadInt64LittleEndian(source[0x08..]);
        if (rawSize < 0 || rawSize > maxRawSize)
        {
            return false;
        }

        var chunkCount = BinaryPrimitives.ReadInt32LittleEndian(source[0x1C..]);
        if (chunkCount != AscfFileFormat.GetChunkCount(rawSize, rawChunkSize))
        {
            return false;
        }

        if (BinaryPrimitives.ReadInt32LittleEndian(source[0x2C..]) != 0
            || !HeaderChecksumMatches(source))
        {
            return false;
        }

        var streamId = new Guid(source.Slice(0x30, 16));
        var encodedSize = BinaryPrimitives.ReadInt64LittleEndian(source[0x40..]);
        if (encodedSize < 0)
        {
            return false;
        }

        header = new AscfFileHeader(rawSize, flags, rawChunkSize, chunkCount, streamId, encodedSize);
        return true;
    }

    public static AscfFileHeader Read(ReadOnlySpan<byte> source, long maxRawSize)
        => TryRead(source, maxRawSize, out var header)
            ? header
            : throw new InvalidDataException(".ascf header is invalid.");

    private static bool HeaderChecksumMatches(ReadOnlySpan<byte> source)
    {
        Span<byte> header = stackalloc byte[AscfFileFormat.HeaderSize];
        source[..AscfFileFormat.HeaderSize].CopyTo(header);
        var expected = BinaryPrimitives.ReadUInt64LittleEndian(header[HeaderChecksumOffset..]);
        return AscfChecksum.ComputeXxHash3WithZeroedField(header, HeaderChecksumOffset) == expected;
    }

    private static ulong ComputeHeaderChecksum(Span<byte> header)
        => AscfChecksum.ComputeXxHash3WithZeroedField(header, HeaderChecksumOffset);
}
