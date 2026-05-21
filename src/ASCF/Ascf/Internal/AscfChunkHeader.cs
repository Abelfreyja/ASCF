using System.Buffers.Binary;
using System.Runtime.InteropServices;
using ASCF.Lz4;

namespace ASCF;

[StructLayout(LayoutKind.Auto)]
internal readonly record struct AscfChunkHeader(
    int ChunkIndex,
    int Method,
    long RawOffset,
    int RawLength,
    int StoredLength,
    ulong RawChecksum,
    ulong StoredChecksum,
    int Flags)
{
    public bool StoresRaw => Method == AscfFileFormat.MethodRaw;
}

internal static class AscfChunkHeaderCodec
{
    private const int ChunkHeaderChecksumOffset = 0x30;
    private const int KnownFlags = AscfFileFormat.ChunkFlagRawChecksumPresent
        | AscfFileFormat.ChunkFlagStoredChecksumPresent
        | AscfFileFormat.ChunkFlagFinalChunk;

    //
    //  chunk header, 64 bytes
    //
    //      +0x00  +------------------------------+
    //             | magic               ASCH     | u32
    //      +0x04  +------------------------------+
    //             | header size                  | u16
    //      +0x06  +------------------------------+
    //             | flags                        | u16
    //      +0x08  +------------------------------+
    //             | chunk index                  | i32
    //      +0x0c  +------------------------------+
    //             | method                       | u16
    //      +0x0e  +------------------------------+
    //             | checksum kind                | u16
    //      +0x10  +------------------------------+
    //             | raw offset                   | i64
    //      +0x18  +------------------------------+
    //             | raw length                   | i32
    //      +0x1c  +------------------------------+
    //             | stored length                | i32
    //      +0x20  +------------------------------+
    //             | raw checksum                 | u64
    //      +0x28  +------------------------------+
    //             | stored checksum              | u64
    //      +0x30  +------------------------------+
    //             | header checksum              | u64
    //      +0x38  +------------------------------+
    //             | reserved                     | u64
    //      +0x40  +------------------------------+
    //

    public static void Write(Span<byte> destination, AscfChunkHeader header)
    {
        destination.Clear();
        BinaryPrimitives.WriteInt32LittleEndian(destination[0x00..], AscfFileFormat.ChunkMagic);
        BinaryPrimitives.WriteUInt16LittleEndian(destination[0x04..], AscfFileFormat.ChunkHeaderSize);
        BinaryPrimitives.WriteUInt16LittleEndian(destination[0x06..], (ushort)header.Flags);
        BinaryPrimitives.WriteInt32LittleEndian(destination[0x08..], header.ChunkIndex);
        BinaryPrimitives.WriteUInt16LittleEndian(destination[0x0C..], (ushort)header.Method);
        BinaryPrimitives.WriteUInt16LittleEndian(destination[0x0E..], AscfFileFormat.ChecksumKindXxHash3);
        BinaryPrimitives.WriteInt64LittleEndian(destination[0x10..], header.RawOffset);
        BinaryPrimitives.WriteInt32LittleEndian(destination[0x18..], header.RawLength);
        BinaryPrimitives.WriteInt32LittleEndian(destination[0x1C..], header.StoredLength);
        BinaryPrimitives.WriteUInt64LittleEndian(destination[0x20..], header.RawChecksum);
        BinaryPrimitives.WriteUInt64LittleEndian(destination[0x28..], header.StoredChecksum);
        BinaryPrimitives.WriteUInt64LittleEndian(destination[ChunkHeaderChecksumOffset..], ComputeHeaderChecksum(destination));
    }

    public static AscfChunkHeader Read(
        ReadOnlySpan<byte> source,
        AscfFileHeader fileHeader,
        int expectedChunkIndex,
        long expectedRawOffset)
    {
        if (source.Length < AscfFileFormat.ChunkHeaderSize
            || BinaryPrimitives.ReadInt32LittleEndian(source[0x00..]) != AscfFileFormat.ChunkMagic
            || BinaryPrimitives.ReadUInt16LittleEndian(source[0x04..]) != AscfFileFormat.ChunkHeaderSize
            || BinaryPrimitives.ReadUInt16LittleEndian(source[0x0E..]) != AscfFileFormat.ChecksumKindXxHash3
            || BinaryPrimitives.ReadInt64LittleEndian(source[0x38..]) != 0
            || !HeaderChecksumMatches(source))
        {
            throw new InvalidDataException(".ascf chunk header is invalid.");
        }

        var flags = BinaryPrimitives.ReadUInt16LittleEndian(source[0x06..]);
        var chunkIndex = BinaryPrimitives.ReadInt32LittleEndian(source[0x08..]);
        var method = BinaryPrimitives.ReadUInt16LittleEndian(source[0x0C..]);
        var rawOffset = BinaryPrimitives.ReadInt64LittleEndian(source[0x10..]);
        var rawLength = BinaryPrimitives.ReadInt32LittleEndian(source[0x18..]);
        var storedLength = BinaryPrimitives.ReadInt32LittleEndian(source[0x1C..]);
        var rawChecksum = BinaryPrimitives.ReadUInt64LittleEndian(source[0x20..]);
        var storedChecksum = BinaryPrimitives.ReadUInt64LittleEndian(source[0x28..]);

        Validate(
            flags,
            chunkIndex,
            method,
            rawOffset,
            rawLength,
            storedLength,
            fileHeader,
            expectedChunkIndex,
            expectedRawOffset);

        return new AscfChunkHeader(
            chunkIndex,
            method,
            rawOffset,
            rawLength,
            storedLength,
            rawChecksum,
            storedChecksum,
            flags);
    }

    public static int GetFlags(bool isFinalChunk)
        => AscfFileFormat.RequiredChunkChecksumFlags
            | (isFinalChunk ? AscfFileFormat.ChunkFlagFinalChunk : 0);

    private static void Validate(
        int flags,
        int chunkIndex,
        int method,
        long rawOffset,
        int rawLength,
        int storedLength,
        AscfFileHeader fileHeader,
        int expectedChunkIndex,
        long expectedRawOffset)
    {
        if ((flags & ~KnownFlags) != 0
            || (flags & AscfFileFormat.RequiredChunkChecksumFlags) != AscfFileFormat.RequiredChunkChecksumFlags)
        {
            throw new InvalidDataException($"Invalid .ascf chunk flags {flags}.");
        }

        if (chunkIndex != expectedChunkIndex || rawOffset != expectedRawOffset)
        {
            throw new InvalidDataException(".ascf chunk ordering is invalid.");
        }

        var isFinalChunk = expectedChunkIndex == fileHeader.ChunkCount - 1;
        if (((flags & AscfFileFormat.ChunkFlagFinalChunk) != 0) != isFinalChunk)
        {
            throw new InvalidDataException(".ascf final chunk flag is invalid.");
        }

        if (method < AscfFileFormat.MethodRaw
            || method > AscfFileFormat.MethodLz4HighCompression
            || (AscfFileFormat.SupportedMethodMask & (1 << method)) == 0)
        {
            throw new InvalidDataException($"Unsupported .ascf chunk method {method}.");
        }

        if (rawLength <= 0 || rawLength > fileHeader.RawChunkSize)
        {
            throw new InvalidDataException($"Invalid .ascf raw chunk length {rawLength}.");
        }

        if (rawOffset + rawLength > fileHeader.RawSize)
        {
            throw new InvalidDataException(".ascf raw chunk exceeds declared file size.");
        }

        var expectedRawLength = isFinalChunk
            ? checked((int)(fileHeader.RawSize - expectedRawOffset))
            : fileHeader.RawChunkSize;
        if (rawLength != expectedRawLength)
        {
            throw new InvalidDataException(".ascf fixed raw chunk length is invalid.");
        }

        if (method == AscfFileFormat.MethodRaw)
        {
            if (storedLength != rawLength)
            {
                throw new InvalidDataException(".ascf raw chunk has mismatched stored length.");
            }

            return;
        }

        var maxStoredLength = Lz4BlockCodec.MaxCompressedLength(rawLength);
        if (storedLength <= 0 || storedLength > maxStoredLength)
        {
            throw new InvalidDataException($"Invalid .ascf compressed chunk length {storedLength}.");
        }

        if (storedLength >= rawLength)
        {
            throw new InvalidDataException(".ascf compressed chunk should have been stored raw.");
        }
    }

    private static bool HeaderChecksumMatches(ReadOnlySpan<byte> source)
    {
        Span<byte> header = stackalloc byte[AscfFileFormat.ChunkHeaderSize];
        source[..AscfFileFormat.ChunkHeaderSize].CopyTo(header);
        var expected = BinaryPrimitives.ReadUInt64LittleEndian(header[ChunkHeaderChecksumOffset..]);
        return AscfChecksum.ComputeXxHash3WithZeroedField(header, ChunkHeaderChecksumOffset) == expected;
    }

    private static ulong ComputeHeaderChecksum(Span<byte> header)
        => AscfChecksum.ComputeXxHash3WithZeroedField(header, ChunkHeaderChecksumOffset);
}
