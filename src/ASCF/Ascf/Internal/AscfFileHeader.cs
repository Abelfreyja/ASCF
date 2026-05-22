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
    long EncodedSize,
    AscfRawHashBytes RawHashes);

internal static class AscfFileHeaderCodec
{
    private const int RawHashAlgorithmsOffset = 0x48;
    private const int Sha1HashOffset = 0x50;
    private const int Blake3HashOffset = 0x70;
    private const int HeaderChecksumOffset = 0x98;
    private const int KnownFlags = AscfFileFormat.RequiredHeaderFlags;

    //
    //  file header, 160 bytes
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
    //             | raw hash algorithms          | u32
    //      +0x4c  +------------------------------+
    //             | reserved                     | u32
    //      +0x50  +------------------------------+
    //             | raw SHA-1                    | 20 bytes
    //      +0x64  +------------------------------+
    //             | reserved                     | 12 bytes
    //      +0x70  +------------------------------+
    //             | raw BLAKE3                   | 32 bytes
    //      +0x90  +------------------------------+
    //             | reserved                     | u64
    //      +0x98  +------------------------------+
    //             | header checksum              | u64
    //      +0xa0  +------------------------------+
    //

    public static void Write(
        Span<byte> destination,
        long rawSize,
        int rawChunkSize,
        int chunkCount,
        Guid streamId,
        long encodedSize,
        AscfRawHashBytes rawHashes)
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
        ValidateRawHashLengths(rawHashes);
        BinaryPrimitives.WriteInt32LittleEndian(destination[RawHashAlgorithmsOffset..], (int)rawHashes.Algorithms);
        if (rawHashes.Sha1 != null)
        {
            rawHashes.Sha1.CopyTo(destination.Slice(Sha1HashOffset, AscfFileFormat.Sha1HashSize));
        }

        if (rawHashes.Blake3 != null)
        {
            rawHashes.Blake3.CopyTo(destination.Slice(Blake3HashOffset, AscfFileFormat.Blake3HashSize));
        }

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

        if (!TryReadRawHashes(source, out var rawHashes))
        {
            return false;
        }

        if (BinaryPrimitives.ReadInt32LittleEndian(source[0x2C..]) != 0
            || BinaryPrimitives.ReadInt32LittleEndian(source[0x4C..]) != 0
            || !ReservedBytesAreZero(source.Slice(0x64, 12))
            || BinaryPrimitives.ReadInt64LittleEndian(source[0x90..]) != 0
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

        header = new AscfFileHeader(rawSize, flags, rawChunkSize, chunkCount, streamId, encodedSize, rawHashes);
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

    private static bool TryReadRawHashes(ReadOnlySpan<byte> source, out AscfRawHashBytes rawHashes)
    {
        rawHashes = default;
        var algorithms = (AscfRawHashAlgorithms)BinaryPrimitives.ReadInt32LittleEndian(source[RawHashAlgorithmsOffset..]);
        if (!AscfRawHashAlgorithmFlags.IsSupported(algorithms))
        {
            return false;
        }

        byte[]? sha1 = null;
        if (AscfRawHashAlgorithmFlags.Has(algorithms, AscfRawHashAlgorithms.Sha1))
        {
            sha1 = source.Slice(Sha1HashOffset, AscfFileFormat.Sha1HashSize).ToArray();
        }
        else if (!ReservedBytesAreZero(source.Slice(Sha1HashOffset, AscfFileFormat.Sha1HashSize)))
        {
            return false;
        }

        byte[]? blake3 = null;
        if (AscfRawHashAlgorithmFlags.Has(algorithms, AscfRawHashAlgorithms.Blake3))
        {
            blake3 = source.Slice(Blake3HashOffset, AscfFileFormat.Blake3HashSize).ToArray();
        }
        else if (!ReservedBytesAreZero(source.Slice(Blake3HashOffset, AscfFileFormat.Blake3HashSize)))
        {
            return false;
        }

        rawHashes = new AscfRawHashBytes(sha1, blake3);
        return true;
    }

    private static void ValidateRawHashLengths(AscfRawHashBytes rawHashes)
    {
        if (rawHashes.Sha1 is { Length: not AscfFileFormat.Sha1HashSize })
        {
            throw new ArgumentException("SHA-1 hash length is invalid.", nameof(rawHashes));
        }

        if (rawHashes.Blake3 is { Length: not AscfFileFormat.Blake3HashSize })
        {
            throw new ArgumentException("BLAKE3 hash length is invalid.", nameof(rawHashes));
        }
    }

    private static bool ReservedBytesAreZero(ReadOnlySpan<byte> source)
    {
        foreach (var value in source)
        {
            if (value != 0)
            {
                return false;
            }
        }

        return true;
    }
}
