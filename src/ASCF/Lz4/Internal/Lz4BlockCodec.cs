using System.Runtime.InteropServices;
using K4os.Compression.LZ4;

namespace ASCF.Lz4;

internal static unsafe class Lz4BlockCodec
{
    [StructLayout(LayoutKind.Auto)]
    public readonly record struct EncodedBlock(int RawLength, int StoredLength)
    {
        public bool StoresRaw => StoredLength == RawLength;
    }

    public static int MaxUsefulCompressedLength(int rawLength)
        => rawLength <= 13 ? 0 : rawLength - 1;

    public static EncodedBlock Encode(ReadOnlySpan<byte> raw, Span<byte> compressedDestination)
    {
        var encodedLength = LZ4Codec.Encode(raw, compressedDestination, LZ4Level.L08_HC);
        return new EncodedBlock(raw.Length, ShouldStoreRaw(encodedLength, raw.Length) ? raw.Length : encodedLength);
    }

    public static EncodedBlock EncodeWithFastCheck(ReadOnlySpan<byte> raw, Span<byte> compressedDestination)
    {
        if (ShouldUseHighCompressionDirectly(raw))
        {
            return Encode(raw, compressedDestination);
        }

        // use fast lz4 as a cheap check before high compression
        var fastLength = LZ4Codec.Encode(raw, compressedDestination, LZ4Level.L00_FAST);
        if (ShouldStoreRaw(fastLength, raw.Length))
        {
            return new EncodedBlock(raw.Length, raw.Length);
        }

        return Encode(raw, compressedDestination);
    }

    public static EncodedBlock EncodeOrCopyRaw(byte* raw, int rawLength, byte* destination, int destinationLength)
    {
        var encodedLength = LZ4Codec.Encode(raw, rawLength, destination, destinationLength, LZ4Level.L08_HC);
        if (!ShouldStoreRaw(encodedLength, rawLength))
        {
            return new EncodedBlock(rawLength, encodedLength);
        }

        Buffer.MemoryCopy(raw, destination, destinationLength, rawLength);
        return new EncodedBlock(rawLength, rawLength);
    }

    public static bool IsStoredRaw(int rawLength, int storedLength)
        => rawLength == storedLength;

    public static int Decode(ReadOnlySpan<byte> stored, Span<byte> raw, int expectedRawLength)
    {
        var decodedLength = LZ4Codec.Decode(stored, raw[..expectedRawLength]);
        ValidateDecodedLength(decodedLength, expectedRawLength);
        return decodedLength;
    }

    public static int Decode(byte[] stored, int storedOffset, int storedLength, byte[] raw, int rawOffset, int expectedRawLength)
    {
        var decodedLength = LZ4Codec.Decode(stored, storedOffset, storedLength, raw, rawOffset, expectedRawLength);
        ValidateDecodedLength(decodedLength, expectedRawLength);
        return decodedLength;
    }

    public static int Decode(byte* stored, int storedLength, byte* raw, int expectedRawLength)
    {
        var decodedLength = LZ4Codec.Decode(stored, storedLength, raw, expectedRawLength);
        ValidateDecodedLength(decodedLength, expectedRawLength);
        return decodedLength;
    }

    private static bool ShouldStoreRaw(int encodedLength, int rawLength)
        => encodedLength <= 0 || encodedLength >= rawLength;

    private static bool ShouldUseHighCompressionDirectly(ReadOnlySpan<byte> raw)
    {
        var first = raw[0];
        var step = Math.Max(1, raw.Length / 16);
        for (var i = step; i < raw.Length; i += step)
        {
            if (raw[i] != first)
            {
                return false;
            }
        }

        return raw[^1] == first;
    }

    private static void ValidateDecodedLength(int decodedLength, int expectedRawLength)
    {
        if (decodedLength != expectedRawLength)
        {
            throw new InvalidDataException($"LZ4 decode length mismatch (expected {expectedRawLength}, got {decodedLength}).");
        }
    }
}
