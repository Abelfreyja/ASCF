using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace ASCF;

[StructLayout(LayoutKind.Auto)]
internal readonly record struct AscfRawHashBytes
{
    private readonly AscfHash20 _sha1;
    private readonly AscfHash32 _blake3;

    private AscfRawHashBytes(AscfRawHashAlgorithms algorithms, AscfHash20 sha1, AscfHash32 blake3)
    {
        Algorithms = algorithms;
        _sha1 = sha1;
        _blake3 = blake3;
    }

    public static AscfRawHashBytes Empty => default;

    public AscfRawHashAlgorithms Algorithms { get; }

    public bool HasSha1
        => AscfRawHashAlgorithmFlags.Has(Algorithms, AscfRawHashAlgorithms.Sha1);

    public bool HasBlake3
        => AscfRawHashAlgorithmFlags.Has(Algorithms, AscfRawHashAlgorithms.Blake3);

    public AscfRawHashBytes WithSha1(ReadOnlySpan<byte> sha1)
        => new(Algorithms | AscfRawHashAlgorithms.Sha1, AscfHash20.Read(sha1), _blake3);

    public AscfRawHashBytes WithBlake3(ReadOnlySpan<byte> blake3)
        => new(Algorithms | AscfRawHashAlgorithms.Blake3, _sha1, AscfHash32.Read(blake3));

    public AscfRawHashBytes Filter(AscfRawHashAlgorithms algorithms)
        => new(
            Algorithms & algorithms,
            AscfRawHashAlgorithmFlags.Has(algorithms, AscfRawHashAlgorithms.Sha1) ? _sha1 : default,
            AscfRawHashAlgorithmFlags.Has(algorithms, AscfRawHashAlgorithms.Blake3) ? _blake3 : default);

    public AscfRawHashBytes Merge(AscfRawHashBytes other)
    {
        var algorithms = Algorithms;
        var sha1 = _sha1;
        var blake3 = _blake3;
        if (!HasSha1 && other.HasSha1)
        {
            algorithms |= AscfRawHashAlgorithms.Sha1;
            sha1 = other._sha1;
        }

        if (!HasBlake3 && other.HasBlake3)
        {
            algorithms |= AscfRawHashAlgorithms.Blake3;
            blake3 = other._blake3;
        }

        return new AscfRawHashBytes(algorithms, sha1, blake3);
    }

    public bool HasHash(AscfRawHashAlgorithms algorithm)
        => AscfRawHashAlgorithmFlags.Has(Algorithms, algorithm);

    public bool HashEquals(AscfRawHashAlgorithms algorithm, AscfRawHashBytes other)
        => algorithm switch
        {
            AscfRawHashAlgorithms.Sha1 => HasSha1 && other.HasSha1 && _sha1.FixedTimeEquals(other._sha1),
            AscfRawHashAlgorithms.Blake3 => HasBlake3 && other.HasBlake3 && _blake3.FixedTimeEquals(other._blake3),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Select one raw hash algorithm.")
        };

    public void CopySha1To(Span<byte> destination)
        => _sha1.CopyTo(destination);

    public void CopyBlake3To(Span<byte> destination)
        => _blake3.CopyTo(destination);

    public AscfRawHashes ToPublic()
        => new(HasSha1 ? _sha1.ToHexString() : null, HasBlake3 ? _blake3.ToHexString() : null);

    [StructLayout(LayoutKind.Auto)]
    private readonly record struct AscfHash20
    {
        private readonly ulong _a;
        private readonly ulong _b;
        private readonly uint _c;

        private AscfHash20(ulong a, ulong b, uint c)
        {
            _a = a;
            _b = b;
            _c = c;
        }

        public static AscfHash20 Read(ReadOnlySpan<byte> source)
        {
            if (source.Length != AscfFileFormat.Sha1HashSize)
            {
                throw new ArgumentException("SHA-1 hash length is invalid.", nameof(source));
            }

            return new AscfHash20(
                BinaryPrimitives.ReadUInt64LittleEndian(source),
                BinaryPrimitives.ReadUInt64LittleEndian(source[8..]),
                BinaryPrimitives.ReadUInt32LittleEndian(source[16..]));
        }

        public void CopyTo(Span<byte> destination)
        {
            if (destination.Length < AscfFileFormat.Sha1HashSize)
            {
                throw new ArgumentException("Destination is too small.", nameof(destination));
            }

            BinaryPrimitives.WriteUInt64LittleEndian(destination, _a);
            BinaryPrimitives.WriteUInt64LittleEndian(destination[8..], _b);
            BinaryPrimitives.WriteUInt32LittleEndian(destination[16..], _c);
        }

        public bool FixedTimeEquals(AscfHash20 other)
        {
            Span<byte> left = stackalloc byte[AscfFileFormat.Sha1HashSize];
            Span<byte> right = stackalloc byte[AscfFileFormat.Sha1HashSize];
            CopyTo(left);
            other.CopyTo(right);
            return CryptographicOperations.FixedTimeEquals(left, right);
        }

        public string ToHexString()
        {
            Span<byte> bytes = stackalloc byte[AscfFileFormat.Sha1HashSize];
            CopyTo(bytes);
            return Convert.ToHexString(bytes);
        }
    }

    [StructLayout(LayoutKind.Auto)]
    private readonly record struct AscfHash32
    {
        private readonly ulong _a;
        private readonly ulong _b;
        private readonly ulong _c;
        private readonly ulong _d;

        private AscfHash32(ulong a, ulong b, ulong c, ulong d)
        {
            _a = a;
            _b = b;
            _c = c;
            _d = d;
        }

        public static AscfHash32 Read(ReadOnlySpan<byte> source)
        {
            if (source.Length != AscfFileFormat.Blake3HashSize)
            {
                throw new ArgumentException("BLAKE3 hash length is invalid.", nameof(source));
            }

            return new AscfHash32(
                BinaryPrimitives.ReadUInt64LittleEndian(source),
                BinaryPrimitives.ReadUInt64LittleEndian(source[8..]),
                BinaryPrimitives.ReadUInt64LittleEndian(source[16..]),
                BinaryPrimitives.ReadUInt64LittleEndian(source[24..]));
        }

        public void CopyTo(Span<byte> destination)
        {
            if (destination.Length < AscfFileFormat.Blake3HashSize)
            {
                throw new ArgumentException("Destination is too small.", nameof(destination));
            }

            BinaryPrimitives.WriteUInt64LittleEndian(destination, _a);
            BinaryPrimitives.WriteUInt64LittleEndian(destination[8..], _b);
            BinaryPrimitives.WriteUInt64LittleEndian(destination[16..], _c);
            BinaryPrimitives.WriteUInt64LittleEndian(destination[24..], _d);
        }

        public bool FixedTimeEquals(AscfHash32 other)
        {
            Span<byte> left = stackalloc byte[AscfFileFormat.Blake3HashSize];
            Span<byte> right = stackalloc byte[AscfFileFormat.Blake3HashSize];
            CopyTo(left);
            other.CopyTo(right);
            return CryptographicOperations.FixedTimeEquals(left, right);
        }

        public string ToHexString()
        {
            Span<byte> bytes = stackalloc byte[AscfFileFormat.Blake3HashSize];
            CopyTo(bytes);
            return Convert.ToHexString(bytes);
        }
    }
}
