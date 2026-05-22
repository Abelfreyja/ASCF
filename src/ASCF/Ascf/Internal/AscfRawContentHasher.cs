using System.Security.Cryptography;
using Blake3;

namespace ASCF;

internal sealed class AscfRawContentHasher : IDisposable
{
    private readonly IncrementalHash? _sha1;
    private Hasher _blake3;
    private readonly bool _hasBlake3;

    private AscfRawContentHasher(AscfRawHashAlgorithms algorithms)
    {
        _sha1 = AscfRawHashAlgorithmFlags.Has(algorithms, AscfRawHashAlgorithms.Sha1)
            ? IncrementalHash.CreateHash(HashAlgorithmName.SHA1)
            : null;
        if (AscfRawHashAlgorithmFlags.Has(algorithms, AscfRawHashAlgorithms.Blake3))
        {
            _blake3 = Hasher.New();
            _hasBlake3 = true;
        }
    }

    public static AscfRawContentHasher? Create(AscfRawHashAlgorithms algorithms)
        => algorithms == AscfRawHashAlgorithms.None ? null : new AscfRawContentHasher(algorithms);

    public void AppendData(ReadOnlySpan<byte> data)
    {
        _sha1?.AppendData(data);
        if (_hasBlake3)
        {
            _blake3.Update(data);
        }
    }

    public AscfRawHashBytes FinalizeHashes()
    {
        var sha1 = _sha1?.GetHashAndReset();
        byte[]? blake3 = null;
        if (_hasBlake3)
        {
            blake3 = new byte[AscfFileFormat.Blake3HashSize];
            _blake3.Finalize(blake3);
        }

        return new AscfRawHashBytes(sha1, blake3);
    }

    public void Dispose()
    {
        _sha1?.Dispose();
        if (_hasBlake3)
        {
            _blake3.Dispose();
        }
    }
}
