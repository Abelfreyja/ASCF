using System.Security.Cryptography;
using Blake3;

namespace ASCF;

internal sealed class AscfRawContentHasher : IDisposable
{
    private readonly IncrementalHash? _sha1;
    private readonly Hasher? _blake3;

    private AscfRawContentHasher(AscfRawHashAlgorithms algorithms)
    {
        _sha1 = AscfRawHashAlgorithmFlags.Has(algorithms, AscfRawHashAlgorithms.Sha1)
            ? IncrementalHash.CreateHash(HashAlgorithmName.SHA1)
            : null;
        _blake3 = AscfRawHashAlgorithmFlags.Has(algorithms, AscfRawHashAlgorithms.Blake3)
            ? AscfBlake3.CreateHasher()
            : null;
    }

    public static AscfRawContentHasher? Create(AscfRawHashAlgorithms algorithms)
        => algorithms == AscfRawHashAlgorithms.None ? null : new AscfRawContentHasher(algorithms);

    public void AppendData(ReadOnlySpan<byte> data)
    {
        _sha1?.AppendData(data);
        _blake3?.Update(data);
    }

    public AscfRawHashBytes FinalizeHashes()
    {
        var hashes = AscfRawHashBytes.Empty;
        if (_sha1 != null)
        {
            Span<byte> sha1 = stackalloc byte[AscfFileFormat.Sha1HashSize];
            if (!_sha1.TryGetHashAndReset(sha1, out var bytesWritten) || bytesWritten != AscfFileFormat.Sha1HashSize)
            {
                throw new InvalidOperationException("SHA-1 hash finalization failed.");
            }

            hashes = hashes.WithSha1(sha1);
        }

        if (_blake3 != null)
        {
            Span<byte> blake3 = stackalloc byte[AscfFileFormat.Blake3HashSize];
            _blake3.Finalize(blake3);
            hashes = hashes.WithBlake3(blake3);
        }

        return hashes;
    }

    public void Dispose()
    {
        _sha1?.Dispose();
        _blake3?.Dispose();
    }
}
