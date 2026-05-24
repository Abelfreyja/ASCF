using System.Security.Cryptography;
using System.Text;

namespace ASCF;

public static class AscfStreamIds
{
    public static Guid CreateDeterministic(string seed)
    {
        ArgumentNullException.ThrowIfNull(seed);
        return CreateDeterministic(Encoding.UTF8.GetBytes(seed));
    }

    public static Guid CreateDeterministic(ReadOnlySpan<byte> seed)
    {
        Span<byte> hash = stackalloc byte[SHA256.HashSizeInBytes];
        SHA256.HashData(seed, hash);
        return new Guid(hash[..16]);
    }
}
