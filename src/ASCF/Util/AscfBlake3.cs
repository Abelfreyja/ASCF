using Blake3;

namespace ASCF;

public static class AscfBlake3
{
    private static readonly System.Threading.Lock NativeLoadLock = new();
    private static volatile bool NativeLoaded;

    public static Hasher CreateHasher()
    {
        if (NativeLoaded)
        {
            return Hasher.New();
        }

        lock (NativeLoadLock)
        {
            if (!NativeLoaded)
            {
                var hasher = Hasher.New();
                NativeLoaded = true;
                return hasher;
            }
        }

        return Hasher.New();
    }
}
