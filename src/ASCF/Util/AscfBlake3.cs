using Blake3;

namespace ASCF;

public static class AscfBlake3
{
    public static Hasher CreateHasher()
        => Hasher.New();
}
