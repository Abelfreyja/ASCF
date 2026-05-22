namespace ASCF;

[Flags]
public enum AscfRawHashAlgorithms
{
    None = 0,
    Sha1 = 1,
    Blake3 = 1 << 1,
}
