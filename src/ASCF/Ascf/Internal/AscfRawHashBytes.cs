namespace ASCF;

internal readonly record struct AscfRawHashBytes(byte[]? Sha1, byte[]? Blake3)
{
    public static AscfRawHashBytes Empty { get; } = new(null, null);

    public AscfRawHashAlgorithms Algorithms
        => AscfRawHashAlgorithmFlags.FromPresence(Sha1 != null, Blake3 != null);

    public AscfRawHashBytes Filter(AscfRawHashAlgorithms algorithms)
        => new(
            AscfRawHashAlgorithmFlags.Has(algorithms, AscfRawHashAlgorithms.Sha1) ? Sha1 : null,
            AscfRawHashAlgorithmFlags.Has(algorithms, AscfRawHashAlgorithms.Blake3) ? Blake3 : null);

    public AscfRawHashBytes Merge(AscfRawHashBytes other)
        => new(Sha1 ?? other.Sha1, Blake3 ?? other.Blake3);

    public AscfRawHashes ToPublic()
        => new(Sha1 == null ? null : Convert.ToHexString(Sha1), Blake3 == null ? null : Convert.ToHexString(Blake3));
}
