namespace ASCF;

public readonly record struct AscfRawHashes(string? Sha1, string? Blake3)
{
    public AscfRawHashAlgorithms Algorithms
        => AscfRawHashAlgorithmFlags.FromPresence(Sha1 != null, Blake3 != null);

    public string? GetHash(AscfRawHashAlgorithms algorithm)
        => algorithm switch
        {
            AscfRawHashAlgorithms.Sha1 => Sha1,
            AscfRawHashAlgorithms.Blake3 => Blake3,
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Select one raw hash algorithm.")
        };
}
