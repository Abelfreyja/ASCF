namespace ASCF;

internal static class AscfRawHashAlgorithmFlags
{
    public static bool IsSupported(AscfRawHashAlgorithms algorithms)
        => ((int)algorithms & ~AscfFileFormat.SupportedRawHashAlgorithms) == 0;

    public static void ValidateSupported(AscfRawHashAlgorithms algorithms, string paramName)
    {
        if (!IsSupported(algorithms))
        {
            throw new ArgumentOutOfRangeException(paramName, algorithms, "Raw hash algorithms contain unsupported values.");
        }
    }

    public static bool Has(AscfRawHashAlgorithms algorithms, AscfRawHashAlgorithms algorithm)
        => (algorithms & algorithm) != AscfRawHashAlgorithms.None;

    public static string GetDisplayName(AscfRawHashAlgorithms algorithm)
        => algorithm switch
        {
            AscfRawHashAlgorithms.Sha1 => "SHA-1",
            AscfRawHashAlgorithms.Blake3 => "BLAKE3",
            _ => "raw"
        };

    public static AscfRawHashAlgorithms FromPresence(bool hasSha1, bool hasBlake3)
    {
        var algorithms = AscfRawHashAlgorithms.None;
        if (hasSha1)
        {
            algorithms |= AscfRawHashAlgorithms.Sha1;
        }

        if (hasBlake3)
        {
            algorithms |= AscfRawHashAlgorithms.Blake3;
        }

        return algorithms;
    }
}
