using ASCF.Lz4;

namespace ASCF.Files;

/// <summary> options for format identification </summary>
public sealed record EncodedFileFormatIdentificationOptions
{
    public static EncodedFileFormatIdentificationOptions Default { get; } = new();

    public AscfReaderOptions AscfReader { get; init; } = AscfReaderOptions.Default;
    public Lz4FormatOptions Lz4 { get; init; } = Lz4FormatOptions.Default;

    internal void Validate()
    {
        (AscfReader ?? throw new ArgumentNullException(nameof(AscfReader))).Validate();
        (Lz4 ?? throw new ArgumentNullException(nameof(Lz4))).Validate();
    }
}
