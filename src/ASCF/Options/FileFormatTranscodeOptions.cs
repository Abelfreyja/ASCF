using ASCF.Lz4;

namespace ASCF.Transcoding;

/// <summary> options used while moving between supported formats </summary>
public sealed record FileFormatTranscodeOptions
{
    public static FileFormatTranscodeOptions Default { get; } = new();

    public AscfReaderOptions AscfReader { get; init; } = AscfReaderOptions.Default;
    public AscfWriterOptions AscfWriter { get; init; } = AscfWriterOptions.Default;
    public Lz4FormatOptions Lz4 { get; init; } = Lz4FormatOptions.Default;

    internal void Validate()
    {
        (AscfReader ?? throw new ArgumentNullException(nameof(AscfReader))).Validate();
        (AscfWriter ?? throw new ArgumentNullException(nameof(AscfWriter))).Validate();
        (Lz4 ?? throw new ArgumentNullException(nameof(Lz4))).Validate();
    }
}
