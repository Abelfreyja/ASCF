namespace ASCF;

/// <summary> validation state for a complete or partial .ascf file </summary>
public readonly record struct AscfPartialValidationResult(
    bool HeaderValid,
    bool IsComplete,
    bool IsCorrupt,
    int CompleteChunkCount,
    long RawBytes,
    long EncodedBytes)
{
    /// <summary> next chunk after the valid prefix </summary>
    public int NextChunkIndex => CompleteChunkCount;

    /// <summary> next raw offset after the valid prefix </summary>
    public long NextRawOffset => RawBytes;

    /// <summary> next encoded offset after the valid prefix </summary>
    public long NextEncodedOffset => EncodedBytes;
}
