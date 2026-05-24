namespace ASCF;

/// <summary> resume metadata for an encoded .ascf file </summary>
public readonly record struct AscfResumeInfo(
    AscfFileMetadata Metadata,
    AscfResumePosition Position);

/// <summary> chunk aligned resume point for an encoded .ascf file </summary>
public readonly record struct AscfResumePosition(
    int NextChunkIndex,
    long NextEncodedOffset,
    long NextRawOffset,
    bool IsComplete)
{
    /// <summary> true when an encoded range request can continue from this point </summary>
    public bool CanResume => !IsComplete && NextEncodedOffset > 0;
}
