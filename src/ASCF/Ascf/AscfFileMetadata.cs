namespace ASCF;

public readonly record struct AscfFileMetadata(
    long RawSize,
    long EncodedSize,
    int RawChunkSize,
    int ChunkCount,
    Guid StreamId,
    AscfRawHashes StoredHashes);
