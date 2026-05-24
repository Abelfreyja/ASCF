namespace ASCF.Util;

public readonly record struct FileFormatHashResult(string Hash, long RawSize);

public readonly record struct FileFormatRawHashResult(AscfRawHashes Hashes, long RawSize);
