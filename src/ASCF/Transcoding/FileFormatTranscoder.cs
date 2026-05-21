using ASCF.Lz4;
using System.Runtime.InteropServices;

namespace ASCF.Transcoding;

public static class FileFormatTranscoder
{
    [StructLayout(LayoutKind.Auto)]
    public readonly record struct ConvertResult(long RawSize, long StoredSize);

    [StructLayout(LayoutKind.Auto)]
    public readonly record struct ConvertHashResult(string Hash, long RawSize, long StoredSize, Lz4PayloadFormat Format);

    public enum Lz4PayloadFormat
    {
        WrappedLz4,
        Lz4Stream
    }

    public static Task<WrappedLz4FileFormat.WriteResult> ConvertAscfFileToWrappedLz4Async(
        string ascfPath,
        string rawTempPath,
        string wrappedTempPath,
        CancellationToken token)
        => ConvertAscfFileToWrappedLz4Async(ascfPath, rawTempPath, wrappedTempPath, FileFormatTranscodeOptions.Default, token);

    public static async Task<WrappedLz4FileFormat.WriteResult> ConvertAscfFileToWrappedLz4Async(
        string ascfPath,
        string rawTempPath,
        string wrappedTempPath,
        FileFormatTranscodeOptions options,
        CancellationToken token)
    {
        options.Validate();
        if (await AscfFileReader.TryWriteStoredRawWrappedLz4Async(ascfPath, wrappedTempPath, options.AscfReader, token).ConfigureAwait(false) is { } storedRaw)
        {
            return storedRaw;
        }

        var decoded = await AscfFileReader.DecodeFileToRawFileAsync(ascfPath, rawTempPath, options.AscfReader, token)
            .ConfigureAwait(false);
        var wrapped = await WrappedLz4FileFormat.WriteFromRawFileAsync(rawTempPath, wrappedTempPath, options.Lz4, token)
            .ConfigureAwait(false);
        if (wrapped.OriginalSize != decoded.RawSize)
        {
            throw new InvalidDataException($"Wrapped LZ4 raw size mismatch (expected {decoded.RawSize}, got {wrapped.OriginalSize}).");
        }

        return wrapped;
    }

    public static Task<ConvertResult> ConvertWrappedLz4ToAscfAsync(
        string wrappedPath,
        string rawTempPath,
        string ascfTempPath,
        CancellationToken token)
        => ConvertWrappedLz4ToAscfAsync(wrappedPath, rawTempPath, ascfTempPath, FileFormatTranscodeOptions.Default, token);

    public static async Task<ConvertResult> ConvertWrappedLz4ToAscfAsync(
        string wrappedPath,
        string rawTempPath,
        string ascfTempPath,
        FileFormatTranscodeOptions options,
        CancellationToken token)
    {
        options.Validate();
        var wrappedInfo = new FileInfo(wrappedPath);
        if (wrappedInfo.Exists
            && WrappedLz4FileFormat.TryReadHeader(wrappedPath, wrappedInfo.Length, options.Lz4.BufferSize, options.Lz4) is { } header
            && Lz4BlockCodec.IsStoredRaw(header.OutputLength, header.InputLength))
        {
            var storedRawSize = await AscfFileWriter
                .WriteStoredRawFileAsync(wrappedPath, WrappedLz4FileFormat.HeaderSize, header.OutputLength, ascfTempPath, options.AscfWriter, token)
                .ConfigureAwait(false);
            return new ConvertResult(header.OutputLength, storedRawSize);
        }

        var rawSize = await WrappedLz4FileFormat.ExtractToRawFileAsync(wrappedPath, rawTempPath, options.Lz4, token)
            .ConfigureAwait(false);
        var storedSize = await AscfFileWriter.WriteFileAsync(rawTempPath, ascfTempPath, options.AscfWriter, token).ConfigureAwait(false);
        return new ConvertResult(rawSize, storedSize);
    }

    public static Task<ConvertHashResult> ConvertLz4PayloadToAscfWithHashAsync(
        string lz4Path,
        long lz4Length,
        string rawTempPath,
        string ascfTempPath,
        int streamBufferSize,
        CancellationToken token)
        => ConvertLz4PayloadToAscfWithHashAsync(lz4Path, lz4Length, rawTempPath, ascfTempPath, streamBufferSize, FileFormatTranscodeOptions.Default, token);

    public static async Task<ConvertHashResult> ConvertLz4PayloadToAscfWithHashAsync(
        string lz4Path,
        long lz4Length,
        string rawTempPath,
        string ascfTempPath,
        int streamBufferSize,
        FileFormatTranscodeOptions options,
        CancellationToken token)
    {
        options.Validate();
        if (await WrappedLz4FileFormat.TryReadHeaderAsync(lz4Path, lz4Length, streamBufferSize, options.Lz4, token).ConfigureAwait(false) is { } header)
        {
            var wrapped = await ConvertWrappedLz4ToAscfWithHashAsync(lz4Path, header, rawTempPath, ascfTempPath, options, token)
                .ConfigureAwait(false);
            return new ConvertHashResult(wrapped.Hash, wrapped.RawSize, wrapped.StoredSize, Lz4PayloadFormat.WrappedLz4);
        }

        var stream = await ConvertLz4StreamToAscfWithHashAsync(lz4Path, ascfTempPath, streamBufferSize, options, token)
            .ConfigureAwait(false);
        return new ConvertHashResult(stream.Hash, stream.RawSize, stream.StoredSize, Lz4PayloadFormat.Lz4Stream);
    }

    public static Task<ConvertHashResult> ConvertWrappedLz4ToAscfWithHashAsync(
        string wrappedPath,
        string rawTempPath,
        string ascfTempPath,
        CancellationToken token)
        => ConvertWrappedLz4ToAscfWithHashAsync(wrappedPath, rawTempPath, ascfTempPath, FileFormatTranscodeOptions.Default, token);

    public static async Task<ConvertHashResult> ConvertWrappedLz4ToAscfWithHashAsync(
        string wrappedPath,
        string rawTempPath,
        string ascfTempPath,
        FileFormatTranscodeOptions options,
        CancellationToken token)
    {
        options.Validate();
        var wrappedInfo = new FileInfo(wrappedPath);
        if (!wrappedInfo.Exists)
        {
            throw new FileNotFoundException($"No wrapped LZ4 source found at {wrappedPath}.", wrappedPath);
        }

        var header = WrappedLz4FileFormat.TryReadHeader(wrappedPath, wrappedInfo.Length, options.Lz4.BufferSize, options.Lz4)
            ?? throw new InvalidDataException("Wrapped LZ4 header is invalid.");
        var result = await ConvertWrappedLz4ToAscfWithHashAsync(wrappedPath, header, rawTempPath, ascfTempPath, options, token)
            .ConfigureAwait(false);
        return new ConvertHashResult(result.Hash, result.RawSize, result.StoredSize, Lz4PayloadFormat.WrappedLz4);
    }

    public static Task<ConvertHashResult> ConvertLz4StreamToAscfWithHashAsync(
        string streamPath,
        string ascfTempPath,
        int streamBufferSize,
        CancellationToken token)
        => ConvertLz4StreamToAscfWithHashAsync(streamPath, ascfTempPath, streamBufferSize, FileFormatTranscodeOptions.Default, token);

    public static async Task<ConvertHashResult> ConvertLz4StreamToAscfWithHashAsync(
        string streamPath,
        string ascfTempPath,
        int streamBufferSize,
        FileFormatTranscodeOptions options,
        CancellationToken token)
    {
        options.Validate();
        var result = await Lz4StreamFormat.ConvertToAscfFileWithHashAsync(streamPath, ascfTempPath, streamBufferSize, options.AscfWriter, token)
            .ConfigureAwait(false);
        return new ConvertHashResult(result.Hash, result.RawSize, result.StoredSize, Lz4PayloadFormat.Lz4Stream);
    }

    public static Task<ConvertResult> ConvertLz4StreamToAscfAsync(
        string streamPath,
        string ascfTempPath,
        int streamBufferSize,
        CancellationToken token)
        => ConvertLz4StreamToAscfAsync(streamPath, ascfTempPath, streamBufferSize, FileFormatTranscodeOptions.Default, token);

    public static async Task<ConvertResult> ConvertLz4StreamToAscfAsync(
        string streamPath,
        string ascfTempPath,
        int streamBufferSize,
        FileFormatTranscodeOptions options,
        CancellationToken token)
    {
        options.Validate();
        var result = await Lz4StreamFormat.ConvertToAscfFileAsync(streamPath, ascfTempPath, streamBufferSize, options.AscfWriter, token)
            .ConfigureAwait(false);
        return new ConvertResult(result.RawSize, result.StoredSize);
    }

    private static async Task<AscfFileWriter.HashedWriteResult> ConvertWrappedLz4ToAscfWithHashAsync(
        string wrappedPath,
        WrappedLz4FileFormat.Header header,
        string rawTempPath,
        string ascfTempPath,
        FileFormatTranscodeOptions options,
        CancellationToken token)
    {
        if (Lz4BlockCodec.IsStoredRaw(header.OutputLength, header.InputLength))
        {
            return await AscfFileWriter
                .WriteStoredRawFileWithHashAsync(wrappedPath, WrappedLz4FileFormat.HeaderSize, header.OutputLength, ascfTempPath, options.AscfWriter, token)
                .ConfigureAwait(false);
        }

        var rawSize = await WrappedLz4FileFormat.ExtractToRawFileAsync(wrappedPath, rawTempPath, options.Lz4, token)
            .ConfigureAwait(false);
        var result = await AscfFileWriter.WriteFileWithHashAsync(rawTempPath, ascfTempPath, options.AscfWriter, token)
            .ConfigureAwait(false);
        if (result.RawSize != rawSize)
        {
            throw new InvalidDataException($".ascf raw size mismatch (expected {rawSize}, got {result.RawSize}).");
        }

        return result;
    }
}
