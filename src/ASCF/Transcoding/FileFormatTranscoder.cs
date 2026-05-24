using ASCF.Lz4;
using ASCF.Util;
using System.Buffers;
using System.Runtime.InteropServices;

namespace ASCF.Transcoding;

public static class FileFormatTranscoder
{
    [StructLayout(LayoutKind.Auto)]
    public readonly record struct ConvertResult(long RawSize, long StoredSize);

    [StructLayout(LayoutKind.Auto)]
    public readonly record struct ConvertHashResult(AscfRawHashes Hashes, long RawSize, long StoredSize, Lz4PayloadFormat Format)
    {
        public string Sha1Hash => RequireHash(AscfRawHashAlgorithms.Sha1);
        public string Blake3Hash => RequireHash(AscfRawHashAlgorithms.Blake3);

        public string? GetHash(AscfRawHashAlgorithms algorithm)
            => Hashes.GetHash(algorithm);

        public string RequireHash(AscfRawHashAlgorithms algorithm)
            => Hashes.RequireHash(algorithm);
    }

    public enum Lz4PayloadFormat
    {
        WrappedLz4,
        Lz4Stream
    }

    public static Task<WrappedLz4FileFormat.WriteResult> ConvertAscfFileToWrappedLz4Async(
        string ascfPath,
        string wrappedPath,
        CancellationToken token)
        => ConvertAscfFileToWrappedLz4Async(ascfPath, wrappedPath, FileFormatTranscodeOptions.Default, token);

    public static async Task<WrappedLz4FileFormat.WriteResult> ConvertAscfFileToWrappedLz4Async(
        string ascfPath,
        string wrappedPath,
        FileFormatTranscodeOptions options,
        CancellationToken token)
    {
        options.Validate();
        return await RunWithRawTempFileAsync(
                wrappedPath,
                rawTempPath => ConvertAscfFileToWrappedLz4Async(ascfPath, rawTempPath, wrappedPath, options, token))
            .ConfigureAwait(false);
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

        var rawSize = await AscfFileReader.DecodeFileToFileParallelAsync(ascfPath, rawTempPath, options.AscfReader, token)
            .ConfigureAwait(false);
        var wrapped = await WrappedLz4FileFormat.WriteFromRawFileAsync(rawTempPath, wrappedTempPath, options.Lz4, token)
            .ConfigureAwait(false);
        if (wrapped.OriginalSize != rawSize)
        {
            throw new InvalidDataException($"Wrapped LZ4 raw size mismatch (expected {rawSize}, got {wrapped.OriginalSize}).");
        }

        return wrapped;
    }

    public static Task<ConvertResult> ConvertWrappedLz4ToAscfAsync(
        string wrappedPath,
        string ascfPath,
        CancellationToken token)
        => ConvertWrappedLz4ToAscfAsync(wrappedPath, ascfPath, FileFormatTranscodeOptions.Default, token);

    public static async Task<ConvertResult> ConvertWrappedLz4ToAscfAsync(
        string wrappedPath,
        string ascfPath,
        FileFormatTranscodeOptions options,
        CancellationToken token)
    {
        options.Validate();
        return await RunWithRawTempFileAsync(
                ascfPath,
                rawTempPath => ConvertWrappedLz4ToAscfAsync(wrappedPath, rawTempPath, ascfPath, options, token))
            .ConfigureAwait(false);
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
        var header = TryReadWrappedHeader(wrappedPath, options.Lz4);
        if (header is { } storedRawHeader
            && Lz4BlockCodec.IsStoredRaw(storedRawHeader.OutputLength, storedRawHeader.InputLength))
        {
            var storedRawSize = await AscfFileWriter
                .WriteStoredRawFileAsync(wrappedPath, WrappedLz4FileFormat.HeaderSize, storedRawHeader.OutputLength, ascfTempPath, options.AscfWriter, token)
                .ConfigureAwait(false);
            return new ConvertResult(storedRawHeader.OutputLength, storedRawSize);
        }

        if (header is { } wrappedHeader
            && ShouldDecodeWrappedPayloadInMemory(wrappedHeader, options))
        {
            var raw = await DecodeWrappedPayloadToArrayAsync(wrappedPath, wrappedHeader, options.Lz4, token).ConfigureAwait(false);
            using var rawStream = new MemoryStream(raw, writable: false);
            var result = await AscfFileWriter.WriteStreamToFileAsync(rawStream, ascfTempPath, options.AscfWriter, token)
                .ConfigureAwait(false);
            ValidateConvertedRawSize(wrappedHeader.OutputLength, result.RawSize);
            return new ConvertResult(result.RawSize, result.StoredSize);
        }

        var rawSize = await WrappedLz4FileFormat.ExtractToRawFileAsync(wrappedPath, rawTempPath, options.Lz4, token)
            .ConfigureAwait(false);
        var storedSize = await AscfFileWriter.WriteFileAsync(rawTempPath, ascfTempPath, options.AscfWriter, token).ConfigureAwait(false);
        return new ConvertResult(rawSize, storedSize);
    }

    public static Task<ConvertHashResult> ConvertLz4PayloadToAscfWithHashAsync(
        string lz4Path,
        long lz4Length,
        string ascfPath,
        int streamBufferSize,
        CancellationToken token)
        => ConvertLz4PayloadToAscfWithHashAsync(lz4Path, lz4Length, ascfPath, streamBufferSize, FileFormatTranscodeOptions.Default, token);

    public static async Task<ConvertHashResult> ConvertLz4PayloadToAscfWithHashAsync(
        string lz4Path,
        long lz4Length,
        string ascfPath,
        int streamBufferSize,
        FileFormatTranscodeOptions options,
        CancellationToken token)
    {
        options.Validate();
        return await RunWithRawTempFileAsync(
                ascfPath,
                rawTempPath => ConvertLz4PayloadToAscfWithHashAsync(lz4Path, lz4Length, rawTempPath, ascfPath, streamBufferSize, options, token))
            .ConfigureAwait(false);
    }

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
            return new ConvertHashResult(wrapped.Hashes, wrapped.RawSize, wrapped.StoredSize, Lz4PayloadFormat.WrappedLz4);
        }

        var stream = await ConvertLz4StreamToAscfWithHashAsync(lz4Path, ascfTempPath, streamBufferSize, options, token)
            .ConfigureAwait(false);
        return new ConvertHashResult(stream.Hashes, stream.RawSize, stream.StoredSize, Lz4PayloadFormat.Lz4Stream);
    }

    public static Task<ConvertHashResult> ConvertWrappedLz4ToAscfWithHashAsync(
        string wrappedPath,
        string ascfPath,
        CancellationToken token)
        => ConvertWrappedLz4ToAscfWithHashAsync(wrappedPath, ascfPath, FileFormatTranscodeOptions.Default, token);

    public static async Task<ConvertHashResult> ConvertWrappedLz4ToAscfWithHashAsync(
        string wrappedPath,
        string ascfPath,
        FileFormatTranscodeOptions options,
        CancellationToken token)
    {
        options.Validate();
        return await RunWithRawTempFileAsync(
                ascfPath,
                rawTempPath => ConvertWrappedLz4ToAscfWithHashAsync(wrappedPath, rawTempPath, ascfPath, options, token))
            .ConfigureAwait(false);
    }

    public static async Task<ConvertHashResult> ConvertWrappedLz4ToAscfWithHashAsync(
        string wrappedPath,
        string rawTempPath,
        string ascfTempPath,
        FileFormatTranscodeOptions options,
        CancellationToken token)
    {
        options.Validate();
        var header = ReadWrappedHeader(wrappedPath, options.Lz4);
        var result = await ConvertWrappedLz4ToAscfWithHashAsync(wrappedPath, header, rawTempPath, ascfTempPath, options, token)
            .ConfigureAwait(false);
        return new ConvertHashResult(result.Hashes, result.RawSize, result.StoredSize, Lz4PayloadFormat.WrappedLz4);
    }

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
        return new ConvertHashResult(result.Hashes, result.RawSize, result.StoredSize, Lz4PayloadFormat.Lz4Stream);
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

        if (ShouldDecodeWrappedPayloadInMemory(header, options))
        {
            var raw = await DecodeWrappedPayloadToArrayAsync(wrappedPath, header, options.Lz4, token).ConfigureAwait(false);
            using var rawStream = new MemoryStream(raw, writable: false);
            var streamResult = await AscfFileWriter.WriteStreamToFileWithHashAsync(rawStream, ascfTempPath, options.AscfWriter, token)
                .ConfigureAwait(false);
            ValidateConvertedRawSize(header.OutputLength, streamResult.RawSize);
            return streamResult;
        }

        var rawSize = await WrappedLz4FileFormat.ExtractToRawFileAsync(wrappedPath, rawTempPath, options.Lz4, token)
            .ConfigureAwait(false);
        var fileResult = await AscfFileWriter.WriteFileWithHashAsync(rawTempPath, ascfTempPath, options.AscfWriter, token)
            .ConfigureAwait(false);
        ValidateConvertedRawSize(rawSize, fileResult.RawSize);

        return fileResult;
    }

    private static bool ShouldDecodeWrappedPayloadInMemory(WrappedLz4FileFormat.Header header, FileFormatTranscodeOptions options)
        => header.OutputLength <= options.AscfWriter.RawChunkSize
            && header.OutputLength <= options.Lz4.MaxInMemoryDecodeBytes;

    private static async Task<T> RunWithRawTempFileAsync<T>(string outputPath, Func<string, Task<T>> action)
    {
        var rawTempPath = FileFormatPaths.CreateSiblingTempPath(outputPath, ".raw.tmp");
        try
        {
            return await action(rawTempPath).ConfigureAwait(false);
        }
        finally
        {
            FileFormatPaths.TryDeleteFile(rawTempPath);
        }
    }

    private static WrappedLz4FileFormat.Header ReadWrappedHeader(string wrappedPath, Lz4FormatOptions options)
    {
        if (TryReadWrappedHeader(wrappedPath, options) is { } header)
        {
            return header;
        }

        if (!File.Exists(wrappedPath))
        {
            throw new FileNotFoundException($"No wrapped LZ4 source found at {wrappedPath}.", wrappedPath);
        }

        throw new InvalidDataException("Wrapped LZ4 header is invalid.");
    }

    private static WrappedLz4FileFormat.Header? TryReadWrappedHeader(string wrappedPath, Lz4FormatOptions options)
    {
        var wrappedInfo = new FileInfo(wrappedPath);
        return wrappedInfo.Exists
            ? WrappedLz4FileFormat.TryReadHeader(wrappedPath, wrappedInfo.Length, options.BufferSize, options)
            : null;
    }

    private static async Task<byte[]> DecodeWrappedPayloadToArrayAsync(
        string wrappedPath,
        WrappedLz4FileFormat.Header header,
        Lz4FormatOptions options,
        CancellationToken token)
    {
        var input = new FileStream(wrappedPath, FileMode.Open, FileAccess.Read, FileShare.Read, options.BufferSize, useAsync: true);
        await using (input.ConfigureAwait(false))
        {
            input.Position = WrappedLz4FileFormat.HeaderSize;
            var stored = ArrayPool<byte>.Shared.Rent(header.InputLength);
            try
            {
                await input.ReadExactlyAsync(stored.AsMemory(0, header.InputLength), token).ConfigureAwait(false);
                var raw = GC.AllocateUninitializedArray<byte>(header.OutputLength);
                Lz4BlockCodec.Decode(stored.AsSpan(0, header.InputLength), raw, header.OutputLength);
                return raw;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(stored);
            }
        }
    }

    private static void ValidateConvertedRawSize(long expectedRawSize, long actualRawSize)
    {
        if (actualRawSize != expectedRawSize)
        {
            throw new InvalidDataException($".ascf raw size mismatch (expected {expectedRawSize}, got {actualRawSize}).");
        }
    }
}
