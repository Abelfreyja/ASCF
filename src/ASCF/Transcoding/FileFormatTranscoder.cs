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
        var input = FileFormatStreams.OpenRandomReadAsync(ascfPath, options.AscfReader.BufferSize);
        await using (input.ConfigureAwait(false))
            return await ConvertAscfFileToWrappedLz4Async(input, rawTempPath, wrappedTempPath, options, token).ConfigureAwait(false);
    }

    public static Task<WrappedLz4FileFormat.WriteResult> ConvertAscfFileToWrappedLz4Async(
        FileStream input,
        string wrappedPath,
        FileFormatTranscodeOptions options,
        CancellationToken token)
        => RunWithRawTempFileAsync(wrappedPath,
            rawPath => ConvertAscfFileToWrappedLz4Async(input, rawPath, wrappedPath, options, token));

    private static async Task<WrappedLz4FileFormat.WriteResult> ConvertAscfFileToWrappedLz4Async(
        FileStream input,
        string rawTempPath,
        string wrappedTempPath,
        FileFormatTranscodeOptions options,
        CancellationToken token)
    {
        options.Validate();
        if (await AscfFileReader.TryWriteStoredRawWrappedLz4Async(input, wrappedTempPath, options.AscfReader, token).ConfigureAwait(false) is { } storedRaw)
        {
            return storedRaw;
        }

        var rawSize = await AscfFileReader.DecodeFileToFileParallelAsync(input, rawTempPath, options.AscfReader, token)
            .ConfigureAwait(false);
        var wrapped = await WrappedLz4FileFormat.WriteFromRawFileAsync(rawTempPath, wrappedTempPath, options.Lz4, token)
            .ConfigureAwait(false);
        if (wrapped.OriginalSize != rawSize)
        {
            throw new InvalidDataException($"Wrapped LZ4 raw size mismatch (expected {rawSize}, got {wrapped.OriginalSize}).");
        }

        return wrapped;
    }

    public static Task<WrappedLz4FileFormat.WriteResult> ConvertLz4StreamToWrappedLz4Async(
        FileStream input,
        string wrappedPath,
        FileFormatTranscodeOptions options,
        CancellationToken token)
        => RunWithRawTempFileAsync(wrappedPath, async rawPath =>
        {
            options.Validate();
            input.Position = 0;
            var rawSize = await Lz4StreamFormat.ExtractToRawFileAsync(input, rawPath, options.Lz4, token).ConfigureAwait(false);
            var result = await WrappedLz4FileFormat.WriteFromRawFileAsync(rawPath, wrappedPath, options.Lz4, token).ConfigureAwait(false);
            ValidateConvertedRawSize(rawSize, result.OriginalSize);
            return result;
        });

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
        if (options.AscfWriter.ResultHashAlgorithms != AscfRawHashAlgorithms.None)
            options = options with { AscfWriter = options.AscfWriter with { ResultHashAlgorithms = AscfRawHashAlgorithms.None } };
        var input = FileFormatStreams.OpenReadAsync(wrappedPath, options.Lz4.BufferSize);
        await using (input.ConfigureAwait(false))
        {
            var header = await TryReadWrappedHeaderAsync(input, options.Lz4, token).ConfigureAwait(false)
                ?? throw new InvalidDataException("Wrapped LZ4 header is invalid.");
            var result = await ConvertWrappedLz4ToAscfAsync(input, header, rawTempPath, ascfTempPath, options, token)
                .ConfigureAwait(false);
            return new ConvertResult(result.RawSize, result.StoredSize);
        }
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
        var input = FileFormatStreams.OpenReadAsync(lz4Path, streamBufferSize);
        await using (input.ConfigureAwait(false))
            return await ConvertLz4PayloadToAscfWithHashAsync(input, rawTempPath, ascfTempPath, options, token).ConfigureAwait(false);
    }

    public static Task<ConvertHashResult> ConvertLz4PayloadToAscfWithHashAsync(
        FileStream input,
        string ascfPath,
        FileFormatTranscodeOptions options,
        CancellationToken token)
        => RunWithRawTempFileAsync(ascfPath,
            rawPath => ConvertLz4PayloadToAscfWithHashAsync(input, rawPath, ascfPath, options, token));

    private static async Task<ConvertHashResult> ConvertLz4PayloadToAscfWithHashAsync(
        FileStream input,
        string rawTempPath,
        string ascfTempPath,
        FileFormatTranscodeOptions options,
        CancellationToken token)
    {
        options.Validate();
        AscfFileWriter.ValidateHashOptions(options.AscfWriter);
        if (await TryReadWrappedHeaderAsync(input, options.Lz4, token).ConfigureAwait(false) is { } header)
        {
            var wrapped = await ConvertWrappedLz4ToAscfAsync(input, header, rawTempPath, ascfTempPath, options, token)
                .ConfigureAwait(false);
            return new ConvertHashResult(wrapped.Hashes, wrapped.RawSize, wrapped.StoredSize, Lz4PayloadFormat.WrappedLz4);
        }

        var stream = await Lz4StreamFormat.ConvertToAscfFileWithHashAsync(input, ascfTempPath, options.AscfWriter, token)
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
        AscfFileWriter.ValidateHashOptions(options.AscfWriter);
        var input = FileFormatStreams.OpenReadAsync(wrappedPath, options.Lz4.BufferSize);
        await using (input.ConfigureAwait(false))
        {
            var header = await TryReadWrappedHeaderAsync(input, options.Lz4, token).ConfigureAwait(false)
                ?? throw new InvalidDataException("Wrapped LZ4 header is invalid.");
            var result = await ConvertWrappedLz4ToAscfAsync(input, header, rawTempPath, ascfTempPath, options, token)
                .ConfigureAwait(false);
            return new ConvertHashResult(result.Hashes, result.RawSize, result.StoredSize, Lz4PayloadFormat.WrappedLz4);
        }
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

    private static async Task<AscfFileWriter.HashedWriteResult> ConvertWrappedLz4ToAscfAsync(
        FileStream input,
        WrappedLz4FileFormat.Header header,
        string rawTempPath,
        string ascfTempPath,
        FileFormatTranscodeOptions options,
        CancellationToken token)
    {
        var computeHashes = options.AscfWriter.ResultHashAlgorithms != AscfRawHashAlgorithms.None;
        if (Lz4BlockCodec.IsStoredRaw(header.OutputLength, header.InputLength))
        {
            input.Position = WrappedLz4FileFormat.HeaderSize;
            if (computeHashes)
                return await AscfFileWriter.WriteStoredRawStreamToFileWithHashAsync(input, header.OutputLength, ascfTempPath, options.AscfWriter, token)
                    .ConfigureAwait(false);
            var storedSize = await AscfFileWriter.WriteStoredRawStreamToFileAsync(input, header.OutputLength, ascfTempPath, options.AscfWriter, token)
                .ConfigureAwait(false);
            return new AscfFileWriter.HashedWriteResult(default, header.OutputLength, storedSize);
        }

        if (ShouldDecodeWrappedPayloadInMemory(header, options))
        {
            var raw = await DecodeWrappedPayloadToArrayAsync(input, header, token).ConfigureAwait(false);
            using var rawStream = new MemoryStream(raw, writable: false);
            if (computeHashes)
                return await AscfFileWriter.WriteStreamToFileWithHashAsync(rawStream, ascfTempPath, options.AscfWriter, token)
                    .ConfigureAwait(false);
            var result = await AscfFileWriter.WriteStreamToFileAsync(rawStream, ascfTempPath, options.AscfWriter, token)
                .ConfigureAwait(false);
            return new AscfFileWriter.HashedWriteResult(default, result.RawSize, result.StoredSize);
        }

        var extracted = await WrappedLz4FileFormat.ExtractToRawFileWithHashAsync(input, rawTempPath, AscfRawHashAlgorithms.None, options.Lz4, token)
            .ConfigureAwait(false);
        if (computeHashes)
        {
            var result = await AscfFileWriter.WriteFileWithHashAsync(rawTempPath, ascfTempPath, options.AscfWriter, token)
                .ConfigureAwait(false);
            ValidateConvertedRawSize(extracted.RawSize, result.RawSize);
            return result;
        }

        var storedFileSize = await AscfFileWriter.WriteFileAsync(rawTempPath, ascfTempPath, options.AscfWriter, token).ConfigureAwait(false);
        return new AscfFileWriter.HashedWriteResult(default, extracted.RawSize, storedFileSize);
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

    private static async Task<byte[]> DecodeWrappedPayloadToArrayAsync(
        FileStream input,
        WrappedLz4FileFormat.Header header,
        CancellationToken token)
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

    private static async Task<WrappedLz4FileFormat.Header?> TryReadWrappedHeaderAsync(
        FileStream input, Lz4FormatOptions options, CancellationToken token)
    {
        input.Position = 0;
        var header = new byte[WrappedLz4FileFormat.HeaderSize];
        try
        {
            var read = await FileFormatStreamReader.ReadUpToAsync(input, header, token).ConfigureAwait(false);
            return read == header.Length ? WrappedLz4FileFormat.TryReadHeader(input.Length, header, options) : null;
        }
        finally
        {
            input.Position = 0;
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
