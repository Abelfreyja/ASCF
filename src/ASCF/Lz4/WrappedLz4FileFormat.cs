using System.Buffers;
using System.Buffers.Binary;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;
using ASCF.Util;

namespace ASCF.Lz4;

public static class WrappedLz4FileFormat
{
    public const int HeaderSize = 8;

    [StructLayout(LayoutKind.Auto)]
    public readonly record struct WriteResult(long OriginalSize, long CompressedSize);

    [StructLayout(LayoutKind.Auto)]
    public readonly record struct HashedWriteResult(AscfRawHashes Hashes, long OriginalSize, long CompressedSize);

    [StructLayout(LayoutKind.Auto)]
    public readonly record struct DecodedArrayResult(byte[] Raw, AscfRawHashes Hashes, long RawSize);

    [StructLayout(LayoutKind.Auto)]
    public readonly record struct Header(int OutputLength, int InputLength);

    public static Task<WriteResult> WriteFromRawFileAsync(string sourcePath, string outputPath, CancellationToken token)
        => WriteFromRawFileAsync(sourcePath, outputPath, Lz4FormatOptions.Default, token);

    public static async Task<WriteResult> WriteFromRawFileAsync(string sourcePath, string outputPath, Lz4FormatOptions options, CancellationToken token)
    {
        var result = await WriteFromRawFileInternalAsync(
            sourcePath,
            outputPath,
            AscfRawHashAlgorithms.None,
            options,
            token).ConfigureAwait(false);

        return new WriteResult(result.OriginalSize, result.CompressedSize);
    }

    public static Task<HashedWriteResult> WriteFromRawFileWithHashAsync(
        string sourcePath,
        string outputPath,
        AscfRawHashAlgorithms algorithms,
        CancellationToken token)
        => WriteFromRawFileWithHashAsync(sourcePath, outputPath, algorithms, Lz4FormatOptions.Default, token);

    public static Task<HashedWriteResult> WriteFromRawFileWithHashAsync(
        string sourcePath,
        string outputPath,
        AscfRawHashAlgorithms algorithms,
        Lz4FormatOptions options,
        CancellationToken token)
        => WriteFromRawFileInternalAsync(sourcePath, outputPath, algorithms, options, token);

    private static async Task<HashedWriteResult> WriteFromRawFileInternalAsync(
        string sourcePath,
        string outputPath,
        AscfRawHashAlgorithms algorithms,
        Lz4FormatOptions options,
        CancellationToken token)
    {
        options.Validate();
        AscfRawHashAlgorithmFlags.ValidateSupported(algorithms, nameof(algorithms));
        var sourceInfo = new FileInfo(sourcePath);
        if (!sourceInfo.Exists)
        {
            throw new FileNotFoundException($"No raw source found at {sourcePath}.", sourcePath);
        }

        if (sourceInfo.Length > int.MaxValue)
        {
            throw new InvalidDataException($"Wrapped LZ4 cannot encode files larger than {int.MaxValue} bytes.");
        }

        if (sourceInfo.Length > options.MaxRawFileBytes)
        {
            throw new InvalidDataException($"Wrapped LZ4 output length too large ({sourceInfo.Length} bytes).");
        }

        FileFormatPaths.EnsureOutputDirectory(outputPath);

        return sourceInfo.Length == 0 || sourceInfo.Length < options.MemoryMappedCompressionThreshold
            ? await WriteSmallFileAsync(sourcePath, outputPath, algorithms, options, token).ConfigureAwait(false)
            : WriteMemoryMappedFile(sourcePath, outputPath, algorithms, options, token);
    }

    public static Task<long> ExtractToRawFileAsync(string wrappedPath, string outputPath, CancellationToken token)
        => ExtractToRawFileAsync(wrappedPath, outputPath, Lz4FormatOptions.Default, token);

    public static async Task<long> ExtractToRawFileAsync(string wrappedPath, string outputPath, Lz4FormatOptions options, CancellationToken token)
    {
        var result = await ExtractToRawFileWithHashAsync(
            wrappedPath,
            outputPath,
            AscfRawHashAlgorithms.None,
            options,
            token).ConfigureAwait(false);

        return result.RawSize;
    }

    public static Task<long> ExtractToRawStreamAsync(string wrappedPath, Stream output, CancellationToken token)
        => ExtractToRawStreamAsync(wrappedPath, output, Lz4FormatOptions.Default, token);

    public static async Task<long> ExtractToRawStreamAsync(string wrappedPath, Stream output, Lz4FormatOptions options, CancellationToken token)
    {
        options.Validate();
        ArgumentNullException.ThrowIfNull(output);
        if (!output.CanWrite)
        {
            throw new ArgumentException("Output stream must be writable.", nameof(output));
        }

        var input = FileFormatStreams.OpenReadAsync(wrappedPath, options.BufferSize);
        await using (input.ConfigureAwait(false))
        {
            var headerBytes = new byte[HeaderSize];
            await input.ReadExactlyAsync(headerBytes.AsMemory(0, headerBytes.Length), token).ConfigureAwait(false);
            var header = ReadHeader(input.Length, headerBytes, options);
            await ExtractPayloadToStreamAsync(input, output, header, transform: null, options, token)
                .ConfigureAwait(false);
            return header.OutputLength;
        }
    }

    public static Task<FileFormatRawHashResult> ExtractToRawFileWithHashAsync(
        string wrappedPath,
        string outputPath,
        AscfRawHashAlgorithms algorithms,
        CancellationToken token)
        => ExtractToRawFileWithHashAsync(wrappedPath, outputPath, algorithms, Lz4FormatOptions.Default, token);

    public static async Task<FileFormatRawHashResult> ExtractToRawFileWithHashAsync(
        string wrappedPath,
        string outputPath,
        AscfRawHashAlgorithms algorithms,
        Lz4FormatOptions options,
        CancellationToken token)
    {
        options.Validate();
        AscfRawHashAlgorithmFlags.ValidateSupported(algorithms, nameof(algorithms));
        var input = FileFormatStreams.OpenReadAsync(wrappedPath, options.BufferSize);
        await using (input.ConfigureAwait(false))
        {
            var header = new byte[HeaderSize];
            await input.ReadExactlyAsync(header.AsMemory(0, header.Length), token).ConfigureAwait(false);

            var wrappedHeader = ReadHeader(input.Length, header, options);

            using var staged = FileFormatPaths.CreateStagedFile(outputPath);
            using var hasher = AscfRawContentHasher.Create(algorithms);
            if (CanDecodeStreamPayloadDirectly(wrappedHeader, options))
            {
                await ExtractDirectPayloadToStagedFileAsync(input, staged, wrappedHeader, hasher, transform: null, options, token)
                    .ConfigureAwait(false);
            }
            else
            {
                await DecodeMemoryMappedCompressedPayloadToRawFileAsync(
                        wrappedPath,
                        staged,
                        wrappedHeader.InputLength,
                        wrappedHeader.OutputLength,
                        hasher,
                        options,
                        token)
                    .ConfigureAwait(false);
            }

            staged.Commit();
            return ToRawHashResult(hasher, wrappedHeader.OutputLength);
        }
    }

    public static Task<long> ExtractStreamToRawFileAsync(
        Stream wrappedStream,
        long wrappedLength,
        string outputPath,
        CancellationToken token)
        => ExtractStreamToRawFileAsync(wrappedStream, wrappedLength, outputPath, transform: null, Lz4FormatOptions.Default, token);

    public static Task<long> ExtractStreamToRawFileAsync(
        Stream wrappedStream,
        long wrappedLength,
        string outputPath,
        AscfBufferTransform? transform,
        CancellationToken token)
        => ExtractStreamToRawFileAsync(wrappedStream, wrappedLength, outputPath, transform, Lz4FormatOptions.Default, token);

    public static async Task<long> ExtractStreamToRawFileAsync(
        Stream wrappedStream,
        long wrappedLength,
        string outputPath,
        AscfBufferTransform? transform,
        Lz4FormatOptions options,
        CancellationToken token)
    {
        var result = await ExtractStreamToRawFileWithHashAsync(
            wrappedStream,
            wrappedLength,
            outputPath,
            AscfRawHashAlgorithms.None,
            transform,
            options,
            token).ConfigureAwait(false);

        return result.RawSize;
    }

    public static Task<long> ExtractStreamToRawStreamAsync(
        Stream wrappedStream,
        long wrappedLength,
        Stream output,
        CancellationToken token)
        => ExtractStreamToRawStreamAsync(wrappedStream, wrappedLength, output, transform: null, Lz4FormatOptions.Default, token);

    public static Task<long> ExtractStreamToRawStreamAsync(
        Stream wrappedStream,
        long wrappedLength,
        Stream output,
        AscfBufferTransform? transform,
        CancellationToken token)
        => ExtractStreamToRawStreamAsync(wrappedStream, wrappedLength, output, transform, Lz4FormatOptions.Default, token);

    public static async Task<long> ExtractStreamToRawStreamAsync(
        Stream wrappedStream,
        long wrappedLength,
        Stream output,
        AscfBufferTransform? transform,
        Lz4FormatOptions options,
        CancellationToken token)
    {
        options.Validate();
        ArgumentNullException.ThrowIfNull(wrappedStream);
        ArgumentNullException.ThrowIfNull(output);
        if (!output.CanWrite)
        {
            throw new ArgumentException("Output stream must be writable.", nameof(output));
        }

        ArgumentOutOfRangeException.ThrowIfNegative(wrappedLength);
        if (wrappedLength < HeaderSize)
        {
            throw new InvalidDataException("Wrapped LZ4 stream is too short.");
        }

        var headerBytes = new byte[HeaderSize];
        await wrappedStream.ReadExactlyAsync(headerBytes.AsMemory(0, headerBytes.Length), token).ConfigureAwait(false);
        transform?.Invoke(headerBytes);

        var header = ReadHeader(wrappedLength, headerBytes, options);
        await ExtractPayloadToStreamAsync(wrappedStream, output, header, transform, options, token)
            .ConfigureAwait(false);
        return header.OutputLength;
    }

    public static Task<FileFormatRawHashResult> ExtractStreamToRawFileWithHashAsync(
        Stream wrappedStream,
        long wrappedLength,
        string outputPath,
        AscfRawHashAlgorithms algorithms,
        CancellationToken token)
        => ExtractStreamToRawFileWithHashAsync(
            wrappedStream,
            wrappedLength,
            outputPath,
            algorithms,
            transform: null,
            Lz4FormatOptions.Default,
            token);

    public static Task<FileFormatRawHashResult> ExtractStreamToRawFileWithHashAsync(
        Stream wrappedStream,
        long wrappedLength,
        string outputPath,
        AscfRawHashAlgorithms algorithms,
        AscfBufferTransform? transform,
        CancellationToken token)
        => ExtractStreamToRawFileWithHashAsync(
            wrappedStream,
            wrappedLength,
            outputPath,
            algorithms,
            transform,
            Lz4FormatOptions.Default,
            token);

    public static async Task<FileFormatRawHashResult> ExtractStreamToRawFileWithHashAsync(
        Stream wrappedStream,
        long wrappedLength,
        string outputPath,
        AscfRawHashAlgorithms algorithms,
        AscfBufferTransform? transform,
        Lz4FormatOptions options,
        CancellationToken token)
    {
        options.Validate();
        AscfRawHashAlgorithmFlags.ValidateSupported(algorithms, nameof(algorithms));
        ArgumentOutOfRangeException.ThrowIfNegative(wrappedLength);
        if (wrappedLength < HeaderSize)
        {
            throw new InvalidDataException("Wrapped LZ4 stream is too short.");
        }

        var headerBytes = new byte[HeaderSize];
        await wrappedStream.ReadExactlyAsync(headerBytes.AsMemory(0, headerBytes.Length), token).ConfigureAwait(false);
        transform?.Invoke(headerBytes);

        var header = ReadHeader(wrappedLength, headerBytes, options);
        if (!CanDecodeStreamPayloadDirectly(header, options))
        {
            return await ExtractStreamViaTempFileWithHashAsync(
                wrappedStream,
                wrappedLength,
                headerBytes,
                outputPath,
                algorithms,
                transform,
                options,
                token)
                .ConfigureAwait(false);
        }

        using var staged = FileFormatPaths.CreateStagedFile(outputPath);
        using var hasher = AscfRawContentHasher.Create(algorithms);
        await ExtractDirectPayloadToStagedFileAsync(wrappedStream, staged, header, hasher, transform, options, token)
            .ConfigureAwait(false);
        staged.Commit();
        return ToRawHashResult(hasher, header.OutputLength);
    }

    public static Task<long> DecodeFileToFileAsync(string inputPath, string outputPath, CancellationToken token)
        => ExtractToRawFileAsync(inputPath, outputPath, token);

    public static byte[] DecodeToArray(byte[] wrapped)
        => DecodeToArray(wrapped, Lz4FormatOptions.Default);

    public static byte[] DecodeToArray(byte[] wrapped, Lz4FormatOptions options)
    {
        options.Validate();
        var header = ReadHeader(wrapped.LongLength, wrapped, options);
        if (header.OutputLength > options.MaxInMemoryDecodeBytes)
        {
            throw new InvalidDataException($"Wrapped LZ4 output length is too large for an in-memory decode ({header.OutputLength} bytes).");
        }

        if (header.OutputLength == 0)
        {
            return [];
        }

        var payload = wrapped.AsSpan(HeaderSize, header.InputLength);
        if (Lz4BlockCodec.IsStoredRaw(header.OutputLength, header.InputLength))
        {
            return payload.ToArray();
        }

        var raw = new byte[header.OutputLength];
        Lz4BlockCodec.Decode(payload, raw, header.OutputLength);
        return raw;
    }

    public static DecodedArrayResult DecodeToArrayWithHash(byte[] wrapped, AscfRawHashAlgorithms algorithms)
        => DecodeToArrayWithHash(wrapped, algorithms, Lz4FormatOptions.Default);

    public static DecodedArrayResult DecodeToArrayWithHash(byte[] wrapped, AscfRawHashAlgorithms algorithms, Lz4FormatOptions options)
    {
        options.Validate();
        AscfRawHashAlgorithmFlags.ValidateSupported(algorithms, nameof(algorithms));
        var header = ReadHeader(wrapped.LongLength, wrapped, options);
        if (header.OutputLength > options.MaxInMemoryDecodeBytes)
        {
            throw new InvalidDataException($"Wrapped LZ4 output length is too large for an in-memory decode ({header.OutputLength} bytes).");
        }

        using var hasher = AscfRawContentHasher.Create(algorithms);
        if (header.OutputLength == 0)
        {
            return new DecodedArrayResult([], FinalizeRawHashes(hasher), 0);
        }

        var payload = wrapped.AsSpan(HeaderSize, header.InputLength);
        if (Lz4BlockCodec.IsStoredRaw(header.OutputLength, header.InputLength))
        {
            var raw = payload.ToArray();
            hasher?.AppendData(raw);
            return new DecodedArrayResult(raw, FinalizeRawHashes(hasher), header.OutputLength);
        }

        var decoded = new byte[header.OutputLength];
        Lz4BlockCodec.Decode(payload, decoded, header.OutputLength);
        hasher?.AppendData(decoded);
        return new DecodedArrayResult(decoded, FinalizeRawHashes(hasher), header.OutputLength);
    }

    public static Header? TryReadHeader(long fileLength, ReadOnlySpan<byte> header)
        => TryReadHeader(fileLength, header, Lz4FormatOptions.Default);

    public static Header? TryReadHeader(long fileLength, ReadOnlySpan<byte> header, Lz4FormatOptions options)
    {
        options.Validate();
        if (header.Length < HeaderSize)
        {
            return null;
        }

        var outputLength = BinaryPrimitives.ReadInt32LittleEndian(header[..4]);
        var inputLength = BinaryPrimitives.ReadInt32LittleEndian(header.Slice(4, 4));
        if (outputLength < 0 || inputLength < 0)
        {
            return null;
        }

        if (outputLength > options.MaxRawFileBytes)
        {
            return null;
        }

        var remainingLength = fileLength - HeaderSize;
        if (inputLength != remainingLength)
        {
            return null;
        }

        if ((outputLength == 0 && inputLength != 0) || inputLength > outputLength)
        {
            return null;
        }

        return new Header(outputLength, inputLength);
    }

    public static Header ReadHeader(long fileLength, ReadOnlySpan<byte> header)
        => ReadHeader(fileLength, header, Lz4FormatOptions.Default);

    public static Header ReadHeader(long fileLength, ReadOnlySpan<byte> header, Lz4FormatOptions options)
        => TryReadHeader(fileLength, header, options) ?? throw new InvalidDataException("Wrapped LZ4 header is invalid.");

    public static void WriteHeader(Span<byte> header, int outputLength, int inputLength)
    {
        if (header.Length < HeaderSize)
        {
            throw new ArgumentException("Wrapped LZ4 header buffer is too small.", nameof(header));
        }

        if (outputLength < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(outputLength), outputLength, "Output length must be non-negative.");
        }

        if (inputLength < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(inputLength), inputLength, "Input length must be non-negative.");
        }

        if ((outputLength == 0 && inputLength != 0) || inputLength > outputLength)
        {
            throw new ArgumentException("Wrapped LZ4 input length must fit inside the output length.", nameof(inputLength));
        }

        BinaryPrimitives.WriteInt32LittleEndian(header[..4], outputLength);
        BinaryPrimitives.WriteInt32LittleEndian(header.Slice(4, 4), inputLength);
    }

    public static Task<Header?> TryReadHeaderAsync(string path, long fileLength, int bufferSize, CancellationToken token)
        => TryReadHeaderAsync(path, fileLength, bufferSize, Lz4FormatOptions.Default, token);

    public static async Task<Header?> TryReadHeaderAsync(string path, long fileLength, int bufferSize, Lz4FormatOptions options, CancellationToken token)
    {
        options.Validate();
        FileFormatBuffers.ValidateBufferSize(bufferSize, nameof(bufferSize));
        if (fileLength < HeaderSize)
        {
            return null;
        }

        var input = FileFormatStreams.OpenReadAsync(path, bufferSize);
        await using (input.ConfigureAwait(false))
        {
            var header = new byte[HeaderSize];
            var read = await FileFormatStreamReader.ReadUpToAsync(input, header.AsMemory(0, header.Length), token).ConfigureAwait(false);
            return read == header.Length ? TryReadHeader(fileLength, header, options) : null;
        }
    }

    public static Header? TryReadHeader(string path, long fileLength, int bufferSize)
        => TryReadHeader(path, fileLength, bufferSize, Lz4FormatOptions.Default);

    public static Header? TryReadHeader(string path, long fileLength, int bufferSize, Lz4FormatOptions options)
    {
        options.Validate();
        FileFormatBuffers.ValidateBufferSize(bufferSize, nameof(bufferSize));
        if (fileLength < HeaderSize)
        {
            return null;
        }

        using var input = FileFormatStreams.OpenSequentialRead(path, bufferSize);
        var header = new byte[HeaderSize];
        var read = FileFormatStreamReader.ReadUpTo(input, header);
        return read == header.Length ? TryReadHeader(fileLength, header, options) : null;
    }

    public static async Task<FileFormatHashResult> ComputeFileHashAsync(
        string wrappedPath,
        Header header,
        int streamBufferSize,
        int copyBufferSize,
        CancellationToken token)
    {
        var result = await ComputeRawHashesAsync(
            wrappedPath,
            header,
            AscfRawHashAlgorithms.Sha1,
            streamBufferSize,
            copyBufferSize,
            token).ConfigureAwait(false);

        return ToSha1HashResult(result);
    }

    public static async Task<FileFormatRawHashResult> ComputeRawHashesAsync(
        string wrappedPath,
        Header header,
        AscfRawHashAlgorithms algorithms,
        int streamBufferSize,
        int copyBufferSize,
        CancellationToken token)
    {
        FileFormatBuffers.ValidateBufferSize(streamBufferSize, nameof(streamBufferSize));
        FileFormatBuffers.ValidateBufferSize(copyBufferSize, nameof(copyBufferSize));
        AscfRawHashAlgorithmFlags.ValidateSupported(algorithms, nameof(algorithms));

        var input = FileFormatStreams.OpenReadAsync(wrappedPath, streamBufferSize);
        await using (input.ConfigureAwait(false))
        {
            input.Position = HeaderSize;
            using var hasher = AscfRawContentHasher.Create(algorithms);
            if (header.OutputLength == 0)
            {
                return ToRawHashResult(hasher, 0);
            }

            if (Lz4BlockCodec.IsStoredRaw(header.OutputLength, header.InputLength))
            {
                await FileFormatHashing.AppendExactlyAsync(input, hasher, header.InputLength, copyBufferSize, token).ConfigureAwait(false);
                return ToRawHashResult(hasher, header.OutputLength);
            }

            var compressed = ArrayPool<byte>.Shared.Rent(header.InputLength);
            var raw = ArrayPool<byte>.Shared.Rent(header.OutputLength);
            try
            {
                await input.ReadExactlyAsync(compressed.AsMemory(0, header.InputLength), token).ConfigureAwait(false);
                Lz4BlockCodec.Decode(compressed.AsSpan(0, header.InputLength), raw.AsSpan(0, header.OutputLength), header.OutputLength);
                hasher?.AppendData(raw.AsSpan(0, header.OutputLength));
                return ToRawHashResult(hasher, header.OutputLength);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(raw);
                ArrayPool<byte>.Shared.Return(compressed);
            }
        }
    }

    public static FileFormatHashResult ComputeFileHash(
        string wrappedPath,
        Header header,
        int streamBufferSize,
        int copyBufferSize)
    {
        var result = ComputeRawHashes(wrappedPath, header, AscfRawHashAlgorithms.Sha1, streamBufferSize, copyBufferSize);
        return ToSha1HashResult(result);
    }

    public static FileFormatRawHashResult ComputeRawHashes(
        string wrappedPath,
        Header header,
        AscfRawHashAlgorithms algorithms,
        int streamBufferSize,
        int copyBufferSize)
    {
        FileFormatBuffers.ValidateBufferSize(streamBufferSize, nameof(streamBufferSize));
        FileFormatBuffers.ValidateBufferSize(copyBufferSize, nameof(copyBufferSize));
        AscfRawHashAlgorithmFlags.ValidateSupported(algorithms, nameof(algorithms));

        using var input = FileFormatStreams.OpenSequentialRead(wrappedPath, streamBufferSize);
        input.Position = HeaderSize;

        using var hasher = AscfRawContentHasher.Create(algorithms);
        if (header.OutputLength == 0)
        {
            return ToRawHashResult(hasher, 0);
        }

        if (Lz4BlockCodec.IsStoredRaw(header.OutputLength, header.InputLength))
        {
            FileFormatHashing.AppendExactly(input, hasher, header.InputLength, copyBufferSize);
            return ToRawHashResult(hasher, header.OutputLength);
        }

        var compressed = ArrayPool<byte>.Shared.Rent(header.InputLength);
        var raw = ArrayPool<byte>.Shared.Rent(header.OutputLength);
        try
        {
            input.ReadExactly(compressed.AsSpan(0, header.InputLength));
            Lz4BlockCodec.Decode(compressed.AsSpan(0, header.InputLength), raw.AsSpan(0, header.OutputLength), header.OutputLength);
            hasher?.AppendData(raw.AsSpan(0, header.OutputLength));
            return ToRawHashResult(hasher, header.OutputLength);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(raw);
            ArrayPool<byte>.Shared.Return(compressed);
        }
    }

    public static FileFormatRawHashResult ComputeRawHashes(
        ReadOnlySpan<byte> wrapped,
        AscfRawHashAlgorithms algorithms,
        Lz4FormatOptions options)
    {
        options.Validate();
        AscfRawHashAlgorithmFlags.ValidateSupported(algorithms, nameof(algorithms));
        var header = ReadHeader(wrapped.Length, wrapped, options);
        if (header.OutputLength == 0)
        {
            using var emptyHasher = AscfRawContentHasher.Create(algorithms);
            return ToRawHashResult(emptyHasher, 0);
        }

        if (header.OutputLength > options.MaxInMemoryDecodeBytes)
        {
            throw new InvalidDataException($"Wrapped LZ4 output length is too large for an in-memory hash ({header.OutputLength} bytes).");
        }

        var payload = wrapped.Slice(HeaderSize, header.InputLength);
        using var hasher = AscfRawContentHasher.Create(algorithms);
        if (Lz4BlockCodec.IsStoredRaw(header.OutputLength, header.InputLength))
        {
            hasher?.AppendData(payload[..header.OutputLength]);
            return ToRawHashResult(hasher, header.OutputLength);
        }

        var raw = ArrayPool<byte>.Shared.Rent(header.OutputLength);
        try
        {
            Lz4BlockCodec.Decode(payload, raw.AsSpan(0, header.OutputLength), header.OutputLength);
            hasher?.AppendData(raw.AsSpan(0, header.OutputLength));
            return ToRawHashResult(hasher, header.OutputLength);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(raw);
        }
    }

    private static async Task CreateEmptyFileAsync(FileFormatPaths.StagedFile output, Lz4FormatOptions options, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var emptyStream = output.OpenSequentialWrite(options.BufferSize);
        await emptyStream.DisposeAsync().ConfigureAwait(false);
    }

    private static async Task CopyStoredRawPayloadAsync(
        Stream input,
        FileFormatPaths.StagedFile output,
        int inputLength,
        AscfRawContentHasher? hasher,
        AscfBufferTransform? transform,
        Lz4FormatOptions options,
        CancellationToken token)
    {
        var outputStream = output.OpenSequentialWrite(options.BufferSize);
        await using (outputStream.ConfigureAwait(false))
        {
            await CopyRawPayloadAsync(input, outputStream, inputLength, hasher, transform, options, token).ConfigureAwait(false);
        }
    }

    private static async Task ExtractDirectPayloadToStagedFileAsync(
        Stream input,
        FileFormatPaths.StagedFile output,
        Header header,
        AscfRawContentHasher? hasher,
        AscfBufferTransform? transform,
        Lz4FormatOptions options,
        CancellationToken token)
    {
        if (header.OutputLength == 0)
        {
            await CreateEmptyFileAsync(output, options, token).ConfigureAwait(false);
            return;
        }

        if (Lz4BlockCodec.IsStoredRaw(header.OutputLength, header.InputLength))
        {
            await CopyStoredRawPayloadAsync(input, output, header.InputLength, hasher, transform, options, token).ConfigureAwait(false);
            return;
        }

        await DecodeSmallCompressedPayloadToRawFileAsync(
                input,
                output,
                header.InputLength,
                header.OutputLength,
                hasher,
                transform,
                options,
                token)
            .ConfigureAwait(false);
    }

    private static async Task DecodeSmallCompressedPayloadToRawFileAsync(
        Stream input,
        FileFormatPaths.StagedFile output,
        int inputLength,
        int outputLength,
        AscfRawContentHasher? hasher,
        AscfBufferTransform? transform,
        Lz4FormatOptions options,
        CancellationToken token)
    {
        var compressed = GC.AllocateUninitializedArray<byte>(inputLength);
        var raw = GC.AllocateUninitializedArray<byte>(outputLength);
        await input.ReadExactlyAsync(compressed.AsMemory(0, inputLength), token).ConfigureAwait(false);
        transform?.Invoke(compressed.AsSpan(0, inputLength));
        Lz4BlockCodec.Decode(compressed, 0, inputLength, raw, 0, outputLength);
        hasher?.AppendData(raw.AsSpan(0, outputLength));

        var outputStream = output.OpenSequentialWrite(options.BufferSize);
        await using (outputStream.ConfigureAwait(false))
        {
            await outputStream.WriteAsync(raw.AsMemory(0, outputLength), token).ConfigureAwait(false);
        }
    }

    private static async Task DecodeMemoryMappedCompressedPayloadToRawFileAsync(
        string wrappedPath,
        FileFormatPaths.StagedFile output,
        int inputLength,
        int outputLength,
        AscfRawContentHasher? hasher,
        Lz4FormatOptions options,
        CancellationToken token)
    {
        token.ThrowIfCancellationRequested();

        var mappedOutputStream = output.OpenRandomReadWrite(options.BufferSize);
        await using (mappedOutputStream.ConfigureAwait(false))
        {
            mappedOutputStream.SetLength(outputLength);

            using var inputMap = MemoryMappedFile.CreateFromFile(wrappedPath, FileMode.Open, null, 0, MemoryMappedFileAccess.Read);
            using var inputView = inputMap.CreateViewAccessor(HeaderSize, inputLength, MemoryMappedFileAccess.Read);
            using var outputMap = MemoryMappedFile.CreateFromFile(mappedOutputStream, null, outputLength, MemoryMappedFileAccess.ReadWrite, HandleInheritability.None, leaveOpen: true);
            using var outputView = outputMap.CreateViewAccessor(0, outputLength, MemoryMappedFileAccess.ReadWrite);

            unsafe
            {
                byte* inputPtr = null;
                byte* outputPtr = null;
                try
                {
                    inputView.SafeMemoryMappedViewHandle.AcquirePointer(ref inputPtr);
                    outputView.SafeMemoryMappedViewHandle.AcquirePointer(ref outputPtr);

                    inputPtr += inputView.PointerOffset;
                    outputPtr += outputView.PointerOffset;

                    Lz4BlockCodec.Decode(inputPtr, inputLength, outputPtr, outputLength);
                    hasher?.AppendData(new ReadOnlySpan<byte>(outputPtr, outputLength));
                }
                finally
                {
                    if (inputPtr != null)
                    {
                        inputView.SafeMemoryMappedViewHandle.ReleasePointer();
                    }

                    if (outputPtr != null)
                    {
                        outputView.SafeMemoryMappedViewHandle.ReleasePointer();
                    }
                }
            }

            token.ThrowIfCancellationRequested();
            outputView.Flush();
        }
    }

    private static bool CanDecodeStreamPayloadDirectly(Header header, Lz4FormatOptions options)
        => Lz4BlockCodec.IsStoredRaw(header.OutputLength, header.InputLength)
            || (header.OutputLength <= options.MaxInMemoryDecodeBytes
                && header.OutputLength < options.MemoryMappedDecodeThreshold);

    private static async Task ExtractPayloadToStreamAsync(
        Stream input,
        Stream output,
        Header header,
        AscfBufferTransform? transform,
        Lz4FormatOptions options,
        CancellationToken token)
    {
        if (header.OutputLength == 0)
        {
            return;
        }

        if (Lz4BlockCodec.IsStoredRaw(header.OutputLength, header.InputLength))
        {
            await CopyRawPayloadAsync(input, output, header.InputLength, hasher: null, transform, options, token)
                .ConfigureAwait(false);
            return;
        }

        if (header.OutputLength > options.MaxInMemoryDecodeBytes)
        {
            throw new InvalidDataException($"Wrapped LZ4 output length is too large for a streamed decode ({header.OutputLength} bytes).");
        }

        var compressed = ArrayPool<byte>.Shared.Rent(header.InputLength);
        var raw = ArrayPool<byte>.Shared.Rent(header.OutputLength);
        try
        {
            await input.ReadExactlyAsync(compressed.AsMemory(0, header.InputLength), token).ConfigureAwait(false);
            transform?.Invoke(compressed.AsSpan(0, header.InputLength));
            Lz4BlockCodec.Decode(compressed.AsSpan(0, header.InputLength), raw.AsSpan(0, header.OutputLength), header.OutputLength);
            await output.WriteAsync(raw.AsMemory(0, header.OutputLength), token).ConfigureAwait(false);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(raw);
            ArrayPool<byte>.Shared.Return(compressed);
        }
    }

    private static async Task CopyRawPayloadAsync(
        Stream input,
        Stream output,
        long inputLength,
        AscfRawContentHasher? hasher,
        AscfBufferTransform? transform,
        Lz4FormatOptions options,
        CancellationToken token)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(options.CopyBufferSize);
        try
        {
            var remaining = inputLength;
            while (remaining > 0)
            {
                var readLength = checked((int)Math.Min(buffer.Length, remaining));
                var read = await input.ReadAsync(buffer.AsMemory(0, readLength), token).ConfigureAwait(false);
                if (read == 0)
                {
                    throw new EndOfStreamException();
                }

                var span = buffer.AsSpan(0, read);
                transform?.Invoke(span);
                hasher?.AppendData(span);
                await output.WriteAsync(buffer.AsMemory(0, read), token).ConfigureAwait(false);
                remaining -= read;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static async Task<FileFormatRawHashResult> ExtractStreamViaTempFileWithHashAsync(
        Stream wrappedStream,
        long wrappedLength,
        byte[] headerBytes,
        string outputPath,
        AscfRawHashAlgorithms algorithms,
        AscfBufferTransform? transform,
        Lz4FormatOptions options,
        CancellationToken token)
    {
        var tempPath = FileFormatPaths.CreateSiblingTempPath(outputPath, ".wrapped.tmp");
        try
        {
            var temp = new FileStream(
                tempPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                options.BufferSize,
                useAsync: true);
            await using (temp.ConfigureAwait(false))
            {
                await temp.WriteAsync(headerBytes.AsMemory(0, headerBytes.Length), token).ConfigureAwait(false);
                await FileFormatStreamReader
                    .CopyExactlyAsync(
                        wrappedStream,
                        temp,
                        wrappedLength - HeaderSize,
                        options.CopyBufferSize,
                        transform,
                        token)
                    .ConfigureAwait(false);
            }

            return await ExtractToRawFileWithHashAsync(tempPath, outputPath, algorithms, options, token).ConfigureAwait(false);
        }
        finally
        {
            FileFormatPaths.TryDeleteFile(tempPath);
        }
    }

    private static async Task<HashedWriteResult> WriteSmallFileAsync(
        string sourcePath,
        string outputPath,
        AscfRawHashAlgorithms algorithms,
        Lz4FormatOptions options,
        CancellationToken token)
    {
        var raw = await File.ReadAllBytesAsync(sourcePath, token).ConfigureAwait(false);
        using var hasher = AscfRawContentHasher.Create(algorithms);
        hasher?.AppendData(raw);
        var maxCompressedLength = Lz4BlockCodec.MaxUsefulCompressedLength(raw.Length);
        var storedBuffer = maxCompressedLength == 0 ? Array.Empty<byte>() : ArrayPool<byte>.Shared.Rent(maxCompressedLength);
        try
        {
            var encoded = EncodeWrappedPayload(raw, storedBuffer.AsSpan(0, maxCompressedLength));
            var payload = encoded.StoresRaw
                ? raw.AsMemory(0, raw.Length)
                : storedBuffer.AsMemory(0, encoded.StoredLength);

            var header = new byte[HeaderSize];
            WriteHeader(header, raw.Length, encoded.StoredLength);

            using var staged = FileFormatPaths.CreateStagedFile(outputPath);
            var output = staged.OpenSequentialWrite(options.BufferSize);
            await using (output.ConfigureAwait(false))
            {
                await output.WriteAsync(header.AsMemory(0, header.Length), token).ConfigureAwait(false);
                await output.WriteAsync(payload, token).ConfigureAwait(false);
            }

            staged.Commit();
            return new HashedWriteResult(FinalizeRawHashes(hasher), raw.LongLength, HeaderSize + encoded.StoredLength);
        }
        finally
        {
            if (storedBuffer.Length > 0)
            {
                ArrayPool<byte>.Shared.Return(storedBuffer);
            }
        }
    }

    private static unsafe HashedWriteResult WriteMemoryMappedFile(
        string sourcePath,
        string outputPath,
        AscfRawHashAlgorithms algorithms,
        Lz4FormatOptions options,
        CancellationToken token)
    {
        token.ThrowIfCancellationRequested();

        using var sourceStream = FileFormatStreams.OpenSequentialRead(sourcePath, options.BufferSize);
        var rawLength = checked((int)sourceStream.Length);
        var storedLength = rawLength;

        using var sourceMap = MemoryMappedFile.CreateFromFile(sourceStream, null, 0, MemoryMappedFileAccess.Read, HandleInheritability.None, leaveOpen: true);
        using var sourceView = sourceMap.CreateViewAccessor(0, rawLength, MemoryMappedFileAccess.Read);

        AscfRawHashes hashes;
        byte* sourcePointer = null;
        try
        {
            sourceView.SafeMemoryMappedViewHandle.AcquirePointer(ref sourcePointer);
            var sourceData = sourcePointer + sourceView.PointerOffset;
            using var hasher = AscfRawContentHasher.Create(algorithms);
            hasher?.AppendData(new ReadOnlySpan<byte>(sourceData, rawLength));

            token.ThrowIfCancellationRequested();

            using var staged = FileFormatPaths.CreateStagedFile(outputPath);
            using (var outputStream = staged.OpenRandomReadWrite(options.BufferSize))
            {
                outputStream.SetLength((long)HeaderSize + rawLength);

                using (var outputMap = MemoryMappedFile.CreateFromFile(outputStream, null, (long)HeaderSize + rawLength, MemoryMappedFileAccess.ReadWrite, HandleInheritability.None, leaveOpen: true))
                using (var outputView = outputMap.CreateViewAccessor(HeaderSize, rawLength, MemoryMappedFileAccess.ReadWrite))
                {
                    byte* outputPointer = null;
                    try
                    {
                        outputView.SafeMemoryMappedViewHandle.AcquirePointer(ref outputPointer);
                        var outputData = outputPointer + outputView.PointerOffset;

                        storedLength = Lz4BlockCodec.EncodeOrCopyRaw(sourceData, rawLength, outputData, rawLength).StoredLength;
                        outputView.Flush();
                    }
                    finally
                    {
                        if (outputPointer != null)
                        {
                            outputView.SafeMemoryMappedViewHandle.ReleasePointer();
                        }
                    }
                }

                token.ThrowIfCancellationRequested();

                WriteHeader(outputStream, rawLength, storedLength);
            }

            staged.Commit();
            hashes = FinalizeRawHashes(hasher);
        }
        finally
        {
            if (sourcePointer != null)
            {
                sourceView.SafeMemoryMappedViewHandle.ReleasePointer();
            }
        }

        return new HashedWriteResult(hashes, rawLength, (long)HeaderSize + storedLength);
    }

    private static Lz4BlockCodec.EncodedBlock EncodeWrappedPayload(ReadOnlySpan<byte> raw, Span<byte> compressedDestination)
    {
        if (raw.IsEmpty)
        {
            return new Lz4BlockCodec.EncodedBlock(0, 0);
        }

        if (compressedDestination.IsEmpty)
        {
            return new Lz4BlockCodec.EncodedBlock(raw.Length, raw.Length);
        }

        return Lz4BlockCodec.Encode(raw, compressedDestination);
    }

    private static void WriteHeader(FileStream outputStream, int rawLength, int storedLength)
    {
        Span<byte> header = stackalloc byte[HeaderSize];
        WriteHeader(header, rawLength, storedLength);
        outputStream.Position = 0;
        outputStream.Write(header);
        outputStream.SetLength((long)HeaderSize + storedLength);
    }

    private static AscfRawHashes FinalizeRawHashes(AscfRawContentHasher? hasher)
        => (hasher?.FinalizeHashes() ?? AscfRawHashBytes.Empty).ToPublic();

    private static FileFormatHashResult ToSha1HashResult(FileFormatRawHashResult result)
        => new(result.Hashes.RequireHash(AscfRawHashAlgorithms.Sha1), result.RawSize);

    private static FileFormatRawHashResult ToRawHashResult(AscfRawContentHasher? hasher, long rawSize)
        => new(FinalizeRawHashes(hasher), rawSize);

}
