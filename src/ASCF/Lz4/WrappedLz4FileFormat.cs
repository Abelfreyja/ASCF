using System.Buffers;
using System.Buffers.Binary;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using ASCF.Util;

namespace ASCF.Lz4;

public static class WrappedLz4FileFormat
{
    public const int HeaderSize = 8;

    [StructLayout(LayoutKind.Auto)]
    public readonly record struct WriteResult(long OriginalSize, long CompressedSize);

    [StructLayout(LayoutKind.Auto)]
    public readonly record struct Header(int OutputLength, int InputLength);

    public static Task<WriteResult> WriteFromRawFileAsync(string sourcePath, string outputPath, CancellationToken token)
        => WriteFromRawFileAsync(sourcePath, outputPath, Lz4FormatOptions.Default, token);

    public static async Task<WriteResult> WriteFromRawFileAsync(string sourcePath, string outputPath, Lz4FormatOptions options, CancellationToken token)
    {
        options.Validate();
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
            ? await WriteSmallFileAsync(sourcePath, outputPath, options, token).ConfigureAwait(false)
            : WriteMemoryMappedFile(sourcePath, outputPath, options, token);
    }

    public static Task<long> ExtractToRawFileAsync(string wrappedPath, string outputPath, CancellationToken token)
        => ExtractToRawFileAsync(wrappedPath, outputPath, Lz4FormatOptions.Default, token);

    public static async Task<long> ExtractToRawFileAsync(string wrappedPath, string outputPath, Lz4FormatOptions options, CancellationToken token)
    {
        options.Validate();
        var input = new FileStream(wrappedPath, FileMode.Open, FileAccess.Read, FileShare.Read, options.BufferSize, useAsync: true);
        await using (input.ConfigureAwait(false))
        {
            var header = new byte[HeaderSize];
            await input.ReadExactlyAsync(header.AsMemory(0, header.Length), token).ConfigureAwait(false);

            var outputLength = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(0, 4));
            var inputLength = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(4, 4));
            ValidateHeader(input.Length, outputLength, inputLength, options.MaxRawFileBytes);

            FileFormatPaths.EnsureOutputDirectory(outputPath);
            if (outputLength == 0)
            {
                await CreateEmptyFileAsync(outputPath, token).ConfigureAwait(false);
                return 0;
            }

            if (inputLength == outputLength)
            {
                await CopyStoredRawPayloadAsync(input, outputPath, inputLength, options, token).ConfigureAwait(false);
                return outputLength;
            }

            await DecodeCompressedPayloadToRawFileAsync(wrappedPath, outputPath, inputLength, outputLength, token).ConfigureAwait(false);
            return outputLength;
        }
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

        var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize, useAsync: true);
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

        using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize, FileOptions.SequentialScan);
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
        FileFormatBuffers.ValidateBufferSize(streamBufferSize, nameof(streamBufferSize));
        FileFormatBuffers.ValidateBufferSize(copyBufferSize, nameof(copyBufferSize));

        var input = new FileStream(wrappedPath, FileMode.Open, FileAccess.Read, FileShare.Read, streamBufferSize, useAsync: true);
        await using (input.ConfigureAwait(false))
        {
            input.Position = HeaderSize;
            using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
            if (header.OutputLength == 0)
            {
                return new FileFormatHashResult(Convert.ToHexString(hasher.GetHashAndReset()), 0);
            }

            if (Lz4BlockCodec.IsStoredRaw(header.OutputLength, header.InputLength))
            {
                await FileFormatHashing.AppendExactlyAsync(input, hasher, header.InputLength, copyBufferSize, token).ConfigureAwait(false);
                return new FileFormatHashResult(Convert.ToHexString(hasher.GetHashAndReset()), header.OutputLength);
            }

            var compressed = new byte[header.InputLength];
            await input.ReadExactlyAsync(compressed.AsMemory(0, compressed.Length), token).ConfigureAwait(false);
            var raw = new byte[header.OutputLength];
            Lz4BlockCodec.Decode(compressed.AsSpan(0, header.InputLength), raw, header.OutputLength);

            hasher.AppendData(raw);
            return new FileFormatHashResult(Convert.ToHexString(hasher.GetHashAndReset()), header.OutputLength);
        }
    }

    public static FileFormatHashResult ComputeFileHash(
        string wrappedPath,
        Header header,
        int streamBufferSize,
        int copyBufferSize)
    {
        FileFormatBuffers.ValidateBufferSize(streamBufferSize, nameof(streamBufferSize));
        FileFormatBuffers.ValidateBufferSize(copyBufferSize, nameof(copyBufferSize));

        using var input = new FileStream(wrappedPath, FileMode.Open, FileAccess.Read, FileShare.Read, streamBufferSize, FileOptions.SequentialScan);
        input.Position = HeaderSize;

        using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
        if (header.OutputLength == 0)
        {
            return new FileFormatHashResult(Convert.ToHexString(hasher.GetHashAndReset()), 0);
        }

        if (Lz4BlockCodec.IsStoredRaw(header.OutputLength, header.InputLength))
        {
            FileFormatHashing.AppendExactly(input, hasher, header.InputLength, copyBufferSize);
            return new FileFormatHashResult(Convert.ToHexString(hasher.GetHashAndReset()), header.OutputLength);
        }

        var compressed = new byte[header.InputLength];
        input.ReadExactly(compressed);
        var raw = new byte[header.OutputLength];
        Lz4BlockCodec.Decode(compressed.AsSpan(0, header.InputLength), raw, header.OutputLength);

        hasher.AppendData(raw);
        return new FileFormatHashResult(Convert.ToHexString(hasher.GetHashAndReset()), header.OutputLength);
    }

    private static async Task CreateEmptyFileAsync(string outputPath, CancellationToken token)
    {
        var emptyStream = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None, 4096, useAsync: true);
        await using (emptyStream.ConfigureAwait(false))
        {
            await emptyStream.FlushAsync(token).ConfigureAwait(false);
        }
    }

    private static async Task CopyStoredRawPayloadAsync(Stream input, string outputPath, int inputLength, Lz4FormatOptions options, CancellationToken token)
    {
        var outputStream = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None, options.BufferSize, useAsync: true);
        await using (outputStream.ConfigureAwait(false))
        {
            await FileFormatStreamReader.CopyExactlyAsync(input, outputStream, inputLength, options.CopyBufferSize, token).ConfigureAwait(false);
            await outputStream.FlushAsync(token).ConfigureAwait(false);
        }
    }

    private static async Task DecodeCompressedPayloadToRawFileAsync(string wrappedPath, string outputPath, int inputLength, int outputLength, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();

        var mappedOutputStream = new FileStream(outputPath, FileMode.Create, FileAccess.ReadWrite, FileShare.None, 4096, FileOptions.SequentialScan);
        await using (mappedOutputStream.ConfigureAwait(false))
        {
            mappedOutputStream.SetLength(outputLength);

            using var inputMap = MemoryMappedFile.CreateFromFile(wrappedPath, FileMode.Open, null, 0, MemoryMappedFileAccess.Read);
            using var inputView = inputMap.CreateViewAccessor(HeaderSize, inputLength, MemoryMappedFileAccess.Read);
            using var outputMap = MemoryMappedFile.CreateFromFile(mappedOutputStream, null, outputLength, MemoryMappedFileAccess.ReadWrite, HandleInheritability.None, leaveOpen: true);
            using var outputView = outputMap.CreateViewAccessor(0, outputLength, MemoryMappedFileAccess.Write);

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

    private static async Task<WriteResult> WriteSmallFileAsync(string sourcePath, string outputPath, Lz4FormatOptions options, CancellationToken token)
    {
        var raw = await File.ReadAllBytesAsync(sourcePath, token).ConfigureAwait(false);
        var maxStoredLength = raw.Length == 0 ? 0 : Math.Max(raw.Length, Lz4BlockCodec.MaxCompressedLength(raw.Length));
        var storedBuffer = maxStoredLength == 0 ? Array.Empty<byte>() : ArrayPool<byte>.Shared.Rent(maxStoredLength);
        try
        {
            var encoded = raw.Length == 0
                ? new Lz4BlockCodec.EncodedBlock(0, 0)
                : Lz4BlockCodec.Encode(raw, storedBuffer.AsSpan(0, maxStoredLength));
            var payload = encoded.StoresRaw
                ? raw.AsMemory(0, raw.Length)
                : storedBuffer.AsMemory(0, encoded.StoredLength);

            var header = new byte[HeaderSize];
            WriteHeader(header, raw.Length, encoded.StoredLength);

            var output = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None, options.BufferSize, useAsync: true);
            await using (output.ConfigureAwait(false))
            {
                await output.WriteAsync(header.AsMemory(0, header.Length), token).ConfigureAwait(false);
                await output.WriteAsync(payload, token).ConfigureAwait(false);
                await output.FlushAsync(token).ConfigureAwait(false);
            }

            return new WriteResult(raw.LongLength, HeaderSize + encoded.StoredLength);
        }
        finally
        {
            if (storedBuffer.Length > 0)
            {
                ArrayPool<byte>.Shared.Return(storedBuffer);
            }
        }
    }

    private static unsafe WriteResult WriteMemoryMappedFile(string sourcePath, string outputPath, Lz4FormatOptions options, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();

        using var sourceStream = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.Read, options.BufferSize, FileOptions.SequentialScan);
        var rawLength = checked((int)sourceStream.Length);
        var storedLength = rawLength;

        using var sourceMap = MemoryMappedFile.CreateFromFile(sourceStream, null, 0, MemoryMappedFileAccess.Read, HandleInheritability.None, leaveOpen: true);
        using var sourceView = sourceMap.CreateViewAccessor(0, rawLength, MemoryMappedFileAccess.Read);

        byte* sourcePointer = null;
        try
        {
            sourceView.SafeMemoryMappedViewHandle.AcquirePointer(ref sourcePointer);
            var sourceData = sourcePointer + sourceView.PointerOffset;

            token.ThrowIfCancellationRequested();

            using var outputStream = new FileStream(outputPath, FileMode.Create, FileAccess.ReadWrite, FileShare.None, options.BufferSize, FileOptions.SequentialScan);
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
        finally
        {
            if (sourcePointer != null)
            {
                sourceView.SafeMemoryMappedViewHandle.ReleasePointer();
            }
        }

        return new WriteResult(rawLength, (long)HeaderSize + storedLength);
    }

    private static void WriteHeader(FileStream outputStream, int rawLength, int storedLength)
    {
        Span<byte> header = stackalloc byte[HeaderSize];
        WriteHeader(header, rawLength, storedLength);
        outputStream.Position = 0;
        outputStream.Write(header);
        outputStream.SetLength((long)HeaderSize + storedLength);
        outputStream.Flush(flushToDisk: false);
    }

    private static void ValidateHeader(long fileLength, int outputLength, int inputLength, long maxRawFileBytes)
    {
        if (outputLength < 0 || inputLength < 0)
        {
            throw new InvalidDataException("LZ4 header contained a negative length.");
        }

        if (outputLength > maxRawFileBytes)
        {
            throw new InvalidDataException($"Wrapped LZ4 output length too large ({outputLength} bytes).");
        }

        var remainingLength = fileLength - HeaderSize;
        if (inputLength != remainingLength)
        {
            throw new InvalidDataException("LZ4 header length does not match file size.");
        }

        if ((outputLength == 0 && inputLength != 0) || inputLength > outputLength)
        {
            throw new InvalidDataException("LZ4 header is invalid.");
        }
    }

}
