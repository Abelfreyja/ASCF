using ASCF.Util;
using K4os.Compression.LZ4.Legacy;
using System.Buffers;
using System.Security.Cryptography;

namespace ASCF.Lz4;

public static class Lz4StreamFormat
{
    public static Task<AscfFileWriter.WriteResult> ConvertToAscfFileAsync(
        string compressedPath,
        string outputPath,
        int streamBufferSize,
        CancellationToken token)
        => ConvertToAscfFileAsync(compressedPath, outputPath, streamBufferSize, AscfWriterOptions.Default, token);

    public static Task<AscfFileWriter.WriteResult> ConvertToAscfFileAsync(
        string compressedPath,
        string outputPath,
        int streamBufferSize,
        AscfWriterOptions ascfOptions,
        CancellationToken token)
        => UseDecompressedStreamAsync(
            compressedPath,
            streamBufferSize,
            lz4Stream => AscfFileWriter.WriteStreamToFileAsync(lz4Stream, outputPath, ascfOptions, token));

    public static Task<AscfFileWriter.HashedWriteResult> ConvertToAscfFileWithHashAsync(
        string compressedPath,
        string outputPath,
        int streamBufferSize,
        AscfWriterOptions ascfOptions,
        CancellationToken token)
        => UseDecompressedStreamAsync(
            compressedPath,
            streamBufferSize,
            lz4Stream => AscfFileWriter.WriteStreamToFileWithHashAsync(lz4Stream, outputPath, ascfOptions, token));

    public static Task<long> ExtractToRawFileAsync(
        string compressedPath,
        string outputPath,
        int streamBufferSize,
        int copyBufferSize,
        CancellationToken token)
        => ExtractToRawFileAsync(compressedPath, outputPath, streamBufferSize, copyBufferSize, Lz4FormatOptions.Default, token);

    public static async Task<long> ExtractToRawFileAsync(
        string compressedPath,
        string outputPath,
        int streamBufferSize,
        int copyBufferSize,
        Lz4FormatOptions options,
        CancellationToken token)
    {
        options.Validate();
        FileFormatBuffers.ValidateBufferSize(copyBufferSize, nameof(copyBufferSize));
        using var stagedFile = FileFormatPaths.CreateStagedFile(outputPath);

        var outputStream = stagedFile.OpenSequentialWrite(streamBufferSize);
        long rawSize;
        await using (outputStream.ConfigureAwait(false))
        {
            rawSize = await UseDecompressedStreamAsync(
                    compressedPath,
                    streamBufferSize,
                    async lz4Stream =>
                    {
                        var buffer = ArrayPool<byte>.Shared.Rent(copyBufferSize);
                        try
                        {
                            long written = 0;
                            int read;
                            while ((read = await lz4Stream.ReadAsync(buffer.AsMemory(0, buffer.Length), token).ConfigureAwait(false)) > 0)
                            {
                                written = AddRawSize(written, read, options.MaxRawFileBytes);
                                await outputStream.WriteAsync(buffer.AsMemory(0, read), token).ConfigureAwait(false);
                            }

                            return written;
                        }
                        finally
                        {
                            ArrayPool<byte>.Shared.Return(buffer);
                        }
                    })
                .ConfigureAwait(false);
        }

        stagedFile.Commit();
        return rawSize;
    }

    public static Task<FileFormatHashResult> ComputeFileHashAsync(
        string compressedPath,
        int streamBufferSize,
        int copyBufferSize,
        CancellationToken token)
        => ComputeFileHashAsync(compressedPath, streamBufferSize, copyBufferSize, Lz4FormatOptions.Default, token);

    public static Task<FileFormatHashResult> ComputeFileHashAsync(
        string compressedPath,
        int streamBufferSize,
        int copyBufferSize,
        Lz4FormatOptions options,
        CancellationToken token)
    {
        options.Validate();
        FileFormatBuffers.ValidateBufferSize(copyBufferSize, nameof(copyBufferSize));
        return UseDecompressedStreamAsync(
            compressedPath,
            streamBufferSize,
            async lz4Stream =>
            {
                using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
                var buffer = ArrayPool<byte>.Shared.Rent(copyBufferSize);
                try
                {
                    long rawSize = 0;
                    int read;
                    while ((read = await lz4Stream.ReadAsync(buffer.AsMemory(0, buffer.Length), token).ConfigureAwait(false)) > 0)
                    {
                        hasher.AppendData(buffer.AsSpan(0, read));
                        rawSize = AddRawSize(rawSize, read, options.MaxRawFileBytes);
                    }

                    return new FileFormatHashResult(Convert.ToHexString(hasher.GetHashAndReset()), rawSize);
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(buffer);
                }
            });
    }

    public static FileFormatHashResult ComputeFileHash(
        string compressedPath,
        int streamBufferSize,
        int copyBufferSize)
        => ComputeFileHash(compressedPath, streamBufferSize, copyBufferSize, Lz4FormatOptions.Default);

    public static FileFormatHashResult ComputeFileHash(
        string compressedPath,
        int streamBufferSize,
        int copyBufferSize,
        Lz4FormatOptions options)
    {
        options.Validate();
        FileFormatBuffers.ValidateBufferSize(streamBufferSize, nameof(streamBufferSize));
        FileFormatBuffers.ValidateBufferSize(copyBufferSize, nameof(copyBufferSize));
        using var compressedStream = FileFormatStreams.OpenSequentialRead(compressedPath, streamBufferSize);
        using var lz4Stream = new LZ4Stream(compressedStream, LZ4StreamMode.Decompress, LZ4StreamFlags.HighCompression);
        using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
        var buffer = ArrayPool<byte>.Shared.Rent(copyBufferSize);
        try
        {
            long rawSize = 0;
            int read;
            while ((read = lz4Stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                hasher.AppendData(buffer.AsSpan(0, read));
                rawSize = AddRawSize(rawSize, read, options.MaxRawFileBytes);
            }

            return new FileFormatHashResult(Convert.ToHexString(hasher.GetHashAndReset()), rawSize);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static long AddRawSize(long rawSize, int read, long maxRawFileBytes)
    {
        var next = rawSize + read;
        if (next > maxRawFileBytes)
        {
            throw new InvalidDataException($"LZ4 stream raw size too large ({next} bytes).");
        }

        return next;
    }

    private static async Task<T> UseDecompressedStreamAsync<T>(
        string compressedPath,
        int streamBufferSize,
        Func<Stream, Task<T>> action)
    {
        FileFormatBuffers.ValidateBufferSize(streamBufferSize, nameof(streamBufferSize));

        var compressedStream = FileFormatStreams.OpenReadAsync(compressedPath, streamBufferSize);
        await using (compressedStream.ConfigureAwait(false))
        using (var lz4Stream = new LZ4Stream(compressedStream, LZ4StreamMode.Decompress, LZ4StreamFlags.HighCompression))
        {
            return await action(lz4Stream).ConfigureAwait(false);
        }
    }
}
