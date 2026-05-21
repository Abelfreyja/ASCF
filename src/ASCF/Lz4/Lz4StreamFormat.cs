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

    public static async Task<AscfFileWriter.WriteResult> ConvertToAscfFileAsync(
        string compressedPath,
        string outputPath,
        int streamBufferSize,
        AscfWriterOptions ascfOptions,
        CancellationToken token)
    {
        FileFormatBuffers.ValidateBufferSize(streamBufferSize, nameof(streamBufferSize));

        var compressedStream = new FileStream(compressedPath, FileMode.Open, FileAccess.Read, FileShare.Read, streamBufferSize, useAsync: true);
        await using (compressedStream.ConfigureAwait(false))
        using (var lz4Stream = new LZ4Stream(compressedStream, LZ4StreamMode.Decompress, LZ4StreamFlags.HighCompression))
        {
            return await AscfFileWriter.WriteStreamToFileAsync(lz4Stream, outputPath, ascfOptions, token).ConfigureAwait(false);
        }
    }

    public static Task<AscfFileWriter.HashedWriteResult> ConvertToAscfFileWithHashAsync(
        string compressedPath,
        string outputPath,
        int streamBufferSize,
        CancellationToken token)
        => ConvertToAscfFileWithHashAsync(compressedPath, outputPath, streamBufferSize, AscfWriterOptions.Default, token);

    public static async Task<AscfFileWriter.HashedWriteResult> ConvertToAscfFileWithHashAsync(
        string compressedPath,
        string outputPath,
        int streamBufferSize,
        AscfWriterOptions ascfOptions,
        CancellationToken token)
    {
        FileFormatBuffers.ValidateBufferSize(streamBufferSize, nameof(streamBufferSize));

        var compressedStream = new FileStream(compressedPath, FileMode.Open, FileAccess.Read, FileShare.Read, streamBufferSize, useAsync: true);
        await using (compressedStream.ConfigureAwait(false))
        using (var lz4Stream = new LZ4Stream(compressedStream, LZ4StreamMode.Decompress, LZ4StreamFlags.HighCompression))
        {
            return await AscfFileWriter.WriteStreamToFileWithHashAsync(lz4Stream, outputPath, ascfOptions, token).ConfigureAwait(false);
        }
    }

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
        FileFormatBuffers.ValidateBufferSize(streamBufferSize, nameof(streamBufferSize));
        FileFormatBuffers.ValidateBufferSize(copyBufferSize, nameof(copyBufferSize));
        FileFormatPaths.EnsureOutputDirectory(outputPath);

        var compressedStream = new FileStream(compressedPath, FileMode.Open, FileAccess.Read, FileShare.Read, streamBufferSize, useAsync: true);
        var outputStream = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None, streamBufferSize, useAsync: true);
        await using (compressedStream.ConfigureAwait(false))
        await using (outputStream.ConfigureAwait(false))
        using (var lz4Stream = new LZ4Stream(compressedStream, LZ4StreamMode.Decompress, LZ4StreamFlags.HighCompression))
        {
            var buffer = ArrayPool<byte>.Shared.Rent(copyBufferSize);
            try
            {
                long rawSize = 0;
                int read;
                while ((read = await lz4Stream.ReadAsync(buffer.AsMemory(0, buffer.Length), token).ConfigureAwait(false)) > 0)
                {
                    rawSize = AddRawSize(rawSize, read, options.MaxRawFileBytes);
                    await outputStream.WriteAsync(buffer.AsMemory(0, read), token).ConfigureAwait(false);
                }

                await outputStream.FlushAsync(token).ConfigureAwait(false);
                return rawSize;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }
    }

    public static Task<FileFormatHashResult> ComputeFileHashAsync(
        string compressedPath,
        int streamBufferSize,
        int copyBufferSize,
        CancellationToken token)
        => ComputeFileHashAsync(compressedPath, streamBufferSize, copyBufferSize, Lz4FormatOptions.Default, token);

    public static async Task<FileFormatHashResult> ComputeFileHashAsync(
        string compressedPath,
        int streamBufferSize,
        int copyBufferSize,
        Lz4FormatOptions options,
        CancellationToken token)
    {
        options.Validate();
        FileFormatBuffers.ValidateBufferSize(streamBufferSize, nameof(streamBufferSize));
        FileFormatBuffers.ValidateBufferSize(copyBufferSize, nameof(copyBufferSize));
        var compressedStream = new FileStream(compressedPath, FileMode.Open, FileAccess.Read, FileShare.Read, streamBufferSize, useAsync: true);
        await using (compressedStream.ConfigureAwait(false))
        using (var lz4Stream = new LZ4Stream(compressedStream, LZ4StreamMode.Decompress, LZ4StreamFlags.HighCompression))
        using (var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA1))
        {
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
        }
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
        using var compressedStream = new FileStream(compressedPath, FileMode.Open, FileAccess.Read, FileShare.Read, streamBufferSize, FileOptions.SequentialScan);
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
}
