using ASCF.Lz4;
using ASCF.Util;
using System.Buffers;

namespace ASCF.Files;

public enum EncodedFileFormat
{
    Unknown,
    WrappedLz4,
    Ascf
}

public static class EncodedFileFormatIdentifier
{
    private static readonly int HeaderBufferSize = Math.Max(AscfFileFormat.HeaderSize, WrappedLz4FileFormat.HeaderSize);

    public static EncodedFileFormat Identify(FileInfo file)
        => Identify(file, EncodedFileFormatIdentificationOptions.Default);

    public static EncodedFileFormat Identify(FileInfo file, EncodedFileFormatIdentificationOptions options)
    {
        options.Validate();
        file.Refresh();
        if (!file.Exists || file.Length <= 0)
        {
            return EncodedFileFormat.Unknown;
        }

        return Identify(file.FullName, file.Length, options);
    }

    public static EncodedFileFormat Identify(string path)
        => Identify(new FileInfo(path), EncodedFileFormatIdentificationOptions.Default);

    public static EncodedFileFormat Identify(string path, EncodedFileFormatIdentificationOptions options)
        => Identify(new FileInfo(path), options);

    public static EncodedFileFormat Identify(string path, long length)
        => Identify(path, length, EncodedFileFormatIdentificationOptions.Default);

    public static EncodedFileFormat Identify(string path, long length, EncodedFileFormatIdentificationOptions options)
    {
        options.Validate();
        if (length <= 0)
        {
            return EncodedFileFormat.Unknown;
        }

        Span<byte> header = stackalloc byte[HeaderBufferSize];
        var bytesToRead = (int)Math.Min(header.Length, length);
        int read;
        try
        {
            using var input = FileFormatStreams.OpenSequentialRead(path, HeaderBufferSize, FileShare.ReadWrite | FileShare.Delete);

            read = FileFormatStreamReader.ReadUpTo(input, header[..bytesToRead]);
        }
        catch (FileNotFoundException)
        {
            return EncodedFileFormat.Unknown;
        }
        catch (DirectoryNotFoundException)
        {
            return EncodedFileFormat.Unknown;
        }

        return IdentifyHeader(header[..read], length, options);
    }

    public static Task<EncodedFileFormat> IdentifyAsync(
        Stream stream,
        long length,
        CancellationToken token)
        => IdentifyAsync(stream, length, transform: null, EncodedFileFormatIdentificationOptions.Default, token);

    public static Task<EncodedFileFormat> IdentifyAsync(
        Stream stream,
        long length,
        AscfBufferTransform? transform,
        EncodedFileFormatIdentificationOptions options,
        CancellationToken token)
    {
        if (!stream.CanSeek)
        {
            throw new InvalidOperationException("Encoded stream must be seekable.");
        }

        return IdentifySeekableStreamAsync(stream, length, transform, options, token);
    }

    private static async Task<EncodedFileFormat> IdentifySeekableStreamAsync(
        Stream stream,
        long length,
        AscfBufferTransform? transform,
        EncodedFileFormatIdentificationOptions options,
        CancellationToken token)
    {
        options.Validate();
        if (length <= 0)
        {
            return EncodedFileFormat.Unknown;
        }

        var startPosition = stream.Position;
        var headerLength = checked((int)Math.Min(HeaderBufferSize, length));
        var header = ArrayPool<byte>.Shared.Rent(headerLength);
        try
        {
            await stream.ReadExactlyAsync(header.AsMemory(0, headerLength), token).ConfigureAwait(false);
            transform?.Invoke(header.AsSpan(0, headerLength));
            return IdentifyHeader(header.AsSpan(0, headerLength), length, options);
        }
        catch (EndOfStreamException)
        {
            return EncodedFileFormat.Unknown;
        }
        finally
        {
            stream.Position = startPosition;
            ArrayPool<byte>.Shared.Return(header);
        }
    }

    private static EncodedFileFormat IdentifyHeader(
        ReadOnlySpan<byte> header,
        long length,
        EncodedFileFormatIdentificationOptions options)
    {
        if (header.Length >= AscfFileFormat.HeaderSize
            && AscfFileReader.LooksLikeAscf(header[..AscfFileFormat.HeaderSize], options.AscfReader))
        {
            return EncodedFileFormat.Ascf;
        }

        if (header.Length >= WrappedLz4FileFormat.HeaderSize
            && WrappedLz4FileFormat.TryReadHeader(length, header[..WrappedLz4FileFormat.HeaderSize], options.Lz4).HasValue)
        {
            return EncodedFileFormat.WrappedLz4;
        }

        return EncodedFileFormat.Unknown;
    }
}
