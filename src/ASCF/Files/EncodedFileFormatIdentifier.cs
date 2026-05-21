using ASCF.Lz4;
using ASCF.Util;

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
            using var input = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                bufferSize: HeaderBufferSize,
                FileOptions.SequentialScan);

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

        if (read >= AscfFileFormat.HeaderSize
            && AscfFileReader.LooksLikeAscf(header[..AscfFileFormat.HeaderSize], options.AscfReader))
        {
            return EncodedFileFormat.Ascf;
        }

        if (read >= WrappedLz4FileFormat.HeaderSize
            && WrappedLz4FileFormat.TryReadHeader(length, header[..WrappedLz4FileFormat.HeaderSize], options.Lz4).HasValue)
        {
            return EncodedFileFormat.WrappedLz4;
        }

        return EncodedFileFormat.Unknown;
    }
}
