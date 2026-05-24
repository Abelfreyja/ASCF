namespace ASCF.Util;

internal static class FileFormatStreams
{
    public static FileStream OpenReadAsync(string path, int bufferSize, FileShare share = FileShare.Read)
        => OpenRead(path, bufferSize, FileOptions.Asynchronous, share);

    public static FileStream OpenSequentialRead(string path, int bufferSize, FileShare share = FileShare.Read)
        => OpenRead(path, bufferSize, FileOptions.SequentialScan, share);

    public static FileStream OpenSequentialReadAsync(string path, int bufferSize, FileShare share = FileShare.Read)
        => OpenRead(path, bufferSize, FileOptions.Asynchronous | FileOptions.SequentialScan, share);

    public static FileStream OpenRandomReadAsync(string path, int bufferSize, FileShare share = FileShare.Read)
        => OpenRead(path, bufferSize, FileOptions.Asynchronous | FileOptions.RandomAccess, share);

    private static FileStream OpenRead(string path, int bufferSize, FileOptions options, FileShare share)
    {
        FileFormatBuffers.ValidateBufferSize(bufferSize, nameof(bufferSize));
        return new FileStream(
            path,
            new FileStreamOptions
            {
                Mode = FileMode.Open,
                Access = FileAccess.Read,
                Share = share,
                BufferSize = bufferSize,
                Options = options
            });
    }
}
