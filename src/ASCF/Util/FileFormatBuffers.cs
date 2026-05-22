namespace ASCF.Util;

public static class FileFormatBuffers
{
    public const int DefaultBufferSize = AscfFileFormat.DefaultBufferSize;
    internal const int IndexEntriesPerPage = 1024;
    internal const int IndexDirectReadThreshold = 512;

    internal static void ValidateBufferSize(int bufferSize, string parameterName)
    {
        if (bufferSize <= 0)
        {
            throw new ArgumentOutOfRangeException(parameterName, bufferSize, "Buffer size must be positive.");
        }
    }
}
