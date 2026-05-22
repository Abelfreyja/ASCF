namespace ASCF.Util;

internal static class FileFormatWorkerCounts
{
    public static int Resolve(int workerCount, int maxWorkerCount, string workerParameterName, string maxParameterName)
    {
        if (maxWorkerCount <= 0)
        {
            throw new ArgumentOutOfRangeException(maxParameterName, maxWorkerCount, "Maximum worker count must be positive.");
        }

        if (workerCount < AscfFileFormat.AutoWorkerCount)
        {
            throw new ArgumentOutOfRangeException(
                workerParameterName,
                workerCount,
                $"Worker count must be {AscfFileFormat.AutoWorkerCount} for auto, or at least 1.");
        }

        var resolved = workerCount == AscfFileFormat.AutoWorkerCount
            ? AscfFileFormat.GetDefaultWorkerCount(maxWorkerCount)
            : workerCount;
        if (resolved > maxWorkerCount)
        {
            throw new ArgumentOutOfRangeException(
                workerParameterName,
                workerCount,
                $"Worker count must be {AscfFileFormat.AutoWorkerCount} for auto, or between 1 and {maxWorkerCount}.");
        }

        return resolved;
    }

    public static int ResolveByteWindow(
        long bytesPerItem,
        long maxBytes,
        int minItemCount,
        long maxItemCount,
        string maxBytesParameterName)
    {
        if (bytesPerItem <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(bytesPerItem), bytesPerItem, "Pipeline item size must be positive.");
        }

        if (maxBytes <= 0)
        {
            throw new ArgumentOutOfRangeException(maxBytesParameterName, maxBytes, "Pipeline byte limit must be positive.");
        }

        if (minItemCount <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(minItemCount), minItemCount, "Minimum item count must be positive.");
        }

        if (maxItemCount < minItemCount)
        {
            throw new ArgumentOutOfRangeException(nameof(maxItemCount), maxItemCount, "Maximum item count must be at least the minimum item count.");
        }

        var maxByBytes = maxBytes / bytesPerItem;
        if (maxByBytes < minItemCount)
        {
            var minimumBytes = checked(bytesPerItem * minItemCount);
            throw new ArgumentOutOfRangeException(
                maxBytesParameterName,
                maxBytes,
                $"Pipeline byte limit must allow at least {minItemCount} items ({minimumBytes} bytes).");
        }

        return checked((int)Math.Min(maxItemCount, maxByBytes));
    }
}
