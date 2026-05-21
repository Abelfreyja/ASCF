using System.Buffers;
using System.Security.Cryptography;

namespace ASCF.Util;

internal static class FileFormatHashing
{
    public static async Task AppendExactlyAsync(
        Stream input,
        IncrementalHash hasher,
        int byteCount,
        int bufferSize,
        CancellationToken token)
    {
        FileFormatBuffers.ValidateBufferSize(bufferSize, nameof(bufferSize));

        var buffer = ArrayPool<byte>.Shared.Rent(bufferSize);
        try
        {
            var remaining = byteCount;
            while (remaining > 0)
            {
                var read = await input.ReadAsync(buffer.AsMemory(0, Math.Min(buffer.Length, remaining)), token).ConfigureAwait(false);
                if (read == 0)
                {
                    throw new EndOfStreamException();
                }

                hasher.AppendData(buffer.AsSpan(0, read));
                remaining -= read;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    public static void AppendExactly(
        Stream input,
        IncrementalHash hasher,
        int byteCount,
        int bufferSize)
    {
        FileFormatBuffers.ValidateBufferSize(bufferSize, nameof(bufferSize));

        var buffer = ArrayPool<byte>.Shared.Rent(bufferSize);
        try
        {
            var remaining = byteCount;
            while (remaining > 0)
            {
                var read = input.Read(buffer, 0, Math.Min(buffer.Length, remaining));
                if (read == 0)
                {
                    throw new EndOfStreamException();
                }

                hasher.AppendData(buffer.AsSpan(0, read));
                remaining -= read;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }
}
