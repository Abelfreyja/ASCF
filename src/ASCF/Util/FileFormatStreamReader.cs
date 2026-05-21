using System.Buffers;

namespace ASCF.Util;

internal static class FileFormatStreamReader
{
    public static async Task ReadExactlyAsync(Stream stream, Memory<byte> buffer, CancellationToken token)
    {
        var read = await ReadUpToAsync(stream, buffer, token).ConfigureAwait(false);
        if (read != buffer.Length)
        {
            throw new EndOfStreamException();
        }
    }

    public static void ReadExactly(Stream stream, Span<byte> buffer)
    {
        var read = ReadUpTo(stream, buffer);
        if (read != buffer.Length)
        {
            throw new EndOfStreamException();
        }
    }

    public static async Task<byte[]> ReadExactlyToArrayAsync(Stream stream, int length, CancellationToken token)
    {
        var buffer = new byte[length];
        await ReadExactlyAsync(stream, buffer.AsMemory(0, length), token).ConfigureAwait(false);
        return buffer;
    }

    public static byte[] ReadExactlyToArray(Stream stream, int length)
    {
        var buffer = new byte[length];
        ReadExactly(stream, buffer);
        return buffer;
    }

    public static async Task<int> ReadUpToAsync(Stream stream, Memory<byte> buffer, CancellationToken token)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.Slice(offset), token).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            offset += read;
        }

        return offset;
    }

    public static int ReadUpTo(Stream stream, Span<byte> buffer)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = stream.Read(buffer[offset..]);
            if (read == 0)
            {
                break;
            }

            offset += read;
        }

        return offset;
    }

    public static async Task CopyExactlyAsync(Stream source, Stream destination, long bytesToCopy, int bufferSize, CancellationToken token)
    {
        if (bytesToCopy <= 0)
        {
            return;
        }

        FileFormatBuffers.ValidateBufferSize(bufferSize, nameof(bufferSize));

        var buffer = ArrayPool<byte>.Shared.Rent(bufferSize);
        try
        {
            await CopyExactlyAsync(source, destination, bytesToCopy, buffer, token).ConfigureAwait(false);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    public static async Task CopyExactlyAsync(Stream source, Stream destination, long bytesToCopy, byte[] buffer, CancellationToken token)
    {
        if (bytesToCopy <= 0)
        {
            return;
        }

        if (buffer.Length == 0)
        {
            throw new ArgumentException("Copy buffer must not be empty.", nameof(buffer));
        }

        var remaining = bytesToCopy;
        while (remaining > 0)
        {
            var read = await source.ReadAsync(buffer.AsMemory(0, (int)Math.Min(buffer.Length, remaining)), token).ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException();
            }

            await destination.WriteAsync(buffer.AsMemory(0, read), token).ConfigureAwait(false);
            remaining -= read;
        }
    }
}
