using System.Buffers;

namespace ASCF.Util;

internal sealed class PooledBufferOwner : IDisposable
{
    private readonly int _offset;
    private byte[] _buffer;

    public PooledBufferOwner(byte[] buffer, int length, int offset = 0)
    {
        if (offset < 0 || length < 0 || offset > buffer.Length - length)
        {
            throw new ArgumentOutOfRangeException(nameof(length), length, "Pooled buffer range is invalid.");
        }

        _buffer = buffer;
        _offset = offset;
        Length = length;
    }

    public int Length { get; }
    public ReadOnlyMemory<byte> ReadOnlyMemory => _buffer.AsMemory(_offset, Length);

    public byte[] TakeBuffer()
    {
        if (_offset != 0)
        {
            throw new InvalidOperationException("Cannot take an offset pooled buffer.");
        }

        var ownedBuffer = _buffer;
        _buffer = [];
        return ownedBuffer;
    }

    public void Dispose()
    {
        if (_buffer.Length == 0)
        {
            return;
        }

        ArrayPool<byte>.Shared.Return(_buffer);
        _buffer = [];
    }
}
