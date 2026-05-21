using System.Buffers;
using ASCF.Lz4;

namespace ASCF;

internal static class AscfChunkCompressor
{
    public static async Task<Task<EncodedChunk>> StartAsync(
        byte[] rawBuffer,
        int rawLength,
        int maxCompressedSize,
        SemaphoreSlim workerSlots,
        CancellationToken token)
    {
        await workerSlots.WaitAsync(token).ConfigureAwait(false);

        try
        {
            // worker must run after slot acquisition so pooled buffers are returned
            return Task.Run(() =>
            {
                try
                {
                    return Encode(rawBuffer, rawLength, maxCompressedSize);
                }
                finally
                {
                    workerSlots.Release();
                }
            });
        }
        catch
        {
            workerSlots.Release();
            throw;
        }
    }

    public static EncodedChunk Encode(byte[] rawBuffer, int rawLength, int maxCompressedSize)
    {
        var compressedBuffer = ArrayPool<byte>.Shared.Rent(maxCompressedSize);
        try
        {
            var raw = rawBuffer.AsSpan(0, rawLength);
            var rawChecksum = AscfChecksum.ComputeXxHash3(raw);
            var encoded = Lz4BlockCodec.EncodeWithFastCheck(raw, compressedBuffer.AsSpan(0, maxCompressedSize));
            if (encoded.StoresRaw)
            {
                ArrayPool<byte>.Shared.Return(compressedBuffer);
                return new EncodedChunk(
                    rawLength,
                    rawLength,
                    AscfFileFormat.MethodRaw,
                    rawChecksum,
                    rawChecksum,
                    rawBuffer);
            }

            var storedChecksum = AscfChecksum.ComputeXxHash3(compressedBuffer.AsSpan(0, encoded.StoredLength));
            ArrayPool<byte>.Shared.Return(rawBuffer);
            return new EncodedChunk(
                rawLength,
                encoded.StoredLength,
                AscfFileFormat.MethodLz4HighCompression,
                rawChecksum,
                storedChecksum,
                compressedBuffer);
        }
        catch
        {
            ArrayPool<byte>.Shared.Return(compressedBuffer);
            ArrayPool<byte>.Shared.Return(rawBuffer);
            throw;
        }
    }

    public sealed class EncodedChunk : IDisposable
    {
        private byte[] _payloadBuffer;

        public EncodedChunk(
            int rawLength,
            int storedLength,
            int method,
            ulong rawChecksum,
            ulong storedChecksum,
            byte[] payloadBuffer)
        {
            RawLength = rawLength;
            StoredLength = storedLength;
            Method = method;
            RawChecksum = rawChecksum;
            StoredChecksum = storedChecksum;
            _payloadBuffer = payloadBuffer;
        }

        public int RawLength { get; }
        public int StoredLength { get; }
        public int Method { get; }
        public ulong RawChecksum { get; }
        public ulong StoredChecksum { get; }
        public ReadOnlyMemory<byte> Payload => _payloadBuffer.AsMemory(0, StoredLength);

        public void Dispose()
        {
            if (_payloadBuffer.Length == 0)
            {
                return;
            }

            ArrayPool<byte>.Shared.Return(_payloadBuffer);
            _payloadBuffer = Array.Empty<byte>();
        }
    }
}
