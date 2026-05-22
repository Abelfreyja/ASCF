using System.Buffers;
using ASCF.Lz4;
using ASCF.Util;

namespace ASCF;

internal static class AscfChunkCompressor
{
    public static EncodedChunk Encode(byte[] rawBuffer, int rawLength, int maxCompressedSize)
    {
        byte[]? rawBufferOwner = rawBuffer;
        byte[]? compressedBuffer = ArrayPool<byte>.Shared.Rent(maxCompressedSize);
        try
        {
            var raw = rawBufferOwner!.AsSpan(0, rawLength);
            var rawChecksum = AscfChecksum.ComputeXxHash3(raw);
            var encoded = Lz4BlockCodec.EncodeWithFastCheck(raw, compressedBuffer.AsSpan(0, maxCompressedSize));
            if (encoded.StoresRaw)
            {
                ArrayPool<byte>.Shared.Return(compressedBuffer);
                compressedBuffer = null;

                var payload = new PooledBufferOwner(rawBufferOwner, rawLength);
                rawBufferOwner = null;
                return new EncodedChunk(
                    rawLength,
                    rawLength,
                    AscfFileFormat.MethodRaw,
                    rawChecksum,
                    rawChecksum,
                    payload);
            }

            var storedChecksum = AscfChecksum.ComputeXxHash3(compressedBuffer.AsSpan(0, encoded.StoredLength));
            ArrayPool<byte>.Shared.Return(rawBufferOwner);
            rawBufferOwner = null;

            var storedPayload = new PooledBufferOwner(compressedBuffer, encoded.StoredLength);
            compressedBuffer = null;
            return new EncodedChunk(
                rawLength,
                encoded.StoredLength,
                AscfFileFormat.MethodLz4HighCompression,
                rawChecksum,
                storedChecksum,
                storedPayload);
        }
        finally
        {
            if (compressedBuffer != null)
            {
                ArrayPool<byte>.Shared.Return(compressedBuffer);
            }

            if (rawBufferOwner != null)
            {
                ArrayPool<byte>.Shared.Return(rawBufferOwner);
            }
        }
    }

    public sealed class EncodedChunk : IDisposable
    {
        private readonly PooledBufferOwner _payload;

        public EncodedChunk(
            int rawLength,
            int storedLength,
            int method,
            ulong rawChecksum,
            ulong storedChecksum,
            PooledBufferOwner payload)
        {
            RawLength = rawLength;
            StoredLength = storedLength;
            Method = method;
            RawChecksum = rawChecksum;
            StoredChecksum = storedChecksum;
            _payload = payload;
        }

        public int RawLength { get; }
        public int StoredLength { get; }
        public int Method { get; }
        public ulong RawChecksum { get; }
        public ulong StoredChecksum { get; }
        public ReadOnlyMemory<byte> Payload => _payload.ReadOnlyMemory;

        public void Dispose()
            => _payload.Dispose();
    }
}
