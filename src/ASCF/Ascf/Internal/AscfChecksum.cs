using System.Buffers.Binary;
using System.IO.Hashing;

namespace ASCF;

internal static class AscfChecksum
{
    public static ulong ComputeXxHash3(ReadOnlySpan<byte> data)
        => XxHash3.HashToUInt64(data);

    public static ulong ComputeXxHash3WithZeroedField(Span<byte> data, int fieldOffset)
    {
        BinaryPrimitives.WriteUInt64LittleEndian(data[fieldOffset..], 0);
        return ComputeXxHash3(data);
    }
}
