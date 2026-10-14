using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace ASCF.Lz4;

internal static unsafe partial class NativeLz4
{
    private const string _library = "ascf_lz4_v1_10_0.dll";

    static NativeLz4()
    {
        if (GetVersion() != 11000)
        {
            throw new InvalidOperationException("The bundled ASCF LZ4 library must be version 1.10.0.");
        }
    }

    internal static int EncodeHigh(ReadOnlySpan<byte> raw, Span<byte> destination)
    {
        fixed (byte* source = raw)
        fixed (byte* output = destination)
        {
            return EncodeHigh(source, output, raw.Length, destination.Length, 8);
        }
    }

    internal static int EncodeFast(ReadOnlySpan<byte> raw, Span<byte> destination)
    {
        fixed (byte* source = raw)
        fixed (byte* output = destination)
        {
            return EncodeFast(source, output, raw.Length, destination.Length);
        }
    }

    internal static int Decode(ReadOnlySpan<byte> stored, Span<byte> raw)
    {
        fixed (byte* source = stored)
        fixed (byte* output = raw)
        {
            return Decode(source, output, stored.Length, raw.Length);
        }
    }

    [LibraryImport(_library, EntryPoint = "LZ4_versionNumber")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
    private static partial int GetVersion();

    [LibraryImport(_library, EntryPoint = "LZ4_compress_HC")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
    private static partial int EncodeHigh(byte* source, byte* destination, int sourceLength, int destinationLength, int level);

    [LibraryImport(_library, EntryPoint = "LZ4_compress_default")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
    private static partial int EncodeFast(byte* source, byte* destination, int sourceLength, int destinationLength);

    [LibraryImport(_library, EntryPoint = "LZ4_decompress_safe")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
    private static partial int Decode(byte* source, byte* destination, int sourceLength, int destinationLength);
}
