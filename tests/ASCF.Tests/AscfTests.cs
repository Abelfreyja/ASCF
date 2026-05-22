using ASCF.Files;
using ASCF.Lz4;
using ASCF.Transcoding;
using System.Buffers.Binary;
using System.IO.Hashing;
using System.Security.Cryptography;

namespace ASCF.Tests;

public sealed class AscfTests : IDisposable
{
    private readonly string _testDirectory = Path.Combine(Path.GetTempPath(), $"ascf-tests-{Guid.NewGuid():N}");

    public AscfTests()
    {
        Directory.CreateDirectory(_testDirectory);
    }

    [Fact]
    public async Task WriteFilePreservesRawBytes()
    {
        var raw = CreateMixedPayload(2 * 1024 * 1024 + 173);
        var sourcePath = WriteSource(raw);
        var ascfPath = Path.Combine(_testDirectory, "payload.ascf");
        var decodedPath = Path.Combine(_testDirectory, "decoded.bin");

        var storedSize = await AscfFileWriter.WriteFileAsync(sourcePath, ascfPath, CancellationToken.None);
        var hash = AscfFileReader.ComputeFileHash(ascfPath);
        var decodedSize = await AscfFileReader.DecodeFileToFileAsync(ascfPath, decodedPath, CancellationToken.None);
        var decoded = await File.ReadAllBytesAsync(decodedPath);
        var encoded = await File.ReadAllBytesAsync(ascfPath);
        var decodedFromArray = AscfFileReader.DecodeToArray(encoded);
        var wrappedEncoded = new byte[encoded.Length + 32];
        encoded.CopyTo(wrappedEncoded.AsSpan(17));
        var decodedFromSpan = AscfFileReader.DecodeToArray(wrappedEncoded.AsSpan(17, encoded.Length));

        Assert.True(storedSize > AscfFileFormat.HeaderSize);
        Assert.Equal(EncodedFileFormat.Ascf, EncodedFileFormatIdentifier.Identify(ascfPath, new FileInfo(ascfPath).Length));
        Assert.True(await AscfFileReader.FileLooksLikeAscfAsync(ascfPath, CancellationToken.None));
        Assert.Equal(Convert.ToHexString(SHA1.HashData(raw)), hash.Hash);
        Assert.Equal(raw.Length, hash.RawSize);
        Assert.Equal(raw.Length, decodedSize);
        Assert.Equal(raw, decoded);
        Assert.Equal(raw, decodedFromArray);
        Assert.Equal(raw, decodedFromSpan);
    }

    [Fact]
    public async Task CopyMungedUpload()
    {
        var raw = CreateMixedPayload(512 * 1024 + 19);
        var sourcePath = WriteSource(raw);
        await using var upload = new MemoryStream();
        long progressed = 0;

        await AscfFileWriter.WriteFileAsync(
            sourcePath,
            upload,
            waitForBytes: static (_, _) => ValueTask.CompletedTask,
            progress: new Progress<long>(value => progressed = value),
            transform: ApplyUploadMask,
            CancellationToken.None);

        upload.Position = 0;
        var storedPath = Path.Combine(_testDirectory, "upload.ascf");
        var result = await AscfFileReader.CopyEncodedStreamToFileAsync(upload, storedPath, ApplyUploadMask, CancellationToken.None);
        var decoded = AscfFileReader.DecodeToArray(await File.ReadAllBytesAsync(storedPath));

        Assert.Equal(raw.Length, progressed);
        Assert.Equal(Convert.ToHexString(SHA1.HashData(raw)), result.Hash);
        Assert.Equal(raw.Length, result.RawSize);
        Assert.Equal(raw, decoded);
    }

    [Fact]
    public async Task WriteStreamWithSingleCompressionWorkerPreservesRawBytes()
    {
        var raw = CreateMixedPayload((AscfFileFormat.MinRawChunkBytes * 3) + 97);
        await using var source = new MemoryStream(raw);
        var ascfPath = Path.Combine(_testDirectory, "single-worker.ascf");
        var options = AscfWriterOptions.Default with
        {
            RawChunkSize = AscfFileFormat.MinRawChunkBytes,
            CompressionWorkerCount = 1
        };

        var result = await AscfFileWriter.WriteStreamToFileAsync(source, ascfPath, options, CancellationToken.None);
        var decoded = AscfFileReader.DecodeToArray(await File.ReadAllBytesAsync(ascfPath));

        Assert.Equal(raw.Length, result.RawSize);
        Assert.Equal(raw, decoded);
    }

    [Fact]
    public async Task WriteFileWithPagedIndexPreservesRawBytes()
    {
        const int chunkCount = 1025;
        var raw = CreateRepeatingPayload((AscfFileFormat.MinRawChunkBytes * chunkCount) + 11);
        var sourcePath = WriteSource(raw);
        var ascfPath = Path.Combine(_testDirectory, "paged-index.ascf");
        var options = AscfWriterOptions.Default with
        {
            RawChunkSize = AscfFileFormat.MinRawChunkBytes
        };

        await AscfFileWriter.WriteStoredRawFileAsync(sourcePath, 0, raw.Length, ascfPath, options, CancellationToken.None);
        var chunkIndex = AscfFileReader.ReadChunkIndex(ascfPath);
        var asyncChunkIndex = await AscfFileReader.ReadChunkIndexAsync(ascfPath, CancellationToken.None);
        var decoded = AscfFileReader.DecodeToArray(await File.ReadAllBytesAsync(ascfPath));
        var expectedChunkCount = (raw.Length + AscfFileFormat.MinRawChunkBytes - 1) / AscfFileFormat.MinRawChunkBytes;

        Assert.Equal(expectedChunkCount, chunkIndex.Entries.Count);
        Assert.Equal(expectedChunkCount, asyncChunkIndex.Entries.Count);
        Assert.Equal(raw, decoded);
    }

    [Fact]
    public async Task ConvertStoredRawAscfToWrappedLz4()
    {
        var raw = CreateIncompressiblePayload(1024 * 1024 + 7);
        var sourcePath = WriteSource(raw);
        var ascfPath = Path.Combine(_testDirectory, "raw.ascf");
        var wrappedPath = Path.Combine(_testDirectory, "raw.llz4");

        await AscfFileWriter.WriteStoredRawFileAsync(sourcePath, 0, raw.Length, ascfPath, CancellationToken.None);
        var result = await AscfFileReader.TryWriteStoredRawWrappedLz4Async(ascfPath, wrappedPath, CancellationToken.None);
        var wrappedHeader = WrappedLz4FileFormat.TryReadHeader(new FileInfo(wrappedPath).Length, await ReadHeaderAsync(wrappedPath, WrappedLz4FileFormat.HeaderSize));
        var decoded = WrappedLz4FileFormat.DecodeToArray(await File.ReadAllBytesAsync(wrappedPath));

        Assert.NotNull(result);
        Assert.NotNull(wrappedHeader);
        Assert.Equal(raw.Length, wrappedHeader.Value.OutputLength);
        Assert.Equal(raw.Length, wrappedHeader.Value.InputLength);
        Assert.Equal(raw, decoded);
    }

    [Fact]
    public async Task StoredRawWrappedLz4ShortcutLeavesNoPartialFileForCompressedAscf()
    {
        var raw = new byte[256 * 1024];
        var sourcePath = WriteSource(raw);
        var ascfPath = Path.Combine(_testDirectory, "compressed.ascf");
        var wrappedPath = Path.Combine(_testDirectory, "partial.llz4");

        await AscfFileWriter.WriteFileAsync(sourcePath, ascfPath, CancellationToken.None);
        var result = await AscfFileReader.TryWriteStoredRawWrappedLz4Async(ascfPath, wrappedPath, CancellationToken.None);

        Assert.Null(result);
        Assert.False(File.Exists(wrappedPath));
        Assert.Equal(raw, AscfFileReader.DecodeToArray(await File.ReadAllBytesAsync(ascfPath)));
    }

    [Fact]
    public async Task TranscodeWrappedLz4ToAscfAndBack()
    {
        var raw = CreateMixedPayload(768 * 1024 + 31);
        var sourcePath = WriteSource(raw);
        var wrappedPath = Path.Combine(_testDirectory, "source.llz4");
        var rawTempPath = Path.Combine(_testDirectory, "temp.raw");
        var ascfPath = Path.Combine(_testDirectory, "source.ascf");
        var wrappedAgainPath = Path.Combine(_testDirectory, "again.llz4");

        await WrappedLz4FileFormat.WriteFromRawFileAsync(sourcePath, wrappedPath, CancellationToken.None);
        await FileFormatTranscoder.ConvertWrappedLz4ToAscfAsync(wrappedPath, rawTempPath, ascfPath, CancellationToken.None);
        await FileFormatTranscoder.ConvertAscfFileToWrappedLz4Async(ascfPath, rawTempPath, wrappedAgainPath, CancellationToken.None);

        Assert.Equal(raw, AscfFileReader.DecodeToArray(await File.ReadAllBytesAsync(ascfPath)));
        Assert.Equal(raw, WrappedLz4FileFormat.DecodeToArray(await File.ReadAllBytesAsync(wrappedAgainPath)));
    }

    [Fact]
    public async Task WriteEmptyWrappedLz4WithMemoryMappedThresholdZero()
    {
        var sourcePath = WriteSource([]);
        var wrappedPath = Path.Combine(_testDirectory, "empty.llz4");
        var options = Lz4FormatOptions.Default with
        {
            MemoryMappedCompressionThreshold = 0
        };

        var result = await WrappedLz4FileFormat.WriteFromRawFileAsync(sourcePath, wrappedPath, options, CancellationToken.None);
        var decoded = WrappedLz4FileFormat.DecodeToArray(await File.ReadAllBytesAsync(wrappedPath));

        Assert.Equal(0, result.OriginalSize);
        Assert.Equal(WrappedLz4FileFormat.HeaderSize, result.CompressedSize);
        Assert.Empty(decoded);
    }

    [Fact]
    public async Task RejectInvalidStoredRawSourceRange()
    {
        var raw = CreateMixedPayload(1024);
        var sourcePath = WriteSource(raw);
        var ascfPath = Path.Combine(_testDirectory, "range.ascf");

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            AscfFileWriter.WriteStoredRawFileAsync(sourcePath, raw.Length + 1, 0, ascfPath, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            AscfFileWriter.WriteStoredRawFileAsync(sourcePath, 512, raw.Length, ascfPath, CancellationToken.None));
    }

    [Fact]
    public async Task RejectInvalidPublicBufferSizes()
    {
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            WrappedLz4FileFormat.TryReadHeaderAsync("missing.llz4", WrappedLz4FileFormat.HeaderSize, 0, CancellationToken.None));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            Lz4StreamFormat.ComputeFileHash("missing.lz4", 0, AscfFileFormat.DefaultBufferSize));
    }

    [Fact]
    public async Task RejectCorruptPayload()
    {
        var raw = CreateMixedPayload(128 * 1024 + 1);
        var sourcePath = WriteSource(raw);
        var ascfPath = Path.Combine(_testDirectory, "corrupt.ascf");

        await AscfFileWriter.WriteFileAsync(sourcePath, ascfPath, CancellationToken.None);
        var encoded = await File.ReadAllBytesAsync(ascfPath);
        encoded[^1] ^= 0x5A;

        Assert.Throws<InvalidDataException>(() => AscfFileReader.DecodeToArray(encoded));
    }

    [Fact]
    public async Task RejectVariableSizedNonFinalRawChunk()
    {
        var raw = CreateIncompressiblePayload((AscfFileFormat.MinRawChunkBytes * 2) + 17);
        var sourcePath = WriteSource(raw);
        var ascfPath = Path.Combine(_testDirectory, "variable-chunk.ascf");
        var options = AscfWriterOptions.Default with
        {
            RawChunkSize = AscfFileFormat.MinRawChunkBytes
        };

        await AscfFileWriter.WriteStoredRawFileAsync(sourcePath, 0, raw.Length, ascfPath, options, CancellationToken.None);
        var encoded = await File.ReadAllBytesAsync(ascfPath);
        var chunkHeader = encoded.AsSpan(AscfFileFormat.HeaderSize, AscfFileFormat.ChunkHeaderSize);
        BinaryPrimitives.WriteInt32LittleEndian(chunkHeader[0x18..], AscfFileFormat.MinRawChunkBytes / 2);
        RecomputeChunkHeaderChecksum(chunkHeader);

        Assert.Throws<InvalidDataException>(() => AscfFileReader.DecodeToArray(encoded));
    }

    [Fact]
    public async Task RejectCompressedChunkThatShouldHaveBeenStoredRaw()
    {
        var raw = new byte[(AscfFileFormat.MinRawChunkBytes * 2) + 17];
        var sourcePath = WriteSource(raw);
        var ascfPath = Path.Combine(_testDirectory, "noncanonical-compressed.ascf");
        var options = AscfWriterOptions.Default with
        {
            RawChunkSize = AscfFileFormat.MinRawChunkBytes
        };

        await AscfFileWriter.WriteFileAsync(sourcePath, ascfPath, options, CancellationToken.None);
        var encoded = await File.ReadAllBytesAsync(ascfPath);
        var chunkHeader = encoded.AsSpan(AscfFileFormat.HeaderSize, AscfFileFormat.ChunkHeaderSize);
        var method = BinaryPrimitives.ReadUInt16LittleEndian(chunkHeader[0x0C..]);
        Assert.NotEqual(AscfFileFormat.MethodRaw, method);

        BinaryPrimitives.WriteInt32LittleEndian(chunkHeader[0x1C..], AscfFileFormat.MinRawChunkBytes);
        RecomputeChunkHeaderChecksum(chunkHeader);

        Assert.Throws<InvalidDataException>(() => AscfFileReader.DecodeToArray(encoded));
    }

    [Fact]
    public void ValidateFormatConstants()
    {
        Assert.Equal(0x46435341, AscfFileFormat.Magic);
        Assert.Equal(0x48435341, AscfFileFormat.ChunkMagic);
        Assert.Equal(1, AscfFileFormat.Version);
        Assert.Equal(80, AscfFileFormat.HeaderSize);
        Assert.Equal(64, AscfFileFormat.ChunkHeaderSize);
        Assert.Equal(8, WrappedLz4FileFormat.HeaderSize);
    }

    public void Dispose()
    {
        if (Directory.Exists(_testDirectory))
        {
            Directory.Delete(_testDirectory, recursive: true);
        }
    }

    private string WriteSource(byte[] raw)
    {
        var path = Path.Combine(_testDirectory, $"{Guid.NewGuid():N}.raw");
        File.WriteAllBytes(path, raw);
        return path;
    }

    private static async Task<byte[]> ReadHeaderAsync(string path, int byteCount)
    {
        var header = new byte[byteCount];
        var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        await using (input.ConfigureAwait(false))
        {
            var read = await input.ReadAsync(header).ConfigureAwait(false);
            Assert.Equal(byteCount, read);
            return header;
        }
    }

    private static byte[] CreateMixedPayload(int length)
    {
        var data = new byte[length];
        RandomNumberGenerator.Fill(data);

        for (var i = 0; i < data.Length; i += 4096)
        {
            var span = data.AsSpan(i, Math.Min(2048, data.Length - i));
            span.Fill((byte)(i / 4096));
        }

        return data;
    }

    private static byte[] CreateIncompressiblePayload(int length)
    {
        var data = new byte[length];
        RandomNumberGenerator.Fill(data);
        return data;
    }

    private static byte[] CreateRepeatingPayload(int length)
    {
        var data = new byte[length];
        for (var i = 0; i < data.Length; i++)
        {
            data[i] = (byte)i;
        }

        return data;
    }

    private static void RecomputeChunkHeaderChecksum(Span<byte> chunkHeader)
    {
        BinaryPrimitives.WriteUInt64LittleEndian(chunkHeader[0x30..], 0);
        BinaryPrimitives.WriteUInt64LittleEndian(chunkHeader[0x30..], XxHash3.HashToUInt64(chunkHeader));
    }

    private static void ApplyUploadMask(Span<byte> buffer)
    {
        for (var i = 0; i < buffer.Length; i++)
        {
            buffer[i] ^= 0x69;
        }
    }
}
