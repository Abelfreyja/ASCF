using ASCF.Files;
using ASCF.Lz4;
using ASCF.Transcoding;
using Blake3;
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
        var streamDecodedPath = Path.Combine(_testDirectory, "stream-decoded.bin");

        var storedSize = await AscfFileWriter.WriteFileAsync(sourcePath, ascfPath, CancellationToken.None);
        var hash = AscfFileReader.ComputeFileHash(ascfPath);
        var storedHashes = AscfFileReader.ReadRawHashes(ascfPath);
        var decodedSize = await AscfFileReader.DecodeFileToFileAsync(ascfPath, decodedPath, CancellationToken.None);
        var streamDecodedSize = await DecodeStreamToFileAsync(ascfPath, streamDecodedPath);
        var decoded = await File.ReadAllBytesAsync(decodedPath);
        var streamDecoded = await File.ReadAllBytesAsync(streamDecodedPath);
        var encoded = await File.ReadAllBytesAsync(ascfPath);
        var decodedFromArray = AscfFileReader.DecodeToArray(encoded);
        var wrappedEncoded = new byte[encoded.Length + 32];
        encoded.CopyTo(wrappedEncoded.AsSpan(17));
        var decodedFromSpan = AscfFileReader.DecodeToArray(wrappedEncoded.AsSpan(17, encoded.Length));

        Assert.True(storedSize > AscfFileFormat.HeaderSize);
        Assert.Equal(EncodedFileFormat.Ascf, EncodedFileFormatIdentifier.Identify(ascfPath, new FileInfo(ascfPath).Length));
        Assert.True(await AscfFileReader.FileLooksLikeAscfAsync(ascfPath, CancellationToken.None));
        var expectedSha1 = Convert.ToHexString(SHA1.HashData(raw));
        Assert.Equal(expectedSha1, hash.Hashes.Sha1);
        Assert.Null(storedHashes.Sha1);
        Assert.Null(storedHashes.Blake3);
        Assert.Equal(raw.Length, hash.RawSize);
        Assert.Equal(raw.Length, decodedSize);
        Assert.Equal(raw.Length, streamDecodedSize);
        Assert.Equal(raw, decoded);
        Assert.Equal(raw, streamDecoded);
        Assert.Equal(raw, decodedFromArray);
        Assert.Equal(raw, decodedFromSpan);
    }

    [Fact]
    public async Task WriteFileCanStoreSha1RawHash()
    {
        var raw = CreateMixedPayload(512 * 1024 + 29);
        var sourcePath = WriteSource(raw);
        var ascfPath = Path.Combine(_testDirectory, "sha1.ascf");
        var options = AscfWriterOptions.Default with
        {
            RawHashAlgorithms = AscfRawHashAlgorithms.Sha1
        };

        await AscfFileWriter.WriteFileAsync(sourcePath, ascfPath, options, CancellationToken.None);
        var hashes = AscfFileReader.ReadRawHashes(ascfPath);

        Assert.Equal(Convert.ToHexString(SHA1.HashData(raw)), hashes.Sha1);
        Assert.Null(hashes.Blake3);
    }

    [Fact]
    public async Task WriteFileCanStoreOnlyBlake3RawHash()
    {
        var raw = CreateMixedPayload(512 * 1024 + 37);
        var sourcePath = WriteSource(raw);
        var ascfPath = Path.Combine(_testDirectory, "blake3-stored.ascf");
        var options = AscfWriterOptions.Default with
        {
            RawHashAlgorithms = AscfRawHashAlgorithms.Blake3
        };

        await AscfFileWriter.WriteFileAsync(sourcePath, ascfPath, options, CancellationToken.None);
        var hashes = AscfFileReader.ReadRawHashes(ascfPath);

        Assert.Null(hashes.Sha1);
        Assert.Equal(ComputeBlake3Hex(raw), hashes.Blake3);
    }

    [Fact]
    public async Task WriteFileCanStoreSelectedRawHashes()
    {
        var raw = CreateMixedPayload(512 * 1024 + 73);
        var sourcePath = WriteSource(raw);
        var ascfPath = Path.Combine(_testDirectory, "hashes.ascf");
        var options = AscfWriterOptions.Default with
        {
            RawHashAlgorithms = AscfRawHashAlgorithms.Sha1 | AscfRawHashAlgorithms.Blake3
        };

        await AscfFileWriter.WriteFileAsync(sourcePath, ascfPath, options, CancellationToken.None);
        var hashes = await AscfFileReader.ReadRawHashesAsync(ascfPath, CancellationToken.None);

        Assert.Equal(Convert.ToHexString(SHA1.HashData(raw)), hashes.Sha1);
        Assert.Equal(ComputeBlake3Hex(raw), hashes.Blake3);
    }

    [Fact]
    public async Task WriteFileWithHashRequiresSelectedResultHash()
    {
        var raw = CreateMixedPayload(64 * 1024 + 11);
        var sourcePath = WriteSource(raw);
        var ascfPath = Path.Combine(_testDirectory, "hash-required.ascf");

        await Assert.ThrowsAsync<ArgumentException>(() =>
            AscfFileWriter.WriteFileWithHashAsync(sourcePath, ascfPath, AscfWriterOptions.Default, CancellationToken.None));
    }

    [Fact]
    public async Task WriteStoredRawFileWithHashRequiresSelectedResultHash()
    {
        var raw = CreateMixedPayload(64 * 1024 + 13);
        var sourcePath = WriteSource(raw);
        var ascfPath = Path.Combine(_testDirectory, "stored-hash-required.ascf");

        await Assert.ThrowsAsync<ArgumentException>(() =>
            AscfFileWriter.WriteStoredRawFileWithHashAsync(sourcePath, 0, raw.Length, ascfPath, AscfWriterOptions.Default, CancellationToken.None));
    }

    [Fact]
    public async Task DecodeFileWithHashRequiresSelectedResultHash()
    {
        var raw = CreateMixedPayload(64 * 1024 + 17);
        var sourcePath = WriteSource(raw);
        var ascfPath = Path.Combine(_testDirectory, "decode-hash-required.ascf");
        var decodedPath = Path.Combine(_testDirectory, "decode-hash-required.raw");
        var readOptions = AscfReaderOptions.Default with
        {
            ResultHashAlgorithms = AscfRawHashAlgorithms.None
        };

        await AscfFileWriter.WriteFileAsync(
            sourcePath,
            ascfPath,
            AscfWriterOptions.Default with
            {
                RawHashAlgorithms = AscfRawHashAlgorithms.Sha1
            },
            CancellationToken.None);

        Assert.Throws<ArgumentException>(() => AscfFileReader.ComputeFileHash(ascfPath, readOptions));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            AscfFileReader.DecodeFileToRawFileAsync(ascfPath, decodedPath, readOptions, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            AscfFileReader.DecodeFileToRawFileParallelAsync(ascfPath, decodedPath, readOptions, CancellationToken.None));
    }

    [Fact]
    public async Task DecodeFileToFileAllowsNoResultHash()
    {
        var raw = CreateMixedPayload(64 * 1024 + 19);
        var sourcePath = WriteSource(raw);
        var ascfPath = Path.Combine(_testDirectory, "decode-no-hash.ascf");
        var decodedPath = Path.Combine(_testDirectory, "decode-no-hash.raw");
        var readOptions = AscfReaderOptions.Default with
        {
            ResultHashAlgorithms = AscfRawHashAlgorithms.None
        };

        await AscfFileWriter.WriteFileAsync(sourcePath, ascfPath, CancellationToken.None);

        var decodedSize = await AscfFileReader.DecodeFileToFileAsync(ascfPath, decodedPath, readOptions, CancellationToken.None);

        Assert.Equal(raw.Length, decodedSize);
        Assert.Equal(raw, await File.ReadAllBytesAsync(decodedPath));
    }

    [Fact]
    public async Task CopyEncodedStreamToFileRequiresSelectedResultHash()
    {
        var raw = CreateMixedPayload(64 * 1024 + 23);
        var sourcePath = WriteSource(raw);
        var ascfPath = Path.Combine(_testDirectory, "copy-hash-required-source.ascf");
        var copiedPath = Path.Combine(_testDirectory, "copy-hash-required.ascf");
        var readOptions = AscfReaderOptions.Default with
        {
            ResultHashAlgorithms = AscfRawHashAlgorithms.None
        };

        await AscfFileWriter.WriteFileAsync(sourcePath, ascfPath, CancellationToken.None);
        await using var encodedStream = File.OpenRead(ascfPath);

        await Assert.ThrowsAsync<ArgumentException>(() =>
            AscfFileReader.CopyEncodedStreamToFileAsync(encodedStream, copiedPath, transform: null, readOptions, CancellationToken.None));
    }

    [Fact]
    public async Task WriteFileWithHashCanReturnBothRawHashes()
    {
        var raw = CreateMixedPayload(256 * 1024 + 13);
        var sourcePath = WriteSource(raw);
        var ascfPath = Path.Combine(_testDirectory, "both-hashes.ascf");
        var options = AscfWriterOptions.Default with
        {
            RawHashAlgorithms = AscfRawHashAlgorithms.Sha1 | AscfRawHashAlgorithms.Blake3,
            ResultHashAlgorithms = AscfRawHashAlgorithms.Sha1 | AscfRawHashAlgorithms.Blake3
        };

        var result = await AscfFileWriter.WriteFileWithHashAsync(sourcePath, ascfPath, options, CancellationToken.None);
        var expectedSha1 = Convert.ToHexString(SHA1.HashData(raw));
        var expectedBlake3 = ComputeBlake3Hex(raw);

        Assert.Equal(expectedSha1, result.Hashes.Sha1);
        Assert.Equal(expectedBlake3, result.Hashes.Blake3);
    }

    [Fact]
    public async Task WriteFileWithHashCanUseBlake3WithoutSha1()
    {
        var raw = CreateMixedPayload(256 * 1024 + 41);
        var sourcePath = WriteSource(raw);
        var ascfPath = Path.Combine(_testDirectory, "blake3-only.ascf");
        var decodedPath = Path.Combine(_testDirectory, "blake3-only.raw");
        var writeOptions = AscfWriterOptions.Default with
        {
            RawHashAlgorithms = AscfRawHashAlgorithms.Blake3,
            ResultHashAlgorithms = AscfRawHashAlgorithms.Blake3
        };
        var readOptions = AscfReaderOptions.Default with
        {
            ResultHashAlgorithms = AscfRawHashAlgorithms.Blake3
        };

        var writeResult = await AscfFileWriter.WriteFileWithHashAsync(sourcePath, ascfPath, writeOptions, CancellationToken.None);
        var hashes = AscfFileReader.ReadRawHashes(ascfPath);
        var computed = AscfFileReader.ComputeFileHash(ascfPath, readOptions);
        var decoded = await AscfFileReader.DecodeFileToRawFileAsync(ascfPath, decodedPath, readOptions, CancellationToken.None);
        var expectedBlake3 = ComputeBlake3Hex(raw);

        Assert.Equal(expectedBlake3, writeResult.Hashes.Blake3);
        Assert.Null(hashes.Sha1);
        Assert.Equal(expectedBlake3, hashes.Blake3);
        Assert.Equal(expectedBlake3, computed.Hashes.Blake3);
        Assert.Equal(expectedBlake3, decoded.Hashes.Blake3);
        Assert.Equal(raw, await File.ReadAllBytesAsync(decodedPath));
    }

    [Fact]
    public async Task RejectMismatchedStoredRawSha1WhenHashing()
    {
        var raw = CreateMixedPayload(256 * 1024 + 19);
        var sourcePath = WriteSource(raw);
        var ascfPath = Path.Combine(_testDirectory, "mismatched-sha1.ascf");
        var decodedPath = Path.Combine(_testDirectory, "mismatched-sha1.raw");
        var blake3Options = AscfReaderOptions.Default with
        {
            ResultHashAlgorithms = AscfRawHashAlgorithms.Blake3
        };

        await AscfFileWriter.WriteFileAsync(
            sourcePath,
            ascfPath,
            AscfWriterOptions.Default with
            {
                RawHashAlgorithms = AscfRawHashAlgorithms.Sha1
            },
            CancellationToken.None);
        var encoded = await File.ReadAllBytesAsync(ascfPath);
        encoded[0x50] ^= 0x5A;
        RecomputeFileHeaderChecksum(encoded);
        await File.WriteAllBytesAsync(ascfPath, encoded);

        Assert.Throws<InvalidDataException>(() => AscfFileReader.ComputeFileHash(ascfPath));
        Assert.Throws<InvalidDataException>(() => AscfFileReader.ComputeFileHash(ascfPath, blake3Options));
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            AscfFileReader.DecodeFileToRawFileAsync(ascfPath, decodedPath, CancellationToken.None));
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
        Assert.Equal(Convert.ToHexString(SHA1.HashData(raw)), result.Hashes.Sha1);
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
    public async Task WriteFileWithSmallCompressionPipelinePreservesRawBytes()
    {
        var raw = CreateMixedPayload((AscfFileFormat.MinRawChunkBytes * 12) + 97);
        var sourcePath = WriteSource(raw);
        var ascfPath = Path.Combine(_testDirectory, "small-pipeline.ascf");
        var options = AscfWriterOptions.Default with
        {
            RawChunkSize = AscfFileFormat.MinRawChunkBytes,
            CompressionWorkerCount = 8,
            MaxCompressionPipelineBytes = 128 * 1024
        };

        var result = await AscfFileWriter.WriteFileAsync(sourcePath, ascfPath, options, CancellationToken.None);
        var decoded = AscfFileReader.DecodeToArray(await File.ReadAllBytesAsync(ascfPath));

        Assert.Equal(raw, decoded);
        Assert.True(result > AscfFileFormat.HeaderSize);
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
    public async Task ParallelDecodePreservesRawBytes()
    {
        var raw = CreateMixedPayload((AscfFileFormat.MinRawChunkBytes * 8) + 59);
        var sourcePath = WriteSource(raw);
        var ascfPath = Path.Combine(_testDirectory, "parallel.ascf");
        var autoPath = Path.Combine(_testDirectory, "parallel-auto.raw");
        var randomPath = Path.Combine(_testDirectory, "parallel-random.raw");
        var orderedPath = Path.Combine(_testDirectory, "parallel-ordered.raw");
        var writeOptions = AscfWriterOptions.Default with
        {
            RawChunkSize = AscfFileFormat.MinRawChunkBytes,
            CompressionWorkerCount = 65,
            MaxCompressionWorkerCount = 128
        };
        var readOptions = AscfReaderOptions.Default with
        {
            ParallelDecodeWorkerCount = 65,
            MaxParallelDecodeWorkerCount = 128
        };
        var randomReadOptions = readOptions with
        {
            ParallelDecodeMode = AscfParallelDecodeMode.RandomWrite
        };
        var expectedHash = Convert.ToHexString(SHA1.HashData(raw));

        await AscfFileWriter.WriteFileAsync(sourcePath, ascfPath, writeOptions, CancellationToken.None);
        var autoResult = await AscfFileReader.DecodeFileToRawFileParallelAsync(ascfPath, autoPath, readOptions, CancellationToken.None);
        var randomResult = await AscfFileReader.DecodeFileToRawFileParallelAsync(ascfPath, randomPath, randomReadOptions, CancellationToken.None);
        var orderedResult = await AscfFileReader.DecodeFileToRawFileParallelOrderedAsync(ascfPath, orderedPath, readOptions, CancellationToken.None);

        Assert.Equal(raw.Length, autoResult.RawSize);
        Assert.Equal(raw.Length, randomResult.RawSize);
        Assert.Equal(raw.Length, orderedResult.RawSize);
        Assert.Equal(expectedHash, autoResult.Hashes.Sha1);
        Assert.Equal(expectedHash, randomResult.Hashes.Sha1);
        Assert.Equal(expectedHash, orderedResult.Hashes.Sha1);
        Assert.Equal(raw, await File.ReadAllBytesAsync(autoPath));
        Assert.Equal(raw, await File.ReadAllBytesAsync(randomPath));
        Assert.Equal(raw, await File.ReadAllBytesAsync(orderedPath));
    }

    [Fact]
    public async Task ParallelDecodeStoredRawPreservesRawBytes()
    {
        var raw = CreateIncompressiblePayload((AscfFileFormat.MinRawChunkBytes * 4) + 17);
        var sourcePath = WriteSource(raw);
        var ascfPath = Path.Combine(_testDirectory, "parallel-stored-raw.ascf");
        var randomPath = Path.Combine(_testDirectory, "parallel-stored-raw-random.raw");
        var orderedPath = Path.Combine(_testDirectory, "parallel-stored-raw-ordered.raw");
        var options = AscfWriterOptions.Default with
        {
            RawChunkSize = AscfFileFormat.MinRawChunkBytes
        };

        await AscfFileWriter.WriteStoredRawFileAsync(sourcePath, 0, raw.Length, ascfPath, options, CancellationToken.None);
        var randomSize = await AscfFileReader.DecodeFileToFileParallelAsync(ascfPath, randomPath, CancellationToken.None);
        var orderedResult = await AscfFileReader.DecodeFileToRawFileParallelAsync(ascfPath, orderedPath, CancellationToken.None);

        Assert.Equal(raw.Length, randomSize);
        Assert.Equal(raw.Length, orderedResult.RawSize);
        Assert.Equal(raw, await File.ReadAllBytesAsync(randomPath));
        Assert.Equal(raw, await File.ReadAllBytesAsync(orderedPath));
    }

    [Fact]
    public async Task RejectInvalidWorkerSettings()
    {
        var outputPath = Path.Combine(_testDirectory, "unused.ascf");

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            AscfFileWriter.WriteFileAsync(
                "missing.raw",
                outputPath,
                AscfWriterOptions.Default with
                {
                    CompressionWorkerCount = 65
                },
                CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            AscfFileWriter.WriteFileAsync(
                "missing.raw",
                outputPath,
                AscfWriterOptions.Default with
                {
                    MaxCompressionPipelineBytes = 1
                },
                CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            AscfFileReader.DecodeFileToRawFileParallelAsync(
                "missing.ascf",
                outputPath,
                AscfReaderOptions.Default with
                {
                    ParallelDecodeWorkerCount = 65
                },
                CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            AscfFileReader.DecodeFileToRawFileParallelAsync(
                "missing.ascf",
                outputPath,
                AscfReaderOptions.Default with
                {
                    ParallelDecodeMode = (AscfParallelDecodeMode)999
                },
                CancellationToken.None));
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
    public async Task DecodeFileToFileReplacesExistingOutputAfterValidation()
    {
        var raw = CreateMixedPayload(128 * 1024 + 1);
        var sourcePath = WriteSource(raw);
        var ascfPath = Path.Combine(_testDirectory, "replace-success.ascf");
        var outputPath = Path.Combine(_testDirectory, "replace-success.raw");

        await AscfFileWriter.WriteFileAsync(sourcePath, ascfPath, CancellationToken.None);
        await File.WriteAllBytesAsync(outputPath, [0xAC, 0xCF]);

        var rawSize = await AscfFileReader.DecodeFileToFileAsync(ascfPath, outputPath, CancellationToken.None);

        Assert.Equal(raw.Length, rawSize);
        Assert.Equal(raw, await File.ReadAllBytesAsync(outputPath));
        AssertNoStagingFiles(outputPath);
    }

    [Fact]
    public async Task DecodeFileToFileKeepsExistingOutputOnFailure()
    {
        var raw = CreateMixedPayload(128 * 1024 + 1);
        var sourcePath = WriteSource(raw);
        var ascfPath = Path.Combine(_testDirectory, "decode-fail.ascf");
        var outputPath = Path.Combine(_testDirectory, "decode-fail.raw");
        byte[] existing = [0xA5, 0x5A, 0x11];

        await AscfFileWriter.WriteFileAsync(sourcePath, ascfPath, CancellationToken.None);
        var encoded = await File.ReadAllBytesAsync(ascfPath);
        encoded[^1] ^= 0x5A;
        await File.WriteAllBytesAsync(ascfPath, encoded);
        await File.WriteAllBytesAsync(outputPath, existing);

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            AscfFileReader.DecodeFileToFileAsync(ascfPath, outputPath, CancellationToken.None));

        Assert.Equal(existing, await File.ReadAllBytesAsync(outputPath));
        AssertNoStagingFiles(outputPath);
    }

    [Fact]
    public async Task WriteStreamToFileKeepsExistingOutputOnCancellation()
    {
        var raw = CreateMixedPayload(128 * 1024 + 9);
        var outputPath = Path.Combine(_testDirectory, "write-cancel.ascf");
        byte[] existing = [0x13, 0x37, 0x42];
        using var input = new MemoryStream(raw);
        using var cts = new CancellationTokenSource();

        await File.WriteAllBytesAsync(outputPath, existing);
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            AscfFileWriter.WriteStreamToFileAsync(input, outputPath, cts.Token));

        Assert.Equal(existing, await File.ReadAllBytesAsync(outputPath));
        AssertNoStagingFiles(outputPath);
    }

    [Fact]
    public async Task CopyEncodedStreamToFileKeepsExistingOutputOnFailure()
    {
        var raw = CreateMixedPayload(128 * 1024 + 1);
        var sourcePath = WriteSource(raw);
        var ascfPath = Path.Combine(_testDirectory, "copy-fail-source.ascf");
        var outputPath = Path.Combine(_testDirectory, "copy-fail.ascf");
        byte[] existing = [0xC0, 0xFF, 0xEE];

        await AscfFileWriter.WriteFileAsync(sourcePath, ascfPath, CancellationToken.None);
        var encoded = await File.ReadAllBytesAsync(ascfPath);
        encoded[^1] ^= 0x5A;
        await File.WriteAllBytesAsync(outputPath, existing);
        await using var encodedStream = new MemoryStream(encoded);

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            AscfFileReader.CopyEncodedStreamToFileAsync(encodedStream, outputPath, CancellationToken.None));

        Assert.Equal(existing, await File.ReadAllBytesAsync(outputPath));
        AssertNoStagingFiles(outputPath);
    }

    [Fact]
    public async Task ParallelDecodeKeepsExistingOutputOnFailure()
    {
        var raw = CreateMixedPayload((AscfFileFormat.MinRawChunkBytes * 4) + 1);
        var sourcePath = WriteSource(raw);
        var ascfPath = Path.Combine(_testDirectory, "parallel-fail.ascf");
        var outputPath = Path.Combine(_testDirectory, "parallel-fail.raw");
        var options = AscfWriterOptions.Default with
        {
            RawChunkSize = AscfFileFormat.MinRawChunkBytes
        };
        byte[] existing = [0x5A, 0xA5, 0x22];

        await AscfFileWriter.WriteFileAsync(sourcePath, ascfPath, options, CancellationToken.None);
        var encoded = await File.ReadAllBytesAsync(ascfPath);
        encoded[AscfFileFormat.HeaderSize + AscfFileFormat.ChunkHeaderSize] ^= 0x5A;
        await File.WriteAllBytesAsync(ascfPath, encoded);
        await File.WriteAllBytesAsync(outputPath, existing);

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            AscfFileReader.DecodeFileToRawFileParallelAsync(ascfPath, outputPath, CancellationToken.None));

        Assert.Equal(existing, await File.ReadAllBytesAsync(outputPath));
        AssertNoStagingFiles(outputPath);
    }

    [Fact]
    public async Task RejectMismatchedEncodedSizeForCompleteFiles()
    {
        var raw = CreateMixedPayload(128 * 1024 + 31);
        var sourcePath = WriteSource(raw);
        var ascfPath = Path.Combine(_testDirectory, "encoded-size.ascf");
        var decodedPath = Path.Combine(_testDirectory, "encoded-size.raw");

        await AscfFileWriter.WriteFileAsync(sourcePath, ascfPath, CancellationToken.None);
        var encoded = await File.ReadAllBytesAsync(ascfPath);
        BinaryPrimitives.WriteInt64LittleEndian(encoded.AsSpan(0x40), encoded.Length + 1L);
        RecomputeFileHeaderChecksum(encoded);
        await File.WriteAllBytesAsync(ascfPath, encoded);

        Assert.Throws<InvalidDataException>(() => AscfFileReader.DecodeToArray(encoded));
        Assert.Throws<InvalidDataException>(() => AscfFileReader.ComputeFileHash(ascfPath));
        Assert.Throws<InvalidDataException>(() => AscfFileReader.ReadChunkIndex(ascfPath));
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            AscfFileReader.DecodeFileToRawFileAsync(ascfPath, decodedPath, CancellationToken.None));
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            AscfFileReader.DecodeFileToFileAsync(ascfPath, decodedPath, CancellationToken.None));
    }

    [Fact]
    public async Task RejectIndexEntryPayloadPastIndex()
    {
        var raw = CreateIncompressiblePayload((AscfFileFormat.MinRawChunkBytes * 2) + 17);
        var sourcePath = WriteSource(raw);
        var ascfPath = Path.Combine(_testDirectory, "index-payload-overlap.ascf");
        var options = AscfWriterOptions.Default with
        {
            RawChunkSize = AscfFileFormat.MinRawChunkBytes
        };

        await AscfFileWriter.WriteStoredRawFileAsync(sourcePath, 0, raw.Length, ascfPath, options, CancellationToken.None);
        var encoded = await File.ReadAllBytesAsync(ascfPath);
        var footer = GetFooter(encoded);
        var entryCount = BinaryPrimitives.ReadInt32LittleEndian(footer[0x10..]);
        var lastEntry = GetIndexEntry(encoded, entryCount - 1);
        var rawLength = BinaryPrimitives.ReadInt32LittleEndian(lastEntry[0x18..]);
        BinaryPrimitives.WriteInt32LittleEndian(lastEntry[0x1C..], rawLength + 1);
        RecomputeIndexEntryChecksum(lastEntry);
        RecomputeIndexAndFooterChecksums(encoded);
        await File.WriteAllBytesAsync(ascfPath, encoded);

        Assert.Throws<InvalidDataException>(() => AscfFileReader.ReadChunkIndex(ascfPath));
        await Assert.ThrowsAsync<InvalidDataException>(() => AscfFileReader.ReadChunkIndexAsync(ascfPath, CancellationToken.None));
    }

    [Fact]
    public async Task RejectFooterLengthOverflow()
    {
        var raw = CreateMixedPayload(128 * 1024 + 31);
        var sourcePath = WriteSource(raw);
        var ascfPath = Path.Combine(_testDirectory, "footer-overflow.ascf");

        await AscfFileWriter.WriteFileAsync(sourcePath, ascfPath, CancellationToken.None);
        var encoded = await File.ReadAllBytesAsync(ascfPath);
        var footer = GetFooter(encoded);
        BinaryPrimitives.WriteInt64LittleEndian(footer[0x20..], long.MaxValue);
        RecomputeFooterChecksum(footer);
        await File.WriteAllBytesAsync(ascfPath, encoded);

        Assert.Throws<InvalidDataException>(() => AscfFileReader.ReadChunkIndex(ascfPath));
        await Assert.ThrowsAsync<InvalidDataException>(() => AscfFileReader.ReadChunkIndexAsync(ascfPath, CancellationToken.None));
    }

    [Fact]
    public void RejectOverflowingPayloadOffset()
    {
        var entry = new AscfChunkIndexEntry(0, AscfFileFormat.MethodRaw, 0, long.MaxValue, 1, 1, 0, 0);

        Assert.Throws<OverflowException>(() => _ = entry.PayloadOffset);
    }

    [Fact]
    public async Task RejectCompressedIndexEntryThatShouldHaveBeenStoredRaw()
    {
        var raw = CreateIncompressiblePayload((AscfFileFormat.MinRawChunkBytes * 2) + 17);
        var sourcePath = WriteSource(raw);
        var ascfPath = Path.Combine(_testDirectory, "index-noncanonical-compressed.ascf");
        var options = AscfWriterOptions.Default with
        {
            RawChunkSize = AscfFileFormat.MinRawChunkBytes
        };

        await AscfFileWriter.WriteStoredRawFileAsync(sourcePath, 0, raw.Length, ascfPath, options, CancellationToken.None);
        var encoded = await File.ReadAllBytesAsync(ascfPath);
        var footer = GetFooter(encoded);
        var entryCount = BinaryPrimitives.ReadInt32LittleEndian(footer[0x10..]);
        var lastEntry = GetIndexEntry(encoded, entryCount - 1);
        BinaryPrimitives.WriteUInt16LittleEndian(lastEntry[0x04..], AscfFileFormat.MethodLz4Fast);
        RecomputeIndexEntryChecksum(lastEntry);
        RecomputeIndexAndFooterChecksums(encoded);
        await File.WriteAllBytesAsync(ascfPath, encoded);

        Assert.Throws<InvalidDataException>(() => AscfFileReader.ReadChunkIndex(ascfPath));
        await Assert.ThrowsAsync<InvalidDataException>(() => AscfFileReader.ReadChunkIndexAsync(ascfPath, CancellationToken.None));
    }

    [Fact]
    public async Task ValidatePartialFileChecksDeclaredEncodedSize()
    {
        var raw = CreateMixedPayload(128 * 1024 + 31);
        var sourcePath = WriteSource(raw);
        var ascfPath = Path.Combine(_testDirectory, "partial-size.ascf");
        var partialPath = Path.Combine(_testDirectory, "partial-size-short.ascf");
        var oversizedPath = Path.Combine(_testDirectory, "partial-size-oversized.ascf");

        await AscfFileWriter.WriteFileAsync(sourcePath, ascfPath, CancellationToken.None);
        var encoded = await File.ReadAllBytesAsync(ascfPath);
        await File.WriteAllBytesAsync(partialPath, encoded.AsMemory(0, AscfFileFormat.HeaderSize));
        await File.WriteAllBytesAsync(oversizedPath, encoded.Concat([(byte)0]).ToArray());

        var partial = await AscfFileReader.ValidatePartialFileAsync(partialPath, CancellationToken.None);
        var oversized = await AscfFileReader.ValidatePartialFileAsync(oversizedPath, CancellationToken.None);

        Assert.True(partial.HeaderValid);
        Assert.False(partial.IsComplete);
        Assert.False(partial.IsCorrupt);
        Assert.True(oversized.HeaderValid);
        Assert.False(oversized.IsComplete);
        Assert.True(oversized.IsCorrupt);
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
        Assert.Equal(160, AscfFileFormat.HeaderSize);
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

    private static async Task<long> DecodeStreamToFileAsync(string ascfPath, string outputPath)
    {
        var input = new FileStream(ascfPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        await using (input.ConfigureAwait(false))
        {
            return await AscfFileReader.DecodeStreamToFileAsync(input, outputPath, CancellationToken.None)
                .ConfigureAwait(false);
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

    private static void RecomputeFileHeaderChecksum(Span<byte> fileHeader)
    {
        BinaryPrimitives.WriteUInt64LittleEndian(fileHeader[0x98..], 0);
        BinaryPrimitives.WriteUInt64LittleEndian(fileHeader[0x98..], XxHash3.HashToUInt64(fileHeader[..AscfFileFormat.HeaderSize]));
    }

    private static string ComputeBlake3Hex(ReadOnlySpan<byte> raw)
    {
        var hash = Hasher.Hash(raw);
        return Convert.ToHexString(hash.AsSpan());
    }

    private static Span<byte> GetFooter(byte[] encoded)
        => encoded.AsSpan(encoded.Length - AscfFileFormat.IndexFooterSize, AscfFileFormat.IndexFooterSize);

    private static Span<byte> GetIndexEntry(byte[] encoded, int entryIndex)
    {
        var footer = GetFooter(encoded);
        var indexOffset = checked((int)BinaryPrimitives.ReadInt64LittleEndian(footer[0x20..]));
        return encoded.AsSpan(indexOffset + (entryIndex * AscfFileFormat.IndexEntrySize), AscfFileFormat.IndexEntrySize);
    }

    private static void RecomputeIndexEntryChecksum(Span<byte> indexEntry)
    {
        BinaryPrimitives.WriteUInt64LittleEndian(indexEntry[0x30..], 0);
        BinaryPrimitives.WriteUInt64LittleEndian(indexEntry[0x30..], XxHash3.HashToUInt64(indexEntry));
    }

    private static void RecomputeIndexAndFooterChecksums(byte[] encoded)
    {
        var footer = GetFooter(encoded);
        var indexOffset = checked((int)BinaryPrimitives.ReadInt64LittleEndian(footer[0x20..]));
        var indexLength = checked((int)BinaryPrimitives.ReadInt64LittleEndian(footer[0x28..]));
        var index = encoded.AsSpan(indexOffset, indexLength);
        BinaryPrimitives.WriteUInt64LittleEndian(footer[0x30..], XxHash3.HashToUInt64(index));
        RecomputeFooterChecksum(footer);
    }

    private static void RecomputeFooterChecksum(Span<byte> footer)
    {
        BinaryPrimitives.WriteUInt64LittleEndian(footer[0x38..], 0);
        BinaryPrimitives.WriteUInt64LittleEndian(footer[0x38..], XxHash3.HashToUInt64(footer));
    }

    private static void AssertNoStagingFiles(string outputPath)
    {
        var fullPath = Path.GetFullPath(outputPath);
        var directory = Path.GetDirectoryName(fullPath) ?? throw new InvalidOperationException("Missing output directory.");
        var fileName = Path.GetFileName(fullPath);

        Assert.Empty(Directory.EnumerateFiles(directory, $".{fileName}.*.tmp"));
    }

    private static void ApplyUploadMask(Span<byte> buffer)
    {
        for (var i = 0; i < buffer.Length; i++)
        {
            buffer[i] ^= 0x69;
        }
    }
}
