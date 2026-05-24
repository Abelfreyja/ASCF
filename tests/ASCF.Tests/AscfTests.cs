using ASCF.Files;
using ASCF.Lz4;
using ASCF.Transcoding;
using Blake3;
using K4os.Compression.LZ4.Legacy;
using System.Buffers.Binary;
using System.IO.Hashing;
using System.Security.Cryptography;
using System.Text;

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
        Assert.True(AscfFileReader.TryReadMetadata(encoded.AsSpan(0, AscfFileFormat.HeaderSize), encoded.Length, out var metadata));
        Assert.Equal(raw.Length, metadata.RawSize);
        Assert.Equal(encoded.Length, metadata.EncodedSize);

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
    public async Task BoundedStreamDecodeDoesNotReadNextPayload()
    {
        var raw = CreateMixedPayload(256 * 1024 + 23);
        var sourcePath = WriteSource(raw);
        var ascfPath = Path.Combine(_testDirectory, "bounded-source.ascf");
        var outputPath = Path.Combine(_testDirectory, "bounded-output.raw");
        byte[] sentinel = [0xAC, 0xCF, 0x42];

        await AscfFileWriter.WriteFileAsync(sourcePath, ascfPath, CancellationToken.None);
        var encoded = await File.ReadAllBytesAsync(ascfPath);
        using var stream = new MemoryStream(encoded.Concat(sentinel).ToArray());

        var result = await AscfFileReader
            .DecodeStreamToRawFileAsync(stream, encoded.Length, outputPath, transform: null, AscfReaderOptions.Default, CancellationToken.None)
            .ConfigureAwait(false);

        Assert.Equal(raw.Length, result.RawSize);
        Assert.Equal(encoded.Length, stream.Position);
        Assert.Equal(sentinel, stream.ToArray().AsSpan(encoded.Length).ToArray());
        Assert.Equal(raw, await File.ReadAllBytesAsync(outputPath));
    }

    [Fact]
    public async Task IdentifyAsyncResetsTransformedStreamPosition()
    {
        var raw = CreateMixedPayload(128 * 1024 + 11);
        var sourcePath = WriteSource(raw);
        var ascfPath = Path.Combine(_testDirectory, "identify-stream.ascf");
        AscfBufferTransform transform = static buffer =>
        {
            foreach (ref var value in buffer)
            {
                value ^= 0x5A;
            }
        };

        await AscfFileWriter.WriteFileAsync(sourcePath, ascfPath, CancellationToken.None);
        var encoded = await File.ReadAllBytesAsync(ascfPath);
        transform(encoded);
        using var stream = new MemoryStream(encoded);

        var format = await EncodedFileFormatIdentifier
            .IdentifyAsync(stream, encoded.Length, transform, EncodedFileFormatIdentificationOptions.Default, CancellationToken.None)
            .ConfigureAwait(false);

        Assert.Equal(EncodedFileFormat.Ascf, format);
        Assert.Equal(0, stream.Position);
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
    public async Task DecodeWithStoredHashesReturnsHeaderHashes()
    {
        var raw = CreateMixedPayload(512 * 1024 + 41);
        var sourcePath = WriteSource(raw);
        var ascfPath = Path.Combine(_testDirectory, "stored-hash-decode.ascf");
        var fileDecodedPath = Path.Combine(_testDirectory, "stored-hash-file.raw");
        var streamDecodedPath = Path.Combine(_testDirectory, "stored-hash-stream.raw");
        var options = AscfWriterOptions.Default with
        {
            RawHashAlgorithms = AscfRawHashAlgorithms.Blake3
        };
        var readOptions = AscfReaderOptions.Default with
        {
            RequiredStoredHashAlgorithms = AscfRawHashAlgorithms.Blake3
        };

        await AscfFileWriter.WriteFileAsync(sourcePath, ascfPath, options, CancellationToken.None);
        var fileResult = await AscfFileReader
            .DecodeFileToFileWithStoredHashesAsync(ascfPath, fileDecodedPath, readOptions, CancellationToken.None);
        await using var stream = File.OpenRead(ascfPath);
        var streamResult = await AscfFileReader
            .DecodeStreamToFileWithStoredHashesAsync(stream, streamDecodedPath, transform: null, readOptions, CancellationToken.None);
        var arrayResult = AscfFileReader.DecodeToArrayWithStoredHashes(await File.ReadAllBytesAsync(ascfPath), readOptions);
        var expectedBlake3 = ComputeBlake3Hex(raw);

        Assert.Equal(raw.Length, fileResult.RawSize);
        Assert.Equal(raw.Length, streamResult.RawSize);
        Assert.Equal(raw.Length, arrayResult.RawSize);
        Assert.Equal(expectedBlake3, fileResult.StoredHashes.Blake3);
        Assert.Equal(expectedBlake3, streamResult.StoredHashes.Blake3);
        Assert.Equal(expectedBlake3, arrayResult.StoredHashes.Blake3);
        Assert.Equal(raw, await File.ReadAllBytesAsync(fileDecodedPath));
        Assert.Equal(raw, await File.ReadAllBytesAsync(streamDecodedPath));
        Assert.Equal(raw, arrayResult.Raw);
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
    public async Task WriteFileCanUseExplicitStreamId()
    {
        var raw = CreateMixedPayload(512 * 1024 + 91);
        var sourcePath = WriteSource(raw);
        var firstPath = Path.Combine(_testDirectory, "stream-id-first.ascf");
        var secondPath = Path.Combine(_testDirectory, "stream-id-second.ascf");
        var differentPath = Path.Combine(_testDirectory, "stream-id-different.ascf");
        var streamId = Guid.Parse("dcb9e6ad-21fb-4a54-8de9-d2f2f237e870");
        var options = AscfWriterOptions.Default with
        {
            StreamId = streamId
        };

        await AscfFileWriter.WriteFileAsync(sourcePath, firstPath, options, CancellationToken.None);
        await AscfFileWriter.WriteFileAsync(sourcePath, secondPath, options, CancellationToken.None);
        await AscfFileWriter.WriteFileAsync(
            sourcePath,
            differentPath,
            options with { StreamId = Guid.Parse("e0efa483-c6cc-493d-a748-e181ee14e07d") },
            CancellationToken.None);

        Assert.Equal(await File.ReadAllBytesAsync(firstPath), await File.ReadAllBytesAsync(secondPath));
        Assert.NotEqual(await File.ReadAllBytesAsync(firstPath), await File.ReadAllBytesAsync(differentPath));
    }

    [Fact]
    public async Task ReadMetadataReturnsHeaderFields()
    {
        var raw = CreateMixedPayload(192 * 1024 + 31);
        var sourcePath = WriteSource(raw);
        var ascfPath = Path.Combine(_testDirectory, "metadata.ascf");
        var streamId = Guid.Parse("04ed6fd0-0ab8-4264-b12a-d0761a2d36e3");
        var options = AscfWriterOptions.Default with
        {
            RawChunkSize = 64 * 1024,
            RawHashAlgorithms = AscfRawHashAlgorithms.Sha1 | AscfRawHashAlgorithms.Blake3,
            StreamId = streamId
        };

        await AscfFileWriter.WriteFileAsync(sourcePath, ascfPath, options, CancellationToken.None);
        var metadata = AscfFileReader.ReadMetadata(ascfPath);

        Assert.Equal(raw.Length, metadata.RawSize);
        Assert.Equal(new FileInfo(ascfPath).Length, metadata.EncodedSize);
        Assert.Equal(options.RawChunkSize, metadata.RawChunkSize);
        Assert.Equal(AscfFileFormat.GetChunkCount(raw.Length, options.RawChunkSize), metadata.ChunkCount);
        Assert.Equal(streamId, metadata.StreamId);
        Assert.Equal(Convert.ToHexString(SHA1.HashData(raw)), metadata.StoredHashes.RequireHash(AscfRawHashAlgorithms.Sha1));
        Assert.Equal(ComputeBlake3Hex(raw), metadata.StoredHashes.RequireHash(AscfRawHashAlgorithms.Blake3));
    }

    [Fact]
    public async Task ReadResumeInfoUsesCompleteChunkBoundaries()
    {
        var raw = CreateMixedPayload((3 * 64 * 1024) + 37);
        var sourcePath = WriteSource(raw);
        var ascfPath = Path.Combine(_testDirectory, "resume-info.ascf");
        var options = AscfWriterOptions.Default with
        {
            RawChunkSize = 64 * 1024
        };

        await AscfFileWriter.WriteFileAsync(sourcePath, ascfPath, options, CancellationToken.None);
        var metadata = AscfFileReader.ReadMetadata(ascfPath);
        var index = AscfFileReader.ReadChunkIndex(ascfPath);
        var firstChunkEnd = index[0].NextEncodedOffset;
        var lastEntry = index[index.Entries.Count - 1];
        var chunkDataEnd = lastEntry.NextEncodedOffset;

        var beforeHeader = await AscfFileReader.ReadResumeInfoAsync(ascfPath, AscfFileFormat.HeaderSize - 1, CancellationToken.None);
        var insideFirstChunk = await AscfFileReader.ReadResumeInfoAsync(ascfPath, index[0].PayloadOffset, CancellationToken.None);
        var afterFirstChunk = await AscfFileReader.ReadResumeInfoAsync(ascfPath, firstChunkEnd, CancellationToken.None);
        var insideIndex = await AscfFileReader.ReadResumeInfoAsync(ascfPath, metadata.EncodedSize - 1, CancellationToken.None);
        var complete = await AscfFileReader.ReadResumeInfoAsync(ascfPath, metadata.EncodedSize, CancellationToken.None);

        Assert.False(beforeHeader.Position.CanResume);
        Assert.Equal(0, beforeHeader.Position.NextEncodedOffset);
        Assert.True(insideFirstChunk.Position.CanResume);
        Assert.Equal(0, insideFirstChunk.Position.NextChunkIndex);
        Assert.Equal(AscfFileFormat.HeaderSize, insideFirstChunk.Position.NextEncodedOffset);
        Assert.True(afterFirstChunk.Position.CanResume);
        Assert.Equal(1, afterFirstChunk.Position.NextChunkIndex);
        Assert.Equal(firstChunkEnd, afterFirstChunk.Position.NextEncodedOffset);
        Assert.Equal(index[1].RawOffset, afterFirstChunk.Position.NextRawOffset);
        Assert.True(insideIndex.Position.CanResume);
        Assert.Equal(metadata.ChunkCount, insideIndex.Position.NextChunkIndex);
        Assert.Equal(chunkDataEnd, insideIndex.Position.NextEncodedOffset);
        Assert.Equal(metadata.RawSize, insideIndex.Position.NextRawOffset);
        Assert.True(complete.Position.IsComplete);
        Assert.False(complete.Position.CanResume);
        Assert.Equal(metadata.EncodedSize, complete.Position.NextEncodedOffset);
    }

    [Fact]
    public async Task ReadResumeInfoMatchesIndexForLargeFiles()
    {
        var raw = CreateIncompressiblePayload((530 * AscfFileFormat.MinRawChunkBytes) + 123);
        var sourcePath = WriteSource(raw);
        var ascfPath = Path.Combine(_testDirectory, "resume-info-large.ascf");
        var options = AscfWriterOptions.Default with
        {
            RawChunkSize = AscfFileFormat.MinRawChunkBytes
        };

        await AscfFileWriter.WriteStoredRawFileAsync(sourcePath, 0, raw.Length, ascfPath, options, CancellationToken.None);
        var metadata = AscfFileReader.ReadMetadata(ascfPath);
        var index = AscfFileReader.ReadChunkIndex(ascfPath);
        var middle = index.Entries.Count / 2;
        var probes = new[]
        {
            index[0].PayloadOffset,
            index[middle].PayloadOffset + 1,
            index[middle].NextEncodedOffset,
            metadata.EncodedSize - 1
        };

        Assert.True(metadata.ChunkCount > 512);
        foreach (var encodedBytes in probes)
        {
            var expected = index.GetResumePosition(encodedBytes, metadata);
            var actual = await AscfFileReader.ReadResumeInfoAsync(ascfPath, encodedBytes, CancellationToken.None);

            Assert.Equal(metadata, actual.Metadata);
            Assert.Equal(expected, actual.Position);
        }
    }

    [Fact]
    public void DeterministicStreamIdsUseSeedBytes()
    {
        var firstSeed = Encoding.ASCII.GetBytes("stream-id:one");
        var secondSeed = Encoding.ASCII.GetBytes("stream-id:two");

        var first = AscfStreamIds.CreateDeterministic(firstSeed);
        var same = AscfStreamIds.CreateDeterministic(firstSeed);
        var different = AscfStreamIds.CreateDeterministic(secondSeed);
        var fromString = AscfStreamIds.CreateDeterministic("stream-id:one");

        Assert.Equal(first, same);
        Assert.Equal(first, fromString);
        Assert.NotEqual(first, different);
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
    public async Task DecodeToArrayWithHashCanReturnAndValidateRawHashes()
    {
        var raw = CreateMixedPayload(128 * 1024 + 79);
        var sourcePath = WriteSource(raw);
        var ascfPath = Path.Combine(_testDirectory, "array-hash.ascf");
        var writeOptions = AscfWriterOptions.Default with
        {
            RawHashAlgorithms = AscfRawHashAlgorithms.Blake3
        };
        var readOptions = AscfReaderOptions.Default with
        {
            ResultHashAlgorithms = AscfRawHashAlgorithms.Sha1,
            RequiredStoredHashAlgorithms = AscfRawHashAlgorithms.Blake3
        };

        await AscfFileWriter.WriteFileAsync(sourcePath, ascfPath, writeOptions, CancellationToken.None);
        var encoded = await File.ReadAllBytesAsync(ascfPath);
        var decoded = AscfFileReader.DecodeToArrayWithHash(encoded, readOptions);
        var expectedSha1 = Convert.ToHexString(SHA1.HashData(raw));

        Assert.Equal(raw, decoded.Raw);
        Assert.Equal(raw.LongLength, decoded.RawSize);
        Assert.Equal(expectedSha1, decoded.Hashes.RequireHash(AscfRawHashAlgorithms.Sha1));

        encoded[0x70] ^= 0x5A;
        RecomputeFileHeaderChecksum(encoded);

        Assert.Throws<InvalidDataException>(() => AscfFileReader.DecodeToArrayWithHash(encoded, readOptions));
    }

    [Fact]
    public async Task CopyEncodedStreamToFileReturnsStoredHeaderHashes()
    {
        var raw = CreateMixedPayload(256 * 1024 + 67);
        var sourcePath = WriteSource(raw);
        var ascfPath = Path.Combine(_testDirectory, "copy-stored-hashes-source.ascf");
        var copiedPath = Path.Combine(_testDirectory, "copy-stored-hashes.ascf");
        var writeOptions = AscfWriterOptions.Default with
        {
            RawHashAlgorithms = AscfRawHashAlgorithms.Sha1
        };
        var readOptions = AscfReaderOptions.Default with
        {
            ResultHashAlgorithms = AscfRawHashAlgorithms.Blake3
        };

        await AscfFileWriter.WriteFileAsync(sourcePath, ascfPath, writeOptions, CancellationToken.None);
        await using var encodedStream = File.OpenRead(ascfPath);
        var result = await AscfFileReader.CopyEncodedStreamToFileAsync(encodedStream, copiedPath, transform: null, readOptions, CancellationToken.None);
        var storedHashes = AscfFileReader.ReadRawHashes(copiedPath);
        var expectedSha1 = Convert.ToHexString(SHA1.HashData(raw));
        var expectedBlake3 = ComputeBlake3Hex(raw);

        Assert.Equal(expectedBlake3, result.Hashes.RequireHash(AscfRawHashAlgorithms.Blake3));
        Assert.Equal(expectedSha1, result.StoredHashes.RequireHash(AscfRawHashAlgorithms.Sha1));
        Assert.Equal(expectedBlake3, result.StoredHashes.RequireHash(AscfRawHashAlgorithms.Blake3));
        Assert.Equal(result.StoredHashes, storedHashes);
    }

    [Fact]
    public async Task ReaderCanRequireStoredHeaderHash()
    {
        var raw = CreateMixedPayload(128 * 1024 + 17);
        var sourcePath = WriteSource(raw);
        var ascfPath = Path.Combine(_testDirectory, "required-stored-hash-source.ascf");
        var copiedPath = Path.Combine(_testDirectory, "required-stored-hash-copy.ascf");
        var writeOptions = AscfWriterOptions.Default with
        {
            RawHashAlgorithms = AscfRawHashAlgorithms.Sha1
        };
        var readOptions = AscfReaderOptions.Default with
        {
            ResultHashAlgorithms = AscfRawHashAlgorithms.Blake3,
            RequiredStoredHashAlgorithms = AscfRawHashAlgorithms.Blake3
        };

        await AscfFileWriter.WriteFileAsync(sourcePath, ascfPath, writeOptions, CancellationToken.None);
        await using var encodedStream = File.OpenRead(ascfPath);

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            AscfFileReader.CopyEncodedStreamToFileAsync(encodedStream, copiedPath, transform: null, readOptions, CancellationToken.None));
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
        Assert.Equal(result.Hashes.Sha1, result.StoredHashes.Sha1);
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
    public async Task CompleteFileDecodeWithSingleWorkerPreservesRawBytes()
    {
        var raw = CreateMixedPayload((AscfFileFormat.MinRawChunkBytes * 3) + 37);
        var sourcePath = WriteSource(raw);
        var ascfPath = Path.Combine(_testDirectory, "single-worker.ascf");
        var decodedPath = Path.Combine(_testDirectory, "single-worker.raw");
        var writeOptions = AscfWriterOptions.Default with
        {
            RawChunkSize = AscfFileFormat.MinRawChunkBytes
        };
        var readOptions = AscfReaderOptions.Default with
        {
            ParallelDecodeWorkerCount = 1
        };
        var expectedHash = Convert.ToHexString(SHA1.HashData(raw));

        await AscfFileWriter.WriteFileAsync(sourcePath, ascfPath, writeOptions, CancellationToken.None);
        var result = await AscfFileReader.DecodeFileToRawFileAsync(ascfPath, decodedPath, readOptions, CancellationToken.None);

        Assert.Equal(raw.Length, result.RawSize);
        Assert.Equal(expectedHash, result.Hashes.Sha1);
        Assert.Equal(raw, await File.ReadAllBytesAsync(decodedPath));
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
        var ascfPath = Path.Combine(_testDirectory, "source.ascf");
        var wrappedAgainPath = Path.Combine(_testDirectory, "again.llz4");

        await WrappedLz4FileFormat.WriteFromRawFileAsync(sourcePath, wrappedPath, CancellationToken.None);
        await FileFormatTranscoder.ConvertWrappedLz4ToAscfAsync(wrappedPath, ascfPath, CancellationToken.None);
        await FileFormatTranscoder.ConvertAscfFileToWrappedLz4Async(ascfPath, wrappedAgainPath, CancellationToken.None);

        Assert.Equal(raw, AscfFileReader.DecodeToArray(await File.ReadAllBytesAsync(ascfPath)));
        Assert.Equal(raw, WrappedLz4FileFormat.DecodeToArray(await File.ReadAllBytesAsync(wrappedAgainPath)));
        Assert.Empty(Directory.EnumerateFiles(_testDirectory, "*.raw.tmp"));
    }

    [Fact]
    public async Task TranscodeHashResultExposesRequiredHashes()
    {
        var raw = CreateMixedPayload(512 * 1024 + 19);
        var sourcePath = WriteSource(raw);
        var wrappedPath = Path.Combine(_testDirectory, "hash-source.llz4");
        var ascfPath = Path.Combine(_testDirectory, "hash-source.ascf");
        var options = FileFormatTranscodeOptions.Default with
        {
            AscfWriter = AscfWriterOptions.Default with
            {
                RawHashAlgorithms = AscfRawHashAlgorithms.Sha1 | AscfRawHashAlgorithms.Blake3,
                ResultHashAlgorithms = AscfRawHashAlgorithms.Sha1 | AscfRawHashAlgorithms.Blake3
            }
        };

        await WrappedLz4FileFormat.WriteFromRawFileAsync(sourcePath, wrappedPath, CancellationToken.None);
        var result = await FileFormatTranscoder.ConvertWrappedLz4ToAscfWithHashAsync(wrappedPath, ascfPath, options, CancellationToken.None);

        Assert.Equal(Convert.ToHexString(SHA1.HashData(raw)), result.Sha1Hash);
        Assert.Equal(ComputeBlake3Hex(raw), result.Blake3Hash);
    }

    [Fact]
    public async Task WrappedLz4HashHelpersReturnSelectedRawHashes()
    {
        var raw = CreateMixedPayload(512 * 1024 + 47);
        var sourcePath = WriteSource(raw);
        var wrappedPath = Path.Combine(_testDirectory, "wrapped-hashes.llz4");
        var algorithms = AscfRawHashAlgorithms.Sha1 | AscfRawHashAlgorithms.Blake3;

        var writeResult = await WrappedLz4FileFormat
            .WriteFromRawFileWithHashAsync(sourcePath, wrappedPath, algorithms, CancellationToken.None);
        var header = WrappedLz4FileFormat.ReadHeader(new FileInfo(wrappedPath).Length, await ReadHeaderAsync(wrappedPath, WrappedLz4FileFormat.HeaderSize));
        var fileHashes = await WrappedLz4FileFormat
            .ComputeRawHashesAsync(
                wrappedPath,
                header,
                algorithms,
                AscfFileFormat.DefaultBufferSize,
                AscfFileFormat.DefaultBufferSize,
                CancellationToken.None);
        var bufferHashes = WrappedLz4FileFormat.ComputeRawHashes(
            await File.ReadAllBytesAsync(wrappedPath),
            algorithms,
            Lz4FormatOptions.Default);
        var expectedSha1 = Convert.ToHexString(SHA1.HashData(raw));
        var expectedBlake3 = ComputeBlake3Hex(raw);

        Assert.Equal(expectedSha1, writeResult.Hashes.RequireHash(AscfRawHashAlgorithms.Sha1));
        Assert.Equal(expectedBlake3, writeResult.Hashes.RequireHash(AscfRawHashAlgorithms.Blake3));
        Assert.Equal(expectedSha1, fileHashes.Hashes.RequireHash(AscfRawHashAlgorithms.Sha1));
        Assert.Equal(expectedBlake3, fileHashes.Hashes.RequireHash(AscfRawHashAlgorithms.Blake3));
        Assert.Equal(expectedSha1, bufferHashes.Hashes.RequireHash(AscfRawHashAlgorithms.Sha1));
        Assert.Equal(expectedBlake3, bufferHashes.Hashes.RequireHash(AscfRawHashAlgorithms.Blake3));
        Assert.Equal(raw.Length, writeResult.OriginalSize);
        Assert.Equal(raw.Length, fileHashes.RawSize);
        Assert.Equal(raw.Length, bufferHashes.RawSize);
    }

    [Fact]
    public async Task WrappedLz4ExtractKeepsExistingOutputOnFailure()
    {
        var raw = new byte[512 * 1024 + 53];
        var sourcePath = WriteSource(raw);
        var wrappedPath = Path.Combine(_testDirectory, "wrapped-corrupt.llz4");
        var outputPath = Path.Combine(_testDirectory, "wrapped-corrupt.raw");
        byte[] existing = [0x42, 0xAC, 0xCF];

        await WrappedLz4FileFormat.WriteFromRawFileAsync(sourcePath, wrappedPath, CancellationToken.None);
        var encoded = await File.ReadAllBytesAsync(wrappedPath);
        encoded.AsSpan(WrappedLz4FileFormat.HeaderSize).Clear();
        await File.WriteAllBytesAsync(wrappedPath, encoded);
        await File.WriteAllBytesAsync(outputPath, existing);

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            WrappedLz4FileFormat.ExtractToRawFileAsync(wrappedPath, outputPath, CancellationToken.None));

        Assert.Equal(existing, await File.ReadAllBytesAsync(outputPath));
        AssertNoStagingFiles(outputPath);
    }

    [Fact]
    public async Task Lz4StreamExtractKeepsExistingOutputOnFailure()
    {
        var raw = CreateMixedPayload(256 * 1024 + 21);
        var compressedPath = Path.Combine(_testDirectory, "stream-corrupt.lz4");
        var outputPath = Path.Combine(_testDirectory, "stream-corrupt.raw");
        byte[] existing = [0xA5, 0xCF, 0x17];

        await WriteLz4StreamAsync(raw, compressedPath);
        var encoded = await File.ReadAllBytesAsync(compressedPath);
        Array.Resize(ref encoded, encoded.Length / 2);
        await File.WriteAllBytesAsync(compressedPath, encoded);
        await File.WriteAllBytesAsync(outputPath, existing);

        await Assert.ThrowsAnyAsync<Exception>(() =>
            Lz4StreamFormat.ExtractToRawFileAsync(
                compressedPath,
                outputPath,
                AscfFileFormat.DefaultBufferSize,
                AscfFileFormat.DefaultBufferSize,
                CancellationToken.None));

        Assert.Equal(existing, await File.ReadAllBytesAsync(outputPath));
        AssertNoStagingFiles(outputPath);
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
    public async Task WrappedLz4DecodeThresholdsPreserveRawBytes()
    {
        var raw = CreateMixedPayload(512 * 1024 + 61);
        var sourcePath = WriteSource(raw);
        var wrappedPath = Path.Combine(_testDirectory, "wrapped-decode-threshold.llz4");
        var pooledPath = Path.Combine(_testDirectory, "wrapped-decode-pooled.raw");
        var mappedPath = Path.Combine(_testDirectory, "wrapped-decode-mapped.raw");
        var mappedOptions = Lz4FormatOptions.Default with
        {
            MemoryMappedDecodeThreshold = 0
        };

        await WrappedLz4FileFormat.WriteFromRawFileAsync(sourcePath, wrappedPath, CancellationToken.None);
        var header = WrappedLz4FileFormat.ReadHeader(
            new FileInfo(wrappedPath).Length,
            await ReadHeaderAsync(wrappedPath, WrappedLz4FileFormat.HeaderSize));

        await WrappedLz4FileFormat.ExtractToRawFileAsync(wrappedPath, pooledPath, CancellationToken.None);
        await WrappedLz4FileFormat.ExtractToRawFileAsync(wrappedPath, mappedPath, mappedOptions, CancellationToken.None);

        Assert.True(header.InputLength < header.OutputLength);
        Assert.Equal(raw, await File.ReadAllBytesAsync(pooledPath));
        Assert.Equal(raw, await File.ReadAllBytesAsync(mappedPath));
    }

    [Fact]
    public async Task WrappedLz4StreamExtractAppliesTransform()
    {
        await VerifyWrappedLz4StreamExtractAsync(CreateRepeatingPayload(256 * 1024 + 17), expectStoredRaw: false);
        await VerifyWrappedLz4StreamExtractAsync(
            CreateRepeatingPayload(256 * 1024 + 23),
            expectStoredRaw: false,
            Lz4FormatOptions.Default with { MemoryMappedDecodeThreshold = 0 });
        await VerifyWrappedLz4StreamExtractAsync(CreateIncompressiblePayload(256 * 1024 + 19), expectStoredRaw: true);
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

    private static async Task WriteLz4StreamAsync(byte[] raw, string path)
    {
        var output = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, AscfFileFormat.DefaultBufferSize, useAsync: true);
        await using (output.ConfigureAwait(false))
        using (var lz4 = new LZ4Stream(output, LZ4StreamMode.Compress, LZ4StreamFlags.HighCompression))
        {
            await lz4.WriteAsync(raw).ConfigureAwait(false);
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

    private async Task VerifyWrappedLz4StreamExtractAsync(byte[] raw, bool expectStoredRaw, Lz4FormatOptions? options = null)
    {
        var sourcePath = WriteSource(raw);
        var wrappedPath = Path.Combine(_testDirectory, $"{Guid.NewGuid():N}.llz4");
        var outputPath = Path.Combine(_testDirectory, $"{Guid.NewGuid():N}.raw");
        byte[] sentinel = [0xAC, 0xCF, 0x42];
        AscfBufferTransform transform = static buffer =>
        {
            foreach (ref var value in buffer)
            {
                value ^= 0x5A;
            }
        };

        await WrappedLz4FileFormat.WriteFromRawFileAsync(sourcePath, wrappedPath, CancellationToken.None).ConfigureAwait(false);
        var encoded = await File.ReadAllBytesAsync(wrappedPath).ConfigureAwait(false);
        var header = WrappedLz4FileFormat.ReadHeader(encoded.Length, encoded);
        var transformed = encoded.ToArray();
        transform(transformed);
        using var stream = new MemoryStream(transformed.Concat(sentinel).ToArray());

        var rawSize = await WrappedLz4FileFormat
            .ExtractStreamToRawFileAsync(stream, encoded.Length, outputPath, transform, options ?? Lz4FormatOptions.Default, CancellationToken.None)
            .ConfigureAwait(false);

        Assert.Equal(expectStoredRaw, header.InputLength == header.OutputLength);
        Assert.Equal(raw.Length, rawSize);
        Assert.Equal(encoded.Length, stream.Position);
        Assert.Equal(sentinel, stream.ToArray().AsSpan(encoded.Length).ToArray());
        Assert.Equal(raw, await File.ReadAllBytesAsync(outputPath).ConfigureAwait(false));
        AssertNoStagingFiles(outputPath);
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
