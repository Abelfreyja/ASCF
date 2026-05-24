namespace ASCF.Util;

internal static class FileFormatPaths
{
    public static StagedFile CreateStagedFile(string outputPath)
        => new(outputPath, CreateStagingPath(outputPath));

    public static string CreateSiblingTempPath(string outputPath, string extension)
    {
        if (string.IsNullOrWhiteSpace(extension))
        {
            throw new ArgumentException("Temp file extension must not be empty.", nameof(extension));
        }

        EnsureOutputDirectory(outputPath);

        var fullPath = Path.GetFullPath(outputPath);
        var directory = Path.GetDirectoryName(fullPath);
        var fileName = Path.GetFileName(fullPath);
        if (string.IsNullOrEmpty(directory) || string.IsNullOrEmpty(fileName))
        {
            throw new ArgumentException("Output path must include a file name.", nameof(outputPath));
        }

        var normalizedExtension = extension.StartsWith('.') ? extension : "." + extension;
        return Path.Combine(directory, $".{fileName}.{Guid.NewGuid():N}{normalizedExtension}");
    }

    public static void EnsureOutputDirectory(string outputPath)
    {
        var outputDirectory = Path.GetDirectoryName(Path.GetFullPath(outputPath));
        if (!string.IsNullOrEmpty(outputDirectory))
        {
            Directory.CreateDirectory(outputDirectory);
        }
    }

    private static string CreateStagingPath(string outputPath)
        => CreateSiblingTempPath(outputPath, ".tmp");

    private static FileStream OpenStagingWrite(
        string stagingPath,
        FileAccess access,
        int bufferSize,
        FileOptions options)
    {
        FileFormatBuffers.ValidateBufferSize(bufferSize, nameof(bufferSize));

        return new FileStream(
            stagingPath,
            new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = access,
                Share = FileShare.None,
                BufferSize = bufferSize,
                Options = options
            });
    }

    private static void CommitStagedFile(string stagingPath, string outputPath)
    {
        var fullPath = Path.GetFullPath(outputPath);
        if (File.Exists(fullPath))
        {
            File.Replace(stagingPath, fullPath, destinationBackupFileName: null);
            return;
        }

        File.Move(stagingPath, fullPath);
    }

    public static void TryDeleteFile(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch
        {
            // best effort cleanup after a failed file write
        }
    }

    internal sealed class StagedFile : IDisposable
    {
        private readonly string _outputPath;
        private bool _committed;

        internal StagedFile(string outputPath, string path)
        {
            _outputPath = outputPath;
            StagingPath = path;
        }

        private string StagingPath { get; }

        public FileStream OpenSequentialWrite(int bufferSize)
            => OpenStagingWrite(
                StagingPath,
                FileAccess.Write,
                bufferSize,
                FileOptions.Asynchronous | FileOptions.SequentialScan);

        public FileStream OpenRandomReadWrite(int bufferSize)
            => OpenStagingWrite(
                StagingPath,
                FileAccess.ReadWrite,
                bufferSize,
                FileOptions.Asynchronous | FileOptions.RandomAccess);

        public void Commit()
        {
            CommitStagedFile(StagingPath, _outputPath);
            _committed = true;
        }

        public void Dispose()
        {
            if (!_committed)
            {
                TryDeleteFile(StagingPath);
            }
        }
    }
}
