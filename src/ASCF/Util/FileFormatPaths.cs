namespace ASCF.Util;

internal static class FileFormatPaths
{
    public static StagedFile CreateStagedFile(string outputPath)
        => new(outputPath, CreateStagingPath(outputPath));

    public static FileStream OpenSequentialStagingWrite(string stagingPath, int bufferSize)
        => new(
            stagingPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            bufferSize,
            FileOptions.Asynchronous | FileOptions.SequentialScan);

    public static FileStream OpenRandomStagingReadWrite(string stagingPath, int bufferSize)
        => new(
            stagingPath,
            FileMode.CreateNew,
            FileAccess.ReadWrite,
            FileShare.None,
            bufferSize,
            FileOptions.Asynchronous | FileOptions.RandomAccess);

    public static void EnsureOutputDirectory(string outputPath)
    {
        var outputDirectory = Path.GetDirectoryName(Path.GetFullPath(outputPath));
        if (!string.IsNullOrEmpty(outputDirectory))
        {
            Directory.CreateDirectory(outputDirectory);
        }
    }

    private static string CreateStagingPath(string outputPath)
    {
        EnsureOutputDirectory(outputPath);

        var fullPath = Path.GetFullPath(outputPath);
        var directory = Path.GetDirectoryName(fullPath);
        var fileName = Path.GetFileName(fullPath);
        if (string.IsNullOrEmpty(directory) || string.IsNullOrEmpty(fileName))
        {
            throw new ArgumentException("Output path must include a file name.", nameof(outputPath));
        }

        return Path.Combine(directory, $".{fileName}.{Guid.NewGuid():N}.tmp");
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

    private static void TryDeleteFile(string path)
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

        public string StagingPath { get; }

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
