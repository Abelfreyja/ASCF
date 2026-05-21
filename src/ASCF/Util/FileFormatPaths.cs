namespace ASCF.Util;

internal static class FileFormatPaths
{
    public static void EnsureOutputDirectory(string outputPath)
    {
        var outputDirectory = Path.GetDirectoryName(outputPath);
        if (!string.IsNullOrEmpty(outputDirectory))
        {
            Directory.CreateDirectory(outputDirectory);
        }
    }
}
