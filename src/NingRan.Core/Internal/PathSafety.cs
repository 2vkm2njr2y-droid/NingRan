namespace NingRan.Core.Internal;

internal static class PathSafety
{
    private static readonly HashSet<string> ReservedNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        "COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³",
    };

    public static string ValidateNameSegment(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value is "." or "..")
        {
            throw new NingRanException("文件或文件夹名称不能为空，也不能使用点号路径。");
        }

        if (value.EndsWith(' ') || value.EndsWith('.') ||
            value.Any(character => character < 32 || "<>:\"/\\|?*".Contains(character)))
        {
            throw new NingRanException($"名称“{value}”包含 Windows 不支持的字符。");
        }

        var deviceName = value.Split('.', 2)[0];
        if (ReservedNames.Contains(deviceName))
        {
            throw new NingRanException($"名称“{value}”是 Windows 保留名称，无法安全处理。");
        }

        return value;
    }

    public static string NormalizeRelativePath(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || Path.IsPathRooted(value))
        {
            throw new NingRanException("加密文件包含不安全的路径。");
        }

        var parts = value.Replace('\\', '/').Split('/');
        if (parts.Length == 0 || parts.Any(string.IsNullOrEmpty))
        {
            throw new NingRanException("加密文件包含不安全的路径。");
        }

        foreach (var part in parts)
        {
            ValidateNameSegment(part);
        }

        return string.Join('/', parts);
    }

    public static string GetSafeDestination(string stagingRoot, string relativePath)
    {
        var normalized = NormalizeRelativePath(relativePath);
        var root = Path.GetFullPath(stagingRoot);
        var rootWithSeparator = Path.EndsInDirectorySeparator(root)
            ? root
            : root + Path.DirectorySeparatorChar;
        var combined = Path.GetFullPath(Path.Combine(root, normalized.Replace('/', Path.DirectorySeparatorChar)));
        if (!combined.StartsWith(rootWithSeparator, StringComparison.OrdinalIgnoreCase))
        {
            throw new NingRanException("加密文件包含试图越过保存位置的不安全路径。");
        }

        return combined;
    }

    public static bool IsReparsePoint(string path)
    {
        try
        {
            return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new NingRanException($"无法检查路径是否安全：{path}", exception);
        }
    }

    public static bool IsWithinDirectory(string candidatePath, string directoryPath)
    {
        var candidate = Path.GetFullPath(candidatePath);
        var directory = Path.GetFullPath(directoryPath);
        var directoryWithSeparator = Path.EndsInDirectorySeparator(directory)
            ? directory
            : directory + Path.DirectorySeparatorChar;
        return candidate.StartsWith(directoryWithSeparator, StringComparison.OrdinalIgnoreCase);
    }

    public static string GetUniquePath(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path))
        {
            return path;
        }

        var directory = Path.GetDirectoryName(path)
            ?? throw new NingRanException("保存位置不正确。");
        var name = Path.GetFileNameWithoutExtension(path);
        var extension = Path.GetExtension(path);
        for (var index = 1; ; index++)
        {
            var candidate = Path.Combine(directory, $"{name} ({index}){extension}");
            if (!File.Exists(candidate) && !Directory.Exists(candidate))
            {
                return candidate;
            }
        }
    }
}
