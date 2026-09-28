using System.Text.Json;
using System.IO;
using System.Text.RegularExpressions;

namespace NingRan.Windows;

/// <summary>诊断日志仅保留文件名、数量和结果，避免记录解锁材料或完整路径。</summary>
internal static class OperationLog
{
    public static void Append(string operation, string? path, string result, string? details = null)
    {
        try
        {
            Directory.CreateDirectory(DirectoryPath);
            var entry = new OperationLogEntry(DateTimeOffset.UtcNow, operation,
                string.IsNullOrWhiteSpace(path) ? null : Path.GetFileName(path), result, SanitizeDetails(details));
            File.AppendAllText(LogPath, JsonSerializer.Serialize(entry) + Environment.NewLine);
        }
        catch { /* 日志写入失败不能影响实际操作。 */ }
    }

    private static string? SanitizeDetails(string? details)
    {
        if (string.IsNullOrWhiteSpace(details)) return null;
        var normalized = details.Replace('\r', ' ').Replace('\n', ' ');
        normalized = Regex.Replace(normalized, @"(?i)(?:[a-z]:\\|\\\\)[^;|]*", "[已隐藏完整路径]");
        return normalized.Length > 1_000 ? normalized[..1_000] : normalized;
    }

    public static void Export(string destination)
    {
        if (!File.Exists(LogPath) || new FileInfo(LogPath).Length == 0)
        {
            throw new InvalidOperationException("暂时没有可导出的操作记录。");
        }

        File.Copy(LogPath, destination, overwrite: false);
    }

    private static string DirectoryPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NingRan", "OperationLogs");
    private static string LogPath => Path.Combine(DirectoryPath, "operations.jsonl");
}

internal sealed record OperationLogEntry(DateTimeOffset OccurredAtUtc, string Operation, string? ArchiveName,
    string Result, string? Details);
