using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.IO;

namespace NingRan.Windows;

/// <summary>只保存成功打开过的归档路径；密码和密匙材料从不进入历史文件。</summary>
internal sealed class RecentArchiveHistory
{
    private const int MaximumEntries = 10;
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("NingRan.RecentArchives.v1");

    public IReadOnlyList<RecentArchiveItem> Load()
    {
        try
        {
            if (!File.Exists(FilePath)) return [];
            var encrypted = File.ReadAllBytes(FilePath);
            var json = ProtectedData.Unprotect(encrypted, Entropy, DataProtectionScope.CurrentUser);
            try
            {
                return JsonSerializer.Deserialize<List<RecentArchiveItem>>(json) ?? [];
            }
            finally
            {
                CryptographicOperations.ZeroMemory(json);
            }
        }
        catch
        {
            // 损坏或来自其他 Windows 用户的历史不能影响主程序。
            return [];
        }
    }

    public void Add(string path)
    {
        var fullPath = Path.GetFullPath(path);
        var entries = Load()
            .Where(entry => !string.Equals(entry.Path, fullPath, StringComparison.OrdinalIgnoreCase))
            .Prepend(new RecentArchiveItem(fullPath, DateTimeOffset.UtcNow))
            .Take(MaximumEntries)
            .ToArray();
        Save(entries);
    }

    public void Remove(string path) => Save(Load()
        .Where(entry => !string.Equals(entry.Path, path, StringComparison.OrdinalIgnoreCase))
        .ToArray());

    public void Clear() => Save([]);

    private static void Save(IReadOnlyList<RecentArchiveItem> entries)
    {
        try
        {
            Directory.CreateDirectory(DirectoryPath);
            var json = JsonSerializer.SerializeToUtf8Bytes(entries);
            try
            {
                var encrypted = ProtectedData.Protect(json, Entropy, DataProtectionScope.CurrentUser);
                try { File.WriteAllBytes(FilePath, encrypted); }
                finally { CryptographicOperations.ZeroMemory(encrypted); }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(json);
            }
        }
        catch
        {
            // 历史只是便利功能，写入失败不应阻止用户打开文件。
        }
    }

    private static string DirectoryPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NingRan", "History");
    private static string FilePath => Path.Combine(DirectoryPath, "recent-archives.dat");
}

internal sealed record RecentArchiveItem(string Path, DateTimeOffset OpenedAtUtc);
