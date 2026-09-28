using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace NingRan.Windows;

/// <summary>
/// 最近交付只保存包路径、创建/到期时间和自动检查结果，并使用当前 Windows 用户保护。
/// 不保存密码、密匙、原始资料路径或包内文件清单。
/// </summary>
internal sealed class RecentDeliveryHistory
{
    private const int MaximumEntries = 10;
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("NingRan.RecentDeliveries.v1");
    private readonly string _filePath;

    public RecentDeliveryHistory()
        : this(DefaultFilePath)
    {
    }

    internal RecentDeliveryHistory(string filePath)
    {
        _filePath = Path.GetFullPath(filePath);
    }

    public IReadOnlyList<RecentDeliveryItem> Load()
    {
        try
        {
            if (!File.Exists(_filePath)) return [];
            var encrypted = File.ReadAllBytes(_filePath);
            var json = ProtectedData.Unprotect(encrypted, Entropy, DataProtectionScope.CurrentUser);
            try { return JsonSerializer.Deserialize<List<RecentDeliveryItem>>(json) ?? []; }
            finally { CryptographicOperations.ZeroMemory(json); }
        }
        catch
        {
            return [];
        }
    }

    public void Add(string packagePath, DateTimeOffset createdAtUtc, DateTimeOffset? expiresAtUtc,
        bool verificationPassed)
    {
        var fullPath = Path.GetFullPath(packagePath);
        var entries = Load()
            .Where(entry => !string.Equals(entry.Path, fullPath, StringComparison.OrdinalIgnoreCase))
            .Prepend(new RecentDeliveryItem(fullPath, createdAtUtc, expiresAtUtc, verificationPassed))
            .Take(MaximumEntries)
            .ToArray();
        Save(entries);
    }

    public void Clear() => Save([]);

    private void Save(IReadOnlyList<RecentDeliveryItem> entries)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_filePath)!);
            var json = JsonSerializer.SerializeToUtf8Bytes(entries);
            try
            {
                var encrypted = ProtectedData.Protect(json, Entropy, DataProtectionScope.CurrentUser);
                try { File.WriteAllBytes(_filePath, encrypted); }
                finally { CryptographicOperations.ZeroMemory(encrypted); }
            }
            finally { CryptographicOperations.ZeroMemory(json); }
        }
        catch
        {
            // 最近记录只是便利功能，失败不能影响已经生成的交付包。
        }
    }

    private static string DirectoryPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NingRan", "History");
    private static string DefaultFilePath => Path.Combine(DirectoryPath, "recent-deliveries.dat");
}

internal sealed record RecentDeliveryItem(
    string Path,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset? ExpiresAtUtc,
    bool VerificationPassed)
{
    public string DisplayText =>
        $"{System.IO.Path.GetFileName(Path)}  ·  " +
        $"{(ExpiresAtUtc is { } expires && DateTimeOffset.UtcNow >= expires ? "已过期" : "有效")}  ·  " +
        $"{(VerificationPassed ? "检查通过" : "检查失败")}";
}
