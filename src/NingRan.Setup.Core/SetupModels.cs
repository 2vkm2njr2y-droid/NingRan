using System.Text.Json;
using System.Text.Json.Serialization;

namespace NingRan.Setup;

public static class SetupProduct
{
#if NINGRAN_MEDIA_PLAYER
    public const string Id = "NingRan.MediaPlayer";
    public const string Name = "凝然媒体播放器";
    public const string MainExecutableName = "NingRan.MediaPlayer.exe";
    public const string UninstallerName = "卸载凝然媒体播放器.exe";
    public const string UninstallRegistryPath =
        @"Software\Microsoft\Windows\CurrentVersion\Uninstall\NingRanMediaPlayer";
    public static bool IsMediaPlayer => true;
    public static bool SupportsFileAssociations => true;
    public static bool HasUserData => false;
#else
    public const string Id = "NingRan.Encryption";
    public const string Name = "凝然加密";
    public const string MainExecutableName = "NingRan.exe";
    public const string UninstallerName = "卸载凝然加密.exe";
    public const string UninstallRegistryPath =
        @"Software\Microsoft\Windows\CurrentVersion\Uninstall\NingRan";
    public static bool IsMediaPlayer => false;
    public static bool SupportsFileAssociations => true;
    public static bool HasUserData => true;
#endif
    public const string Version = "6.1.16";
    public const string StateFileName = "install-state.json";
    public const string PayloadManifestName = "payload-manifest.json";

    public static string DefaultInstallPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        Name);

    public static string LegacyInstallPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Programs",
        Name);

    public static string UserDataPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        Id);
}

public sealed record SetupOptions(
    string InstallPath,
    bool CreateDesktopShortcut,
    bool CreateStartMenuShortcut,
    bool AssociateSupportedFiles,
    string Language = "zh");

public sealed record AssociationBackup(string Extension, string? PreviousProgramId);

public sealed class InstallState
{
    public string ProductId { get; init; } = SetupProduct.Id;

    public string Version { get; init; } = SetupProduct.Version;

    public required string InstallPath { get; init; }

    public string? MigratedFromPath { get; init; }

    public bool DesktopShortcut { get; init; }

    public bool StartMenuShortcut { get; init; }

    public bool FileAssociations { get; init; }

    public string Language { get; init; } = "zh";

    public IReadOnlyList<AssociationBackup> AssociationBackups { get; init; } = [];

    public DateTimeOffset InstalledAtUtc { get; init; } = DateTimeOffset.UtcNow;

    public static InstallState? TryLoad(string installPath)
    {
        try
        {
            var normalizedPath = Path.GetFullPath(installPath);
            var statePath = Path.Combine(normalizedPath, SetupProduct.StateFileName);
            if (!File.Exists(statePath))
            {
                return null;
            }

            var json = File.ReadAllText(statePath);
            var state = JsonSerializer.Deserialize(json, SetupJsonContext.Default.InstallState);
            if (state is null ||
                !string.Equals(state.ProductId, SetupProduct.Id, StringComparison.Ordinal) ||
                !string.Equals(Path.GetFullPath(state.InstallPath), normalizedPath, StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            return state;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException or ArgumentException)
        {
            return null;
        }
    }

    public void Save(string directory)
    {
        var path = Path.Combine(directory, SetupProduct.StateFileName);
        File.WriteAllText(path, JsonSerializer.Serialize(this, SetupJsonContext.Default.InstallState));
    }
}

public sealed record PayloadFile(string Path, long Size, string Sha256);

public sealed class PayloadManifest
{
    public string ProductId { get; init; } = SetupProduct.Id;

    public string Version { get; init; } = SetupProduct.Version;

    public IReadOnlyList<PayloadFile> Files { get; init; } = [];
}

public sealed record UserDataInventory(long FileCount, long DirectoryCount, long TotalBytes)
{
    public bool IsEmpty => FileCount == 0 && DirectoryCount == 0;
}

public sealed record SetupProgress(int Percentage, string Message);

[JsonSourceGenerationOptions(WriteIndented = true, PropertyNameCaseInsensitive = true)]
[JsonSerializable(typeof(InstallState))]
[JsonSerializable(typeof(PayloadManifest))]
internal partial class SetupJsonContext : JsonSerializerContext;
