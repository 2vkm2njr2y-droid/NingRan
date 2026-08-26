using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace NingRan.Setup;

public static class ShellIntegration
{
    private const string ClassesPath = @"Software\Classes";
#if NINGRAN_MEDIA_PLAYER
    private static readonly AssociationDefinition[] Associations =
    [
        new(".mp3", "NingRan.MediaPlayer.Mp3", "凝然媒体播放器 MP3 音频", @"Assets\AppIcon.ico"),
        new(".wav", "NingRan.MediaPlayer.Wav", "凝然媒体播放器 WAV 音频", @"Assets\AppIcon.ico"),
        new(".m4a", "NingRan.MediaPlayer.M4a", "凝然媒体播放器 M4A 音频", @"Assets\AppIcon.ico"),
        new(".aac", "NingRan.MediaPlayer.Aac", "凝然媒体播放器 AAC 音频", @"Assets\AppIcon.ico"),
        new(".flac", "NingRan.MediaPlayer.Flac", "凝然媒体播放器 FLAC 音频", @"Assets\AppIcon.ico"),
        new(".ogg", "NingRan.MediaPlayer.Ogg", "凝然媒体播放器 OGG 音频", @"Assets\AppIcon.ico"),
        new(".wma", "NingRan.MediaPlayer.Wma", "凝然媒体播放器 WMA 音频", @"Assets\AppIcon.ico"),
        new(".mp4", "NingRan.MediaPlayer.Mp4", "凝然媒体播放器 MP4 视频", @"Assets\AppIcon.ico"),
        new(".m4v", "NingRan.MediaPlayer.M4v", "凝然媒体播放器 M4V 视频", @"Assets\AppIcon.ico"),
        new(".mov", "NingRan.MediaPlayer.Mov", "凝然媒体播放器 MOV 视频", @"Assets\AppIcon.ico"),
        new(".avi", "NingRan.MediaPlayer.Avi", "凝然媒体播放器 AVI 视频", @"Assets\AppIcon.ico"),
        new(".wmv", "NingRan.MediaPlayer.Wmv", "凝然媒体播放器 WMV 视频", @"Assets\AppIcon.ico"),
        new(".webm", "NingRan.MediaPlayer.Webm", "凝然媒体播放器 WEBM 视频", @"Assets\AppIcon.ico"),
        new(".mkv", "NingRan.MediaPlayer.Mkv", "凝然媒体播放器 MKV 视频", @"Assets\AppIcon.ico"),
        new(".mpeg", "NingRan.MediaPlayer.Mpeg", "凝然媒体播放器 MPEG 视频", @"Assets\AppIcon.ico"),
        new(".mpg", "NingRan.MediaPlayer.Mpg", "凝然媒体播放器 MPG 视频", @"Assets\AppIcon.ico"),
        new(".3gp", "NingRan.MediaPlayer.ThreeGp", "凝然媒体播放器 3GP 视频", @"Assets\AppIcon.ico"),
        new(".ts", "NingRan.MediaPlayer.Ts", "凝然媒体播放器 TS 视频", @"Assets\AppIcon.ico"),
        new(".mpv", "NingRan.MediaPlayer.Mpv", "凝然媒体播放器 MPV 视频", @"Assets\AppIcon.ico"),
    ];
#else
    private static readonly AssociationDefinition[] Associations =
    [
        new(".nrenc", "NingRan.EncryptedFile", "凝然加密文件", @"Assets\EncryptedFileIcon.ico", "NingRan encrypted file"),
        new(".nrid", "NingRan.IdentityBackup", "凝然身份备份", @"Assets\IdentityBackupIcon.ico", "NingRan identity backup"),
        new(".nrpub", "NingRan.PublicIdentity", "凝然公开身份", @"Assets\PublicIdentityIcon.ico", "NingRan public identity"),
    ];
#endif

    public static string? FindInstalledPath()
    {
        foreach (var hive in GetUninstallHives())
        {
            using var key = hive.OpenSubKey(SetupProduct.UninstallRegistryPath, writable: false);
            var value = key?.GetValue("InstallLocation") as string;
            if (string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            try
            {
                var path = Path.GetFullPath(value);
                if (SetupPathSafety.IsSupportedInstallPath(path) && InstallState.TryLoad(path) is not null)
                {
                    return path;
                }
            }
            catch (Exception exception) when (exception is ArgumentException or IOException or UnauthorizedAccessException)
            {
                // 继续检查另一个注册表位置。
            }
        }

        return null;
    }

    public static IReadOnlyList<AssociationBackup> CaptureAssociationBackups()
    {
        var result = new List<AssociationBackup>(Associations.Length);
        foreach (var association in Associations)
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                $@"{ClassesPath}\{association.Extension}",
                writable: false);
            result.Add(new AssociationBackup(
                association.Extension,
                key?.GetValue(null) as string));
        }

        return result;
    }

    public static void Apply(InstallState state)
    {
        var executable = Path.Combine(state.InstallPath, SetupProduct.MainExecutableName);
        var uninstaller = Path.Combine(state.InstallPath, SetupProduct.UninstallerName);
        var displayName = GetDisplayName(state);
        RemoveShortcutsForTarget(executable);
        if (state.DesktopShortcut)
        {
            CreateShortcut(GetDesktopShortcutPath(displayName), executable, state.InstallPath, displayName);
        }

        if (state.StartMenuShortcut)
        {
            CreateShortcut(GetStartMenuShortcutPath(displayName), executable, state.InstallPath, displayName);
        }

        if (state.FileAssociations)
        {
            foreach (var association in Associations)
            {
                var description = GetAssociationDescription(association, state);
                using (var programKey = Registry.CurrentUser.CreateSubKey(
                           $@"{ClassesPath}\{association.ProgramId}",
                           writable: true))
                {
                    programKey.SetValue(null, description, RegistryValueKind.String);
                    programKey.SetValue("FriendlyTypeName", description, RegistryValueKind.String);
                }

                using (var iconKey = Registry.CurrentUser.CreateSubKey(
                           $@"{ClassesPath}\{association.ProgramId}\DefaultIcon",
                           writable: true))
                {
                    var associationIcon = Path.Combine(state.InstallPath, association.IconRelativePath);
                    iconKey.SetValue(null, $"\"{associationIcon}\",0", RegistryValueKind.String);
                }

                using (var commandKey = Registry.CurrentUser.CreateSubKey(
                           $@"{ClassesPath}\{association.ProgramId}\shell\open\command",
                           writable: true))
                {
                    commandKey.SetValue(null, $"\"{executable}\" \"%1\"", RegistryValueKind.String);
                }

                using var extensionKey = Registry.CurrentUser.CreateSubKey(
                    $@"{ClassesPath}\{association.Extension}",
                    writable: true);
                extensionKey.SetValue(null, association.ProgramId, RegistryValueKind.String);
            }
        }

        using (var uninstallKey = GetUninstallHive(state).CreateSubKey(
                   SetupProduct.UninstallRegistryPath,
                   writable: true))
        {
            uninstallKey.SetValue("DisplayName", displayName, RegistryValueKind.String);
            uninstallKey.SetValue("DisplayVersion", SetupProduct.Version, RegistryValueKind.String);
            uninstallKey.SetValue("Publisher", SetupProduct.IsMediaPlayer || state.Language != "en" ? "凝然" : "NingRan", RegistryValueKind.String);
            uninstallKey.SetValue("InstallLocation", state.InstallPath, RegistryValueKind.String);
            uninstallKey.SetValue("DisplayIcon", $"\"{executable}\",0", RegistryValueKind.String);
            uninstallKey.SetValue("UninstallString", $"\"{uninstaller}\" --uninstall", RegistryValueKind.String);
            uninstallKey.SetValue("NoModify", 1, RegistryValueKind.DWord);
            uninstallKey.SetValue("NoRepair", 1, RegistryValueKind.DWord);
            uninstallKey.SetValue("EstimatedSize", GetEstimatedSizeKib(state.InstallPath), RegistryValueKind.DWord);
        }

        NotifyShellChanged();
    }

    public static void Remove(InstallState state, bool removeUninstallEntry = true)
    {
        var executable = Path.Combine(state.InstallPath, SetupProduct.MainExecutableName);
        RemoveShortcutsForTarget(executable);

        foreach (var association in Associations)
        {
            using (var extensionKey = Registry.CurrentUser.OpenSubKey(
                       $@"{ClassesPath}\{association.Extension}",
                       writable: true))
            {
                if (string.Equals(
                        extensionKey?.GetValue(null) as string,
                        association.ProgramId,
                        StringComparison.Ordinal))
                {
                    var previous = state.AssociationBackups.FirstOrDefault(backup =>
                        string.Equals(backup.Extension, association.Extension, StringComparison.OrdinalIgnoreCase));
                    if (string.IsNullOrWhiteSpace(previous?.PreviousProgramId))
                    {
                        extensionKey?.DeleteValue(string.Empty, throwOnMissingValue: false);
                    }
                    else
                    {
                        extensionKey?.SetValue(null, previous.PreviousProgramId, RegistryValueKind.String);
                    }
                }
            }

            Registry.CurrentUser.DeleteSubKeyTree(
                $@"{ClassesPath}\{association.ProgramId}",
                throwOnMissingSubKey: false);
        }

        if (removeUninstallEntry)
        {
            var isLegacy = SetupPathSafety.IsLegacyInstallPath(state.InstallPath);
            var hive = isLegacy ? Registry.CurrentUser : Registry.LocalMachine;
            using (var uninstallKey = hive.OpenSubKey(
                       SetupProduct.UninstallRegistryPath,
                       writable: false))
            {
                var recordedPath = uninstallKey?.GetValue("InstallLocation") as string;
                if (string.Equals(recordedPath, state.InstallPath, StringComparison.OrdinalIgnoreCase))
                {
                    uninstallKey?.Dispose();
                    hive.DeleteSubKeyTree(
                        SetupProduct.UninstallRegistryPath,
                        throwOnMissingSubKey: false);
                }
            }

            // 旧版安装曾把卸载登记写入当前用户注册表；升级或卸载时一并清理同路径残留。
            if (!isLegacy)
            {
                using var legacyKey = Registry.CurrentUser.OpenSubKey(
                    SetupProduct.UninstallRegistryPath,
                    writable: false);
                if (string.Equals(legacyKey?.GetValue("InstallLocation") as string, state.InstallPath, StringComparison.OrdinalIgnoreCase))
                {
                    legacyKey?.Dispose();
                    Registry.CurrentUser.DeleteSubKeyTree(
                        SetupProduct.UninstallRegistryPath,
                        throwOnMissingSubKey: false);
                }
            }
        }

        NotifyShellChanged();
    }

    private static void CreateShortcut(string shortcutPath, string targetPath, string workingDirectory, string displayName)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(shortcutPath)!);
        var shellType = Type.GetTypeFromProgID("WScript.Shell")
            ?? throw new InvalidOperationException("Windows 无法创建快捷方式。");
        object? shell = null;
        object? shortcut = null;
        try
        {
            shell = Activator.CreateInstance(shellType);
            dynamic dynamicShell = shell ?? throw new InvalidOperationException("Windows 无法创建快捷方式。");
            shortcut = dynamicShell.CreateShortcut(shortcutPath);
            dynamic dynamicShortcut = shortcut;
            dynamicShortcut.TargetPath = targetPath;
            dynamicShortcut.WorkingDirectory = workingDirectory;
            dynamicShortcut.IconLocation = $"{targetPath},0";
            dynamicShortcut.Description = displayName;
            dynamicShortcut.Save();
        }
        finally
        {
            if (shortcut is not null && Marshal.IsComObject(shortcut))
            {
                Marshal.FinalReleaseComObject(shortcut);
            }

            if (shell is not null && Marshal.IsComObject(shell))
            {
                Marshal.FinalReleaseComObject(shell);
            }
        }
    }

    private static void RemoveShortcutsForTarget(string targetPath)
    {
        TryDeleteShortcut(GetDesktopShortcutPath(SetupProduct.Name), targetPath);
        TryDeleteShortcut(GetStartMenuShortcutPath(SetupProduct.Name), targetPath);
        if (!SetupProduct.IsMediaPlayer)
        {
            TryDeleteShortcut(GetDesktopShortcutPath("NingRan Encryption"), targetPath);
            TryDeleteShortcut(GetStartMenuShortcutPath("NingRan Encryption"), targetPath);
        }
    }

    private static void TryDeleteShortcut(string shortcutPath, string expectedTarget)
    {
        if (!File.Exists(shortcutPath))
        {
            return;
        }

        var shellType = Type.GetTypeFromProgID("WScript.Shell");
        object? shell = null;
        object? shortcut = null;
        try
        {
            shell = shellType is null ? null : Activator.CreateInstance(shellType);
            if (shell is null)
            {
                return;
            }

            dynamic dynamicShell = shell;
            shortcut = dynamicShell.CreateShortcut(shortcutPath);
            dynamic dynamicShortcut = shortcut;
            var actualTarget = (string?)dynamicShortcut.TargetPath;
            if (string.Equals(
                    Path.GetFullPath(actualTarget ?? string.Empty),
                    Path.GetFullPath(expectedTarget),
                    StringComparison.OrdinalIgnoreCase))
            {
                File.Delete(shortcutPath);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or COMException)
        {
            // 不删除无法确认归属的快捷方式。
        }
        finally
        {
            if (shortcut is not null && Marshal.IsComObject(shortcut))
            {
                Marshal.FinalReleaseComObject(shortcut);
            }

            if (shell is not null && Marshal.IsComObject(shell))
            {
                Marshal.FinalReleaseComObject(shell);
            }
        }
    }

    private static int GetEstimatedSizeKib(string directory)
    {
        try
        {
            var bytes = Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories)
                .Sum(path => new FileInfo(path).Length);
            return (int)Math.Clamp((bytes + 1023) / 1024, 0, int.MaxValue);
        }
        catch
        {
            return 0;
        }
    }

    private static string GetDesktopShortcutPath(string displayName) => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
        $"{displayName}.lnk");

    private static string GetStartMenuShortcutPath(string displayName) => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.Programs),
        $"{displayName}.lnk");

    private static string GetDisplayName(InstallState state) =>
        SetupProduct.IsMediaPlayer || !string.Equals(state.Language, "en", StringComparison.OrdinalIgnoreCase)
            ? SetupProduct.Name
            : "NingRan Encryption";

    private static string GetAssociationDescription(AssociationDefinition association, InstallState state) =>
        SetupProduct.IsMediaPlayer || !string.Equals(state.Language, "en", StringComparison.OrdinalIgnoreCase)
            ? association.Description
            : association.DescriptionEnglish ?? association.Description;

    private static void NotifyShellChanged() => SHChangeNotify(0x08000000, 0, IntPtr.Zero, IntPtr.Zero);

    private static RegistryKey GetUninstallHive(InstallState state) =>
        SetupPathSafety.IsLegacyInstallPath(state.InstallPath)
            ? Registry.CurrentUser
            : Registry.LocalMachine;

    private static IEnumerable<RegistryKey> GetUninstallHives()
    {
        yield return Registry.LocalMachine;
        yield return Registry.CurrentUser;
    }

    [DllImport("shell32.dll")]
    private static extern void SHChangeNotify(uint eventId, uint flags, IntPtr item1, IntPtr item2);

    private sealed record AssociationDefinition(
        string Extension,
        string ProgramId,
        string Description,
        string IconRelativePath,
        string? DescriptionEnglish = null);
}
