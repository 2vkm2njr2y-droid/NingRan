using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace NingRan.Setup;

public static class ShellIntegration
{
    private const string ClassesPath = @"Software\Classes";
#if NINGRAN_MEDIA_PLAYER
    private const string MediaPlayerProgramId = "Ningran.MediaPlayer";
    private static readonly AssociationDefinition[] Associations =
    [
        new(".mp3", MediaPlayerProgramId, "凝然媒体播放器", @"Assets\AppIcon.ico"),
        new(".wav", MediaPlayerProgramId, "凝然媒体播放器", @"Assets\AppIcon.ico"),
        new(".m4a", MediaPlayerProgramId, "凝然媒体播放器", @"Assets\AppIcon.ico"),
        new(".aac", MediaPlayerProgramId, "凝然媒体播放器", @"Assets\AppIcon.ico"),
        new(".flac", MediaPlayerProgramId, "凝然媒体播放器", @"Assets\AppIcon.ico"),
        new(".ogg", MediaPlayerProgramId, "凝然媒体播放器", @"Assets\AppIcon.ico"),
        new(".wma", MediaPlayerProgramId, "凝然媒体播放器", @"Assets\AppIcon.ico"),
        new(".mp4", MediaPlayerProgramId, "凝然媒体播放器", @"Assets\AppIcon.ico"),
        new(".m4v", MediaPlayerProgramId, "凝然媒体播放器", @"Assets\AppIcon.ico"),
        new(".mov", MediaPlayerProgramId, "凝然媒体播放器", @"Assets\AppIcon.ico"),
        new(".avi", MediaPlayerProgramId, "凝然媒体播放器", @"Assets\AppIcon.ico"),
        new(".wmv", MediaPlayerProgramId, "凝然媒体播放器", @"Assets\AppIcon.ico"),
        new(".webm", MediaPlayerProgramId, "凝然媒体播放器", @"Assets\AppIcon.ico"),
        new(".mkv", MediaPlayerProgramId, "凝然媒体播放器", @"Assets\AppIcon.ico"),
        new(".mpeg", MediaPlayerProgramId, "凝然媒体播放器", @"Assets\AppIcon.ico"),
        new(".mpg", MediaPlayerProgramId, "凝然媒体播放器", @"Assets\AppIcon.ico"),
        new(".3gp", MediaPlayerProgramId, "凝然媒体播放器", @"Assets\AppIcon.ico"),
        new(".ts", MediaPlayerProgramId, "凝然媒体播放器", @"Assets\AppIcon.ico"),
        new(".mpv", MediaPlayerProgramId, "凝然媒体播放器", @"Assets\AppIcon.ico"),
    ];
    private static readonly string[] LegacyMediaPlayerProgramIds =
    [
        "NingRan.MediaPlayer.Mp3", "NingRan.MediaPlayer.Wav", "NingRan.MediaPlayer.M4a",
        "NingRan.MediaPlayer.Aac", "NingRan.MediaPlayer.Flac", "NingRan.MediaPlayer.Ogg",
        "NingRan.MediaPlayer.Wma", "NingRan.MediaPlayer.Mp4", "NingRan.MediaPlayer.M4v",
        "NingRan.MediaPlayer.Mov", "NingRan.MediaPlayer.Avi", "NingRan.MediaPlayer.Wmv",
        "NingRan.MediaPlayer.Webm", "NingRan.MediaPlayer.Mkv", "NingRan.MediaPlayer.Mpeg",
        "NingRan.MediaPlayer.Mpg", "NingRan.MediaPlayer.ThreeGp", "NingRan.MediaPlayer.Ts",
        "NingRan.MediaPlayer.Mpv",
        "NingRan.MediaViewer.video", "NingRan.MediaViewer.image", "NingRan.MediaViewer.audio",
        "NingRan.MediaViewer.pdf",
        "Ningran Media Image", "Ningran Media Video", "Ningran Media Audio",
        "Ningran.MediaViewer.video", "Ningran.MediaViewer.image", "Ningran.MediaViewer.audio",
        "Ningran.MediaViewer.pdf", "com.ningran.mediaviewer",
    ];
    private static readonly string[] LegacyMediaApplicationNames =
        ["凝然媒体查看器.exe", "NingRan.MediaPlayer.exe", "凝然媒体播放器.exe"];
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
#if NINGRAN_MEDIA_PLAYER
            CleanupLegacyMediaPlayerRegistrations();
#endif
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
                using var openWith = extensionKey.CreateSubKey("OpenWithProgids", writable: true);
                openWith.SetValue(association.ProgramId, Array.Empty<byte>(), RegistryValueKind.None);
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
                        StringComparison.OrdinalIgnoreCase) ||
                    IsLegacyMediaPlayerProgramId(extensionKey?.GetValue(null) as string))
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

#if NINGRAN_MEDIA_PLAYER
        CleanupLegacyMediaPlayerRegistrations();
#endif

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

#if NINGRAN_MEDIA_PLAYER
    private static bool IsLegacyMediaPlayerProgramId(string? value) =>
        value is not null && LegacyMediaPlayerProgramIds.Contains(value, StringComparer.OrdinalIgnoreCase);

    private static void CleanupLegacyMediaPlayerRegistrations()
    {
        using var classes = Registry.CurrentUser.OpenSubKey(ClassesPath, writable: true);
        if (classes is null) return;

        foreach (var legacyId in LegacyMediaPlayerProgramIds)
            classes.DeleteSubKeyTree(legacyId, throwOnMissingSubKey: false);
        foreach (var legacyName in LegacyMediaApplicationNames)
            classes.DeleteSubKeyTree($@"Applications\{legacyName}", throwOnMissingSubKey: false);

        foreach (var association in Associations)
        {
            using var extensionKey = classes.OpenSubKey(association.Extension, writable: true);
            var current = extensionKey?.GetValue(null) as string;
            if (string.Equals(current, MediaPlayerProgramId, StringComparison.OrdinalIgnoreCase) ||
                IsLegacyMediaPlayerProgramId(current))
            {
                extensionKey?.DeleteValue(string.Empty, throwOnMissingValue: false);
            }

            using var openWith = extensionKey?.OpenSubKey("OpenWithProgids", writable: true);
            if (openWith is null) continue;
            openWith.DeleteValue(MediaPlayerProgramId, throwOnMissingValue: false);
            foreach (var legacyId in LegacyMediaPlayerProgramIds)
                openWith.DeleteValue(legacyId, throwOnMissingValue: false);
        }

        using var fileExtensions = Registry.CurrentUser.OpenSubKey(
            @"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts", writable: true);
        if (fileExtensions is null) return;
        foreach (var association in Associations)
        {
            using var fileExtensionKey = fileExtensions.OpenSubKey(
                association.Extension,
                writable: true);
            using var fileOpenWithProgids = fileExtensionKey?.OpenSubKey(
                "OpenWithProgids",
                writable: true);
            fileOpenWithProgids?.DeleteValue(MediaPlayerProgramId, throwOnMissingValue: false);
            if (fileOpenWithProgids is not null)
            {
                foreach (var legacyId in LegacyMediaPlayerProgramIds)
                    fileOpenWithProgids.DeleteValue(legacyId, throwOnMissingValue: false);
            }

            using var openWithList = fileExtensions.OpenSubKey(
                $@"{association.Extension}\OpenWithList", writable: true);
            if (openWithList is null) continue;
            var removedValueNames = new List<string>();
            foreach (var valueName in openWithList.GetValueNames())
            {
                if (string.Equals(valueName, "MRUList", StringComparison.OrdinalIgnoreCase)) continue;
                var value = openWithList.GetValue(valueName) as string;
                if (value is not null && LegacyMediaApplicationNames.Contains(value, StringComparer.OrdinalIgnoreCase))
                {
                    removedValueNames.Add(valueName);
                    openWithList.DeleteValue(valueName, throwOnMissingValue: false);
                }
            }

            var mru = openWithList.GetValue("MRUList") as string;
            if (mru is null) continue;
            foreach (var removed in removedValueNames)
                mru = mru.Replace(removed, string.Empty, StringComparison.OrdinalIgnoreCase);
            if (mru.Length == 0) openWithList.DeleteValue("MRUList", throwOnMissingValue: false);
            else openWithList.SetValue("MRUList", mru, RegistryValueKind.String);
        }
    }
#else
    private static bool IsLegacyMediaPlayerProgramId(string? value) => false;
#endif

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
