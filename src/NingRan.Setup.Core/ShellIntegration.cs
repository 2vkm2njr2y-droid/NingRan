using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace NingRan.Setup;

public static class ShellIntegration
{
    private const string ClassesPath = @"Software\Classes";
    private static readonly AssociationDefinition[] Associations =
    [
        new(".nrenc", "NingRan.EncryptedFile", "凝然加密文件", @"Assets\EncryptedFileIcon.ico"),
        new(".nrid", "NingRan.IdentityBackup", "凝然身份备份", @"Assets\IdentityBackupIcon.ico"),
        new(".nrpub", "NingRan.PublicIdentity", "凝然公开身份", @"Assets\PublicIdentityIcon.ico"),
    ];

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
        RemoveShortcutsForTarget(executable);
        if (state.DesktopShortcut)
        {
            CreateShortcut(GetDesktopShortcutPath(), executable, state.InstallPath);
        }

        if (state.StartMenuShortcut)
        {
            CreateShortcut(GetStartMenuShortcutPath(), executable, state.InstallPath);
        }

        if (state.FileAssociations)
        {
            foreach (var association in Associations)
            {
                using (var programKey = Registry.CurrentUser.CreateSubKey(
                           $@"{ClassesPath}\{association.ProgramId}",
                           writable: true))
                {
                    programKey.SetValue(null, association.Description, RegistryValueKind.String);
                    programKey.SetValue("FriendlyTypeName", association.Description, RegistryValueKind.String);
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
            uninstallKey.SetValue("DisplayName", SetupProduct.Name, RegistryValueKind.String);
            uninstallKey.SetValue("DisplayVersion", SetupProduct.Version, RegistryValueKind.String);
            uninstallKey.SetValue("Publisher", "凝然", RegistryValueKind.String);
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

    private static void CreateShortcut(string shortcutPath, string targetPath, string workingDirectory)
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
            dynamicShortcut.Description = "凝然加密";
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
        TryDeleteShortcut(GetDesktopShortcutPath(), targetPath);
        TryDeleteShortcut(GetStartMenuShortcutPath(), targetPath);
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

    private static string GetDesktopShortcutPath() => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
        "凝然加密.lnk");

    private static string GetStartMenuShortcutPath() => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.Programs),
        "凝然加密.lnk");

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
        string IconRelativePath);
}
