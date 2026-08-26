using System.Diagnostics;

namespace NingRan.Setup;

public sealed class InstallerEngine
{
    public async Task<InstallState> InstallAsync(
        SetupOptions options,
        Stream payload,
        Action<string> copySetupExecutable,
        IProgress<SetupProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentNullException.ThrowIfNull(copySetupExecutable);
        var existingPath = ShellIntegration.FindInstalledPath();
        if (existingPath is not null &&
            !SetupPathSafety.IsSupportedInstallPath(existingPath))
        {
            existingPath = null;
        }

        if (existingPath is not null && Directory.Exists(existingPath))
        {
            if (SetupPathSafety.IsLegacyInstallPath(existingPath))
            {
                SetupPathSafety.HardenLegacyInstallDirectory(existingPath);
                SetupPathSafety.ValidateUninstallPath(existingPath);
            }
            else
            {
                SetupPathSafety.VerifyInstallDirectoryPermissions(existingPath);
            }
        }
        var existingState = existingPath is null ? null : InstallState.TryLoad(existingPath);
        var target = SetupPathSafety.ValidateInstallPath(
            options.InstallPath,
            allowExistingInstall: existingState is not null &&
                                  string.Equals(existingPath, options.InstallPath, StringComparison.OrdinalIgnoreCase));
        EnsureMainProgramIsClosed();

        var parent = Path.GetDirectoryName(target)
            ?? throw new InvalidOperationException("无法确定安装位置的上级文件夹。");
        Directory.CreateDirectory(parent);
        var staging = target + $".install-{Guid.NewGuid():N}";
        var backup = target + $".backup-{Guid.NewGuid():N}";
        var targetMovedToBackup = false;
        var stagingMovedToTarget = false;
        InstallState? newState = null;
        try
        {
            progress?.Report(new SetupProgress(2, "正在检查离线安装包…"));
            Directory.CreateDirectory(staging);
            SetupPathSafety.HardenTemporaryInstallDirectory(staging);
            await PayloadExtractor.ExtractAndVerifyAsync(
                payload,
                staging,
                progress,
                cancellationToken).ConfigureAwait(false);
            SetupPathSafety.HardenTemporaryInstallDirectory(staging);

            cancellationToken.ThrowIfCancellationRequested();
            copySetupExecutable(Path.Combine(staging, SetupProduct.UninstallerName));
            var associationBackups = SetupProduct.SupportsFileAssociations
                ? existingState?.AssociationBackups.Count > 0
                    ? existingState.AssociationBackups
                    : ShellIntegration.CaptureAssociationBackups()
                : [];
            newState = new InstallState
            {
                InstallPath = target,
                MigratedFromPath = existingState is not null &&
                                   !string.Equals(existingState.InstallPath, target, StringComparison.OrdinalIgnoreCase)
                    ? existingState.InstallPath
                    : null,
                DesktopShortcut = options.CreateDesktopShortcut,
                StartMenuShortcut = options.CreateStartMenuShortcut,
                FileAssociations = options.AssociateSupportedFiles,
                Language = string.Equals(options.Language, "en", StringComparison.OrdinalIgnoreCase) ? "en" : "zh",
                AssociationBackups = associationBackups,
            };
            newState.Save(staging);

            progress?.Report(new SetupProgress(92, "正在更新程序文件…"));
            if (Directory.Exists(target))
            {
                if (Directory.EnumerateFileSystemEntries(target).Any())
                {
                    Directory.Move(target, backup);
                    targetMovedToBackup = true;
                }
                else
                {
                    Directory.Delete(target);
                }
            }

            Directory.Move(staging, target);
            stagingMovedToTarget = true;
            SetupPathSafety.HardenInstallDirectory(target);
            SetupPathSafety.VerifyInstallDirectoryPermissions(target);

            progress?.Report(new SetupProgress(96, SetupProduct.SupportsFileAssociations
                ? "正在创建快捷方式和文件关联…"
                : "正在创建快捷方式…"));
            if (existingState is not null)
            {
                ShellIntegration.Remove(existingState);
            }

            ShellIntegration.Apply(newState);
            progress?.Report(new SetupProgress(100, "安装完成"));

            if (targetMovedToBackup)
            {
                try
                {
                    SafeDirectoryTree.Delete(backup);
                    targetMovedToBackup = false;
                }
                catch
                {
                    // 新版本已经完整安装；保留无法清理的旧程序备份，避免回滚破坏新安装。
                    targetMovedToBackup = false;
                }
            }

            if (existingState is not null &&
                !string.Equals(existingState.InstallPath, target, StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    var oldPath = SetupPathSafety.ValidateUninstallPath(existingState.InstallPath);
                    SafeDirectoryTree.Delete(oldPath);
                }
                catch
                {
                    // 新位置已经可用；旧程序残留可以稍后由用户手动清理。
                }
            }

            return newState;
        }
        catch
        {
            if (newState is not null)
            {
                try
                {
                    ShellIntegration.Remove(newState);
                }
                catch
                {
                    // 继续恢复旧程序文件。
                }
            }

            if (stagingMovedToTarget && Directory.Exists(target))
            {
                SafeDirectoryTree.Delete(target);
            }

            if (targetMovedToBackup && Directory.Exists(backup) && !Directory.Exists(target))
            {
                Directory.Move(backup, target);
                targetMovedToBackup = false;
            }

            if (existingState is not null)
            {
                try
                {
                    ShellIntegration.Apply(existingState);
                }
                catch
                {
                    // 保留原程序文件，用户仍可手动启动。
                }
            }

            throw;
        }
        finally
        {
            if (Directory.Exists(staging))
            {
                SafeDirectoryTree.Delete(staging);
            }

            if (targetMovedToBackup && Directory.Exists(backup))
            {
                // 未能安全恢复时保留备份，避免丢失旧程序。
            }
        }
    }

    public InstallState PrepareUninstall(string installPath, bool deleteUserData)
    {
        var validatedPath = SetupPathSafety.ValidateUninstallPath(installPath);
        EnsureMainProgramIsClosed();
        var state = InstallState.TryLoad(validatedPath)
            ?? throw new InvalidOperationException("安装记录无法读取，已停止卸载。");
        ShellIntegration.Remove(state, removeUninstallEntry: false);
        if (deleteUserData)
        {
            SafeDirectoryTree.DeleteUserData(SetupProduct.UserDataPath);
        }

        DeleteMigratedInstall(state);
        RemoveInstalledPayloadFiles(validatedPath);
        RemoveInstallArtifacts(validatedPath);
        return state;
    }

    private static void DeleteMigratedInstall(InstallState state)
    {
        if (string.IsNullOrWhiteSpace(state.MigratedFromPath) ||
            !SetupPathSafety.IsLegacyInstallPath(state.MigratedFromPath))
        {
            return;
        }

        var oldPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(state.MigratedFromPath));
        if (Directory.Exists(oldPath))
        {
            SafeDirectoryTree.Delete(oldPath);
        }
    }

    private static void RemoveInstallArtifacts(string installPath)
    {
        var root = SetupPathSafety.ValidateUninstallPath(installPath);
        var parent = Path.GetDirectoryName(root)
            ?? throw new InvalidOperationException("无法确定安装目录的上级位置。");
        var leaf = Path.GetFileName(root);
        foreach (var entry in new DirectoryInfo(parent).EnumerateDirectories())
        {
            if (!entry.Name.StartsWith(leaf + ".install-", StringComparison.OrdinalIgnoreCase) &&
                !entry.Name.StartsWith(leaf + ".backup-", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            SafeDirectoryTree.Delete(entry.FullName);
        }
    }

    public static void EnsureMainProgramIsClosed()
    {
        using var current = Process.GetCurrentProcess();
        foreach (var processName in new[] { "NingRan", "NingRan.StrictMonitor", "NingRan.MediaPlayer" })
        {
            foreach (var process in Process.GetProcessesByName(processName))
            {
                using (process)
                {
                    if (process.Id != current.Id && !process.HasExited)
                    {
                        throw new InvalidOperationException($"{SetupProduct.Name}仍在运行。请先关闭相关窗口，再继续安装或卸载。");
                    }
                }
            }
        }
    }

    private static void RemoveInstalledPayloadFiles(string installPath)
    {
        var root = SetupPathSafety.ValidateUninstallPath(installPath);
        var uninstaller = Path.Combine(root, SetupProduct.UninstallerName);
        foreach (var entry in new DirectoryInfo(root).EnumerateFileSystemInfos())
        {
            if (entry is FileInfo file &&
                (string.Equals(file.FullName, uninstaller, StringComparison.OrdinalIgnoreCase) ||
                 string.Equals(file.FullName, Path.Combine(root, SetupProduct.StateFileName), StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            SafeDirectoryTree.Delete(entry.FullName);
        }
    }
}
