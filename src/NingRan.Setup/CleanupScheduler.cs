using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;
using NingRan.Setup;

namespace NingRan.Setup.Windows;

internal static class CleanupScheduler
{
    private const string CleanupModeArgument = "--cleanup-installed-directory";
    private const string RequestIdArgument = "--request-id";
    private const string WaitProcessArgument = "--wait-pid";
    private const string InstallPathArgument = "--install-path";
    private const string CleanupDirectoryPrefix = "NingRan.Cleanup-";
    private const string CleanupExecutableName = "NingRanCleanup.exe";
    private const int MaximumDeleteAttempts = 120;
    private const int DeleteRetryDelayMilliseconds = 500;
    private const uint MoveFileDelayUntilReboot = 0x00000004;

    public static void ScheduleInstalledDirectoryCleanup(string installPath)
    {
        var validated = SetupPathSafety.ValidateUninstallPath(installPath);
        if (SetupPathSafety.IsLegacyInstallPath(validated))
        {
            throw new InvalidOperationException(
                "旧版用户目录安装不能启动管理员清理程序。请先安装最新版完成安全迁移。");
        }

        SetupPathSafety.VerifyInstallDirectoryPermissions(validated);
        if (!SetupBootstrap.IsBound)
        {
            throw new InvalidOperationException("卸载程序没有通过原生安全引导验证，已停止最后清理。");
        }

        var expectedUninstaller = Path.GetFullPath(Path.Combine(validated, SetupProduct.UninstallerName));
        var authenticatedUninstaller = Path.GetFullPath(SetupBootstrap.OriginExecutablePath);
        if (!string.Equals(authenticatedUninstaller, expectedUninstaller, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("通过安全引导验证的程序不是受保护安装目录中的卸载程序，已停止最后清理。");
        }
        var originalBootstrapProcessId = SetupBootstrap.ParentProcessId;

        var requestId = Guid.NewGuid();
        var cleanupDirectory = GetExpectedCleanupDirectory(requestId);
        var cleanupExecutable = Path.Combine(cleanupDirectory, CleanupExecutableName);
        CreateProtectedCleanupDirectory(cleanupDirectory);
        var launched = false;
        try
        {
            // Copy from the exact origin handle that SetupBootstrap locked and authenticated.
            // Reopening the origin by path here would reintroduce a link/swap race.
            SetupBootstrap.CopyAuthenticatedOriginTo(cleanupExecutable);
            ProtectCleanupExecutable(cleanupExecutable);
            VerifyProtectedCleanupLocation(cleanupDirectory, cleanupExecutable);

            var startInfo = new ProcessStartInfo
            {
                FileName = cleanupExecutable,
                WorkingDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
            };
            startInfo.ArgumentList.Add(CleanupModeArgument);
            startInfo.ArgumentList.Add(RequestIdArgument);
            startInfo.ArgumentList.Add(requestId.ToString("N", CultureInfo.InvariantCulture));
            startInfo.ArgumentList.Add(WaitProcessArgument);
            startInfo.ArgumentList.Add(originalBootstrapProcessId.ToString(CultureInfo.InvariantCulture));
            startInfo.ArgumentList.Add(InstallPathArgument);
            startInfo.ArgumentList.Add(validated);
            using var cleanupProcess = Process.Start(startInfo)
                ?? throw new InvalidOperationException("Windows 未能启动最后清理程序，卸载记录将保留以便重试。");
            launched = true;
        }
        finally
        {
            if (!launched && Directory.Exists(cleanupDirectory))
            {
                SafeDirectoryTree.Delete(cleanupDirectory);
            }
        }
    }

    public static bool IsCleanupInvocation(IReadOnlyList<string> arguments) =>
        arguments.Count > 0 &&
        string.Equals(arguments[0], CleanupModeArgument, StringComparison.Ordinal);

    public static bool TryParseCleanupRequest(
        IReadOnlyList<string> arguments,
        out CleanupRequest? request)
    {
        request = null;
        if (arguments.Count != 7 ||
            !string.Equals(arguments[0], CleanupModeArgument, StringComparison.Ordinal) ||
            !string.Equals(arguments[1], RequestIdArgument, StringComparison.Ordinal) ||
            !Guid.TryParseExact(arguments[2], "N", out var requestId) ||
            !string.Equals(arguments[3], WaitProcessArgument, StringComparison.Ordinal) ||
            !int.TryParse(arguments[4], NumberStyles.None, CultureInfo.InvariantCulture, out var waitProcessId) ||
            waitProcessId <= 0 ||
            !string.Equals(arguments[5], InstallPathArgument, StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(arguments[6]))
        {
            return false;
        }

        try
        {
            request = new CleanupRequest(
                requestId,
                waitProcessId,
                Path.TrimEndingDirectorySeparator(Path.GetFullPath(arguments[6])));
            return true;
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }

    public static int RunCleanup(CleanupRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var cleanupDirectory = GetExpectedCleanupDirectory(request.RequestId);
        var cleanupExecutable = Path.Combine(cleanupDirectory, CleanupExecutableName);
        try
        {
            VerifyProtectedCleanupLocation(cleanupDirectory, cleanupExecutable);
            if (!SetupBootstrap.IsBound ||
                !string.Equals(
                    Path.GetFullPath(SetupBootstrap.OriginExecutablePath),
                    cleanupExecutable,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("最后清理程序没有通过受保护临时位置中的原生安全引导器运行。");
            }

            var validatedInstallPath = SetupPathSafety.ValidateUninstallPath(request.InstallPath);
            if (SetupPathSafety.IsLegacyInstallPath(validatedInstallPath))
            {
                throw new InvalidOperationException("最后清理程序不能删除旧版用户目录安装。");
            }

            var expectedUninstaller = Path.GetFullPath(Path.Combine(
                validatedInstallPath,
                SetupProduct.UninstallerName));
            using (var parentProcess = Process.GetProcessById(request.WaitProcessId))
            {
                var parentExecutable = Path.GetFullPath(parentProcess.MainModule?.FileName
                    ?? throw new InvalidOperationException("无法确认请求最后清理的卸载程序。"));
                if (parentProcess.Id == Environment.ProcessId ||
                    parentProcess.Id == SetupBootstrap.ParentProcessId ||
                    !string.Equals(parentExecutable, expectedUninstaller, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException("请求最后清理的程序不是受保护的卸载程序。");
                }

                // Keeping this process handle open also prevents the PID from being reused
                // while the cleanup helper is waiting for the original uninstaller.
                parentProcess.WaitForExit();
            }

            Exception? lastDeleteError = null;
            for (var attempt = 0; attempt < MaximumDeleteAttempts; attempt++)
            {
                try
                {
                    SafeDirectoryTree.Delete(validatedInstallPath);
                    if (!Directory.Exists(validatedInstallPath) && !File.Exists(validatedInstallPath))
                    {
                        RemoveMatchingUninstallEntries(validatedInstallPath);
                        return 0;
                    }
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                {
                    lastDeleteError = exception;
                }

                Thread.Sleep(DeleteRetryDelayMilliseconds);
            }

            throw new IOException("Windows 未能在等待时间内完成安装目录清理。", lastDeleteError);
        }
        catch
        {
            return 2;
        }
        finally
        {
            ScheduleProtectedHelperDeletion(cleanupExecutable, cleanupDirectory);
        }
    }

    private static string GetExpectedCleanupDirectory(Guid requestId)
    {
        var configuredProgramData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        if (string.IsNullOrWhiteSpace(configuredProgramData))
        {
            throw new InvalidOperationException("Windows 没有提供受保护的公共程序数据位置。");
        }

        var programData = Path.TrimEndingDirectorySeparator(Path.GetFullPath(configuredProgramData));
        VerifyOrdinaryDirectoryPath(programData);
        return Path.Combine(programData, CleanupDirectoryPrefix + requestId.ToString("N", CultureInfo.InvariantCulture));
    }

    private static void CreateProtectedCleanupDirectory(string path)
    {
        if (Directory.Exists(path) || File.Exists(path))
        {
            throw new InvalidOperationException("最后清理程序的临时位置已经存在，已停止操作。");
        }

        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(administrators);
        AddDirectoryFullControl(security, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));
        AddDirectoryFullControl(security, administrators);
        new DirectoryInfo(path).Create(security);
    }

    private static void ProtectCleanupExecutable(string path)
    {
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(administrators);
        AddFileFullControl(security, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));
        AddFileFullControl(security, administrators);
        new FileInfo(path).SetAccessControl(security);
    }

    private static void VerifyProtectedCleanupLocation(string directory, string executable)
    {
        var expectedParent = Path.TrimEndingDirectorySeparator(Path.GetFullPath(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)));
        if (!string.Equals(Path.GetDirectoryName(directory), expectedParent, StringComparison.OrdinalIgnoreCase) ||
            !Path.GetFileName(directory).StartsWith(CleanupDirectoryPrefix, StringComparison.Ordinal) ||
            !string.Equals(Path.GetDirectoryName(executable), directory, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(Path.GetFileName(executable), CleanupExecutableName, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("最后清理程序的临时位置不正确。");
        }

        VerifyOrdinaryDirectoryPath(directory);
        if (!File.Exists(executable) ||
            (File.GetAttributes(executable) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidOperationException("最后清理程序缺失或已被链接替换。");
        }

        VerifyAdministratorsOnlyAcl(new DirectoryInfo(directory).GetAccessControl(AccessControlSections.Access));
        VerifyAdministratorsOnlyAcl(new FileInfo(executable).GetAccessControl(AccessControlSections.Access));
    }

    private static void VerifyOrdinaryDirectoryPath(string path)
    {
        var fullPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        var root = Path.GetPathRoot(fullPath)
            ?? throw new InvalidOperationException("无法确认最后清理程序所在磁盘。");
        var current = Path.TrimEndingDirectorySeparator(root);
        foreach (var segment in Path.GetRelativePath(root, fullPath).Split(
                     [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            if (!Directory.Exists(current) ||
                (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidOperationException("最后清理程序的路径不存在，或经过了文件夹链接。");
            }
        }
    }

    private static void VerifyAdministratorsOnlyAcl(FileSystemSecurity security)
    {
        if (!security.AreAccessRulesProtected)
        {
            throw new InvalidOperationException("最后清理程序仍在继承外部权限。");
        }

        var permitted = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value,
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Value,
        };
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier
            ?? throw new InvalidOperationException("无法确认最后清理程序临时位置的所有者。");
        if (!permitted.Contains(owner.Value))
        {
            throw new InvalidOperationException("最后清理程序的临时位置不属于 Windows 管理员或系统账户。");
        }

        foreach (FileSystemAccessRule rule in security.GetAccessRules(
                     includeExplicit: true,
                     includeInherited: true,
                     targetType: typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType == AccessControlType.Allow &&
                !permitted.Contains(rule.IdentityReference.Value))
            {
                throw new InvalidOperationException("最后清理程序允许普通账户访问，已停止运行。");
            }
        }
    }

    private static void RemoveMatchingUninstallEntries(string installPath)
    {
        foreach (var hive in new[] { Registry.LocalMachine, Registry.CurrentUser })
        {
            using var key = hive.OpenSubKey(SetupProduct.UninstallRegistryPath, writable: false);
            if (!PathsEqual(key?.GetValue("InstallLocation") as string, installPath))
            {
                continue;
            }

            key?.Dispose();
            hive.DeleteSubKeyTree(SetupProduct.UninstallRegistryPath, throwOnMissingSubKey: false);
        }
    }

    private static bool PathsEqual(string? left, string right)
    {
        if (string.IsNullOrWhiteSpace(left))
        {
            return false;
        }

        try
        {
            return string.Equals(
                Path.TrimEndingDirectorySeparator(Path.GetFullPath(left)),
                Path.TrimEndingDirectorySeparator(Path.GetFullPath(right)),
                StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }

    private static void ScheduleProtectedHelperDeletion(string executable, string directory)
    {
        _ = MoveFileExW(executable, null, MoveFileDelayUntilReboot);
        _ = MoveFileExW(directory, null, MoveFileDelayUntilReboot);
    }

    private static void AddDirectoryFullControl(DirectorySecurity security, SecurityIdentifier identity) =>
        security.AddAccessRule(new FileSystemAccessRule(
            identity,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));

    private static void AddFileFullControl(FileSecurity security, SecurityIdentifier identity) =>
        security.AddAccessRule(new FileSystemAccessRule(
            identity,
            FileSystemRights.FullControl,
            InheritanceFlags.None,
            PropagationFlags.None,
            AccessControlType.Allow));

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool MoveFileExW(
        string existingFileName,
        string? newFileName,
        uint flags);

    internal sealed record CleanupRequest(
        Guid RequestId,
        int WaitProcessId,
        string InstallPath);
}
