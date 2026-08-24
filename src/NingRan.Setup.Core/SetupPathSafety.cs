using System.Security.AccessControl;
using System.Security.Principal;

namespace NingRan.Setup;

public static class SetupPathSafety
{
    public static string ValidateInstallPath(
        string path,
        bool allowExistingInstall,
        bool verifyExistingPermissions = true)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var fullPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        var expectedPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(SetupProduct.DefaultInstallPath));
        if (!string.Equals(fullPath, expectedPath, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"为防止其他 Windows 用户替换程序文件，凝然加密只能安装到受保护的系统位置：{expectedPath}");
        }

        ValidateExistingPathSegments(fullPath);
        var root = Path.TrimEndingDirectorySeparator(Path.GetPathRoot(fullPath) ?? string.Empty);
        if (string.Equals(fullPath, root, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("不能把磁盘根目录作为安装位置，请选择一个专用文件夹。");
        }

        var userDataPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(SetupProduct.UserDataPath));
        if (IsSameOrParent(fullPath, userDataPath) || IsSameOrParent(userDataPath, fullPath))
        {
            throw new InvalidOperationException("安装位置不能与凝然加密的身份和设置保存位置重叠。");
        }

        if (Directory.Exists(fullPath))
        {
            var attributes = File.GetAttributes(fullPath);
            if ((attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidOperationException("安装位置不能是快捷链接、符号链接或目录联接。");
            }

            if (allowExistingInstall && verifyExistingPermissions)
            {
                VerifyDirectoryAcl(fullPath);
            }

            if (Directory.EnumerateFileSystemEntries(fullPath).Any() &&
                (!allowExistingInstall || InstallState.TryLoad(fullPath) is null))
            {
                throw new InvalidOperationException("所选文件夹不是空文件夹，也不是现有的凝然加密安装位置。请新建一个空文件夹。");
            }
        }
        else if (File.Exists(fullPath))
        {
            throw new InvalidOperationException("安装位置与一个现有文件重名，请更换位置。");
        }

        return fullPath;
    }

    public static string ValidateFixedInstallPath(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var fullPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        var expectedPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(SetupProduct.DefaultInstallPath));
        if (!string.Equals(fullPath, expectedPath, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("安装位置不是当前用户的凝然加密专用目录，已停止操作。");
        }

        ValidateExistingPathSegments(fullPath);
        return fullPath;
    }

    public static bool IsLegacyInstallPath(string path)
    {
        try
        {
            return string.Equals(
                Path.TrimEndingDirectorySeparator(Path.GetFullPath(path)),
                Path.TrimEndingDirectorySeparator(Path.GetFullPath(SetupProduct.LegacyInstallPath)),
                StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }

    public static bool IsSupportedInstallPath(string path)
    {
        try
        {
            var fullPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
            return string.Equals(fullPath, Path.TrimEndingDirectorySeparator(Path.GetFullPath(SetupProduct.DefaultInstallPath)), StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(fullPath, Path.TrimEndingDirectorySeparator(Path.GetFullPath(SetupProduct.LegacyInstallPath)), StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }

    public static bool IsSecureExistingInstall(string path)
    {
        var fullPath = ValidateFixedInstallPath(path);
        if (!Directory.Exists(fullPath) || !Directory.EnumerateFileSystemEntries(fullPath).Any())
        {
            return false;
        }

        VerifyDirectoryAcl(fullPath);
        return InstallState.TryLoad(fullPath) is not null;
    }

    public static void HardenInstallDirectory(string path)
    {
        var fullPath = ValidateFixedInstallPath(path);
        SetPrivateDirectoryPermissions(fullPath);
        VerifyDirectoryAcl(fullPath);
    }

    public static void HardenLegacyInstallDirectory(string path)
    {
        var fullPath = ValidateLegacyInstallPath(path);
        SetProtectedDirectoryPermissions(fullPath);
        foreach (var entry in new DirectoryInfo(fullPath).EnumerateFileSystemInfos())
        {
            if ((entry.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                continue;
            }

            if (entry is DirectoryInfo directory)
            {
                HardenDirectoryTree(directory.FullName);
            }
            else if (entry is FileInfo file)
            {
                SetProtectedFilePermissions(file.FullName);
            }
        }

        VerifyDirectoryAcl(fullPath);
    }

    public static void HardenTemporaryInstallDirectory(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var fullPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        var expected = Path.TrimEndingDirectorySeparator(Path.GetFullPath(SetupProduct.DefaultInstallPath));
        var expectedParent = Path.GetDirectoryName(expected)
            ?? throw new InvalidOperationException("无法确定安全安装目录的上级位置。");
        if (!string.Equals(Path.GetDirectoryName(fullPath), expectedParent, StringComparison.OrdinalIgnoreCase) ||
            !Path.GetFileName(fullPath).StartsWith(Path.GetFileName(expected) + ".install-", StringComparison.Ordinal))
        {
            throw new InvalidOperationException("临时安装目录不在当前用户的安全安装位置，已停止安装。");
        }

        ValidateExistingPathSegments(fullPath);
        SetPrivateDirectoryPermissions(fullPath);
    }

    private static void SetPrivateDirectoryPermissions(string fullPath)
    {
        Directory.CreateDirectory(fullPath);
        ValidateExistingPathSegments(fullPath);

        SetProtectedDirectoryPermissions(fullPath);
        VerifyDirectoryAcl(fullPath);
    }

    private static void SetProtectedDirectoryPermissions(string fullPath)
    {
        Directory.CreateDirectory(fullPath);
        ValidateExistingPathSegments(fullPath);

        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(administrators);
        AddFullControl(security, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));
        AddFullControl(security, administrators);
        AddReadAndExecute(security, new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null));
        new DirectoryInfo(fullPath).SetAccessControl(security);
    }

    private static void HardenDirectoryTree(string path)
    {
        SetProtectedDirectoryPermissions(path);
        foreach (var entry in new DirectoryInfo(path).EnumerateFileSystemInfos())
        {
            if ((entry.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                continue;
            }

            if (entry is DirectoryInfo directory)
            {
                HardenDirectoryTree(directory.FullName);
            }
            else if (entry is FileInfo file)
            {
                SetProtectedFilePermissions(file.FullName);
            }
        }
    }

    private static void SetProtectedFilePermissions(string path)
    {
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(administrators);
        AddFileFullControl(security, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));
        AddFileFullControl(security, administrators);
        AddFileReadAndExecute(security, new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null));
        new FileInfo(path).SetAccessControl(security);
    }

    public static void VerifyInstallDirectoryPermissions(string path)
    {
        VerifyDirectoryAcl(ValidateFixedInstallPath(path));
    }

    public static string ValidateInstalledProductPath(string path)
    {
        var fullPath = ValidateSupportedExistingPath(path);
        if (!IsLegacyInstallPath(fullPath))
        {
            VerifyDirectoryAcl(fullPath);
        }

        var state = InstallState.TryLoad(fullPath)
            ?? throw new InvalidOperationException("没有找到有效的凝然加密安装记录，已停止卸载。");
        if (!File.Exists(Path.Combine(fullPath, SetupProduct.MainExecutableName)))
        {
            throw new InvalidOperationException("安装文件不完整，已停止自动删除。可以重新安装后再卸载。");
        }

        return state.InstallPath;
    }

    public static string ValidateUninstallPath(string path)
    {
        var fullPath = ValidateSupportedExistingPath(path);
        if (!IsLegacyInstallPath(fullPath))
        {
            VerifyDirectoryAcl(fullPath);
        }

        if (InstallState.TryLoad(fullPath) is null ||
            !File.Exists(Path.Combine(fullPath, SetupProduct.UninstallerName)))
        {
            throw new InvalidOperationException("没有找到可继续卸载的安装记录，已停止操作。请重新安装后再卸载。");
        }

        return fullPath;
    }

    public static bool IsSameOrParent(string possibleParent, string path)
    {
        var parent = Path.TrimEndingDirectorySeparator(Path.GetFullPath(possibleParent));
        var candidate = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        if (string.Equals(parent, candidate, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return candidate.StartsWith(parent + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static void ValidateExistingPathSegments(string path)
    {
        var fullPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        var root = Path.GetPathRoot(fullPath)
            ?? throw new InvalidOperationException("无法确定安装位置所在磁盘。");
        var relative = Path.GetRelativePath(root, fullPath);
        var current = Path.TrimEndingDirectorySeparator(root);
        foreach (var segment in relative.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            if (File.Exists(current))
            {
                throw new InvalidOperationException("安装路径中有同名文件，已停止操作。");
            }

            if (Directory.Exists(current) &&
                (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidOperationException("安装路径不能经过快捷链接、符号链接或目录联接。");
            }
        }
    }

    private static void AddFullControl(FileSystemSecurity security, SecurityIdentifier identity) =>
        security.AddAccessRule(new FileSystemAccessRule(
            identity,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));

    private static void VerifyDirectoryAcl(string path)
    {
        var security = new DirectoryInfo(path).GetAccessControl(AccessControlSections.Access);
        if (!security.AreAccessRulesProtected)
        {
            throw new InvalidOperationException("安装目录仍在继承外部权限，已停止操作以防程序文件被他人替换。");
        }

        var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value,
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Value,
        };
        // Do not include composite rights such as Modify or FullControl here. Those
        // values also contain read/execute bits, which would incorrectly classify
        // the required Builtin Users read-and-execute rule as writable access.
        var dangerous = FileSystemRights.Write |
            FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles |
            FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
        foreach (FileSystemAccessRule rule in security.GetAccessRules(
                     includeExplicit: true,
                     includeInherited: true,
                     targetType: typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType == AccessControlType.Allow &&
                (rule.FileSystemRights & dangerous) != 0 &&
                !allowed.Contains(rule.IdentityReference.Value))
            {
                throw new InvalidOperationException("安装目录允许其他账户修改程序文件，已停止操作。");
            }
        }

        var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null).Value;
        if (!security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().Any(rule =>
                rule.AccessControlType == AccessControlType.Allow &&
                string.Equals(rule.IdentityReference.Value, users, StringComparison.OrdinalIgnoreCase) &&
                (rule.FileSystemRights & (FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize)) ==
                (FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize)))
        {
            throw new InvalidOperationException("安装目录没有为普通用户保留读取和运行权限，已停止操作。");
        }
    }

    private static string ValidateLegacyInstallPath(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var fullPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        var expected = Path.TrimEndingDirectorySeparator(Path.GetFullPath(SetupProduct.LegacyInstallPath));
        if (!string.Equals(fullPath, expected, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("旧版安装位置不正确，已停止操作。");
        }

        ValidateExistingPathSegments(fullPath);
        if (Directory.Exists(fullPath) &&
            (File.GetAttributes(fullPath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidOperationException("旧版安装位置不能是快捷链接、符号链接或目录联接。");
        }

        return fullPath;
    }

    private static string ValidateSupportedExistingPath(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var fullPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        if (string.Equals(fullPath, Path.TrimEndingDirectorySeparator(Path.GetFullPath(SetupProduct.DefaultInstallPath)), StringComparison.OrdinalIgnoreCase))
        {
            ValidateFixedInstallPath(fullPath);
        }
        else
        {
            ValidateLegacyInstallPath(fullPath);
        }

        if (!Directory.Exists(fullPath) || (File.GetAttributes(fullPath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidOperationException("安装位置不存在或不是安全的实际文件夹，已停止操作。");
        }

        return fullPath;
    }

    private static void AddReadAndExecute(FileSystemSecurity security, SecurityIdentifier identity) =>
        security.AddAccessRule(new FileSystemAccessRule(
            identity,
            FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize,
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

    private static void AddFileReadAndExecute(FileSecurity security, SecurityIdentifier identity) =>
        security.AddAccessRule(new FileSystemAccessRule(
            identity,
            FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize,
            InheritanceFlags.None,
            PropagationFlags.None,
            AccessControlType.Allow));
}
