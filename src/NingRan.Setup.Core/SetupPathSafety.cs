using System.Security.AccessControl;
using System.Security.Principal;

namespace NingRan.Setup;

public static class SetupPathSafety
{
    public static string ValidateInstallPath(string path, bool allowExistingInstall)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var fullPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        var expectedPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(SetupProduct.DefaultInstallPath));
        if (!string.Equals(fullPath, expectedPath, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"为防止其他 Windows 用户替换程序文件，凝然加密只能安装到当前用户的专用位置：{expectedPath}");
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

            if (allowExistingInstall)
            {
                using var identity = WindowsIdentity.GetCurrent();
                var currentUser = identity.User
                    ?? throw new InvalidOperationException("无法确定当前 Windows 用户，已停止操作。");
                VerifyInstallDirectoryPermissions(fullPath, currentUser);
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

    public static bool IsSecureExistingInstall(string path)
    {
        var fullPath = ValidateFixedInstallPath(path);
        if (!Directory.Exists(fullPath) || !Directory.EnumerateFileSystemEntries(fullPath).Any())
        {
            return false;
        }

        VerifyInstallDirectoryPermissions(fullPath);
        return InstallState.TryLoad(fullPath) is not null;
    }

    public static void HardenInstallDirectory(string path)
    {
        var fullPath = ValidateFixedInstallPath(path);
        SetPrivateDirectoryPermissions(fullPath);
        VerifyInstallDirectoryPermissions(fullPath);
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

        using var identity = WindowsIdentity.GetCurrent();
        var currentUser = identity.User
            ?? throw new InvalidOperationException("无法确定当前 Windows 用户，已停止安装。");
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(currentUser);
        AddFullControl(security, currentUser);
        AddFullControl(security, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        new DirectoryInfo(fullPath).SetAccessControl(security);
        VerifyInstallDirectoryPermissions(fullPath, currentUser);
    }

    public static void VerifyInstallDirectoryPermissions(string path)
    {
        using var identity = WindowsIdentity.GetCurrent();
        var currentUser = identity.User
            ?? throw new InvalidOperationException("无法确定当前 Windows 用户，已停止操作。");
        VerifyInstallDirectoryPermissions(ValidateFixedInstallPath(path), currentUser);
    }

    public static string ValidateInstalledProductPath(string path)
    {
        var fullPath = ValidateInstallPath(path, allowExistingInstall: true);
        VerifyInstallDirectoryPermissions(fullPath);
        var state = InstallState.TryLoad(fullPath)
            ?? throw new InvalidOperationException("没有找到有效的凝然加密安装记录，已停止卸载。");
        if (!File.Exists(Path.Combine(fullPath, SetupProduct.MainExecutableName)))
        {
            throw new InvalidOperationException("安装文件不完整，已停止自动删除。可以重新安装后再卸载。");
        }

        return state.InstallPath;
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

    private static void AddFullControl(DirectorySecurity security, SecurityIdentifier identity) =>
        security.AddAccessRule(new FileSystemAccessRule(
            identity,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));

    private static void VerifyInstallDirectoryPermissions(string path, SecurityIdentifier currentUser)
    {
        var security = new DirectoryInfo(path).GetAccessControl(AccessControlSections.Access);
        if (!security.AreAccessRulesProtected)
        {
            throw new InvalidOperationException("安装目录仍在继承外部权限，已停止操作以防程序文件被他人替换。");
        }

        var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            currentUser.Value,
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value,
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Value,
        };
        var dangerous = FileSystemRights.Write | FileSystemRights.Modify | FileSystemRights.FullControl |
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
    }
}
