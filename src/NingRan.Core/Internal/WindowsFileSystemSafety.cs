using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace NingRan.Core.Internal;

internal static class WindowsFileSystemSafety
{
    private const uint GenericRead = 0x80000000;
    private const uint GenericWrite = 0x40000000;
    private const uint DeleteAccess = 0x00010000;
    private const uint FileReadAttributes = 0x00000080;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint OpenExisting = 3;
    private const uint CreateNew = 1;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagSequentialScan = 0x08000000;
    private const uint FileFlagOverlapped = 0x40000000;
    private const uint FileFlagWriteThrough = 0x80000000;

    public static bool IsProcessElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    public static void ThrowIfProcessIsElevated()
    {
        if (IsProcessElevated())
        {
            throw new NingRanException(
                "为了防止共享目录中的文件被越权读取或写入，请关闭程序后直接双击运行，不要使用“以管理员身份运行”。");
        }
    }

    public static SafeFileHandle OpenInputFile(string path) => OpenInputFile(path, FileShareRead);

    public static SafeFileHandle OpenExclusiveInputFile(string path) => OpenInputFile(path, 0);

    private static SafeFileHandle OpenInputFile(string path, uint shareMode)
    {
        var fullPath = Path.GetFullPath(path);
        var handle = CreateFileW(
            fullPath,
            GenericRead,
            shareMode,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOpenReparsePoint | FileFlagSequentialScan | FileFlagOverlapped,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = new Win32Exception(Marshal.GetLastWin32Error());
            handle.Dispose();
            throw new NingRanException($"无法安全锁定文件，文件可能正在被修改：{fullPath}", error);
        }

        try
        {
            var attributes = File.GetAttributes(handle);
            if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
            {
                throw new NingRanException($"不能加密快捷链接、符号链接或目录联接：{fullPath}");
            }

            VerifyHandlePath(handle, fullPath);

            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    public static FileStream CreateNewTemporaryFile(string path, int bufferSize = 1024 * 1024)
    {
        var fullPath = Path.GetFullPath(path);
        var handle = CreateFileW(
            fullPath,
            GenericRead | GenericWrite | DeleteAccess,
            FileShareRead,
            IntPtr.Zero,
            CreateNew,
            FileFlagOpenReparsePoint | FileFlagSequentialScan | FileFlagOverlapped | FileFlagWriteThrough,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = new Win32Exception(Marshal.GetLastWin32Error());
            handle.Dispose();
            throw new NingRanException("无法安全创建临时文件。", error);
        }

        try
        {
            var attributes = File.GetAttributes(handle);
            if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
            {
                throw new NingRanException("临时文件不是普通磁盘文件，已停止处理。");
            }

            VerifyHandlePath(handle, fullPath);
            return new FileStream(handle, FileAccess.ReadWrite, bufferSize, isAsync: true);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    public static SafeFileHandle OpenStableDirectory(string path)
    {
        return OpenDirectory(path, FileShareRead | FileShareWrite, "安全锁定");
    }

    public static SafeFileHandle OpenInputDirectory(string path)
    {
        return OpenDirectory(path, FileShareRead, "锁定待加密");
    }

    private static SafeFileHandle OpenDirectory(string path, uint shareMode, string action)
    {
        var fullPath = Path.GetFullPath(path);
        var handle = CreateFileW(
            fullPath,
            FileReadAttributes,
            shareMode,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOpenReparsePoint | FileFlagBackupSemantics,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = new Win32Exception(Marshal.GetLastWin32Error());
            handle.Dispose();
            throw new NingRanException($"无法{action}文件夹，文件夹可能正在被修改：{fullPath}", error);
        }

        try
        {
            var attributes = File.GetAttributes(handle);
            if ((attributes & FileAttributes.Directory) == 0 ||
                (attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new NingRanException($"不能使用快捷链接、符号链接或目录联接作为处理路径：{fullPath}");
            }

            VerifyHandlePath(handle, fullPath);

            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    public static StableDirectoryPath LockDirectoryPath(string path) => new(path);

    public static void VerifyHandlePath(SafeFileHandle handle, string expectedPath)
    {
        var actualPath = GetFinalPath(handle);
        var expected = NormalizeComparablePath(expectedPath);
        var actual = NormalizeComparablePath(actualPath);
        if (!string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
        {
            throw new NingRanException(
                $"处理路径经过了快捷链接、目录联接或被其他程序替换，已停止处理：{Path.GetFullPath(expectedPath)}");
        }
    }

    public static WindowsFileIdentity GetIdentity(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandle(handle, out var information))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        return new WindowsFileIdentity(
            information.VolumeSerialNumber,
            ((ulong)information.FileIndexHigh << 32) | information.FileIndexLow);
    }

    public static void VerifyIdentity(SafeFileHandle handle, WindowsFileIdentity expectedIdentity)
    {
        if (GetIdentity(handle) != expectedIdentity)
        {
            throw new NingRanException("文件身份已经改变，为避免处理被替换的内容，操作已停止。");
        }
    }

    public static void RenameOpenFile(
        SafeFileHandle handle,
        string currentPath,
        string destinationPath)
    {
        var currentFullPath = Path.GetFullPath(currentPath);
        var destinationFullPath = Path.GetFullPath(destinationPath);
        VerifyHandlePath(handle, currentFullPath);
        if (File.Exists(destinationFullPath) || Directory.Exists(destinationFullPath))
        {
            throw new NingRanException("保存位置已经有同名内容，请更换名称。");
        }

        var currentDirectory = Path.GetDirectoryName(currentFullPath)
            ?? throw new NingRanException("无法确定临时文件所在位置。");
        var destinationDirectory = Path.GetDirectoryName(destinationFullPath)
            ?? throw new NingRanException("无法确定正式文件保存位置。");
        if (!string.Equals(
                currentDirectory,
                destinationDirectory,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new NingRanException("临时文件与正式文件必须位于同一个安全锁定的文件夹。");
        }

        var nativeDestinationPath = destinationFullPath.StartsWith(@"\\", StringComparison.Ordinal)
            ? @"\??\UNC\" + destinationFullPath[2..]
            : @"\??\" + destinationFullPath;
        var fileNameBytes = Encoding.Unicode.GetBytes(nativeDestinationPath);
        var fileNameOffset = Marshal.OffsetOf<FileRenameInformationLayout>(
            nameof(FileRenameInformationLayout.FileName)).ToInt32();
        var fileNameLengthOffset = Marshal.OffsetOf<FileRenameInformationLayout>(
            nameof(FileRenameInformationLayout.FileNameLength)).ToInt32();
        var information = new byte[checked(fileNameOffset + fileNameBytes.Length + sizeof(char))];
        BinaryPrimitives.WriteUInt32LittleEndian(
            information.AsSpan(fileNameLengthOffset, sizeof(uint)),
            checked((uint)fileNameBytes.Length));
        fileNameBytes.CopyTo(information, fileNameOffset);

        var pointer = Marshal.AllocHGlobal(information.Length);
        try
        {
            Marshal.Copy(information, 0, pointer, information.Length);
            if (!SetFileInformationByHandle(
                    handle,
                    FileInfoByHandleClass.FileRenameInfo,
                    pointer,
                    checked((uint)information.Length)))
            {
                throw new NingRanException(
                    "无法安全完成文件保存。",
                    new Win32Exception(Marshal.GetLastWin32Error()));
            }
        }
        finally
        {
            Marshal.FreeHGlobal(pointer);
            CryptographicOperations.ZeroMemory(information);
            CryptographicOperations.ZeroMemory(fileNameBytes);
        }

        VerifyHandlePath(handle, destinationFullPath);
    }

    public static void DeleteOpenFile(SafeFileHandle handle, string expectedPath)
    {
        VerifyHandlePath(handle, expectedPath);
        var disposition = new FileDispositionInformation { DeleteFile = true };
        if (!SetFileInformationByHandle(
                handle,
                FileInfoByHandleClass.FileDispositionInfo,
                ref disposition,
                (uint)Marshal.SizeOf<FileDispositionInformation>()))
        {
            throw new NingRanException(
                "无法安全删除临时文件。",
                new Win32Exception(Marshal.GetLastWin32Error()));
        }
    }

    public static void DeleteVerifiedFile(string path, WindowsFileIdentity expectedIdentity)
    {
        var fullPath = Path.GetFullPath(path);
        using var handle = CreateFileW(
            fullPath,
            FileReadAttributes | DeleteAccess,
            FileShareRead,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOpenReparsePoint,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            throw new NingRanException(
                "无法安全清理临时文件。",
                new Win32Exception(Marshal.GetLastWin32Error()));
        }

        var attributes = File.GetAttributes(handle);
        if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
        {
            throw new NingRanException("临时文件已被替换，为避免误删已停止清理。");
        }

        VerifyHandlePath(handle, fullPath);
        if (GetIdentity(handle) != expectedIdentity)
        {
            throw new NingRanException("临时文件身份已经改变，为避免误删已停止清理。");
        }

        var disposition = new FileDispositionInformation { DeleteFile = true };
        if (!SetFileInformationByHandle(
                handle,
                FileInfoByHandleClass.FileDispositionInfo,
                ref disposition,
                (uint)Marshal.SizeOf<FileDispositionInformation>()))
        {
            throw new NingRanException(
                "无法安全删除临时文件。",
                new Win32Exception(Marshal.GetLastWin32Error()));
        }
    }

    public static void CreatePrivateDirectory(string path)
    {
        var fullPath = Path.GetFullPath(path);
        if (File.Exists(fullPath) || Directory.Exists(fullPath))
        {
            throw new IOException($"安全临时目录已经存在：{fullPath}");
        }

        var identity = WindowsIdentity.GetCurrent();
        var currentUser = identity.User
            ?? throw new NingRanException("无法识别当前 Windows 账户，不能安全创建临时目录。");
        var localSystem = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(currentUser);
        security.AddAccessRule(new FileSystemAccessRule(
            currentUser,
            FileSystemRights.FullControl,
            inheritance,
            PropagationFlags.None,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            localSystem,
            FileSystemRights.FullControl,
            inheritance,
            PropagationFlags.None,
            AccessControlType.Allow));

        var directory = new DirectoryInfo(fullPath);
        try
        {
            directory.Create(security);
            VerifyPrivateDirectory(directory, currentUser, localSystem);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
                                          NotSupportedException or PlatformNotSupportedException or
                                          SystemException)
        {
            TryDeleteEmptyDirectory(fullPath);
            throw new NingRanException(
                $"所选位置无法建立仅当前账户可访问的安全临时目录，已停止处理：{Path.GetDirectoryName(fullPath)}",
                exception);
        }
    }

    public static void SecureExistingPrivateDirectory(string path)
    {
        var fullPath = Path.GetFullPath(path);
        if ((File.GetAttributes(fullPath) & FileAttributes.ReparsePoint) != 0)
        {
            throw new NingRanException($"安全恢复目录不能是快捷链接、符号链接或目录联接：{fullPath}");
        }

        var identity = WindowsIdentity.GetCurrent();
        var currentUser = identity.User
            ?? throw new NingRanException("无法识别当前 Windows 账户，不能保护安全恢复目录。");
        var localSystem = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(currentUser);
        security.AddAccessRule(new FileSystemAccessRule(
            currentUser,
            FileSystemRights.FullControl,
            inheritance,
            PropagationFlags.None,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            localSystem,
            FileSystemRights.FullControl,
            inheritance,
            PropagationFlags.None,
            AccessControlType.Allow));

        var directory = new DirectoryInfo(fullPath);
        directory.SetAccessControl(security);
        VerifyPrivateDirectory(directory, currentUser, localSystem);
    }

    public static void DeleteDirectoryWithoutFollowingLinks(
        string path,
        WindowsFileIdentity? expectedIdentity = null)
    {
        var fullPath = Path.GetFullPath(path);
        if (!Directory.Exists(fullPath))
        {
            return;
        }

        DeleteDirectoryCore(fullPath, expectedIdentity);
    }

    public static void DeleteEmptyDirectoryWithoutFollowingLinks(
        string path,
        WindowsFileIdentity expectedIdentity)
    {
        using var handle = OpenEntryForDeletion(path, expectDirectory: true);
        VerifyIdentity(handle, expectedIdentity);
        var attributes = File.GetAttributes(handle);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new NingRanException("待删除文件夹变成了链接，为避免删错内容已停止删除。");
        }

        try
        {
            MarkOpenEntryForDeletion(handle);
        }
        catch (NingRanException exception)
        {
            throw new NingRanException(
                "待删除文件夹中出现了未确认的新内容，为避免删错内容已停止删除。",
                exception);
        }
    }

    private static void DeleteDirectoryCore(string path, WindowsFileIdentity? expectedIdentity = null)
    {
        using var directoryHandle = OpenEntryForDeletion(path, expectDirectory: true);
        if (expectedIdentity is not null)
        {
            VerifyIdentity(directoryHandle, expectedIdentity.Value);
        }

        var directoryAttributes = File.GetAttributes(directoryHandle);
        if ((directoryAttributes & FileAttributes.ReparsePoint) != 0)
        {
            MarkOpenEntryForDeletion(directoryHandle);
            return;
        }

        foreach (var entry in new DirectoryInfo(path).EnumerateFileSystemInfos())
        {
            var attributes = File.GetAttributes(entry.FullName);
            if ((attributes & FileAttributes.Directory) != 0)
            {
                DeleteDirectoryCore(entry.FullName);
            }
            else
            {
                DeleteFileWithoutFollowingLinks(entry.FullName);
            }
        }

        if ((directoryAttributes & FileAttributes.ReadOnly) != 0)
        {
            File.SetAttributes(directoryHandle, directoryAttributes & ~FileAttributes.ReadOnly);
        }

        MarkOpenEntryForDeletion(directoryHandle);
    }

    public static void DeleteFileWithoutFollowingLinks(
        string path,
        WindowsFileIdentity? expectedIdentity = null)
    {
        using var handle = OpenEntryForDeletion(path, expectDirectory: false);
        if (expectedIdentity is not null)
        {
            VerifyIdentity(handle, expectedIdentity.Value);
        }

        var attributes = File.GetAttributes(handle);
        if ((attributes & FileAttributes.ReadOnly) != 0)
        {
            File.SetAttributes(handle, attributes & ~FileAttributes.ReadOnly);
        }

        MarkOpenEntryForDeletion(handle);
    }

    private static SafeFileHandle OpenEntryForDeletion(string path, bool expectDirectory)
    {
        var fullPath = Path.GetFullPath(path);
        var flags = FileFlagOpenReparsePoint | (expectDirectory ? FileFlagBackupSemantics : 0u);
        var handle = CreateFileW(
            fullPath,
            FileReadAttributes | DeleteAccess,
            FileShareRead | FileShareWrite,
            IntPtr.Zero,
            OpenExisting,
            flags,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = new Win32Exception(Marshal.GetLastWin32Error());
            handle.Dispose();
            throw new NingRanException("无法安全打开待清理内容。", error);
        }

        try
        {
            var attributes = File.GetAttributes(handle);
            var isDirectory = (attributes & FileAttributes.Directory) != 0;
            if (isDirectory != expectDirectory)
            {
                throw new NingRanException("待清理内容的类型已经改变，已停止清理。");
            }

            VerifyHandlePath(handle, fullPath);
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private static void MarkOpenEntryForDeletion(SafeFileHandle handle)
    {
        var disposition = new FileDispositionInformation { DeleteFile = true };
        if (!SetFileInformationByHandle(
                handle,
                FileInfoByHandleClass.FileDispositionInfo,
                ref disposition,
                (uint)Marshal.SizeOf<FileDispositionInformation>()))
        {
            throw new NingRanException(
                "无法安全删除临时内容。",
                new Win32Exception(Marshal.GetLastWin32Error()));
        }
    }

    private static void VerifyPrivateDirectory(
        DirectoryInfo directory,
        SecurityIdentifier currentUser,
        SecurityIdentifier localSystem)
    {
        directory.Refresh();
        if (!directory.Exists || (directory.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new UnauthorizedAccessException("安全临时目录被替换或没有成功创建。");
        }

        var security = directory.GetAccessControl(AccessControlSections.Access);
        if (!security.AreAccessRulesProtected)
        {
            throw new UnauthorizedAccessException("安全临时目录仍继承了其他账户的访问权限。");
        }

        var rules = security.GetAccessRules(
            includeExplicit: true,
            includeInherited: true,
            targetType: typeof(SecurityIdentifier));
        foreach (FileSystemAccessRule rule in rules)
        {
            if (rule.AccessControlType == AccessControlType.Allow &&
                rule.IdentityReference is SecurityIdentifier sid &&
                !sid.Equals(currentUser) &&
                !sid.Equals(localSystem))
            {
                throw new UnauthorizedAccessException($"安全临时目录仍允许其他账户访问：{sid.Value}");
            }
        }
    }

    private static void TryDeleteEmptyDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path) && !Directory.EnumerateFileSystemEntries(path).Any())
            {
                Directory.Delete(path, recursive: false);
            }
        }
        catch
        {
            // 创建安全目录的原始错误更重要；这里只处理尚未写入明文的空目录。
        }
    }

    private static string GetFinalPath(SafeFileHandle handle)
    {
        var capacity = 512;
        while (true)
        {
            var builder = new StringBuilder(capacity);
            var length = GetFinalPathNameByHandleW(handle, builder, (uint)builder.Capacity, 0);
            if (length == 0)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            if (length < builder.Capacity)
            {
                return builder.ToString();
            }

            capacity = checked((int)length + 1);
        }
    }

    private static string NormalizeComparablePath(string path)
    {
        var normalized = path;
        if (normalized.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
        {
            normalized = @"\\" + normalized[8..];
        }
        else if (normalized.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
        {
            normalized = normalized[4..];
        }

        return Path.TrimEndingDirectorySeparator(Path.GetFullPath(normalized));
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(
        SafeFileHandle file,
        StringBuilder filePath,
        uint filePathLength,
        uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation information);

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public uint CreationTimeLow;
        public uint CreationTimeHigh;
        public uint LastAccessTimeLow;
        public uint LastAccessTimeHigh;
        public uint LastWriteTimeLow;
        public uint LastWriteTimeHigh;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    private enum FileInfoByHandleClass
    {
        FileDispositionInfo = 4,
        FileRenameInfo = 3,
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileRenameInformationLayout
    {
        public byte ReplaceIfExists;
        public IntPtr RootDirectory;
        public uint FileNameLength;
        public char FileName;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileDispositionInformation
    {
        [MarshalAs(UnmanagedType.Bool)]
        public bool DeleteFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(
        SafeFileHandle file,
        FileInfoByHandleClass fileInformationClass,
        ref FileDispositionInformation fileInformation,
        uint bufferSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(
        SafeFileHandle file,
        FileInfoByHandleClass fileInformationClass,
        IntPtr fileInformation,
        uint bufferSize);
}

internal readonly record struct WindowsFileIdentity(uint VolumeSerialNumber, ulong FileIndex);

internal sealed class StableDirectoryPath : IDisposable
{
    private readonly List<SafeFileHandle> _handles = new();
    private FileStream? _pathLock;

    public StableDirectoryPath(string path)
    {
        FullPath = Path.GetFullPath(path);
        try
        {
            foreach (var component in EnumeratePathComponents(FullPath))
            {
                _handles.Add(WindowsFileSystemSafety.OpenStableDirectory(component));
            }

            var lockPath = Path.Combine(FullPath, $".ningran-path-{Guid.NewGuid():N}.lock");
            _pathLock = new FileStream(
                lockPath,
                FileMode.CreateNew,
                FileAccess.ReadWrite,
                FileShare.None,
                bufferSize: 1,
                FileOptions.DeleteOnClose | FileOptions.WriteThrough);
            WindowsFileSystemSafety.VerifyHandlePath(_pathLock.SafeFileHandle, lockPath);
            File.SetAttributes(
                _pathLock.SafeFileHandle,
                FileAttributes.Hidden | FileAttributes.Temporary);
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    public string FullPath { get; }

    public void Dispose()
    {
        _pathLock?.Dispose();
        _pathLock = null;
        for (var index = _handles.Count - 1; index >= 0; index--)
        {
            _handles[index].Dispose();
        }

        _handles.Clear();
    }

    private static IEnumerable<string> EnumeratePathComponents(string path)
    {
        var root = Path.GetPathRoot(path)
            ?? throw new NingRanException($"无法识别文件夹所在磁盘：{path}");
        yield return root;

        var remainder = path[root.Length..];
        var current = root;
        foreach (var part in remainder.Split(
                     new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar },
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, part);
            yield return current;
        }
    }
}
