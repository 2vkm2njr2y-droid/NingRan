using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace NingRan.Setup;

/// <summary>
/// Deletes a Windows file-system tree without ever traversing a reparse point.
/// Every directory in the path is kept open while its descendants are examined,
/// and each entry is inspected and deleted through the same non-share-delete handle.
/// </summary>
internal static class WindowsSafeTreeDeletion
{
    private const uint DeleteAccess = 0x00010000;
    private const uint FileReadAttributes = 0x00000080;
    private const uint FileWriteAttributes = 0x00000100;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileShareDelete = 0x00000004;
    private const uint OpenExisting = 3;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const int ErrorFileNotFound = 2;
    private const int ErrorPathNotFound = 3;
    private const int ErrorInvalidFunction = 1;
    private const int ErrorNotSupported = 50;
    private const int ErrorInvalidParameter = 87;
    private const int ErrorDirectoryNotEmpty = 145;
    private const int MaximumDirectoryPasses = 16;
    private const uint FileDispositionFlagDelete = 0x00000001;
    private const uint FileDispositionFlagIgnoreReadOnlyAttribute = 0x00000010;

    public static void Delete(string fullPath)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("安全删除只支持 Windows。");
        }

        using var lockedPath = TryLockPathForDeletion(fullPath);
        if (lockedPath is null)
        {
            return;
        }

        DeleteOpenedEntry(fullPath, lockedPath.EntryHandle, lockedPath.EntryAttributes);
    }

    private static void DeleteOpenedEntry(
        string path,
        SafeFileHandle handle,
        FileAttributes attributes)
    {
        var isDirectory = (attributes & FileAttributes.Directory) != 0;
        var isReparsePoint = (attributes & FileAttributes.ReparsePoint) != 0;
        if (isDirectory && !isReparsePoint)
        {
            for (var pass = 0; pass < MaximumDirectoryPasses; pass++)
            {
                foreach (var childPath in Directory.GetFileSystemEntries(path))
                {
                    using var child = TryOpenEntryForDeletion(childPath);
                    if (child is null)
                    {
                        continue;
                    }

                    DeleteOpenedEntry(childPath, child.Handle, child.Attributes);
                }

                if (TryMarkForDeletion(path, handle, attributes, isDirectory: true))
                {
                    return;
                }
            }

            throw new IOException(
                $"文件夹在清理期间持续出现新内容，已停止删除以免删错位置：{path}");
        }

        if (!TryMarkForDeletion(path, handle, attributes, isDirectory))
        {
            // A directory reparse point has no traversable children. Treating it
            // as a normal directory here would follow its target, so fail closed.
            throw new IOException($"无法只删除文件夹链接本身，已停止清理：{path}");
        }
    }

    private static LockedPath? TryLockPathForDeletion(string path)
    {
        var fullPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        var root = Path.GetPathRoot(fullPath)
            ?? throw new IOException($"无法确定待清理位置所在的磁盘：{fullPath}");
        if (string.Equals(
                Path.TrimEndingDirectorySeparator(root),
                fullPath,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("不能删除磁盘或共享位置的根目录。");
        }

        var handles = new List<SafeFileHandle>();
        try
        {
            // A volume/share root cannot be renamed as an ordinary child entry,
            // so it only needs to anchor the path. All later components deny
            // write/delete sharing and remain open until deletion finishes.
            var rootHandle = OpenHandle(
                root,
                FileReadAttributes,
                FileShareRead | FileShareWrite | FileShareDelete,
                out var rootError);
            if (rootHandle is null)
            {
                throw CreateIOException("无法锁定待清理位置所在的磁盘", root, rootError);
            }

            handles.Add(rootHandle);
            EnsureOrdinaryDirectory(rootHandle, root);

            var remainder = fullPath[root.Length..];
            var parts = remainder.Split(
                [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
                StringSplitOptions.RemoveEmptyEntries);
            var current = root;
            FileAttributes entryAttributes = default;
            for (var index = 0; index < parts.Length; index++)
            {
                current = Path.Combine(current, parts[index]);
                var isFinal = index == parts.Length - 1;
                var desiredAccess = FileReadAttributes |
                    (isFinal ? FileWriteAttributes | DeleteAccess : 0u);
                var handle = OpenHandle(current, desiredAccess, FileShareRead, out var error);
                if (handle is null)
                {
                    if (IsMissing(error))
                    {
                        DisposeAll(handles);
                        return null;
                    }

                    throw CreateIOException("无法安全锁定待清理路径", current, error);
                }

                handles.Add(handle);
                entryAttributes = File.GetAttributes(handle);
                if (!isFinal)
                {
                    EnsureOrdinaryDirectory(handle, current, entryAttributes);
                }
            }

            return new LockedPath(handles, entryAttributes);
        }
        catch
        {
            DisposeAll(handles);
            throw;
        }
    }

    private static OpenedEntry? TryOpenEntryForDeletion(string path)
    {
        var handle = OpenHandle(
            path,
            FileReadAttributes | FileWriteAttributes | DeleteAccess,
            FileShareRead,
            out var error);
        if (handle is null)
        {
            if (IsMissing(error))
            {
                return null;
            }

            throw CreateIOException("无法安全锁定待清理内容", path, error);
        }

        try
        {
            return new OpenedEntry(handle, File.GetAttributes(handle));
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private static SafeFileHandle? OpenHandle(
        string path,
        uint desiredAccess,
        uint shareMode,
        out int error)
    {
        var handle = CreateFileW(
            path,
            desiredAccess,
            shareMode,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOpenReparsePoint | FileFlagBackupSemantics,
            IntPtr.Zero);
        if (!handle.IsInvalid)
        {
            error = 0;
            return handle;
        }

        error = Marshal.GetLastWin32Error();
        handle.Dispose();
        return null;
    }

    private static bool TryMarkForDeletion(
        string path,
        SafeFileHandle handle,
        FileAttributes attributes,
        bool isDirectory)
    {
        var extendedDisposition = new FileDispositionInformationEx
        {
            Flags = FileDispositionFlagDelete | FileDispositionFlagIgnoreReadOnlyAttribute,
        };
        if (SetFileInformationByHandle(
                handle,
                FileInfoByHandleClass.FileDispositionInfoEx,
                ref extendedDisposition,
                checked((uint)Marshal.SizeOf<FileDispositionInformationEx>())))
        {
            return true;
        }

        var extendedError = Marshal.GetLastWin32Error();
        if (isDirectory && extendedError == ErrorDirectoryNotEmpty)
        {
            return false;
        }

        if (extendedError is not (ErrorInvalidFunction or ErrorNotSupported or ErrorInvalidParameter))
        {
            throw CreateIOException("Windows 无法删除已锁定的内容", path, extendedError);
        }

        // Older file systems may not support the extended disposition request.
        // Clear read-only through this same handle, then use the legacy request.
        if ((attributes & FileAttributes.ReadOnly) != 0)
        {
            ClearReadOnlyAttribute(handle, attributes);
        }

        var disposition = new FileDispositionInformation { DeleteFile = true };
        if (SetFileInformationByHandle(
                handle,
                FileInfoByHandleClass.FileDispositionInfo,
                ref disposition,
                checked((uint)Marshal.SizeOf<FileDispositionInformation>())))
        {
            return true;
        }

        var error = Marshal.GetLastWin32Error();
        if (isDirectory && error == ErrorDirectoryNotEmpty)
        {
            return false;
        }

        throw CreateIOException("Windows 无法删除已锁定的内容", path, error);
    }

    private static void ClearReadOnlyAttribute(
        SafeFileHandle handle,
        FileAttributes attributes)
    {
        if (!GetFileInformationByHandleEx(
                handle,
                FileInfoByHandleClass.FileBasicInfo,
                out var basicInformation,
                checked((uint)Marshal.SizeOf<FileBasicInformation>())))
        {
            throw CreateIOException(
                "无法读取只读内容的 Windows 属性",
                "",
                Marshal.GetLastWin32Error());
        }

        var updatedAttributes = attributes & ~FileAttributes.ReadOnly;
        if (updatedAttributes == 0)
        {
            updatedAttributes = FileAttributes.Normal;
        }

        basicInformation.FileAttributes = checked((uint)updatedAttributes);
        if (!SetFileInformationByHandle(
                handle,
                FileInfoByHandleClass.FileBasicInfo,
                ref basicInformation,
                checked((uint)Marshal.SizeOf<FileBasicInformation>())))
        {
            throw CreateIOException(
                "无法清除待删除内容的只读属性",
                "",
                Marshal.GetLastWin32Error());
        }
    }

    private static void EnsureOrdinaryDirectory(
        SafeFileHandle handle,
        string path,
        FileAttributes? knownAttributes = null)
    {
        var attributes = knownAttributes ?? File.GetAttributes(handle);
        if ((attributes & FileAttributes.Directory) == 0)
        {
            throw new IOException($"待清理路径中有同名文件，已停止删除：{path}");
        }

        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new IOException(
                $"待清理路径经过了快捷链接、符号链接或目录联接，已停止删除：{path}");
        }
    }

    private static bool IsMissing(int error) =>
        error is ErrorFileNotFound or ErrorPathNotFound;

    private static IOException CreateIOException(string action, string path, int error)
    {
        var detail = new Win32Exception(error);
        var location = string.IsNullOrEmpty(path) ? string.Empty : $"：{path}";
        return new IOException($"{action}{location}。{detail.Message}", detail);
    }

    private static void DisposeAll(List<SafeFileHandle> handles)
    {
        for (var index = handles.Count - 1; index >= 0; index--)
        {
            handles[index].Dispose();
        }

        handles.Clear();
    }

    private sealed class LockedPath : IDisposable
    {
        private readonly List<SafeFileHandle> _handles;

        public LockedPath(List<SafeFileHandle> handles, FileAttributes entryAttributes)
        {
            _handles = handles;
            EntryAttributes = entryAttributes;
        }

        public SafeFileHandle EntryHandle => _handles[^1];
        public FileAttributes EntryAttributes { get; }

        public void Dispose() => DisposeAll(_handles);
    }

    private sealed class OpenedEntry : IDisposable
    {
        public OpenedEntry(SafeFileHandle handle, FileAttributes attributes)
        {
            Handle = handle;
            Attributes = attributes;
        }

        public SafeFileHandle Handle { get; }
        public FileAttributes Attributes { get; }

        public void Dispose() => Handle.Dispose();
    }

    private enum FileInfoByHandleClass
    {
        FileBasicInfo = 0,
        FileDispositionInfo = 4,
        FileDispositionInfoEx = 21,
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileBasicInformation
    {
        public long CreationTime;
        public long LastAccessTime;
        public long LastWriteTime;
        public long ChangeTime;
        public uint FileAttributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileDispositionInformation
    {
        [MarshalAs(UnmanagedType.Bool)]
        public bool DeleteFile;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileDispositionInformationEx
    {
        public uint Flags;
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
        ref FileDispositionInformationEx fileInformation,
        uint bufferSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(
        SafeFileHandle file,
        FileInfoByHandleClass fileInformationClass,
        ref FileBasicInformation fileInformation,
        uint bufferSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle file,
        FileInfoByHandleClass fileInformationClass,
        out FileBasicInformation fileInformation,
        uint bufferSize);
}
