using System.IO;
using System.IO.Enumeration;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using Fsp;
using NingRan.Core;
using FileInfo = Fsp.Interop.FileInfo;
using VolumeInfo = Fsp.Interop.VolumeInfo;

namespace NingRan.Windows;

internal sealed class VaultFileSystem : FileSystemBase
{
    private const uint DataWriteAccessMask =
        0x40000000 | // GENERIC_WRITE
        0x00000002 | // FILE_WRITE_DATA
        0x00000004 | // FILE_APPEND_DATA
        0x00000010 | // FILE_WRITE_EA
        0x00000100;  // FILE_WRITE_ATTRIBUTES
    private const uint WriteAccessMask =
        0x40000000 | // GENERIC_WRITE
        0x00010000 | // DELETE
        0x00040000 | // WRITE_DAC
        0x00080000 | // WRITE_OWNER
        0x00000002 | // FILE_WRITE_DATA
        0x00000004 | // FILE_APPEND_DATA
        0x00000010 | // FILE_WRITE_EA
        0x00000100;  // FILE_WRITE_ATTRIBUTES
    private const int AllocationUnit = 4096;
    private readonly VaultSession _session;
    private readonly byte[] _readWriteSecurity;
    private readonly DateTime _createdUtc;

    public VaultFileSystem(VaultSession session)
    {
        _session = session;
        _createdUtc = session.Info.CreatedAt.UtcDateTime;
        var descriptor = new RawSecurityDescriptor(
            "O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;BU)");
        _readWriteSecurity = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(_readWriteSecurity, 0);
    }

    public override int Init(object hostObject)
    {
        var host = (FileSystemHost)hostObject;
        host.SectorSize = AllocationUnit;
        host.SectorsPerAllocationUnit = 1;
        host.MaxComponentLength = 255;
        host.FileInfoTimeout = 1000;
        // The virtual volume size changes after writes and deletes. Do not let Explorer cache it.
        host.VolumeInfoTimeout = 0;
        host.CaseSensitiveSearch = false;
        host.CasePreservedNames = true;
        host.UnicodeOnDisk = true;
        host.PersistentAcls = true;
        host.VolumeCreationTime = (ulong)_createdUtc.ToFileTimeUtc();
        host.VolumeSerialNumber = BitConverter.ToUInt32(_session.Info.VaultId.ToByteArray(), 0);
        return STATUS_SUCCESS;
    }

    public override int GetVolumeInfo(out VolumeInfo volumeInfo)
    {
        volumeInfo = default;
        try
        {
            var total = Math.Max(_session.WorkspaceCapacityBytes, 1);
            var used = Math.Clamp(_session.WorkspaceUsedBytes, 0, total);
            volumeInfo.TotalSize = (ulong)total;
            volumeInfo.FreeSize = (ulong)(total - used);
        }
        catch
        {
            volumeInfo.TotalSize = (ulong)Math.Max(_session.WorkspaceCapacityBytes, 1);
            volumeInfo.FreeSize = 0;
        }
        volumeInfo.SetVolumeLabel(TrimVolumeLabel(_session.Name));
        return STATUS_SUCCESS;
    }

    public override int SetVolumeLabel(string volumeLabel, out VolumeInfo volumeInfo)
    {
        _ = volumeLabel;
        GetVolumeInfo(out volumeInfo);
        return STATUS_MEDIA_WRITE_PROTECTED;
    }

    public override int GetSecurityByName(
        string fileName,
        out uint fileAttributes,
        ref byte[] securityDescriptor)
    {
        if (!TryResolve(fileName, out var node))
        {
            fileAttributes = 0;
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
        fileAttributes = GetAttributes(node);
        if (securityDescriptor is not null) securityDescriptor = _readWriteSecurity;
        return STATUS_SUCCESS;
    }

    public override int Open(
        string fileName,
        uint createOptions,
        uint grantedAccess,
        out object fileNode,
        out object fileDescriptor,
        out FileInfo fileInfo,
        out string normalizedName)
    {
        fileNode = null!;
        fileDescriptor = null!;
        fileInfo = default;
        normalizedName = null!;
        if (!TryResolve(fileName, out var node))
        {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
        if (node.IsDirectory && (createOptions & FILE_NON_DIRECTORY_FILE) != 0)
        {
            return STATUS_FILE_IS_A_DIRECTORY;
        }
        if (!node.IsDirectory && (createOptions & FILE_DIRECTORY_FILE) != 0)
        {
            return STATUS_NOT_A_DIRECTORY;
        }

        Stream? stream = null;
        if (!node.IsDirectory)
        {
            stream = (grantedAccess & DataWriteAccessMask) != 0
                ? _session.OpenWriteStream(node.RelativePath)
                : _session.OpenReadStream(node.RelativePath);
        }
        var descriptor = new VaultFileDescriptor(node, stream);
        fileNode = node;
        fileDescriptor = descriptor;
        fileInfo = CreateFileInfo(node);
        normalizedName = node.IsRoot ? "\\" : "\\" + node.RelativePath.Replace('/', '\\');
        return STATUS_SUCCESS;
    }

    public override void Close(object fileNode, object fileDescriptor)
    {
        _ = fileNode;
        (fileDescriptor as VaultFileDescriptor)?.Dispose();
    }

    public override void Cleanup(object fileNode, object fileDescriptor, string fileName, uint flags)
    {
        var descriptor = (VaultFileDescriptor)fileDescriptor;
        if (descriptor.DeletePending || (flags & CleanupDelete) != 0)
        {
            descriptor.AbandonWrite();
            _session.DeleteAsync(descriptor.Node.RelativePath).GetAwaiter().GetResult();
            return;
        }
        descriptor.CommitWrite();
        RefreshNode(descriptor.Node);
    }

    public override int Read(
        object fileNode,
        object fileDescriptor,
        IntPtr buffer,
        ulong offset,
        uint length,
        out uint bytesTransferred)
    {
        _ = fileNode;
        bytesTransferred = 0;
        var descriptor = (VaultFileDescriptor)fileDescriptor;
        if (descriptor.Stream is null)
        {
            return STATUS_FILE_IS_A_DIRECTORY;
        }
        if (offset >= (ulong)descriptor.Stream.Length)
        {
            return STATUS_END_OF_FILE;
        }
        var wanted = checked((int)Math.Min(length, (ulong)descriptor.Stream.Length - offset));
        var bytes = new byte[wanted];
        try
        {
            int read;
            lock (descriptor.Gate)
            {
                descriptor.Stream.Position = checked((long)offset);
                read = descriptor.Stream.Read(bytes, 0, wanted);
            }
            if (read > 0)
            {
                Marshal.Copy(bytes, 0, buffer, read);
            }
            bytesTransferred = checked((uint)read);
            return STATUS_SUCCESS;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    public override int GetFileInfo(object fileNode, object fileDescriptor, out FileInfo fileInfo)
    {
        _ = fileDescriptor;
        fileInfo = CreateFileInfo((VaultNode)fileNode);
        return STATUS_SUCCESS;
    }

    public override int GetSecurity(object fileNode, object fileDescriptor, ref byte[] securityDescriptor)
    {
        _ = fileNode;
        _ = fileDescriptor;
        securityDescriptor = _readWriteSecurity;
        return STATUS_SUCCESS;
    }

    public override bool ReadDirectoryEntry(
        object fileNode,
        object fileDescriptor,
        string pattern,
        string marker,
        ref object context,
        out string fileName,
        out FileInfo fileInfo)
    {
        var descriptor = (VaultFileDescriptor)fileDescriptor;
        var directory = (VaultNode)fileNode;
        if (!directory.IsDirectory)
        {
            fileName = null!;
            fileInfo = default;
            return false;
        }

        descriptor.DirectoryEntries ??= BuildDirectoryEntries(directory, pattern);
        var index = context is int current ? current : 0;
        if (context is null && !string.IsNullOrEmpty(marker))
        {
            index = Array.FindIndex(descriptor.DirectoryEntries,
                item => string.Compare(item.Name, marker, StringComparison.OrdinalIgnoreCase) > 0);
            if (index < 0) index = descriptor.DirectoryEntries.Length;
        }
        if (index >= descriptor.DirectoryEntries.Length)
        {
            fileName = null!;
            fileInfo = default;
            return false;
        }
        var entry = descriptor.DirectoryEntries[index];
        context = index + 1;
        fileName = entry.Name;
        fileInfo = CreateFileInfo(entry.Node);
        return true;
    }

    public override int Create(
        string fileName,
        uint createOptions,
        uint grantedAccess,
        uint fileAttributes,
        byte[] securityDescriptor,
        ulong allocationSize,
        out object fileNode,
        out object fileDescriptor,
        out FileInfo fileInfo,
        out string normalizedName)
    {
        _ = grantedAccess; _ = fileAttributes; _ = securityDescriptor;
        fileNode = null!; fileDescriptor = null!; fileInfo = default; normalizedName = null!;
        var relativePath = NormalizeFileName(fileName);
        if (TryResolve(fileName, out _)) return STATUS_OBJECT_NAME_COLLISION;
        if ((createOptions & FILE_DIRECTORY_FILE) != 0)
        {
            _session.CreateDirectoryAsync(relativePath).GetAwaiter().GetResult();
            if (!TryResolve(fileName, out var directory)) return STATUS_UNEXPECTED_IO_ERROR;
            var descriptor = new VaultFileDescriptor(directory, null);
            fileNode = directory;
            fileDescriptor = descriptor;
            fileInfo = CreateFileInfo(directory);
        }
        else
        {
            var write = _session.OpenWriteStream(relativePath, createNew: true);
            if (allocationSize > 0 && allocationSize <= long.MaxValue) write.SetLength(0);
            var node = VaultNode.Pending(relativePath, _createdUtc);
            var descriptor = new VaultFileDescriptor(node, write);
            fileNode = node;
            fileDescriptor = descriptor;
            fileInfo = CreateFileInfo(node);
        }
        normalizedName = "\\" + relativePath.Replace('/', '\\');
        return STATUS_SUCCESS;
    }

    public override int Overwrite(
        object fileNode, object fileDescriptor, uint fileAttributes, bool replaceFileAttributes,
        ulong allocationSize, out FileInfo fileInfo)
    {
        _ = fileNode; _ = fileAttributes; _ = replaceFileAttributes; _ = allocationSize;
        var descriptor = (VaultFileDescriptor)fileDescriptor;
        var write = descriptor.EnsureWrite(_session);
        write.SetLength(0);
        descriptor.Node.SetLength(0);
        fileInfo = CreateFileInfo(descriptor.Node);
        return STATUS_SUCCESS;
    }

    public override int Write(
        object fileNode,
        object fileDescriptor,
        IntPtr buffer,
        ulong offset,
        uint length,
        bool writeToEndOfFile,
        bool constrainedIo,
        out uint bytesTransferred,
        out FileInfo fileInfo)
    {
        _ = fileNode;
        bytesTransferred = 0;
        var descriptor = (VaultFileDescriptor)fileDescriptor;
        if (descriptor.Node.IsDirectory) { fileInfo = default; return STATUS_FILE_IS_A_DIRECTORY; }
        var write = descriptor.EnsureWrite(_session);
        var actualOffset = writeToEndOfFile ? write.Length : checked((long)offset);
        if (constrainedIo && actualOffset >= write.Length)
        {
            fileInfo = CreateFileInfo(descriptor.Node);
            return STATUS_SUCCESS;
        }
        var wanted = constrainedIo ? checked((int)Math.Min(length, (ulong)(write.Length - actualOffset))) : checked((int)length);
        var bytes = new byte[wanted];
        try
        {
            Marshal.Copy(buffer, bytes, 0, wanted);
            write.Position = actualOffset;
            write.Write(bytes, 0, wanted);
            descriptor.Node.SetLength(write.Length);
            bytesTransferred = checked((uint)wanted);
            fileInfo = CreateFileInfo(descriptor.Node);
            return STATUS_SUCCESS;
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    public override int Flush(object fileNode, object fileDescriptor, out FileInfo fileInfo)
    {
        _ = fileNode;
        var descriptor = (VaultFileDescriptor)fileDescriptor;
        descriptor.CommitWrite();
        RefreshNode(descriptor.Node);
        fileInfo = CreateFileInfo(descriptor.Node);
        return STATUS_SUCCESS;
    }

    public override int SetFileSize(
        object fileNode, object fileDescriptor, ulong newSize, bool setAllocationSize, out FileInfo fileInfo)
    {
        _ = fileNode;
        var descriptor = (VaultFileDescriptor)fileDescriptor;
        if (descriptor.Node.IsDirectory || newSize > long.MaxValue) { fileInfo = default; return STATUS_INVALID_PARAMETER; }
        var write = descriptor.EnsureWrite(_session);
        if (!setAllocationSize || (long)newSize < write.Length) write.SetLength((long)newSize);
        descriptor.Node.SetLength(write.Length);
        fileInfo = CreateFileInfo(descriptor.Node);
        return STATUS_SUCCESS;
    }

    public override int SetBasicInfo(
        object fileNode, object fileDescriptor, uint fileAttributes, ulong creationTime,
        ulong lastAccessTime, ulong lastWriteTime, ulong changeTime, out FileInfo fileInfo)
    {
        _ = fileNode; _ = fileAttributes; _ = creationTime; _ = lastAccessTime; _ = changeTime;
        var descriptor = (VaultFileDescriptor)fileDescriptor;
        if (lastWriteTime != 0)
        {
            var value = DateTime.FromFileTimeUtc(checked((long)lastWriteTime));
            descriptor.CommitWrite();
            _session.SetLastWriteTimeAsync(descriptor.Node.RelativePath, value).GetAwaiter().GetResult();
            descriptor.Node.SetLastWrite(value);
        }
        fileInfo = CreateFileInfo(descriptor.Node);
        return STATUS_SUCCESS;
    }

    public override int CanDelete(object fileNode, object fileDescriptor, string fileName)
    {
        _ = fileNode; _ = fileName;
        return ((VaultFileDescriptor)fileDescriptor).Node.IsRoot ? STATUS_ACCESS_DENIED : STATUS_SUCCESS;
    }

    public override int SetDelete(object fileNode, object fileDescriptor, string fileName, bool deleteFile)
    {
        _ = fileNode; _ = fileName;
        var descriptor = (VaultFileDescriptor)fileDescriptor;
        if (descriptor.Node.IsRoot) return STATUS_ACCESS_DENIED;
        descriptor.DeletePending = deleteFile;
        return STATUS_SUCCESS;
    }

    public override int Rename(
        object fileNode, object fileDescriptor, string fileName, string newFileName, bool replaceIfExists)
    {
        _ = fileNode;
        var descriptor = (VaultFileDescriptor)fileDescriptor;
        descriptor.CommitWrite();
        var source = NormalizeFileName(fileName);
        var target = NormalizeFileName(newFileName);
        _session.MoveAsync(source, target, replaceIfExists).GetAwaiter().GetResult();
        descriptor.Node.SetPath(target);
        if (descriptor.Stream is VaultWriteSession write) write.ChangePath(target);
        return STATUS_SUCCESS;
    }

    public override int ExceptionHandler(Exception exception)
    {
        return exception switch
        {
            NingRanException error when error.Message.Contains("空间不足", StringComparison.Ordinal) => STATUS_DISK_FULL,
            NingRanException error when error.Message.Contains("同名", StringComparison.Ordinal) || error.Message.Contains("已经存在", StringComparison.Ordinal) => STATUS_OBJECT_NAME_COLLISION,
            NingRanException error when error.Message.Contains("不存在", StringComparison.Ordinal) || error.Message.Contains("没有找到", StringComparison.Ordinal) => STATUS_OBJECT_NAME_NOT_FOUND,
            NingRanException => STATUS_FILE_CORRUPT_ERROR,
            OperationCanceledException => STATUS_CANCELLED,
            ObjectDisposedException => STATUS_DEVICE_NOT_READY,
            _ => STATUS_UNEXPECTED_IO_ERROR,
        };
    }

    private DirectoryItem[] BuildDirectoryEntries(VaultNode directory, string? pattern)
    {
        var result = new List<DirectoryItem>();
        if (!directory.IsRoot)
        {
            result.Add(new DirectoryItem(".", directory));
            var parentPath = Path.GetDirectoryName(directory.RelativePath.Replace('/', '\\'))?.Replace('\\', '/') ?? string.Empty;
            result.Add(new DirectoryItem("..", ResolveOrRoot(parentPath)));
        }
        foreach (var entry in _session.GetChildren(directory.IsRoot ? null : directory.RelativePath))
        {
            if (!string.IsNullOrEmpty(pattern) &&
                !FileSystemName.MatchesSimpleExpression(NormalizePattern(pattern), entry.Name, ignoreCase: true))
            {
                continue;
            }
            result.Add(new DirectoryItem(entry.Name, new VaultNode(entry)));
        }
        return result.OrderBy(item => item.Name is "." ? 0 : item.Name is ".." ? 1 : item.Node.IsDirectory ? 2 : 3)
            .ThenBy(item => item.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private VaultNode ResolveOrRoot(string path) =>
        string.IsNullOrEmpty(path) ? VaultNode.Root(_createdUtc) :
        _session.TryGetEntry(path, out var entry) && entry is not null ? new VaultNode(entry) : VaultNode.Root(_createdUtc);

    private bool TryResolve(string fileName, out VaultNode node)
    {
        if (string.IsNullOrWhiteSpace(fileName) || fileName == "\\")
        {
            node = VaultNode.Root(_createdUtc);
            return true;
        }
        var path = fileName.TrimStart('\\').Replace('\\', '/');
        if (_session.TryGetEntry(path, out var entry) && entry is not null)
        {
            node = new VaultNode(entry);
            return true;
        }
        node = null!;
        return false;
    }

    private static string NormalizeFileName(string fileName) =>
        fileName.TrimStart('\\').Replace('\\', '/');

    private void RefreshNode(VaultNode node)
    {
        if (node.IsRoot) return;
        if (_session.TryGetEntry(node.RelativePath, out var entry) && entry is not null) node.Refresh(entry);
    }

    private static FileInfo CreateFileInfo(VaultNode node)
    {
        var length = node.IsDirectory ? 0UL : checked((ulong)node.Length);
        var time = checked((ulong)node.LastWriteUtc.ToFileTimeUtc());
        return new FileInfo
        {
            FileAttributes = GetAttributes(node),
            ReparseTag = 0,
            FileSize = length,
            AllocationSize = (length + AllocationUnit - 1) / AllocationUnit * AllocationUnit,
            CreationTime = time,
            LastAccessTime = time,
            LastWriteTime = time,
            ChangeTime = time,
            IndexNumber = node.IndexNumber,
            HardLinks = 1,
        };
    }

    private static uint GetAttributes(VaultNode node) => node.IsDirectory
        ? (uint)System.IO.FileAttributes.Directory
        : (uint)System.IO.FileAttributes.Archive;

    private static string NormalizePattern(string pattern) => pattern
        .Replace('<', '*')
        .Replace('>', '?')
        .Replace('"', '.');

    private static string TrimVolumeLabel(string name) =>
        name.Length <= 32 ? name : name[..32];

    private sealed class VaultFileDescriptor : IDisposable
    {
        public VaultFileDescriptor(VaultNode node, Stream? stream)
        {
            Node = node;
            Stream = stream;
        }
        public VaultNode Node { get; }
        public Stream? Stream { get; private set; }
        public object Gate { get; } = new();
        public DirectoryItem[]? DirectoryEntries { get; set; }
        public bool DeletePending { get; set; }
        public VaultWriteSession EnsureWrite(VaultSession session)
        {
            if (Stream is VaultWriteSession write) return write;
            Stream?.Dispose();
            return (VaultWriteSession)(Stream = session.OpenWriteStream(Node.RelativePath));
        }
        public void CommitWrite()
        {
            if (Stream is VaultWriteSession write && write.HasChanges) write.CommitAsync().GetAwaiter().GetResult();
        }
        public void AbandonWrite()
        {
            if (Stream is VaultWriteSession write) write.Abandon();
            Stream = null;
        }
        public void Dispose() => Stream?.Dispose();
    }

    private sealed record DirectoryItem(string Name, VaultNode Node);

    private sealed class VaultNode
    {
        private VaultNode(string relativePath, bool isDirectory, long length, DateTime lastWriteUtc, ulong indexNumber, bool isRoot)
        {
            RelativePath = relativePath;
            IsDirectory = isDirectory;
            Length = length;
            LastWriteUtc = lastWriteUtc;
            IndexNumber = indexNumber;
            IsRoot = isRoot;
        }
        public VaultNode(VaultEntry entry) : this(
            entry.RelativePath,
            entry.IsDirectory,
            entry.Length,
            entry.LastWriteTimeUtc,
            BitConverter.ToUInt64(entry.Id.ToByteArray(), 0),
            false)
        {
        }
        public string RelativePath { get; private set; }
        public bool IsDirectory { get; private set; }
        public long Length { get; private set; }
        public DateTime LastWriteUtc { get; private set; }
        public ulong IndexNumber { get; private set; }
        public bool IsRoot { get; }
        public static VaultNode Root(DateTime createdUtc) => new(string.Empty, true, 0, createdUtc, 1, true);
        public static VaultNode Pending(string relativePath, DateTime createdUtc) =>
            new(relativePath, false, 0, createdUtc, BitConverter.ToUInt64(Guid.NewGuid().ToByteArray(), 0), false);
        public void SetLength(long length) { Length = length; LastWriteUtc = DateTime.UtcNow; }
        public void SetLastWrite(DateTime value) => LastWriteUtc = value;
        public void SetPath(string path) => RelativePath = path;
        public void Refresh(VaultEntry entry)
        {
            RelativePath = entry.RelativePath;
            IsDirectory = entry.IsDirectory;
            Length = entry.Length;
            LastWriteUtc = entry.LastWriteTimeUtc;
            IndexNumber = BitConverter.ToUInt64(entry.Id.ToByteArray(), 0);
        }
    }
}
