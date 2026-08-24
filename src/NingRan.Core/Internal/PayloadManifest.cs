using Microsoft.Win32.SafeHandles;
using System.Text;

namespace NingRan.Core.Internal;

internal enum PayloadEntryKind : byte
{
    End = 0,
    Directory = 1,
    File = 2,
    Padding = 3,
}

internal sealed record PayloadEntry(
    PayloadEntryKind Kind,
    string FullPath,
    string RelativePath,
    long Length,
    long LastWriteUtcTicks,
    WindowsFileIdentity Identity,
    SafeFileHandle? SourceHandle,
    Func<CancellationToken, ValueTask<Stream>>? ContentFactory = null);

internal sealed class PayloadManifest : IDisposable
{
    private static ReadOnlySpan<byte> PayloadMagic => "NRPAY004"u8;

    private PayloadManifest(
        bool isDirectory,
        string rootName,
        IReadOnlyList<PayloadEntry> entries,
        long totalFileBytes,
        long paddingLength)
    {
        IsDirectory = isDirectory;
        RootName = rootName;
        Entries = entries;
        TotalFileBytes = totalFileBytes;
        PaddingLength = paddingLength;
    }

    public bool IsDirectory { get; }

    public string RootName { get; }

    public IReadOnlyList<PayloadEntry> Entries { get; }

    public long TotalFileBytes { get; }

    public long PaddingLength { get; }

    public void Dispose()
    {
        foreach (var entry in Entries)
        {
            entry.SourceHandle?.Dispose();
        }
    }

    internal static PayloadManifest Create(
        bool isDirectory,
        string rootName,
        IReadOnlyList<PayloadEntry> entries,
        SizePaddingMode sizePadding)
    {
        rootName = PathSafety.ValidateNameSegment(rootName);
        if (entries.Count == 0 || entries.Count > PayloadContainer.MaximumEntries)
        {
            throw new NingRanException("加密文件中的项目数量不正确。");
        }

        long totalBytes = 0;
        var totalNameBytes = Encoding.UTF8.GetByteCount(rootName);
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in entries)
        {
            var normalized = PathSafety.NormalizeRelativePath(entry.RelativePath);
            if (!string.Equals(normalized, entry.RelativePath, StringComparison.Ordinal) || !paths.Add(normalized))
            {
                throw new NingRanException("追加后的文件名存在重复，无法安全保存。");
            }

            totalNameBytes = checked(totalNameBytes + Encoding.UTF8.GetByteCount(normalized));
            if (totalNameBytes > PayloadContainer.MaximumTotalNameBytes)
            {
                throw new NingRanException("追加后的文件和文件夹名称总长度超过安全上限。");
            }

            if (entry.Kind == PayloadEntryKind.File)
            {
                totalBytes = checked(totalBytes + entry.Length);
            }
        }

        var copied = entries.ToArray();
        return new PayloadManifest(isDirectory, rootName, copied, totalBytes,
            CalculatePaddingLength(isDirectory, rootName, copied, sizePadding));
    }

    public static PayloadManifest Build(
        string sourcePath,
        SizePaddingMode sizePadding,
        CancellationToken cancellationToken)
    {
        var fullPath = Path.GetFullPath(sourcePath);
        var isFile = File.Exists(fullPath);
        var isDirectory = Directory.Exists(fullPath);
        if (!isFile && !isDirectory)
        {
            throw new NingRanException("请选择存在的文件或文件夹。");
        }

        var rootName = PathSafety.ValidateNameSegment(
            isFile ? new FileInfo(fullPath).Name : new DirectoryInfo(fullPath).Name);
        var entries = new List<PayloadEntry>();
        long totalBytes = 0;
        long totalNameBytes = Encoding.UTF8.GetByteCount(rootName);

        try
        {
            if (isFile)
            {
                var handle = WindowsFileSystemSafety.OpenInputFile(fullPath);
                var length = RandomAccess.GetLength(handle);
                entries.Add(new PayloadEntry(
                    PayloadEntryKind.File,
                    fullPath,
                    rootName,
                    length,
                    File.GetLastWriteTimeUtc(handle).Ticks,
                    WindowsFileSystemSafety.GetIdentity(handle),
                    handle));
                totalBytes = length;
            }
            else
            {
                var root = new DirectoryInfo(fullPath);
                var rootHandle = WindowsFileSystemSafety.OpenInputDirectory(root.FullName);
                entries.Add(new PayloadEntry(
                    PayloadEntryKind.Directory,
                    root.FullName,
                    rootName,
                    0,
                    File.GetLastWriteTimeUtc(rootHandle).Ticks,
                    WindowsFileSystemSafety.GetIdentity(rootHandle),
                    rootHandle));

                var pending = new Stack<DirectoryInfo>();
                pending.Push(root);
                while (pending.Count > 0)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var directory = pending.Pop();
                    FileSystemInfo[] children;
                    try
                    {
                        children = directory.GetFileSystemInfos()
                            .OrderBy(item => item is FileInfo)
                            .ThenBy(item => item.Name, StringComparer.OrdinalIgnoreCase)
                            .ToArray();
                    }
                    catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                    {
                        throw new NingRanException($"无法读取文件夹：{directory.FullName}", exception);
                    }

                    for (var index = children.Length - 1; index >= 0; index--)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        var child = children[index];
                        if (entries.Count >= PayloadContainer.MaximumEntries)
                        {
                            throw new NingRanException(
                                "所选内容超过 2 万个文件和文件夹，为避免电脑卡顿已停止处理。");
                        }

                        var relative = Path.GetRelativePath(root.Parent?.FullName ?? root.FullName, child.FullName)
                            .Replace('\\', '/');
                        relative = PathSafety.NormalizeRelativePath(relative);
                        totalNameBytes = checked(totalNameBytes + Encoding.UTF8.GetByteCount(relative));
                        if (totalNameBytes > PayloadContainer.MaximumTotalNameBytes)
                        {
                            throw new NingRanException(
                                "所选内容的文件和文件夹名称总长度超过安全上限，已停止处理。");
                        }

                        if (child is DirectoryInfo childDirectory)
                        {
                            var handle = WindowsFileSystemSafety.OpenInputDirectory(childDirectory.FullName);
                            entries.Add(new PayloadEntry(
                                PayloadEntryKind.Directory,
                                childDirectory.FullName,
                                relative,
                                0,
                                File.GetLastWriteTimeUtc(handle).Ticks,
                                WindowsFileSystemSafety.GetIdentity(handle),
                                handle));
                            pending.Push(childDirectory);
                        }
                        else if (child is FileInfo childFile)
                        {
                            var handle = WindowsFileSystemSafety.OpenInputFile(childFile.FullName);
                            var length = RandomAccess.GetLength(handle);
                            totalBytes = checked(totalBytes + length);
                            entries.Add(new PayloadEntry(
                                PayloadEntryKind.File,
                                childFile.FullName,
                                relative,
                                length,
                                File.GetLastWriteTimeUtc(handle).Ticks,
                                WindowsFileSystemSafety.GetIdentity(handle),
                                handle));
                        }
                    }
                }
            }

            var paddingLength = CalculatePaddingLength(isDirectory, rootName, entries, sizePadding);
            return new PayloadManifest(isDirectory, rootName, entries, totalBytes, paddingLength);
        }
        catch
        {
            foreach (var entry in entries)
            {
                entry.SourceHandle?.Dispose();
            }

            throw;
        }
    }

    private static long CalculatePaddingLength(
        bool isDirectory,
        string rootName,
        IReadOnlyList<PayloadEntry> entries,
        SizePaddingMode sizePadding)
    {
        long length = PayloadMagic.Length + 2 + BinaryFormat.EncodedStringLength(rootName) + 1;
        foreach (var entry in entries)
        {
            length = checked(length + 1 + BinaryFormat.EncodedStringLength(entry.RelativePath) + sizeof(long));
            if (entry.Kind == PayloadEntryKind.File)
            {
                length = checked(length + sizeof(long) + entry.Length);
            }
        }

        var withPaddingRecord = checked(length + 1 + sizeof(long));
        var target = sizePadding switch
        {
            SizePaddingMode.None => withPaddingRecord,
            SizePaddingMode.Rounded => RoundToBucket(withPaddingRecord),
            SizePaddingMode.Fixed100MiB => 100L * 1024 * 1024,
            SizePaddingMode.Fixed1GiB => 1024L * 1024 * 1024,
            SizePaddingMode.Fixed10GiB => 10L * 1024 * 1024 * 1024,
            _ => throw new NingRanException("不支持所选的大小隐藏方式。"),
        };
        return Math.Max(0, target - withPaddingRecord);
    }

    private static long RoundToBucket(long length)
    {
        var bucket = length switch
        {
            < 1024L * 1024 * 1024 => 1024L * 1024,
            < 10L * 1024 * 1024 * 1024 => 16L * 1024 * 1024,
            _ => 64L * 1024 * 1024,
        };
        return checked(((length + bucket - 1) / bucket) * bucket);
    }
}
