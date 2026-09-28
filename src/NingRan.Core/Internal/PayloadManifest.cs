using Microsoft.Win32.SafeHandles;
using System.Text;
using System.Windows.Media.Imaging;

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
    Func<CancellationToken, ValueTask<Stream>>? ContentFactory = null,
    ArchiveCompressionLevel? CompressionOverride = null);

internal sealed class PayloadManifest : IDisposable
{
    private static ReadOnlySpan<byte> PayloadMagic => "NRPAY004"u8;

    private PayloadManifest(
        bool isDirectory,
        string rootName,
        IReadOnlyList<PayloadEntry> entries,
        long totalFileBytes,
        long paddingLength,
        IReadOnlyList<string>? temporaryPaths = null,
        IReadOnlyList<PayloadManifest>? childManifests = null)
    {
        IsDirectory = isDirectory;
        RootName = rootName;
        Entries = entries;
        TotalFileBytes = totalFileBytes;
        PaddingLength = paddingLength;
        _temporaryPaths = temporaryPaths ?? [];
        _childManifests = childManifests ?? [];
    }

    private readonly IReadOnlyList<string> _temporaryPaths;
    private readonly IReadOnlyList<PayloadManifest> _childManifests;

    public bool IsDirectory { get; }

    public string RootName { get; }

    public IReadOnlyList<PayloadEntry> Entries { get; }

    public long TotalFileBytes { get; }

    public long PaddingLength { get; }

    public void Dispose()
    {
        if (_childManifests.Count > 0)
        {
            foreach (var child in _childManifests)
            {
                child.Dispose();
            }

            return;
        }

        foreach (var entry in Entries)
        {
            entry.SourceHandle?.Dispose();
        }

        foreach (var path in _temporaryPaths)
        {
            try { if (File.Exists(path)) File.Delete(path); } catch { }
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
        CancellationToken cancellationToken,
        bool lossyMedia = false)
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
        var temporaryPaths = new List<string>();
        long totalBytes = 0;
        long totalNameBytes = Encoding.UTF8.GetByteCount(rootName);

        try
        {
            if (isFile)
            {
                var handle = WindowsFileSystemSafety.OpenInputFile(fullPath);
                var length = RandomAccess.GetLength(handle);
                entries.Add(CreateSourceFileEntry(
                    PayloadEntryKind.File,
                    fullPath,
                    rootName,
                    length,
                    File.GetLastWriteTimeUtc(handle).Ticks,
                    WindowsFileSystemSafety.GetIdentity(handle),
                    handle,
                    lossyMedia,
                    temporaryPaths));
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
                            entries.Add(CreateSourceFileEntry(
                                PayloadEntryKind.File,
                                childFile.FullName,
                                relative,
                                length,
                                File.GetLastWriteTimeUtc(handle).Ticks,
                                WindowsFileSystemSafety.GetIdentity(handle),
                                handle,
                                lossyMedia,
                                temporaryPaths));
                        }
                    }
                }
            }

            var paddingLength = CalculatePaddingLength(isDirectory, rootName, entries, sizePadding);
            return new PayloadManifest(isDirectory, rootName, entries, totalBytes, paddingLength, temporaryPaths);
        }
        catch
        {
            foreach (var entry in entries)
            {
                entry.SourceHandle?.Dispose();
            }

            foreach (var path in temporaryPaths)
            {
                try { if (File.Exists(path)) File.Delete(path); } catch { }
            }

            throw;
        }
    }

    /// <summary>
    /// 从已解锁保险箱直接建立加密包目录。文件正文按需从保险箱读取，
    /// 不经过临时磁盘，也不会在磁盘上生成明文副本。
    /// </summary>
    public static PayloadManifest BuildVault(
        VaultSession session,
        SizePaddingMode sizePadding,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);
        cancellationToken.ThrowIfCancellationRequested();
        var rootName = PathSafety.ValidateNameSegment(session.Info.Name);
        var sourceRoot = session.VaultPath;
        var entries = new List<PayloadEntry>
        {
            new(
                PayloadEntryKind.Directory,
                sourceRoot,
                rootName,
                0,
                session.Info.CreatedAt.UtcDateTime.Ticks,
                default,
                null),
        };

        foreach (var vaultEntry in session.Entries
                     .OrderBy(entry => entry.IsDirectory ? 0 : 1)
                     .ThenBy(entry => entry.RelativePath, StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var relativePath = PathSafety.NormalizeRelativePath($"{rootName}/{vaultEntry.RelativePath}");
            var displayPath = $"{sourceRoot}::{vaultEntry.RelativePath}";
            if (vaultEntry.IsDirectory)
            {
                entries.Add(new PayloadEntry(
                    PayloadEntryKind.Directory,
                    displayPath,
                    relativePath,
                    0,
                    vaultEntry.LastWriteTimeUtc.Ticks,
                    default,
                    null));
                continue;
            }

            var vaultPath = vaultEntry.RelativePath;
            entries.Add(new PayloadEntry(
                PayloadEntryKind.File,
                displayPath,
                relativePath,
                vaultEntry.Length,
                vaultEntry.LastWriteTimeUtc.Ticks,
                default,
                null,
                _ => new ValueTask<Stream>(session.OpenReadStream(vaultPath))));
        }

        return Create(isDirectory: true, rootName, entries, sizePadding);
    }

    /// <summary>
    /// 将多个顶层文件和文件夹放入同一个新根目录。各子清单继续持有已打开的源文件，
    /// 因而从准备、加密到最终验证期间都能检测源内容被替换或改动。
    /// </summary>
    public static PayloadManifest BuildMany(
        IReadOnlyList<string> sourcePaths,
        string rootName,
        SizePaddingMode sizePadding,
        CancellationToken cancellationToken,
        bool lossyMedia = false)
    {
        ArgumentNullException.ThrowIfNull(sourcePaths);
        if (sourcePaths.Count == 0)
        {
            throw new NingRanException("请至少选择一个要交付的文件或文件夹。");
        }

        rootName = PathSafety.ValidateNameSegment(rootName);
        var normalizedSources = sourcePaths
            .Select(Path.GetFullPath)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (normalizedSources.Length != sourcePaths.Count)
        {
            throw new NingRanException("选择列表中包含重复项目，请移除重复项后再生成。");
        }

        for (var outer = 0; outer < normalizedSources.Length; outer++)
        {
            for (var inner = 0; inner < normalizedSources.Length; inner++)
            {
                if (outer == inner) continue;
                var parent = normalizedSources[outer].TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) +
                             Path.DirectorySeparatorChar;
                if (normalizedSources[inner].StartsWith(parent, StringComparison.OrdinalIgnoreCase))
                {
                    throw new NingRanException($"“{normalizedSources[inner]}”已经包含在所选文件夹中，请不要重复选择。");
                }
            }
        }

        var children = new List<PayloadManifest>(normalizedSources.Length);
        try
        {
            foreach (var source in normalizedSources)
            {
                cancellationToken.ThrowIfCancellationRequested();
                children.Add(Build(source, SizePaddingMode.None, cancellationToken, lossyMedia));
            }

            var duplicateTopName = children
                .GroupBy(child => child.RootName, StringComparer.OrdinalIgnoreCase)
                .FirstOrDefault(group => group.Count() > 1);
            if (duplicateTopName is not null)
            {
                throw new NingRanException($"多个所选项目都叫“{duplicateTopName.Key}”，无法在同一交付包中区分，请先改名。");
            }

            var nowTicks = DateTime.UtcNow.Ticks;
            var entries = new List<PayloadEntry>
            {
                new(PayloadEntryKind.Directory, string.Empty, rootName, 0, nowTicks, default, null),
            };
            foreach (var child in children)
            {
                foreach (var entry in child.Entries)
                {
                    entries.Add(entry with
                    {
                        RelativePath = PathSafety.NormalizeRelativePath($"{rootName}/{entry.RelativePath}"),
                    });
                }
            }

            if (entries.Count > PayloadContainer.MaximumEntries)
            {
                throw new NingRanException("所选内容超过 2 万个文件和文件夹，为避免电脑卡顿已停止处理。");
            }

            var totalBytes = children.Sum(child => child.TotalFileBytes);
            var paddingLength = CalculatePaddingLength(true, rootName, entries, sizePadding);
            return new PayloadManifest(true, rootName, entries, totalBytes, paddingLength,
                childManifests: children.ToArray());
        }
        catch
        {
            foreach (var child in children)
            {
                child.Dispose();
            }

            throw;
        }
    }

    private static PayloadEntry CreateSourceFileEntry(
        PayloadEntryKind kind,
        string fullPath,
        string relativePath,
        long length,
        long lastWriteUtcTicks,
        WindowsFileIdentity identity,
        SafeFileHandle handle,
        bool lossyMedia,
        ICollection<string> temporaryPaths)
    {
        if (!lossyMedia || NrMediaFiles.TryGetKind(relativePath) != SecureMediaKind.Image)
        {
            return new PayloadEntry(kind, fullPath, relativePath, length, lastWriteUtcTicks,
                identity, handle);
        }

        var temporaryPath = CreateLossyImage(fullPath, length, temporaryPaths);
        if (temporaryPath is null)
        {
            return new PayloadEntry(kind, fullPath, relativePath, length, lastWriteUtcTicks,
                identity, handle,
                CompressionOverride: ArchiveCompressionLevel.SmallestLossy);
        }

        var transformedLength = new FileInfo(temporaryPath).Length;
        return new PayloadEntry(kind, fullPath, relativePath, transformedLength, lastWriteUtcTicks,
            identity, handle,
            _ => new ValueTask<Stream>(new FileStream(temporaryPath, FileMode.Open, FileAccess.Read,
                FileShare.Read, 1024 * 1024, FileOptions.Asynchronous)),
            CompressionOverride: ArchiveCompressionLevel.SmallestLossy);
    }

    private static string? CreateLossyImage(string sourcePath, long sourceLength, ICollection<string> temporaryPaths)
    {
        var extension = Path.GetExtension(sourcePath);
        if (!string.Equals(extension, ".jpg", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(extension, ".jpeg", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        string? directory = null;
        string? outputPath = null;
        try
        {
            using var input = File.Open(sourcePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            var decoder = BitmapDecoder.Create(input, BitmapCreateOptions.PreservePixelFormat, BitmapCacheOption.OnLoad);
            if (decoder.Frames.Count == 0) return null;
            var frame = decoder.Frames[0];
            if (frame.PixelWidth is <= 0 or > 20_000 || frame.PixelHeight is <= 0 or > 20_000) return null;

            directory = Path.Combine(Path.GetTempPath(), ".ningran-lossy-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            outputPath = Path.Combine(directory, "media.jpg");
            var encoder = new JpegBitmapEncoder { QualityLevel = 65 };
            encoder.Frames.Add(frame);
            using (var output = new FileStream(outputPath, FileMode.CreateNew, FileAccess.Write, FileShare.Read,
                       1024 * 1024, FileOptions.WriteThrough))
            {
                encoder.Save(output);
                output.Flush(flushToDisk: true);
            }

            if (new FileInfo(outputPath).Length >= sourceLength)
            {
                File.Delete(outputPath);
                Directory.Delete(directory);
                return null;
            }

            temporaryPaths.Add(outputPath);
            temporaryPaths.Add(directory);
            return outputPath;
        }
        catch
        {
            if (outputPath is not null)
            {
                try { if (File.Exists(outputPath)) File.Delete(outputPath); } catch { }
            }
            if (directory is not null)
            {
                try { if (Directory.Exists(directory)) Directory.Delete(directory, recursive: false); } catch { }
            }
            return null;
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
