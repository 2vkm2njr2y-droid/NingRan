using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace NingRan.Core.Internal;

/// <summary>
/// 加密照片的外层存储。
/// NTFS 上主文件只保留普通 JPEG，正文放在同名 NTFS 隐藏数据流中；
/// 其他文件系统使用普通 .nrenc 文件。旧版 JPEG 尾部追加格式不再识别。
/// </summary>
internal static class JpegArchiveContainer
{
    private const string AlternateStreamName = "NingRanEncrypted";
    private const long MaximumCoverBytes = 128L * 1024 * 1024;

    public static bool IsPhotoArchivePath(string path)
    {
        var fullPath = Path.GetFullPath(path);
        return IsJpegExtension(fullPath) && IsNtfsPath(fullPath);
    }

    public static bool HasAlternateDataStream(string path)
    {
        var fullPath = Path.GetFullPath(path);
        return IsJpegExtension(fullPath) && File.Exists(GetAlternateDataStreamPath(fullPath));
    }

    public static bool IsEncryptedPhoto(string path)
    {
        var fullPath = Path.GetFullPath(path);
        return File.Exists(fullPath) && IsJpegExtension(fullPath) && HasAlternateDataStream(fullPath);
    }

    public static FileStream OpenArchiveReadStream(string path, bool exclusive)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var fullPath = Path.GetFullPath(path);
        if (IsJpegExtension(fullPath))
        {
            if (!IsNtfsPath(fullPath))
            {
                throw new NingRanException("当前磁盘不是 NTFS，照片隐藏数据流不可用；请打开 .nrenc 文件。");
            }

            if (!File.Exists(fullPath))
            {
                throw new NingRanException("请选择存在的加密照片。");
            }

            if (!File.Exists(GetAlternateDataStreamPath(fullPath)))
            {
                throw new NingRanException(
                    "这张照片没有找到凝然隐藏加密数据。它可能是普通照片，或者隐藏数据流已被删除；请确认文件来自凝然并且仍在 NTFS 磁盘上。");
            }

            // 先核验主文件不是链接，再单独锁定隐藏数据流。这样 Windows 照片仍可正常读取主文件。
            using var mainHandle = WindowsFileSystemSafety.OpenInputFile(fullPath);
            var share = exclusive ? FileShare.None : FileShare.Read;
            return new FileStream(
                GetAlternateDataStreamPath(fullPath),
                FileMode.Open,
                FileAccess.Read,
                share,
                1024 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
        }

        var handle = exclusive
            ? WindowsFileSystemSafety.OpenExclusiveInputFile(fullPath)
            : WindowsFileSystemSafety.OpenInputFile(fullPath);
        return new FileStream(handle, FileAccess.Read, 1024 * 1024, isAsync: true);
    }

    public static ArchiveRegion GetArchiveRegion(FileStream stream, bool isPhotoArchive)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanSeek || !stream.CanRead || stream.Length <= 0)
        {
            throw new NingRanException("凝然加密内容为空或无法定位，文件可能已损坏。");
        }

        return new ArchiveRegion(0, stream.Length, isPhotoArchive);
    }

    public static async Task ValidateCoverAsync(string coverImagePath, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(coverImagePath);
        var fullPath = Path.GetFullPath(coverImagePath);
        if (!File.Exists(fullPath))
        {
            throw new NingRanException("请选择存在的 JPEG 封面照片。");
        }

        using var handle = WindowsFileSystemSafety.OpenInputFile(fullPath);
        await using var input = new FileStream(handle, FileAccess.Read, 1024 * 1024, isAsync: true);
        if (input.Length is < 4 or > MaximumCoverBytes)
        {
            throw new NingRanException("封面照片大小不正确，或超过 128 MB 上限。");
        }

        var jpegStart = new byte[2];
        await BinaryFormat.ReadExactlyAsync(input, jpegStart, cancellationToken).ConfigureAwait(false);
        if (jpegStart[0] != 0xff || jpegStart[1] != 0xd8)
        {
            throw new NingRanException("所选封面不是有效的 JPEG 照片，请选择 .jpg 或 .jpeg 文件。");
        }
    }

    public static async Task CopyCoverToNewFileAsync(
        string coverImagePath,
        string outputPath,
        CancellationToken cancellationToken)
    {
        var directory = Path.GetDirectoryName(outputPath)
            ?? throw new NingRanException("加密照片保存位置不正确。 ");
        var temporaryCoverPath = Path.Combine(directory, $".ningran-cover-{Guid.NewGuid():N}.part");
        try
        {
            await ValidateCoverAsync(coverImagePath, cancellationToken).ConfigureAwait(false);
            using var sourceHandle = WindowsFileSystemSafety.OpenInputFile(Path.GetFullPath(coverImagePath));
            await using var source = new FileStream(sourceHandle, FileAccess.Read, 1024 * 1024, isAsync: true);
            await using (var target = new FileStream(
                             temporaryCoverPath,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             1024 * 1024,
                             FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await source.CopyToAsync(target, 1024 * 1024, cancellationToken).ConfigureAwait(false);
                await target.FlushAsync(cancellationToken).ConfigureAwait(false);
                target.Flush(flushToDisk: true);
            }

            File.Move(temporaryCoverPath, outputPath);
        }
        finally
        {
            TryDelete(temporaryCoverPath);
        }
    }

    public static async Task CopyArchiveToAlternateDataStreamAsync(
        string archiveTemporaryPath,
        string photoPath,
        CancellationToken cancellationToken)
    {
        var adsPath = GetAlternateDataStreamPath(photoPath);
        await using var source = new FileStream(
            archiveTemporaryPath,
            FileMode.Open,
            FileAccess.ReadWrite,
            FileShare.Read,
            1024 * 1024,
            FileOptions.Asynchronous | FileOptions.RandomAccess);
        await using var target = new FileStream(
            adsPath,
            FileMode.CreateNew,
            FileAccess.ReadWrite,
            FileShare.None,
            1024 * 1024,
            FileOptions.Asynchronous | FileOptions.RandomAccess);

        // The encrypted archive has already been fully verified in the staging
        // file. Mark both streams sparse so that the destination can reserve its
        // logical length without allocating another full copy. Each source
        // range is released immediately after its bytes are durable in the ADS;
        // peak physical usage therefore stays close to one archive plus a small
        // buffer instead of briefly requiring two 100 GB files.
        var archiveLength = source.Length;
        MarkSparse(source.SafeFileHandle);
        MarkSparse(target.SafeFileHandle);
        target.SetLength(archiveLength);

        var buffer = new byte[64 * 1024 * 1024];
        for (long offset = 0; offset < archiveLength; offset += buffer.Length)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var count = (int)Math.Min(buffer.Length, archiveLength - offset);
            source.Position = offset;
            await source.ReadExactlyAsync(buffer.AsMemory(0, count), cancellationToken)
                .ConfigureAwait(false);
            target.Position = offset;
            await target.WriteAsync(buffer.AsMemory(0, count), cancellationToken)
                .ConfigureAwait(false);
            await target.FlushAsync(cancellationToken).ConfigureAwait(false);
            target.Flush(flushToDisk: true);
            PunchSparseRange(source.SafeFileHandle, offset, count);
        }

        await target.FlushAsync(cancellationToken).ConfigureAwait(false);
        target.Flush(flushToDisk: true);
    }

    private const uint FsctlSetSparse = 0x000900C4;
    private const uint FsctlSetZeroData = 0x000980C8;

    private static void MarkSparse(SafeFileHandle handle)
    {
        if (!DeviceIoControl(handle, FsctlSetSparse, IntPtr.Zero, 0, IntPtr.Zero, 0, out _, IntPtr.Zero))
        {
            throw new IOException("无法启用大文件节省空间的写入方式。", new Win32Exception(Marshal.GetLastWin32Error()));
        }
    }

    private static void PunchSparseRange(SafeFileHandle handle, long offset, long length)
    {
        var range = new byte[sizeof(long) * 2];
        BinaryPrimitives.WriteInt64LittleEndian(range.AsSpan(0, sizeof(long)), offset);
        BinaryPrimitives.WriteInt64LittleEndian(range.AsSpan(sizeof(long), sizeof(long)), checked(offset + length));
        if (!DeviceIoControl(handle, FsctlSetZeroData, range, (uint)range.Length, IntPtr.Zero, 0, out _, IntPtr.Zero))
        {
            throw new IOException("无法释放已复制的大文件临时空间。", new Win32Exception(Marshal.GetLastWin32Error()));
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(
        SafeFileHandle device,
        uint controlCode,
        IntPtr inputBuffer,
        uint inputBufferSize,
        IntPtr outputBuffer,
        uint outputBufferSize,
        out uint bytesReturned,
        IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(
        SafeFileHandle device,
        uint controlCode,
        byte[] inputBuffer,
        uint inputBufferSize,
        IntPtr outputBuffer,
        uint outputBufferSize,
        out uint bytesReturned,
        IntPtr overlapped);

    public static async Task ReplaceAlternateDataStreamAsync(
        string photoPath,
        string archiveTemporaryPath,
        CancellationToken cancellationToken)
    {
        var adsPath = GetAlternateDataStreamPath(photoPath);
        var backupPath = $"{adsPath}.backup-{Guid.NewGuid():N}";
        var backupCreated = false;
        try
        {
            // NTFS cannot atomically rename one named stream over another. Keep
            // a hidden rollback copy until the verified replacement is durable.
            await CopyStreamAsync(adsPath, backupPath, FileMode.CreateNew, cancellationToken).ConfigureAwait(false);
            backupCreated = true;
            await CopyStreamAsync(archiveTemporaryPath, adsPath, FileMode.Create, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            if (backupCreated)
            {
                try
                {
                    await CopyStreamAsync(backupPath, adsPath, FileMode.Create, CancellationToken.None).ConfigureAwait(false);
                }
                catch
                {
                    // The outer operation reports the failure; keep the hidden
                    // backup stream in place so the user can still recover it.
                    backupCreated = false;
                }
            }
            else
            {
                TryDelete(backupPath);
            }

            throw;
        }
        finally
        {
            if (backupCreated) TryDelete(backupPath);
        }
    }

    public static async Task<byte[]> ComputeArchiveHashAsync(string archivePath, CancellationToken cancellationToken)
    {
        await using var stream = OpenArchiveReadStream(archivePath, exclusive: false);
        return await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
    }

    public static long GetStorageSize(string archivePath)
    {
        var fullPath = Path.GetFullPath(archivePath);
        var mainSize = new FileInfo(fullPath).Length;
        if (!IsEncryptedPhoto(fullPath)) return mainSize;
        return checked(mainSize + new FileInfo(GetAlternateDataStreamPath(fullPath)).Length);
    }

    public static string GetAlternateDataStreamPath(string photoPath) =>
        Path.GetFullPath(photoPath) + ":" + AlternateStreamName;

    public static string NormalizeOutputPath(string outputPath, bool preferPhotoArchive = true)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(outputPath);
        var fullPath = Path.GetFullPath(outputPath);
        if (string.Equals(Path.GetExtension(fullPath), ".nrenc", StringComparison.OrdinalIgnoreCase))
        {
            return fullPath;
        }

        // A JPEG outer container is opt-in. Without a selected cover image the
        // caller must receive a normal, portable .nrenc archive even when the
        // chosen name or destination happens to look like a photo path.
        var extension = preferPhotoArchive && IsNtfsPath(fullPath) ? ".jpg" : ".nrenc";
        return string.Equals(Path.GetExtension(fullPath), ".jpg", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(Path.GetExtension(fullPath), ".jpeg", StringComparison.OrdinalIgnoreCase)
            ? Path.ChangeExtension(fullPath, extension)
            : fullPath + extension;
    }

    private static bool IsJpegExtension(string path) =>
        string.Equals(Path.GetExtension(path), ".jpg", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(Path.GetExtension(path), ".jpeg", StringComparison.OrdinalIgnoreCase);

    private static bool IsNtfsPath(string path)
    {
        try
        {
            var root = Path.GetPathRoot(Path.GetFullPath(path));
            return !string.IsNullOrWhiteSpace(root) &&
                   string.Equals(new DriveInfo(root).DriveFormat, "NTFS", StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception exception) when (exception is ArgumentException or IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static async Task CopyStreamAsync(
        string sourcePath,
        string targetPath,
        FileMode targetMode,
        CancellationToken cancellationToken)
    {
        await using var source = new FileStream(
            sourcePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            1024 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        await using var target = new FileStream(
            targetPath,
            targetMode,
            FileAccess.Write,
            FileShare.None,
            1024 * 1024,
            FileOptions.Asynchronous | FileOptions.WriteThrough);
        await source.CopyToAsync(target, 1024 * 1024, cancellationToken).ConfigureAwait(false);
        await target.FlushAsync(cancellationToken).ConfigureAwait(false);
        target.Flush(flushToDisk: true);
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path)) File.Delete(path);
        }
        catch
        {
            // 临时文件会由外层清理流程再次处理。
        }
    }
}

internal readonly record struct ArchiveRegion(long Offset, long Length, bool IsJpegContainer);
