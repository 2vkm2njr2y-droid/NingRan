using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace NingRan.Core.Internal;

/// <summary>
/// 保存增量段提交前后的最小恢复信息。登记本身使用当前 Windows 用户保护，
/// 不保存密码、密钥或文件内容；只有在目标文件身份仍然一致时才会继续提交。
/// </summary>
internal static class IncrementalArchiveRecovery
{
    private const int MaximumRecords = 1_024;
    private const int MaximumProtectedRecordSize = 16 * 1024;
    private const int CopyBufferSize = 1024 * 1024;
    private static readonly byte[] CommittedMarker = IncrementalArchiveContainer.GetCommittedSegmentMagic();

    internal static Guid Register(
        FileStream archive,
        string archivePath,
        string stagedPath,
        IncrementalArchiveContainer.StagedSegment staged)
    {
        ArgumentNullException.ThrowIfNull(archive);
        var fullArchivePath = Path.GetFullPath(archivePath);
        var fullStagedPath = Path.GetFullPath(stagedPath);
        var directoryPath = Path.GetDirectoryName(fullArchivePath)
            ?? throw new NingRanException("无法确定加密文件所在位置。");
        if (!string.Equals(Path.GetDirectoryName(fullStagedPath), directoryPath, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(Path.GetExtension(fullArchivePath), ".nrenc", StringComparison.OrdinalIgnoreCase) ||
            !IsExpectedStagedName(Path.GetFileName(fullStagedPath)))
        {
            throw new NingRanException("增量恢复登记位置不符合安全规则。");
        }

        WindowsFileSystemSafety.VerifyHandlePath(archive.SafeFileHandle, fullArchivePath);
        using var directoryHandle = WindowsFileSystemSafety.OpenStableDirectory(directoryPath);
        var archiveIdentity = WindowsFileSystemSafety.GetIdentity(archive.SafeFileHandle);
        var directoryIdentity = WindowsFileSystemSafety.GetIdentity(directoryHandle);
        using var stagedInput = new FileStream(
            fullStagedPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            CopyBufferSize,
            FileOptions.SequentialScan);
        WindowsFileSystemSafety.VerifyHandlePath(stagedInput.SafeFileHandle, fullStagedPath);
        if (stagedInput.Length != staged.SegmentLength)
        {
            throw new NingRanException("增量临时文件大小不正确，未登记恢复信息。");
        }
        stagedInput.Position = 0;
        var stagedHash = SHA256.HashData(stagedInput);

        var id = Guid.NewGuid();
        var record = new RecoveryRecord(
            id,
            fullArchivePath,
            fullStagedPath,
            staged.SegmentStart,
            staged.SegmentLength,
            archiveIdentity,
            WindowsFileSystemSafety.GetIdentity(stagedInput.SafeFileHandle),
            stagedHash,
            directoryPath,
            directoryIdentity);
        try
        {
            WriteRecord(record);
            return id;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(stagedHash);
        }
    }

    internal static void Unregister(Guid? id)
    {
        if (id is null) return;
        try
        {
            var path = Path.Combine(RegistryDirectory, $"{id.Value:N}.bin");
            if (File.Exists(path)) File.Delete(path);
        }
        catch
        {
            // 登记只包含恢复元数据；下次启动会再次尝试处理。
        }
    }

    internal static TemporaryContentCleanupResult RecoverAbandoned(string? archivePathFilter = null)
    {
        var recovered = 0;
        var failures = new List<TemporaryContentCleanupFailure>();
        var fullArchivePathFilter = string.IsNullOrWhiteSpace(archivePathFilter)
            ? null
            : Path.GetFullPath(archivePathFilter);
        string directory;
        try
        {
            directory = EnsureRegistryDirectory();
        }
        catch (Exception exception)
        {
            return new TemporaryContentCleanupResult(
                0,
                new[] { new TemporaryContentCleanupFailure(RegistryDirectory, exception.Message) });
        }

        var recordPaths = Directory.EnumerateFiles(directory, "*.bin").Take(MaximumRecords + 1).ToArray();
        if (recordPaths.Length > MaximumRecords)
        {
            failures.Add(new TemporaryContentCleanupFailure(
                directory,
                "增量恢复登记数量超过上限，已停止读取多余登记。"));
            recordPaths = recordPaths[..MaximumRecords];
        }

        foreach (var recordPath in recordPaths)
        {
            RecoveryRecord? record = null;
            byte[]? protectedBytes = null;
            byte[]? jsonBytes = null;
            var entropy = CreateEntropy();
            try
            {
                protectedBytes = BoundedFileReader.ReadAllBytes(
                    recordPath,
                    MaximumProtectedRecordSize,
                    "增量恢复安全登记");
                jsonBytes = ProtectedData.Unprotect(
                    protectedBytes,
                    entropy,
                    DataProtectionScope.CurrentUser);
                record = JsonSerializer.Deserialize<RecoveryRecord>(jsonBytes);
                ValidateRecord(recordPath, record);
                if (fullArchivePathFilter is not null &&
                    !string.Equals(record!.ArchivePath, fullArchivePathFilter, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (!File.Exists(record!.ArchivePath))
                {
                    // 用户已经删除了对应加密包，登记不再有意义。
                    File.Delete(recordPath);
                    continue;
                }

                using var directoryHandle = WindowsFileSystemSafety.OpenStableDirectory(record.DirectoryPath);
                WindowsFileSystemSafety.VerifyIdentity(directoryHandle, record.DirectoryIdentity);
                using var directoryLock = WindowsFileSystemSafety.LockDirectoryPath(record.DirectoryPath);
                using var archive = new FileStream(
                    record.ArchivePath,
                    FileMode.Open,
                    FileAccess.ReadWrite,
                    FileShare.None,
                    CopyBufferSize,
                    FileOptions.WriteThrough | FileOptions.SequentialScan);
                WindowsFileSystemSafety.VerifyHandlePath(archive.SafeFileHandle, record.ArchivePath);
                WindowsFileSystemSafety.VerifyIdentity(archive.SafeFileHandle, record.ArchiveIdentity);

                if (!File.Exists(record.StagedPath))
                {
                    // 临时分段可能已经被用户或清理工具移走；如果正式包已经
                    // 写完并发布标记，则无需再次复制，直接清掉过期登记即可。
                    if (archive.Length >= checked(record.SegmentStart + record.SegmentLength))
                    {
                        var completedMarker = ReadMarker(archive, record.SegmentStart);
                        try
                        {
                            if (completedMarker.SequenceEqual(CommittedMarker))
                            {
                                File.Delete(recordPath);
                                recovered++;
                                continue;
                            }
                        }
                        finally
                        {
                            CryptographicOperations.ZeroMemory(completedMarker);
                        }
                    }

                    throw new NingRanException("增量恢复文件已经不存在，无法继续提交。");
                }

                using var staged = new FileStream(
                    record.StagedPath,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read,
                    CopyBufferSize,
                    FileOptions.SequentialScan);
                WindowsFileSystemSafety.VerifyHandlePath(staged.SafeFileHandle, record.StagedPath);
                WindowsFileSystemSafety.VerifyIdentity(staged.SafeFileHandle, record.StagedIdentity);
                if (staged.Length != record.SegmentLength)
                {
                    throw new NingRanException("增量恢复文件大小已经改变，未继续写入。");
                }
                staged.Position = 0;
                var stagedHash = SHA256.HashData(staged);
                try
                {
                    if (!CryptographicOperations.FixedTimeEquals(stagedHash, record.StagedHash))
                    {
                        throw new NingRanException("增量恢复文件内容已经改变，未继续写入。");
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(stagedHash);
                }

                if (archive.Length < record.SegmentStart)
                {
                    throw new NingRanException("加密包长度已经缩短，未继续恢复增量修改。");
                }

                var existingLength = Math.Min(
                    Math.Max(0, archive.Length - record.SegmentStart),
                    record.SegmentLength);
                if (existingLength > 0 &&
                    !ContentsEqualAllowingCommittedMarker(
                        archive,
                        staged,
                        record.SegmentStart,
                        existingLength))
                {
                    throw new NingRanException(
                        $"加密包尾部与恢复文件不一致，未继续写入（现有 {existingLength} 字节，登记起点 {record.SegmentStart}，包长 {archive.Length}）。");
                }

                if (archive.Length < checked(record.SegmentStart + record.SegmentLength))
                {
                    archive.SetLength(record.SegmentStart);
                    archive.Position = record.SegmentStart;
                    staged.Position = 0;
                    staged.CopyTo(archive, CopyBufferSize);
                    archive.Flush(flushToDisk: true);
                }

                var marker = ReadMarker(archive, record.SegmentStart);
                try
                {
                    if (marker.SequenceEqual(CommittedMarker))
                    {
                        // 已完成最后一步发布，只需清理登记和临时分段。
                    }
                    else if (marker.SequenceEqual("NRUPD000"u8))
                    {
                        archive.Position = record.SegmentStart;
                        archive.Write(CommittedMarker, 0, CommittedMarker.Length);
                        archive.Flush(flushToDisk: true);
                    }
                    else
                    {
                        throw new NingRanException("加密包增量段标记不正确，未继续恢复。");
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(marker);
                }

                staged.Dispose();
                WindowsFileSystemSafety.DeleteVerifiedFile(record.StagedPath, record.StagedIdentity);
                File.Delete(recordPath);
                recovered++;
            }
            catch (NingRanException exception) when (
                exception.InnerException is System.ComponentModel.Win32Exception win32 &&
                win32.NativeErrorCode is 32 or 33)
            {
                // 仍被正在运行的实例使用，下次启动再试。
            }
            catch (IOException exception) when (IsSharingViolation(exception))
            {
                // 仍被正在运行的实例使用，下次启动再试。
            }
            catch (Exception exception)
            {
                failures.Add(new TemporaryContentCleanupFailure(
                    record?.ArchivePath ?? recordPath,
                    exception.Message));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(entropy);
                if (protectedBytes is not null) CryptographicOperations.ZeroMemory(protectedBytes);
                if (jsonBytes is not null) CryptographicOperations.ZeroMemory(jsonBytes);
                if (record?.StagedHash is { } stagedHash) CryptographicOperations.ZeroMemory(stagedHash);
            }
        }

        return new TemporaryContentCleanupResult(recovered, failures);
    }

    private static void WriteRecord(RecoveryRecord record)
    {
        var registryDirectory = EnsureRegistryDirectory();
        var recordPath = Path.Combine(registryDirectory, $"{record.Id:N}.bin");
        var jsonBytes = JsonSerializer.SerializeToUtf8Bytes(record);
        var entropy = CreateEntropy();
        byte[]? protectedBytes = null;
        try
        {
            protectedBytes = ProtectedData.Protect(jsonBytes, entropy, DataProtectionScope.CurrentUser);
            if (protectedBytes.Length is 0 or > MaximumProtectedRecordSize)
            {
                throw new NingRanException("增量恢复安全登记大小异常。");
            }

            using var stream = new FileStream(
                recordPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                4096,
                FileOptions.WriteThrough);
            stream.Write(protectedBytes);
            stream.Flush(flushToDisk: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(jsonBytes);
            CryptographicOperations.ZeroMemory(entropy);
            if (protectedBytes is not null) CryptographicOperations.ZeroMemory(protectedBytes);
        }
    }

    private static bool ContentsEqual(
        FileStream archive,
        FileStream staged,
        long archiveOffset,
        long stagedOffset,
        long length)
    {
        var archiveBuffer = new byte[CopyBufferSize];
        var stagedBuffer = new byte[CopyBufferSize];
        try
        {
            archive.Position = archiveOffset;
            staged.Position = stagedOffset;
            var remaining = length;
            while (remaining > 0)
            {
                var requested = (int)Math.Min(CopyBufferSize, remaining);
                var archiveRead = ReadAtMost(archive, archiveBuffer, requested);
                var stagedRead = ReadAtMost(staged, stagedBuffer, requested);
                if (archiveRead != stagedRead || !archiveBuffer.AsSpan(0, archiveRead).SequenceEqual(stagedBuffer.AsSpan(0, stagedRead)))
                    return false;
                if (archiveRead == 0) return false;
                remaining -= archiveRead;
            }

            return true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(archiveBuffer);
            CryptographicOperations.ZeroMemory(stagedBuffer);
        }
    }

    private static bool ContentsEqualAllowingCommittedMarker(
        FileStream archive,
        FileStream staged,
        long archiveOffset,
        long length)
    {
        if (length < CommittedMarker.Length)
            return ContentsEqual(archive, staged, archiveOffset, 0, length);

        var archiveMarker = ReadMarker(archive, archiveOffset);
        var stagedMarker = ReadMarker(staged, 0);
        try
        {
            if (archiveMarker.SequenceEqual(CommittedMarker) && stagedMarker.SequenceEqual("NRUPD000"u8))
            {
                return ContentsEqual(
                    archive,
                    staged,
                    checked(archiveOffset + CommittedMarker.Length),
                    CommittedMarker.Length,
                    length - CommittedMarker.Length);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(archiveMarker);
            CryptographicOperations.ZeroMemory(stagedMarker);
        }

        return ContentsEqual(archive, staged, archiveOffset, 0, length);
    }

    private static int ReadAtMost(Stream stream, byte[] buffer, int count)
    {
        var total = 0;
        while (total < count)
        {
            var read = stream.Read(buffer, total, count - total);
            if (read == 0) break;
            total += read;
        }

        return total;
    }

    private static byte[] ReadMarker(FileStream stream, long segmentStart)
    {
        var marker = new byte[8];
        stream.Position = segmentStart;
        var read = ReadAtMost(stream, marker, marker.Length);
        if (read != marker.Length)
        {
            CryptographicOperations.ZeroMemory(marker);
            throw new NingRanException("加密包增量段不完整，未继续恢复。");
        }

        return marker;
    }

    private static string RegistryDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "NingRan",
        "IncrementalArchiveRecovery");

    private static string EnsureRegistryDirectory()
    {
        var parent = Path.GetDirectoryName(RegistryDirectory)
            ?? throw new NingRanException("无法确定增量恢复目录的位置。");
        Directory.CreateDirectory(parent);
        if (!Directory.Exists(RegistryDirectory))
        {
            WindowsFileSystemSafety.CreatePrivateDirectory(RegistryDirectory);
        }
        else
        {
            WindowsFileSystemSafety.SecureExistingPrivateDirectory(RegistryDirectory);
        }

        return RegistryDirectory;
    }

    private static void ValidateRecord(string recordPath, RecoveryRecord? record)
    {
        if (record is null || record.Id == Guid.Empty ||
            !string.Equals(Path.GetFileNameWithoutExtension(recordPath), record.Id.ToString("N"), StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("增量恢复安全登记不正确。");
        }

        var archivePath = Path.GetFullPath(record.ArchivePath);
        var stagedPath = Path.GetFullPath(record.StagedPath);
        var directoryPath = Path.GetFullPath(record.DirectoryPath);
        if (!string.Equals(Path.GetDirectoryName(archivePath), directoryPath, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(Path.GetDirectoryName(stagedPath), directoryPath, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(Path.GetExtension(archivePath), ".nrenc", StringComparison.OrdinalIgnoreCase) ||
            !IsExpectedStagedName(Path.GetFileName(stagedPath)) ||
            record.StagedHash is null || record.StagedHash.Length != SHA256.HashSizeInBytes ||
            record.SegmentStart < 0 || record.SegmentLength < IncrementalArchiveContainer.SegmentHeaderSize + IncrementalArchiveContainer.FooterSize)
        {
            throw new InvalidDataException("增量恢复安全登记超出了创建时固定的安全范围。");
        }
    }

    private static bool IsExpectedStagedName(string name) =>
        name.StartsWith(".ningran-increment-", StringComparison.OrdinalIgnoreCase) &&
        name.EndsWith(".part", StringComparison.OrdinalIgnoreCase) &&
        name.IndexOfAny(Path.GetInvalidFileNameChars()) < 0;

    private static byte[] CreateEntropy() => SHA256.HashData(
        Encoding.ASCII.GetBytes("NINGRAN-INCREMENTAL-RECOVERY-V1"));

    private static bool IsSharingViolation(IOException exception) =>
        (exception.HResult & 0xFFFF) is 32 or 33;

    private sealed record RecoveryRecord(
        Guid Id,
        string ArchivePath,
        string StagedPath,
        long SegmentStart,
        long SegmentLength,
        WindowsFileIdentity ArchiveIdentity,
        WindowsFileIdentity StagedIdentity,
        byte[] StagedHash,
        string DirectoryPath,
        WindowsFileIdentity DirectoryIdentity);
}
