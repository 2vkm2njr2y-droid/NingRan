using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace NingRan.Core.Internal;

internal sealed class SecureStagingArea
{
    private const string DirectoryPrefix = ".ningran-decrypt-";
    private const string DirectorySuffix = ".part";
    private const string MarkerFileName = ".ningran-staging";
    private const string LockFileName = ".ningran-lock";
    private const string PayloadDirectoryName = "payload";
    private const string MarkerMagic = "NINGRAN-PLAINTEXT-STAGING-V1";
    private const int MaximumRecoveryRecords = 1_024;
    private const int MaximumProtectedRecordSize = 16 * 1024;
    private FileStream? _lockStream;
    private bool _payloadMoved;
    private readonly WindowsFileIdentity _directoryIdentity;
    private readonly WindowsFileIdentity _payloadIdentity;

    private SecureStagingArea(
        Guid id,
        string directoryPath,
        WindowsFileIdentity directoryIdentity,
        WindowsFileIdentity payloadIdentity,
        FileStream lockStream)
    {
        Id = id;
        DirectoryPath = directoryPath;
        _directoryIdentity = directoryIdentity;
        _payloadIdentity = payloadIdentity;
        _lockStream = lockStream;
    }

    public Guid Id { get; }

    public string DirectoryPath { get; }

    public string PayloadDirectory => Path.Combine(DirectoryPath, PayloadDirectoryName);

    public static SecureStagingArea Create(string destinationDirectory)
    {
        var destination = Path.GetFullPath(destinationDirectory);
        for (var attempt = 0; attempt < 10; attempt++)
        {
            var id = Guid.NewGuid();
            var path = Path.Combine(destination, $"{DirectoryPrefix}{id:N}{DirectorySuffix}");
            try
            {
                WindowsFileSystemSafety.CreatePrivateDirectory(path);
                using var directoryHandle = WindowsFileSystemSafety.OpenStableDirectory(path);
                var directoryIdentity = WindowsFileSystemSafety.GetIdentity(directoryHandle);
                var lockStream = new FileStream(
                    Path.Combine(path, LockFileName),
                    FileMode.CreateNew,
                    FileAccess.ReadWrite,
                    FileShare.None,
                    bufferSize: 1,
                    FileOptions.WriteThrough);
                try
                {
                    WindowsFileSystemSafety.VerifyHandlePath(
                        lockStream.SafeFileHandle,
                        Path.Combine(path, LockFileName));
                    File.WriteAllText(Path.Combine(path, MarkerFileName), BuildMarker(id));
                    var payloadPath = Path.Combine(path, PayloadDirectoryName);
                    Directory.CreateDirectory(payloadPath);
                    using var payloadHandle = WindowsFileSystemSafety.OpenStableDirectory(payloadPath);
                    var payloadIdentity = WindowsFileSystemSafety.GetIdentity(payloadHandle);
                    RecoveryRegistry.Register(
                        id,
                        path,
                        directoryIdentity,
                        payloadIdentity,
                        WindowsFileSystemSafety.GetIdentity(lockStream.SafeFileHandle));
                    return new SecureStagingArea(
                        id,
                        path,
                        directoryIdentity,
                        payloadIdentity,
                        lockStream);
                }
                catch
                {
                    lockStream.Dispose();
                    throw;
                }
            }
            catch (IOException) when (File.Exists(path) || Directory.Exists(path))
            {
            }
            catch
            {
                RecoveryRegistry.Unregister(id);
                TryDeleteUnregisteredDirectory(path);
                throw;
            }
        }

        throw new NingRanException("无法建立不重复的安全临时目录，请更换保存位置后重试。");
    }

    public void MarkPayloadMoved() => _payloadMoved = true;

    public bool TryCleanup(out Exception? error)
    {
        _lockStream?.Dispose();
        _lockStream = null;
        try
        {
            DeleteStagingDirectory(DirectoryPath, _directoryIdentity, _payloadIdentity);
            RecoveryRegistry.Unregister(Id);
            error = null;
            return true;
        }
        catch (Exception exception)
        {
            if (_payloadMoved || !ContainsPlaintextPayload(DirectoryPath))
            {
                RecoveryRegistry.Unregister(Id);
                error = null;
                return true;
            }

            error = exception;
            return false;
        }
    }

    public static TemporaryContentCleanupResult CleanupAbandoned()
    {
        var removed = 0;
        var failures = new List<TemporaryContentCleanupFailure>();
        foreach (var record in RecoveryRegistry.ReadAll(failures))
        {
            var path = Path.GetFullPath(record.DirectoryPath);
            if (!IsExpectedPath(record.Id, path))
            {
                failures.Add(new TemporaryContentCleanupFailure(
                    path,
                    "清理登记与临时目录名称不一致，为避免误删已跳过。"));
                continue;
            }

            if (!Directory.Exists(path))
            {
                RecoveryRegistry.Unregister(record.Id);
                continue;
            }

            var markerPath = Path.Combine(path, MarkerFileName);
            try
            {
                if (!File.Exists(markerPath) ||
                    !string.Equals(
                        Encoding.UTF8.GetString(BoundedFileReader.ReadAllBytes(
                            markerPath,
                            256,
                            "临时目录标记")),
                        BuildMarker(record.Id),
                        StringComparison.Ordinal))
                {
                    failures.Add(new TemporaryContentCleanupFailure(
                        path,
                        "缺少可信的临时目录标记，为避免误删已跳过。"));
                    continue;
                }

                var lockPath = Path.Combine(path, LockFileName);
                if (!File.Exists(lockPath))
                {
                    failures.Add(new TemporaryContentCleanupFailure(
                        path,
                        "临时目录的安全锁文件缺失，为避免误删已跳过。"));
                    continue;
                }

                try
                {
                    using var operationLock = new FileStream(
                        lockPath,
                        FileMode.Open,
                        FileAccess.ReadWrite,
                        FileShare.None);
                    WindowsFileSystemSafety.VerifyHandlePath(operationLock.SafeFileHandle, lockPath);
                    if (WindowsFileSystemSafety.GetIdentity(operationLock.SafeFileHandle) != record.LockIdentity)
                    {
                        failures.Add(new TemporaryContentCleanupFailure(
                            path,
                            "临时目录的身份已经改变，为避免误删已跳过。"));
                        continue;
                    }
                }
                catch (IOException exception) when (IsSharingViolation(exception))
                {
                    // 另一个正在运行的程序仍在使用，不能当成崩溃残留。
                    continue;
                }

                DeleteStagingDirectory(path, record.DirectoryIdentity, record.PayloadIdentity);
                RecoveryRegistry.Unregister(record.Id);
                removed++;
            }
            catch (Exception exception)
            {
                if (!ContainsPlaintextPayload(path))
                {
                    RecoveryRegistry.Unregister(record.Id);
                    removed++;
                }
                else
                {
                    failures.Add(new TemporaryContentCleanupFailure(path, exception.Message));
                }
            }
        }

        return new TemporaryContentCleanupResult(removed, failures);
    }

    private static string BuildMarker(Guid id) => $"{MarkerMagic}\n{id:N}";

    private static bool IsExpectedPath(Guid id, string path) =>
        string.Equals(
            Path.GetFileName(path),
            $"{DirectoryPrefix}{id:N}{DirectorySuffix}",
            StringComparison.OrdinalIgnoreCase);

    private static bool IsSharingViolation(IOException exception)
    {
        var win32Code = exception.HResult & 0xFFFF;
        return win32Code is 32 or 33;
    }

    private static void DeleteStagingDirectory(
        string path,
        WindowsFileIdentity? expectedIdentity = null,
        WindowsFileIdentity? expectedPayloadIdentity = null)
    {
        using (var rootHandle = WindowsFileSystemSafety.OpenStableDirectory(path))
        {
            if (expectedIdentity is not null)
            {
                WindowsFileSystemSafety.VerifyIdentity(rootHandle, expectedIdentity.Value);
            }

            var payloadPath = Path.Combine(path, PayloadDirectoryName);
            if (Directory.Exists(payloadPath))
            {
                WindowsFileSystemSafety.DeleteDirectoryWithoutFollowingLinks(
                    payloadPath,
                    expectedPayloadIdentity);
            }

            var markerPath = Path.Combine(path, MarkerFileName);
            if (File.Exists(markerPath))
            {
                WindowsFileSystemSafety.DeleteFileWithoutFollowingLinks(markerPath);
            }

            var lockPath = Path.Combine(path, LockFileName);
            if (File.Exists(lockPath))
            {
                WindowsFileSystemSafety.DeleteFileWithoutFollowingLinks(lockPath);
            }
        }

        WindowsFileSystemSafety.DeleteDirectoryWithoutFollowingLinks(path, expectedIdentity);
    }

    private static bool ContainsPlaintextPayload(string path)
    {
        var payloadPath = Path.Combine(path, PayloadDirectoryName);
        return Directory.Exists(payloadPath) && Directory.EnumerateFileSystemEntries(payloadPath).Any();
    }

    private static void TryDeleteUnregisteredDirectory(string path)
    {
        try
        {
            WindowsFileSystemSafety.DeleteDirectoryWithoutFollowingLinks(path);
        }
        catch
        {
            // 尚未开始写入明文；保留创建阶段的原始错误。
        }
    }

    private sealed record RecoveryRecord(
        Guid Id,
        string DirectoryPath,
        WindowsFileIdentity DirectoryIdentity,
        WindowsFileIdentity PayloadIdentity,
        WindowsFileIdentity LockIdentity);

    private static class RecoveryRegistry
    {
        private static string RegistryDirectory => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "NingRan",
            "PlaintextRecovery");

        public static void Register(
            Guid id,
            string directoryPath,
            WindowsFileIdentity directoryIdentity,
            WindowsFileIdentity payloadIdentity,
            WindowsFileIdentity lockIdentity)
        {
            EnsureRegistryDirectory();
            var recordPath = GetRecordPath(id);
            var jsonBytes = JsonSerializer.SerializeToUtf8Bytes(
                new RecoveryRecord(
                    id,
                    Path.GetFullPath(directoryPath),
                    directoryIdentity,
                    payloadIdentity,
                    lockIdentity));
            var entropy = CreateRecoveryEntropy();
            byte[]? protectedBytes = null;
            try
            {
                protectedBytes = ProtectedData.Protect(
                    jsonBytes,
                    entropy,
                    DataProtectionScope.CurrentUser);
                if (protectedBytes.Length is 0 or > MaximumProtectedRecordSize)
                {
                    throw new NingRanException("明文恢复安全登记大小异常。");
                }

                using var stream = new FileStream(
                    recordPath,
                    FileMode.CreateNew,
                    FileAccess.Write,
                    FileShare.None,
                    bufferSize: 4096,
                    FileOptions.WriteThrough);
                stream.Write(protectedBytes);
                stream.Flush(flushToDisk: true);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(jsonBytes);
                CryptographicOperations.ZeroMemory(entropy);
                if (protectedBytes is not null)
                {
                    CryptographicOperations.ZeroMemory(protectedBytes);
                }
            }
        }

        public static void Unregister(Guid id)
        {
            try
            {
                var path = GetRecordPath(id);
                if (File.Exists(path))
                {
                    File.Delete(path);
                }
            }
            catch
            {
                // 临时明文目录已删除时，残留登记不包含明文，下次启动还会再次整理。
            }
        }

        public static IReadOnlyList<RecoveryRecord> ReadAll(
            ICollection<TemporaryContentCleanupFailure> failures)
        {
            try
            {
                EnsureRegistryDirectory();
            }
            catch (Exception exception)
            {
                failures.Add(new TemporaryContentCleanupFailure(RegistryDirectory, exception.Message));
                return Array.Empty<RecoveryRecord>();
            }

            foreach (var legacyPath in Directory.EnumerateFiles(RegistryDirectory, "*.json")
                         .Take(MaximumRecoveryRecords + 1))
            {
                try
                {
                    File.Delete(legacyPath);
                }
                catch (Exception exception)
                {
                    failures.Add(new TemporaryContentCleanupFailure(legacyPath, exception.Message));
                }
            }

            var recordPaths = Directory.EnumerateFiles(RegistryDirectory, "*.bin")
                .Take(MaximumRecoveryRecords + 1)
                .ToArray();
            if (recordPaths.Length > MaximumRecoveryRecords)
            {
                failures.Add(new TemporaryContentCleanupFailure(
                    RegistryDirectory,
                    "明文恢复安全登记数量超过上限，已停止读取多余登记。"));
                recordPaths = recordPaths[..MaximumRecoveryRecords];
            }

            var records = new List<RecoveryRecord>(recordPaths.Length);
            foreach (var recordPath in recordPaths)
            {
                byte[]? protectedBytes = null;
                byte[]? jsonBytes = null;
                var entropy = CreateRecoveryEntropy();
                try
                {
                    protectedBytes = BoundedFileReader.ReadAllBytes(
                        recordPath,
                        MaximumProtectedRecordSize,
                        "明文恢复安全登记");
                    jsonBytes = ProtectedData.Unprotect(
                        protectedBytes,
                        entropy,
                        DataProtectionScope.CurrentUser);
                    var record = JsonSerializer.Deserialize<RecoveryRecord>(jsonBytes);
                    if (record is null || record.Id == Guid.Empty || string.IsNullOrWhiteSpace(record.DirectoryPath) ||
                        !string.Equals(Path.GetFileNameWithoutExtension(recordPath), record.Id.ToString("N"),
                            StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidDataException("清理登记内容不完整。");
                    }

                    records.Add(record);
                }
                catch (Exception exception)
                {
                    failures.Add(new TemporaryContentCleanupFailure(recordPath, exception.Message));
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(entropy);
                    if (protectedBytes is not null)
                    {
                        CryptographicOperations.ZeroMemory(protectedBytes);
                    }

                    if (jsonBytes is not null)
                    {
                        CryptographicOperations.ZeroMemory(jsonBytes);
                    }
                }
            }

            return records;
        }

        private static void EnsureRegistryDirectory()
        {
            var parent = Path.GetDirectoryName(RegistryDirectory)
                ?? throw new NingRanException("无法确定安全恢复目录的位置。");
            Directory.CreateDirectory(parent);
            if (!Directory.Exists(RegistryDirectory))
            {
                WindowsFileSystemSafety.CreatePrivateDirectory(RegistryDirectory);
            }
            else
            {
                WindowsFileSystemSafety.SecureExistingPrivateDirectory(RegistryDirectory);
            }
        }

        private static string GetRecordPath(Guid id) => Path.Combine(RegistryDirectory, $"{id:N}.bin");

        private static byte[] CreateRecoveryEntropy() => SHA256.HashData(
            Encoding.ASCII.GetBytes("NINGRAN-PLAINTEXT-RECOVERY-V2"));
    }
}
