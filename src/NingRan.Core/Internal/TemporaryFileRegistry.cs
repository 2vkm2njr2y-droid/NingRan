using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace NingRan.Core.Internal;

internal static class TemporaryFileRegistry
{
    private const int MaximumRecords = 4_096;
    private const int MaximumProtectedRecordSize = 16 * 1024;
    private static readonly ConcurrentDictionary<Guid, FileStream> ActiveRegistrations = new();

    public static Guid Register(FileStream stream, string path)
    {
        var fullPath = Path.GetFullPath(path);
        WindowsFileSystemSafety.VerifyHandlePath(stream.SafeFileHandle, fullPath);
        var directoryPath = Path.GetDirectoryName(fullPath)
            ?? throw new NingRanException("无法确定临时文件所在位置。");
        if (!IsExpectedTemporaryName(Path.GetFileName(fullPath)))
        {
            throw new NingRanException("临时文件登记位置不符合安全规则。");
        }

        using var directoryHandle = WindowsFileSystemSafety.OpenStableDirectory(directoryPath);
        var id = Guid.NewGuid();
        var record = new TemporaryFileRecord(
            id,
            fullPath,
            WindowsFileSystemSafety.GetIdentity(stream.SafeFileHandle),
            directoryPath,
            WindowsFileSystemSafety.GetIdentity(directoryHandle));
        var registryDirectory = EnsureRegistryDirectory();
        var recordPath = Path.Combine(registryDirectory, $"{id:N}.bin");
        var jsonBytes = JsonSerializer.SerializeToUtf8Bytes(record);
        var entropy = CreateEntropy();
        byte[]? protectedBytes = null;
        FileStream? recordStream = null;
        try
        {
            protectedBytes = ProtectedData.Protect(jsonBytes, entropy, DataProtectionScope.CurrentUser);
            if (protectedBytes.Length is 0 or > MaximumProtectedRecordSize)
            {
                throw new NingRanException("临时文件安全登记大小异常。");
            }

            recordStream = new FileStream(
                recordPath,
                FileMode.CreateNew,
                FileAccess.ReadWrite,
                FileShare.None,
                4096,
                FileOptions.WriteThrough);
            recordStream.Write(protectedBytes);
            recordStream.Flush(flushToDisk: true);
            if (!ActiveRegistrations.TryAdd(id, recordStream))
            {
                throw new NingRanException("无法登记临时文件的使用状态。");
            }

            recordStream = null;
            return id;
        }
        finally
        {
            recordStream?.Dispose();
            CryptographicOperations.ZeroMemory(jsonBytes);
            CryptographicOperations.ZeroMemory(entropy);
            if (protectedBytes is not null)
            {
                CryptographicOperations.ZeroMemory(protectedBytes);
            }
        }
    }

    public static void Unregister(Guid? id)
    {
        if (id is null)
        {
            return;
        }

        ReleaseProcessLease(id.Value);
        try
        {
            var path = Path.Combine(RegistryDirectory, $"{id.Value:N}.bin");
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
            // 登记文件不含文件内容，下次启动会再次整理。
        }
    }

    public static TemporaryContentCleanupResult CleanupAbandoned()
    {
        var removed = 0;
        var failures = new List<TemporaryContentCleanupFailure>();
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

        RemoveUntrustedLegacyRecords(directory, failures);
        var recordPaths = Directory.EnumerateFiles(directory, "*.bin").Take(MaximumRecords + 1).ToArray();
        if (recordPaths.Length > MaximumRecords)
        {
            failures.Add(new TemporaryContentCleanupFailure(
                directory,
                "临时文件安全登记数量超过上限，已停止读取多余登记。"));
            recordPaths = recordPaths[..MaximumRecords];
        }

        foreach (var recordPath in recordPaths)
        {
            TemporaryFileRecord? record = null;
            byte[]? protectedBytes = null;
            byte[]? jsonBytes = null;
            var entropy = CreateEntropy();
            try
            {
                protectedBytes = BoundedFileReader.ReadAllBytes(
                    recordPath,
                    MaximumProtectedRecordSize,
                    "临时文件安全登记");
                jsonBytes = ProtectedData.Unprotect(
                    protectedBytes,
                    entropy,
                    DataProtectionScope.CurrentUser);
                record = JsonSerializer.Deserialize<TemporaryFileRecord>(jsonBytes);
                ValidateRecord(recordPath, record);

                using var directoryHandle = WindowsFileSystemSafety.OpenStableDirectory(record!.DirectoryPath);
                WindowsFileSystemSafety.VerifyIdentity(directoryHandle, record.DirectoryIdentity);
                if (!File.Exists(record.Path))
                {
                    File.Delete(recordPath);
                    continue;
                }

                WindowsFileSystemSafety.DeleteVerifiedFile(record.Path, record.Identity);
                File.Delete(recordPath);
                removed++;
            }
            catch (NingRanException exception) when (
                exception.InnerException is System.ComponentModel.Win32Exception win32 &&
                win32.NativeErrorCode is 32 or 33)
            {
                // 仍被另一个正在运行的实例使用，不视为崩溃残留。
            }
            catch (IOException exception) when (IsSharingViolation(exception))
            {
                // 登记文件仍被创建它的进程独占。
            }
            catch (Exception exception)
            {
                failures.Add(new TemporaryContentCleanupFailure(
                    record?.Path ?? recordPath,
                    exception.Message));
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

        return new TemporaryContentCleanupResult(removed, failures);
    }

    internal static void ReleaseProcessLease(Guid id)
    {
        if (ActiveRegistrations.TryRemove(id, out var registration))
        {
            registration.Dispose();
        }
    }

    private static string RegistryDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "NingRan",
        "TemporaryFileRecovery");

    private static string EnsureRegistryDirectory()
    {
        var parent = Path.GetDirectoryName(RegistryDirectory)
            ?? throw new NingRanException("无法确定临时文件恢复目录的位置。");
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

    private static void ValidateRecord(string recordPath, TemporaryFileRecord? record)
    {
        if (record is null || record.Id == Guid.Empty ||
            !string.Equals(
                Path.GetFileNameWithoutExtension(recordPath),
                record.Id.ToString("N"),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("临时文件清理登记不正确。");
        }

        var fullPath = Path.GetFullPath(record.Path);
        var directoryPath = Path.GetFullPath(record.DirectoryPath);
        if (!string.Equals(Path.GetDirectoryName(fullPath), directoryPath, StringComparison.OrdinalIgnoreCase) ||
            !IsExpectedTemporaryName(Path.GetFileName(fullPath)))
        {
            throw new InvalidDataException("临时文件清理登记超出了创建时固定的安全目录。");
        }
    }

    private static bool IsExpectedTemporaryName(string name) =>
        name.StartsWith(".ningran-", StringComparison.OrdinalIgnoreCase) &&
        name.EndsWith(".part", StringComparison.OrdinalIgnoreCase) &&
        name.IndexOfAny(Path.GetInvalidFileNameChars()) < 0;

    private static byte[] CreateEntropy() => SHA256.HashData(
        Encoding.ASCII.GetBytes("NINGRAN-TEMPORARY-FILE-RECOVERY-V2"));

    private static bool IsSharingViolation(IOException exception) =>
        (exception.HResult & 0xFFFF) is 32 or 33;

    private static void RemoveUntrustedLegacyRecords(
        string directory,
        ICollection<TemporaryContentCleanupFailure> failures)
    {
        foreach (var path in Directory.EnumerateFiles(directory, "*.json").Take(MaximumRecords + 1))
        {
            try
            {
                File.Delete(path);
            }
            catch (Exception exception)
            {
                failures.Add(new TemporaryContentCleanupFailure(path, exception.Message));
            }
        }
    }

    private sealed record TemporaryFileRecord(
        Guid Id,
        string Path,
        WindowsFileIdentity Identity,
        string DirectoryPath,
        WindowsFileIdentity DirectoryIdentity);
}
