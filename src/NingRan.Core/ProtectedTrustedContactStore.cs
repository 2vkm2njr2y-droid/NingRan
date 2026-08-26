using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using NingRan.Core.Internal;

namespace NingRan.Core;

internal static class ProtectedTrustedContactStore
{
    private const int RecordVersion = 1;
    private const int MaximumContacts = 1_000;
    private const int MaximumRecordFileSize = 16 * 1024;
    private const int MaximumPublicIdentityFileSize = 4 * 1024;
    private const string RecordExtension = ".nrcontact";
    private const string LockFileName = ".store.lock";

    private static readonly SecurityIdentifier LocalSystem =
        new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier Administrators =
        new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier AuthenticatedUsers =
        new(WellKnownSidType.AuthenticatedUserSid, null);

    public static IReadOnlyList<TrustedContactRecordData> List(
        SecurityIdentifier userSid,
        NrIdentityService identityService)
    {
        ArgumentNullException.ThrowIfNull(userSid);
        ArgumentNullException.ThrowIfNull(identityService);
        var directory = GetUserDirectory(userSid);
        if (!Directory.Exists(directory))
        {
            return [];
        }

        VerifyStoreForReading(userSid, directory);
        var paths = Directory.EnumerateFiles(directory, "*" + RecordExtension)
            .Take(MaximumContacts + 1)
            .ToArray();
        if (paths.Length > MaximumContacts)
        {
            throw new NingRanException("受保护的可信联系人数量超过 1000 个安全上限。");
        }

        var records = new List<TrustedContactRecordData>(paths.Length);
        foreach (var path in paths)
        {
            try
            {
                records.Add(ReadPath(userSid, path, identityService));
            }
            catch
            {
                // 损坏、权限异常或绑定不一致的记录绝不会被信任。
            }
        }

        return records;
    }

    public static TrustedContactRecordData Read(
        SecurityIdentifier userSid,
        string contactId,
        NrIdentityService identityService)
    {
        var normalized = NormalizeRecordId(contactId);
        var directory = GetUserDirectory(userSid);
        if (!Directory.Exists(directory))
        {
            throw new NingRanException("该发送者尚未加入受保护的可信联系人。");
        }

        VerifyStoreForReading(userSid, directory);
        var path = Path.Combine(directory, normalized + RecordExtension);
        if (!File.Exists(path))
        {
            throw new NingRanException("该发送者尚未加入受保护的可信联系人。");
        }

        return ReadPath(userSid, path, identityService);
    }

    public static TrustedContactSummary Add(
        SecurityIdentifier userSid,
        ReadOnlySpan<byte> publicIdentityBytes,
        NrIdentityService identityService)
    {
        ThrowIfNotElevated();
        using var identity = identityService.ReadPublicIdentityBytes(publicIdentityBytes);
        var directory = EnsureStoreForWrite(userSid);
        using var storeLock = OpenStoreLock(directory, userSid);
        var existing = List(userSid, identityService);
        try
        {
            var sameIdentity = existing.FirstOrDefault(record => string.Equals(
                record.Fingerprint,
                identity.Fingerprint,
                StringComparison.OrdinalIgnoreCase));
            if (sameIdentity is not null)
            {
                return sameIdentity.ToSummary();
            }

            var sameName = existing.FirstOrDefault(record => string.Equals(
                record.Name,
                identity.Name,
                StringComparison.OrdinalIgnoreCase));
            if (sameName is not null)
            {
                throw new NingRanException(
                    $"可信联系人中已经有同名的“{sameName.Name}”，但安全核对信息不同。请先删除旧身份再导入。");
            }

            if (existing.Count >= MaximumContacts)
            {
                throw new NingRanException("可信联系人数量已达到 1000 个安全上限。");
            }

            var contactId = Guid.NewGuid().ToString("N");
            var confirmedAt = DateTimeOffset.UtcNow;
            var record = new ProtectedTrustedContactRecord
            {
                Version = RecordVersion,
                ContactId = contactId,
                Name = identity.Name,
                Fingerprint = identity.Fingerprint.ToUpperInvariant(),
                UserSid = userSid.Value,
                ConfirmedAtUtc = confirmedAt,
                PublicIdentity = Convert.ToBase64String(publicIdentityBytes),
            };
            WriteRecordAtomically(directory, userSid, record);
            return new TrustedContactSummary(
                contactId,
                identity.Name,
                confirmedAt.UtcDateTime,
                record.Fingerprint,
                userSid.Value,
                RequiresReverification: false);
        }
        finally
        {
            foreach (var record in existing)
            {
                CryptographicOperations.ZeroMemory(record.PublicIdentityBytes);
            }
        }
    }

    public static void Remove(
        SecurityIdentifier userSid,
        string contactId,
        string expectedFingerprint,
        NrIdentityService identityService)
    {
        ThrowIfNotElevated();
        var normalized = NormalizeRecordId(contactId);
        var directory = EnsureStoreForWrite(userSid);
        using var storeLock = OpenStoreLock(directory, userSid);
        var record = Read(userSid, normalized, identityService);
        try
        {
            if (!string.Equals(record.Fingerprint, expectedFingerprint, StringComparison.OrdinalIgnoreCase))
            {
                throw new NingRanException("可信联系人记录在确认期间发生了变化，已停止删除。");
            }

            var path = Path.Combine(directory, normalized + RecordExtension);
            using var handle = WindowsFileSystemSafety.OpenInputFile(path);
            var fileIdentity = WindowsFileSystemSafety.GetIdentity(handle);
            handle.Dispose();
            WindowsFileSystemSafety.DeleteVerifiedFile(path, fileIdentity);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(record.PublicIdentityBytes);
        }
    }

    private static TrustedContactRecordData ReadPath(
        SecurityIdentifier userSid,
        string path,
        NrIdentityService identityService)
    {
        VerifyProtectedEntry(path, userSid, isDirectory: false);
        var bytes = BoundedFileReader.ReadAllBytes(path, MaximumRecordFileSize, "可信联系人记录");
        byte[]? publicIdentityBytes = null;
        try
        {
            ProtectedTrustedContactRecord record;
            try
            {
                record = JsonSerializer.Deserialize<ProtectedTrustedContactRecord>(bytes)
                    ?? throw new NingRanException("可信联系人记录内容为空。");
            }
            catch (JsonException exception)
            {
                throw new NingRanException("可信联系人记录格式不正确。", exception);
            }

            var fileId = Path.GetFileNameWithoutExtension(path);
            var normalizedId = NormalizeRecordId(record.ContactId);
            var normalizedFingerprint = NormalizeFingerprint(record.Fingerprint);
            if (record.Version != RecordVersion ||
                !string.Equals(fileId, normalizedId, StringComparison.Ordinal) ||
                !string.Equals(record.UserSid, userSid.Value, StringComparison.Ordinal) ||
                record.ConfirmedAtUtc.Offset != TimeSpan.Zero ||
                record.ConfirmedAtUtc < new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero) ||
                record.ConfirmedAtUtc > DateTimeOffset.UtcNow.AddMinutes(5) ||
                string.IsNullOrWhiteSpace(record.PublicIdentity))
            {
                throw new NingRanException("可信联系人记录的账户、编号或确认时间绑定不正确。");
            }

            try
            {
                publicIdentityBytes = Convert.FromBase64String(record.PublicIdentity);
            }
            catch (FormatException exception)
            {
                throw new NingRanException("可信联系人记录中的公开身份格式不正确。", exception);
            }

            if (publicIdentityBytes.Length is <= 0 or > MaximumPublicIdentityFileSize)
            {
                throw new NingRanException("可信联系人记录中的公开身份大小不正确。");
            }

            using var identity = identityService.ReadPublicIdentityBytes(publicIdentityBytes);
            if (!string.Equals(identity.Name, record.Name, StringComparison.Ordinal) ||
                !string.Equals(identity.Fingerprint, normalizedFingerprint, StringComparison.OrdinalIgnoreCase))
            {
                throw new NingRanException("可信联系人记录与其中的公开身份不一致。");
            }

            var result = new TrustedContactRecordData(
                normalizedId,
                identity.Name,
                normalizedFingerprint,
                userSid.Value,
                record.ConfirmedAtUtc,
                publicIdentityBytes);
            publicIdentityBytes = null;
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
            if (publicIdentityBytes is not null)
            {
                CryptographicOperations.ZeroMemory(publicIdentityBytes);
            }
        }
    }

    private static void WriteRecordAtomically(
        string directory,
        SecurityIdentifier userSid,
        ProtectedTrustedContactRecord record)
    {
        var finalPath = Path.Combine(directory, record.ContactId + RecordExtension);
        var temporaryPath = Path.Combine(directory, $".contact-{Guid.NewGuid():N}.tmp");
        var bytes = JsonSerializer.SerializeToUtf8Bytes(record);
        try
        {
            using (var file = WindowsFileSystemSafety.CreateNewTemporaryFile(temporaryPath, 16 * 1024))
            {
                file.Write(bytes);
                file.Flush(flushToDisk: true);
            }

            ApplyProtectedEntrySecurity(temporaryPath, userSid, isDirectory: false);
            File.Move(temporaryPath, finalPath, overwrite: false);
            ApplyProtectedEntrySecurity(finalPath, userSid, isDirectory: false);
            VerifyProtectedEntry(finalPath, userSid, isDirectory: false);
        }
        catch
        {
            TryDeleteFile(temporaryPath);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static FileStream OpenStoreLock(string directory, SecurityIdentifier userSid)
    {
        var path = Path.Combine(directory, LockFileName);
        FileStream stream;
        try
        {
            stream = new FileStream(
                path,
                FileMode.OpenOrCreate,
                FileAccess.ReadWrite,
                FileShare.None,
                1,
                FileOptions.WriteThrough);
        }
        catch (IOException exception)
        {
            throw new NingRanException("另一个可信联系人管理员操作仍在进行，请稍后重试。", exception);
        }

        try
        {
            ApplyProtectedEntrySecurity(path, userSid, isDirectory: false);
            VerifyProtectedEntry(path, userSid, isDirectory: false);
            return stream;
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    private static string EnsureStoreForWrite(SecurityIdentifier userSid)
    {
        ThrowIfNotElevated();
        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        var productDirectory = Path.Combine(programData, "NingRan");
        var storeRoot = Path.Combine(productDirectory, "ProtectedTrustedContacts");
        EnsureBaseDirectory(productDirectory);
        EnsureBaseDirectory(storeRoot);
        var userDirectory = GetUserDirectory(userSid);
        EnsureUserDirectory(userDirectory, userSid);
        VerifyStoreForReading(userSid, userDirectory);
        foreach (var temporaryPath in Directory.EnumerateFiles(userDirectory, ".contact-*.tmp").Take(101))
        {
            TryDeleteFile(temporaryPath);
        }

        return userDirectory;
    }

    private static void VerifyStoreForReading(SecurityIdentifier userSid, string userDirectory)
    {
        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        var productDirectory = Path.Combine(programData, "NingRan");
        var storeRoot = Path.Combine(productDirectory, "ProtectedTrustedContacts");
        VerifyBaseDirectory(productDirectory);
        VerifyBaseDirectory(storeRoot);
        VerifyProtectedEntry(userDirectory, userSid, isDirectory: true);
    }

    private static void EnsureBaseDirectory(string path)
    {
        var security = CreateBaseDirectorySecurity();
        var info = new DirectoryInfo(path);
        if (!info.Exists)
        {
            info.Create(security);
        }
        else if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new NingRanException("受保护的可信联系人目录不能是快捷链接或目录联接。");
        }

        using var lockedDirectory = WindowsFileSystemSafety.OpenInputDirectory(path);
        var expectedIdentity = WindowsFileSystemSafety.GetIdentity(lockedDirectory);
        // Never try to "repair" an existing directory. A low-privilege process may
        // have pre-created it and retained a writable handle that an ACL rewrite
        // cannot revoke. Only an atomically-created directory with the expected
        // owner and ACL is accepted.
        VerifyBaseDirectory(path);
        WindowsFileSystemSafety.VerifyIdentity(lockedDirectory, expectedIdentity);
        WindowsFileSystemSafety.VerifyHandlePath(lockedDirectory, path);
    }

    private static void EnsureUserDirectory(string path, SecurityIdentifier userSid)
    {
        var security = CreateUserEntrySecurity(userSid, isDirectory: true);
        var info = new DirectoryInfo(path);
        if (!info.Exists)
        {
            info.Create(security);
        }
        else if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new NingRanException("当前账户的可信联系人目录不能是快捷链接或目录联接。");
        }

        using var lockedDirectory = WindowsFileSystemSafety.OpenInputDirectory(path);
        var expectedIdentity = WindowsFileSystemSafety.GetIdentity(lockedDirectory);
        // As above, an existing unsafe directory is rejected rather than hardened
        // in place because pre-existing write handles would remain valid.
        VerifyProtectedEntry(path, userSid, isDirectory: true);
        WindowsFileSystemSafety.VerifyIdentity(lockedDirectory, expectedIdentity);
        WindowsFileSystemSafety.VerifyHandlePath(lockedDirectory, path);
    }

    private static DirectorySecurity CreateBaseDirectorySecurity()
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(Administrators);
        var inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        security.AddAccessRule(new FileSystemAccessRule(
            Administrators,
            FileSystemRights.FullControl,
            inheritance,
            PropagationFlags.None,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            LocalSystem,
            FileSystemRights.FullControl,
            inheritance,
            PropagationFlags.None,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            AuthenticatedUsers,
            FileSystemRights.Traverse | FileSystemRights.ReadAttributes |
            FileSystemRights.ReadPermissions | FileSystemRights.Synchronize,
            InheritanceFlags.None,
            PropagationFlags.None,
            AccessControlType.Allow));
        return security;
    }

    private static DirectorySecurity CreateUserEntrySecurity(
        SecurityIdentifier userSid,
        bool isDirectory)
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(Administrators);
        var inheritance = isDirectory
            ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit
            : InheritanceFlags.None;
        security.AddAccessRule(new FileSystemAccessRule(
            Administrators,
            FileSystemRights.FullControl,
            inheritance,
            PropagationFlags.None,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            LocalSystem,
            FileSystemRights.FullControl,
            inheritance,
            PropagationFlags.None,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            userSid,
            FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize,
            inheritance,
            PropagationFlags.None,
            AccessControlType.Allow));
        return security;
    }

    private static FileSecurity CreateFileSecurity(SecurityIdentifier userSid)
    {
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(Administrators);
        security.AddAccessRule(new FileSystemAccessRule(
            Administrators,
            FileSystemRights.FullControl,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            LocalSystem,
            FileSystemRights.FullControl,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            userSid,
            FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize,
            AccessControlType.Allow));
        return security;
    }

    private static void ApplyProtectedEntrySecurity(
        string path,
        SecurityIdentifier userSid,
        bool isDirectory)
    {
        if (isDirectory)
        {
            new DirectoryInfo(path).SetAccessControl(CreateUserEntrySecurity(userSid, isDirectory: true));
        }
        else
        {
            new FileInfo(path).SetAccessControl(CreateFileSecurity(userSid));
        }
    }

    private static void VerifyBaseDirectory(string path)
    {
        var info = new DirectoryInfo(path);
        info.Refresh();
        if (!info.Exists || (info.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new NingRanException("受保护的可信联系人目录不存在或已被链接替换。");
        }

        var security = info.GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
        VerifyOwner(security);
        if (!security.AreAccessRulesProtected)
        {
            throw new NingRanException("受保护的可信联系人目录仍在继承不安全的写入权限。");
        }

        VerifyRules(security, targetUser: null, allowAuthenticatedTraverse: true);
    }

    private static void VerifyProtectedEntry(
        string path,
        SecurityIdentifier userSid,
        bool isDirectory)
    {
        FileSystemSecurity security;
        if (isDirectory)
        {
            var info = new DirectoryInfo(path);
            info.Refresh();
            if (!info.Exists || (info.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new NingRanException("可信联系人目录不存在或已被链接替换。");
            }

            security = info.GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
        }
        else
        {
            var info = new FileInfo(path);
            info.Refresh();
            if (!info.Exists || (info.Attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
            {
                throw new NingRanException("可信联系人记录不存在或已被链接替换。");
            }

            security = info.GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
        }

        VerifyOwner(security);
        if (!security.AreAccessRulesProtected)
        {
            throw new NingRanException("可信联系人记录仍在继承不安全的写入权限。");
        }

        VerifyRules(security, userSid, allowAuthenticatedTraverse: false);
    }

    private static void VerifyOwner(FileSystemSecurity security)
    {
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (owner is null || (!owner.Equals(Administrators) && !owner.Equals(LocalSystem)))
        {
            throw new NingRanException("可信联系人保护记录的所有者不正确，已停止信任。");
        }
    }

    private static void VerifyRules(
        FileSystemSecurity security,
        SecurityIdentifier? targetUser,
        bool allowAuthenticatedTraverse)
    {
        // Keep this mask to the individual rights that can mutate the entry.
        // Composite values such as Write, Modify and FullControl also contain
        // read/execute bits, which would make a legitimate read-only ACE look
        // writable when tested with a bitwise intersection.
        const FileSystemRights writeRights =
            FileSystemRights.WriteData | FileSystemRights.AppendData |
            FileSystemRights.WriteExtendedAttributes | FileSystemRights.WriteAttributes |
            FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles |
            FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership |
            (FileSystemRights)0x10000000 | // GENERIC_ALL
            (FileSystemRights)0x40000000;  // GENERIC_WRITE
        var rules = security.GetAccessRules(
            includeExplicit: true,
            includeInherited: true,
            targetType: typeof(SecurityIdentifier));
        foreach (FileSystemAccessRule rule in rules)
        {
            if (rule.AccessControlType != AccessControlType.Allow ||
                rule.IdentityReference is not SecurityIdentifier sid)
            {
                continue;
            }

            if (sid.Equals(Administrators) || sid.Equals(LocalSystem))
            {
                continue;
            }

            if (targetUser is not null && sid.Equals(targetUser))
            {
                if ((rule.FileSystemRights & writeRights) != 0)
                {
                    throw new NingRanException("当前普通账户仍可修改可信联系人保护记录，已停止信任。");
                }

                continue;
            }

            if (allowAuthenticatedTraverse && sid.Equals(AuthenticatedUsers))
            {
                var unsafeRights = rule.FileSystemRights &
                    ~(FileSystemRights.Traverse | FileSystemRights.ReadAttributes |
                      FileSystemRights.ReadPermissions | FileSystemRights.Synchronize);
                if (unsafeRights == 0)
                {
                    continue;
                }
            }

            throw new NingRanException("可信联系人保护记录允许了未经批准的账户访问，已停止信任。");
        }
    }

    private static string GetUserDirectory(SecurityIdentifier userSid) => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "NingRan",
        "ProtectedTrustedContacts",
        userSid.Value);

    private static string NormalizeRecordId(string contactId)
    {
        var normalized = (contactId ?? string.Empty).ToLowerInvariant();
        if (normalized.Length != 32 || normalized.Any(character => !Uri.IsHexDigit(character)))
        {
            throw new NingRanException("所选可信联系人记录编号不正确。");
        }

        return normalized;
    }

    private static string NormalizeFingerprint(string fingerprint)
    {
        var normalized = (fingerprint ?? string.Empty)
            .Replace("-", string.Empty, StringComparison.Ordinal)
            .ToUpperInvariant();
        if (normalized.Length != 64 || normalized.Any(character => !Uri.IsHexDigit(character)))
        {
            throw new NingRanException("可信联系人身份指纹格式不正确。");
        }

        return normalized;
    }

    private static void ThrowIfNotElevated()
    {
        if (!WindowsFileSystemSafety.IsProcessElevated())
        {
            throw new NingRanException("可信联系人保护记录只能由 Windows 管理员确认进程修改。");
        }
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                return;
            }

            using var handle = WindowsFileSystemSafety.OpenInputFile(path);
            var identity = WindowsFileSystemSafety.GetIdentity(handle);
            handle.Dispose();
            WindowsFileSystemSafety.DeleteVerifiedFile(path, identity);
        }
        catch
        {
            // 临时文件不会参与信任；无法清理时留待下次管理员操作重试。
        }
    }
}

internal sealed record TrustedContactRecordData(
    string ContactId,
    string Name,
    string Fingerprint,
    string UserSid,
    DateTimeOffset ConfirmedAtUtc,
    byte[] PublicIdentityBytes)
{
    public TrustedContactSummary ToSummary() => new(
        ContactId,
        Name,
        ConfirmedAtUtc.UtcDateTime,
        Fingerprint,
        UserSid,
        RequiresReverification: false);
}

internal sealed class ProtectedTrustedContactRecord
{
    public int Version { get; init; }

    public required string ContactId { get; init; }

    public required string Name { get; init; }

    public required string Fingerprint { get; init; }

    public required string UserSid { get; init; }

    public DateTimeOffset ConfirmedAtUtc { get; init; }

    public required string PublicIdentity { get; init; }
}
