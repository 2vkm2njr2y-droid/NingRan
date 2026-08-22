using System.Security.Cryptography;
using NingRan.Core.Internal;

namespace NingRan.Core;

public sealed class NrTrustedContactService
{
    private const int MaximumContacts = 1_000;
    private const int MaximumPublicIdentityFileSize = 4 * 1024;

    private readonly NrIdentityService _identityService;

    public NrTrustedContactService(NrIdentityService? identityService = null)
    {
        _identityService = identityService ?? new NrIdentityService();
    }

    public IReadOnlyList<TrustedContactSummary> ListTrustedContacts()
    {
        var directory = EnsureTrustedDirectory();
        var paths = Directory.EnumerateFiles(directory, "*.nrpub").Take(MaximumContacts + 1).ToArray();
        if (paths.Length > MaximumContacts)
        {
            throw new NingRanException("可信联系人数量超过 1000 个安全上限，请先清理不再使用的联系人。");
        }

        var contacts = new List<TrustedContactSummary>(paths.Length);
        foreach (var path in paths)
        {
            try
            {
                using var identity = _identityService.ReadPublicIdentity(path);
                var trustedAtUtc = File.GetCreationTimeUtc(path);
                var contactId = GetOrMigrateContactId(path, identity.Fingerprint);
                contacts.Add(new TrustedContactSummary(
                    contactId,
                    identity.Name,
                    trustedAtUtc));
            }
            catch
            {
                // 损坏的联系人不会被信任；管理界面仍可继续显示其他联系人。
            }
        }

        return contacts
            .OrderBy(contact => contact.Name, StringComparer.CurrentCultureIgnoreCase)
            .ThenBy(contact => contact.Id, StringComparer.Ordinal)
            .ToArray();
    }

    public TrustedContactSummary? FindTrustedContact(string contactId)
    {
        var normalized = NormalizeRecordId(contactId);
        return ListTrustedContacts().FirstOrDefault(contact =>
            string.Equals(contact.Id, normalized, StringComparison.Ordinal));
    }

    public TrustedContactSummary? FindTrustedContactForPublicIdentity(string publicIdentityPath)
    {
        using var selectedIdentity = _identityService.ReadPublicIdentity(publicIdentityPath);
        return FindTrustedContactByFingerprint(selectedIdentity.Fingerprint);
    }

    internal TrustedContactSummary? FindTrustedContactByFingerprint(string fingerprint)
    {
        var normalized = NormalizeFingerprint(fingerprint);
        foreach (var contact in ListTrustedContacts())
        {
            using var identity = ReadTrustedIdentity(contact.Id);
            if (string.Equals(identity.Fingerprint, normalized, StringComparison.OrdinalIgnoreCase))
            {
                return contact;
            }
        }

        return null;
    }

    public async Task<TrustedContactSummary> TrustPublicIdentityAsync(
        string publicIdentityPath,
        bool userExplicitlyConfirmed,
        CancellationToken cancellationToken = default)
    {
        if (!userExplicitlyConfirmed)
        {
            throw new NingRanException("必须由用户输入通过其他可信方式取得的安全码，并明确确认同意信任。");
        }

        using var selectedIdentity = _identityService.ReadPublicIdentity(publicIdentityPath);
        var existingContacts = ListTrustedContacts();
        foreach (var contact in existingContacts)
        {
            using var existingIdentity = ReadTrustedIdentity(contact.Id);
            if (string.Equals(
                    existingIdentity.Fingerprint,
                    selectedIdentity.Fingerprint,
                    StringComparison.OrdinalIgnoreCase))
            {
                return contact;
            }
        }

        var sameName = existingContacts.FirstOrDefault(contact =>
            string.Equals(contact.Name, selectedIdentity.Name, StringComparison.OrdinalIgnoreCase));
        if (sameName is not null)
        {
            throw new NingRanException(
                $"可信联系人中已经有同名的“{sameName.Name}”，但安全核对信息不同。请在联系人管理中手动删除旧身份后再导入。");
        }

        if (existingContacts.Count >= MaximumContacts)
        {
            throw new NingRanException("可信联系人数量已达到 1000 个安全上限。");
        }

        var bytes = await BoundedFileReader.ReadAllBytesAsync(
            publicIdentityPath,
            MaximumPublicIdentityFileSize,
            "发送者公开身份文件",
            cancellationToken).ConfigureAwait(false);
        var directory = EnsureTrustedDirectory();
        var contactId = CreateRandomRecordId();
        var finalPath = Path.Combine(directory, contactId + ".nrpub");
        var temporaryPath = Path.Combine(directory, $".ningran-contact-{Guid.NewGuid():N}.part");
        Guid? registration = null;
        FileStream? temporaryFile = null;
        try
        {
            using (var copiedIdentity = _identityService.ReadPublicIdentityBytes(bytes))
            {
                if (!string.Equals(
                        copiedIdentity.Fingerprint,
                        selectedIdentity.Fingerprint,
                        StringComparison.OrdinalIgnoreCase) ||
                    !string.Equals(copiedIdentity.Name, selectedIdentity.Name, StringComparison.Ordinal))
                {
                    throw new NingRanException("公开身份在导入过程中发生了变化，已停止信任。");
                }
            }

            temporaryFile = WindowsFileSystemSafety.CreateNewTemporaryFile(temporaryPath, 16 * 1024);
            registration = TemporaryFileRegistry.Register(temporaryFile, temporaryPath);
            await temporaryFile.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
            await temporaryFile.FlushAsync(cancellationToken).ConfigureAwait(false);
            temporaryFile.Flush(flushToDisk: true);

            WindowsFileSystemSafety.RenameOpenFile(temporaryFile.SafeFileHandle, temporaryPath, finalPath);
            TemporaryFileRegistry.Unregister(registration);
            temporaryFile.Dispose();
            temporaryFile = null;
            return new TrustedContactSummary(
                contactId,
                selectedIdentity.Name,
                DateTime.UtcNow);
        }
        catch
        {
            if (temporaryFile is not null)
            {
                try
                {
                    WindowsFileSystemSafety.DeleteOpenFile(temporaryFile.SafeFileHandle, temporaryPath);
                }
                catch
                {
                    // 启动恢复登记会按文件身份继续清理。
                }

                temporaryFile.Dispose();
            }

            if (!File.Exists(temporaryPath))
            {
                TemporaryFileRegistry.Unregister(registration);
            }

            throw;
        }
        finally
        {
            temporaryFile?.Dispose();
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    public void RemoveTrustedContact(string contactId)
    {
        var path = GetTrustedPath(contactId);
        using var handle = WindowsFileSystemSafety.OpenInputFile(path);
        var identity = WindowsFileSystemSafety.GetIdentity(handle);
        handle.Dispose();
        WindowsFileSystemSafety.DeleteVerifiedFile(path, identity);
    }

    internal PublicSigningIdentity ReadTrustedIdentity(string contactId)
    {
        return _identityService.ReadPublicIdentity(GetTrustedPath(contactId));
    }

    private static string GetTrustedPath(string contactId)
    {
        var normalized = NormalizeRecordId(contactId);
        var path = Path.Combine(EnsureTrustedDirectory(), normalized + ".nrpub");
        if (!File.Exists(path))
        {
            throw new NingRanException("该发送者尚未加入本机可信联系人，请先导入公开身份并输入正确的安全码。");
        }

        return path;
    }

    private static string NormalizeFingerprint(string fingerprint)
    {
        var normalized = (fingerprint ?? string.Empty).Replace("-", string.Empty, StringComparison.Ordinal)
            .ToUpperInvariant();
        if (normalized.Length != 64 || normalized.Any(character => !Uri.IsHexDigit(character)))
        {
            throw new NingRanException("发送者身份核对信息格式不正确。");
        }

        return normalized;
    }

    private static string GetOrMigrateContactId(string path, string fingerprint)
    {
        var fileId = Path.GetFileNameWithoutExtension(path);
        if (IsRandomRecordId(fileId))
        {
            return fileId.ToLowerInvariant();
        }

        if (!IsLegacyFingerprint(fileId) ||
            !string.Equals(fileId, fingerprint, StringComparison.OrdinalIgnoreCase))
        {
            throw new NingRanException("可信联系人记录名称不正确，已停止使用该记录。");
        }

        var contactId = CreateRandomRecordId();
        var migratedPath = Path.Combine(Path.GetDirectoryName(path)!, contactId + ".nrpub");
        File.Move(path, migratedPath);
        return contactId;
    }

    private static string NormalizeRecordId(string contactId)
    {
        var normalized = (contactId ?? string.Empty).ToLowerInvariant();
        if (!IsRandomRecordId(normalized))
        {
            throw new NingRanException("所选可信联系人记录不正确。");
        }

        return normalized;
    }

    private static string CreateRandomRecordId() => Guid.NewGuid().ToString("N");

    private static bool IsRandomRecordId(string value) =>
        value.Length == 32 && value.All(Uri.IsHexDigit);

    private static bool IsLegacyFingerprint(string value) =>
        value.Length == 64 && value.All(Uri.IsHexDigit);

    private static string EnsureTrustedDirectory()
    {
        var parent = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "NingRan");
        Directory.CreateDirectory(parent);
        var directory = Path.Combine(parent, "TrustedContacts");
        if (!Directory.Exists(directory))
        {
            WindowsFileSystemSafety.CreatePrivateDirectory(directory);
        }
        else
        {
            WindowsFileSystemSafety.SecureExistingPrivateDirectory(directory);
        }

        return directory;
    }
}
