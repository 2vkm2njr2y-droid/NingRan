using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using NingRan.Core.Internal;

namespace NingRan.Core;

public sealed class NrTrustedContactService
{
    private const int MaximumContacts = 1_000;
    private const string LegacyIdPrefix = "legacy-";

    private readonly NrIdentityService _identityService;

    public NrTrustedContactService(NrIdentityService? identityService = null)
    {
        _identityService = identityService ?? new NrIdentityService();
    }

    /// <summary>
    /// Returns only administrator-protected records that are safe to use for signature verification.
    /// Legacy per-user files are deliberately excluded until the user re-verifies them.
    /// </summary>
    public IReadOnlyList<TrustedContactSummary> ListTrustedContacts()
    {
        var records = ProtectedTrustedContactStore.List(GetCurrentUserSid(), _identityService);
        try
        {
            return records
                .Select(record => record.ToSummary())
                .OrderBy(contact => contact.Name, StringComparer.CurrentCultureIgnoreCase)
                .ThenBy(contact => contact.Id, StringComparer.Ordinal)
                .ToArray();
        }
        finally
        {
            foreach (var record in records)
            {
                CryptographicOperations.ZeroMemory(record.PublicIdentityBytes);
            }
        }
    }

    /// <summary>
    /// Returns protected contacts plus legacy contacts that remain on disk but are no longer trusted.
    /// </summary>
    public IReadOnlyList<TrustedContactSummary> ListContactsForManagement()
    {
        var protectedContacts = ListTrustedContacts();
        var trustedFingerprints = protectedContacts
            .Select(contact => contact.Fingerprint)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var contacts = new List<TrustedContactSummary>(protectedContacts);
        contacts.AddRange(ListLegacyContacts().Where(contact =>
            !trustedFingerprints.Contains(contact.Fingerprint)));
        return contacts
            .OrderBy(contact => contact.Name, StringComparer.CurrentCultureIgnoreCase)
            .ThenBy(contact => contact.RequiresReverification)
            .ThenBy(contact => contact.Id, StringComparer.Ordinal)
            .ToArray();
    }

    public TrustedContactSummary? FindTrustedContact(string contactId)
    {
        var normalized = NormalizeProtectedRecordId(contactId);
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
        return ListTrustedContacts().FirstOrDefault(contact => string.Equals(
            contact.Fingerprint,
            normalized,
            StringComparison.OrdinalIgnoreCase));
    }

    public string CreateTrustRequest(string publicIdentityPath) =>
        TrustedContactBroker.CreateTrustRequest(publicIdentityPath);

    public string CreateReverificationRequest(TrustedContactSummary contact)
    {
        ArgumentNullException.ThrowIfNull(contact);
        if (!contact.RequiresReverification)
        {
            throw new NingRanException("该联系人已经通过管理员保护流程确认，不需要重新核对。");
        }

        var sid = GetCurrentUserSid();
        if (!string.Equals(contact.UserSid, sid.Value, StringComparison.Ordinal))
        {
            throw new NingRanException("所选旧联系人不属于当前 Windows 账户。");
        }

        return TrustedContactBroker.CreateTrustRequest(GetLegacyPathForBroker(contact.Id, sid));
    }

    public string CreateRemoveRequest(TrustedContactSummary contact) =>
        TrustedContactBroker.CreateRemoveRequest(contact);

    internal PublicSigningIdentity ReadTrustedIdentity(string contactId)
    {
        var record = ProtectedTrustedContactStore.Read(
            GetCurrentUserSid(),
            contactId,
            _identityService);
        try
        {
            return _identityService.ReadPublicIdentityBytes(record.PublicIdentityBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(record.PublicIdentityBytes);
        }
    }

    internal static string GetLegacyPathForBroker(
        string legacyContactId,
        SecurityIdentifier expectedUserSid)
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (identity.User is null || !identity.User.Equals(expectedUserSid))
        {
            throw new NingRanException("只能为当前普通 Windows 账户创建旧联系人管理员请求。");
        }

        var fileId = ParseLegacyContactId(legacyContactId);
        var path = Path.Combine(GetLegacyDirectory(), fileId + ".nrpub");
        if (!File.Exists(path))
        {
            throw new NingRanException("所选旧联系人记录已经不存在。");
        }

        using var handle = WindowsFileSystemSafety.OpenInputFile(path);
        return path;
    }

    internal static string ValidateLegacyPathForBroker(
        string legacyContactId,
        string suppliedPath,
        SecurityIdentifier expectedOwner)
    {
        var fileId = ParseLegacyContactId(legacyContactId);
        var fullPath = Path.GetFullPath(suppliedPath);
        if (!string.Equals(Path.GetFileName(fullPath), fileId + ".nrpub", StringComparison.OrdinalIgnoreCase))
        {
            throw new NingRanException("旧联系人编号与文件不一致。");
        }

        var trustedContactsDirectory = new DirectoryInfo(Path.GetDirectoryName(fullPath)
            ?? throw new NingRanException("无法确定旧联系人目录。"));
        var productDirectory = trustedContactsDirectory.Parent;
        if (!string.Equals(trustedContactsDirectory.Name, "TrustedContacts", StringComparison.Ordinal) ||
            productDirectory is null ||
            !string.Equals(productDirectory.Name, "NingRan", StringComparison.Ordinal) ||
            (trustedContactsDirectory.Attributes & FileAttributes.ReparsePoint) != 0 ||
            (productDirectory.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new NingRanException("旧联系人文件不在有效的本机联系人目录中。");
        }

        using var handle = WindowsFileSystemSafety.OpenInputFile(fullPath);
        var security = new FileInfo(fullPath).GetAccessControl(AccessControlSections.Owner);
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (owner is null || !owner.Equals(expectedOwner))
        {
            throw new NingRanException("旧联系人文件与发起请求的 Windows 账户不一致。");
        }

        return fullPath;
    }

    private IReadOnlyList<TrustedContactSummary> ListLegacyContacts()
    {
        var directory = GetLegacyDirectory();
        if (!Directory.Exists(directory))
        {
            return [];
        }

        var directoryInfo = new DirectoryInfo(directory);
        if ((directoryInfo.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new NingRanException("旧可信联系人目录是快捷链接或目录联接，已停止读取。");
        }

        var paths = Directory.EnumerateFiles(directory, "*.nrpub")
            .Take(MaximumContacts + 1)
            .ToArray();
        if (paths.Length > MaximumContacts)
        {
            throw new NingRanException("旧可信联系人数量超过 1000 个安全上限，请先清理。");
        }

        var userSid = GetCurrentUserSid().Value;
        var contacts = new List<TrustedContactSummary>(paths.Length);
        foreach (var path in paths)
        {
            try
            {
                var fileId = Path.GetFileNameWithoutExtension(path);
                if (!IsLegacyFileId(fileId))
                {
                    continue;
                }

                using var identity = _identityService.ReadPublicIdentity(path);
                if (fileId.Length == 64 &&
                    !string.Equals(fileId, identity.Fingerprint, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                contacts.Add(new TrustedContactSummary(
                    LegacyIdPrefix + fileId.ToLowerInvariant(),
                    identity.Name,
                    File.GetCreationTimeUtc(path),
                    NormalizeFingerprint(identity.Fingerprint),
                    userSid,
                    RequiresReverification: true));
            }
            catch
            {
                // 损坏的旧记录不会显示，更不会被信任。
            }
        }

        return contacts;
    }

    private static string ParseLegacyContactId(string contactId)
    {
        if (string.IsNullOrWhiteSpace(contactId) ||
            !contactId.StartsWith(LegacyIdPrefix, StringComparison.Ordinal))
        {
            throw new NingRanException("所选旧联系人记录编号不正确。");
        }

        var fileId = contactId[LegacyIdPrefix.Length..].ToLowerInvariant();
        if (!IsLegacyFileId(fileId))
        {
            throw new NingRanException("所选旧联系人记录编号不正确。");
        }

        return fileId;
    }

    private static bool IsLegacyFileId(string value) =>
        value.Length is 32 or 64 && value.All(Uri.IsHexDigit);

    private static string NormalizeProtectedRecordId(string contactId)
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
            throw new NingRanException("发送者身份核对信息格式不正确。");
        }

        return normalized;
    }

    private static string GetLegacyDirectory() => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "NingRan",
        "TrustedContacts");

    private static SecurityIdentifier GetCurrentUserSid()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.User
            ?? throw new NingRanException("无法识别当前 Windows 账户，不能读取可信联系人。");
    }
}
