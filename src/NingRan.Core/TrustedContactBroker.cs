using System.Collections.Concurrent;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using NingRan.Core.Internal;

namespace NingRan.Core;

public enum TrustedContactBrokerAction
{
    Trust,
    Remove,
}

public sealed record TrustedContactBrokerPreview(
    TrustedContactBrokerAction Action,
    string Name,
    string Fingerprint,
    string VerificationCode,
    string TargetUserSid,
    string TargetAccount,
    DateTime? TrustedAtUtc,
    bool IsLegacyRecord);

public sealed record TrustedContactBrokerLaunchBinding(
    string RequestPath,
    string RequestNonce,
    string RequestSha256,
    TrustedContactBrokerAction Action,
    string? ContactId,
    string ExpectedFingerprint);

public sealed class TrustedContactBrokerOperation : IDisposable
{
    private readonly FileStream _requestStream;
    private readonly TrustedContactBrokerRequest _request;
    private readonly NrIdentityService _identityService;
    private readonly byte[]? _publicIdentityBytes;
    private readonly WindowsFileIdentity? _legacyFileIdentity;
    private bool _committed;
    private bool _disposed;

    internal TrustedContactBrokerOperation(
        FileStream requestStream,
        TrustedContactBrokerRequest request,
        NrIdentityService identityService,
        TrustedContactBrokerPreview preview,
        byte[]? publicIdentityBytes,
        WindowsFileIdentity? legacyFileIdentity)
    {
        _requestStream = requestStream;
        _request = request;
        _identityService = identityService;
        Preview = preview;
        _publicIdentityBytes = publicIdentityBytes;
        _legacyFileIdentity = legacyFileIdentity;
    }

    public TrustedContactBrokerPreview Preview { get; }

    public TrustedContactSummary? Commit()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_committed)
        {
            throw new InvalidOperationException("可信联系人管理员操作已经完成，不能重复执行。");
        }

        if (!WindowsFileSystemSafety.IsProcessElevated())
        {
            throw new NingRanException("可信联系人只能在 Windows 管理员确认窗口中修改。");
        }

        _committed = true;
        var targetSid = new SecurityIdentifier(_request.UserSid);
        if (_request.Action == TrustedContactBrokerAction.Trust)
        {
            if (_publicIdentityBytes is null)
            {
                throw new NingRanException("可信联系人请求中缺少公开身份。");
            }

            return ProtectedTrustedContactStore.Add(
                targetSid,
                _publicIdentityBytes,
                _identityService);
        }

        if (_request.IsLegacyRecord)
        {
            if (_legacyFileIdentity is null || string.IsNullOrWhiteSpace(_request.LegacyPath))
            {
                throw new NingRanException("旧联系人删除请求不完整。");
            }

            WindowsFileSystemSafety.DeleteVerifiedFile(
                _request.LegacyPath,
                _legacyFileIdentity.Value);
            return null;
        }

        ProtectedTrustedContactStore.Remove(
            targetSid,
            _request.ContactId ?? string.Empty,
            Preview.Fingerprint,
            _identityService);
        return null;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _requestStream.Dispose();
        if (_publicIdentityBytes is not null)
        {
            CryptographicOperations.ZeroMemory(_publicIdentityBytes);
        }
    }
}

public static class TrustedContactBroker
{
    private const int RequestVersion = 2;
    private const int MaximumRequestFileSize = 16 * 1024;
    private const int MaximumPublicIdentityFileSize = 4 * 1024;
    private static readonly TimeSpan MaximumRequestAge = TimeSpan.FromMinutes(10);
    private static readonly ConcurrentDictionary<string, TrustedContactBrokerLaunchBinding>
        PendingLaunchBindings = new(StringComparer.OrdinalIgnoreCase);

    public static string CreateTrustRequest(string publicIdentityPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(publicIdentityPath);
        var fullPath = Path.GetFullPath(publicIdentityPath);
        var publicIdentityBytes = BoundedFileReader.ReadAllBytes(
            fullPath,
            MaximumPublicIdentityFileSize,
            "发送者公开身份文件");
        try
        {
            using var identity = new NrIdentityService().ReadPublicIdentityBytes(publicIdentityBytes);
            var expectedFingerprint = NormalizeFingerprint(identity.Fingerprint);
            return WriteRequest(new TrustedContactBrokerRequest
            {
                Version = RequestVersion,
                RequestId = Guid.NewGuid().ToString("N"),
                RequestNonce = CreateRequestNonce(),
                UserSid = GetCurrentUserSid().Value,
                Action = TrustedContactBrokerAction.Trust,
                ExpectedFingerprint = expectedFingerprint,
                PublicIdentity = Convert.ToBase64String(publicIdentityBytes),
                CreatedAtUtc = DateTimeOffset.UtcNow,
            });
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicIdentityBytes);
        }
    }

    public static string CreateRemoveRequest(TrustedContactSummary contact)
    {
        ArgumentNullException.ThrowIfNull(contact);
        var currentSid = GetCurrentUserSid();
        if (!string.Equals(contact.UserSid, currentSid.Value, StringComparison.Ordinal))
        {
            throw new NingRanException("所选联系人不属于当前 Windows 账户。");
        }

        string? legacyPath = null;
        string expectedFingerprint;
        if (contact.RequiresReverification)
        {
            legacyPath = NrTrustedContactService.GetLegacyPathForBroker(contact.Id, currentSid);
            using var identity = new NrIdentityService().ReadPublicIdentity(legacyPath);
            expectedFingerprint = NormalizeFingerprint(identity.Fingerprint);
        }
        else
        {
            var record = ProtectedTrustedContactStore.Read(currentSid, contact.Id, new NrIdentityService());
            try
            {
                expectedFingerprint = NormalizeFingerprint(record.Fingerprint);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(record.PublicIdentityBytes);
            }
        }

        if (!string.Equals(
                expectedFingerprint,
                NormalizeFingerprint(contact.Fingerprint),
                StringComparison.Ordinal))
        {
            throw new NingRanException("所选联系人的身份已经变化，请刷新联系人列表后重新确认。");
        }

        return WriteRequest(new TrustedContactBrokerRequest
        {
            Version = RequestVersion,
            RequestId = Guid.NewGuid().ToString("N"),
            RequestNonce = CreateRequestNonce(),
            UserSid = currentSid.Value,
            Action = TrustedContactBrokerAction.Remove,
            ContactId = contact.Id,
            ExpectedFingerprint = expectedFingerprint,
            LegacyPath = legacyPath,
            IsLegacyRecord = contact.RequiresReverification,
            CreatedAtUtc = DateTimeOffset.UtcNow,
        });
    }

    public static TrustedContactBrokerLaunchBinding TakeLaunchBinding(string requestPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(requestPath);
        var fullPath = Path.GetFullPath(requestPath);
        if (!PendingLaunchBindings.TryRemove(fullPath, out var binding))
        {
            throw new NingRanException("可信联系人管理员请求没有可用的启动校验信息，请重新开始。");
        }

        return binding;
    }

    public static TrustedContactBrokerOperation OpenRequest(TrustedContactBrokerLaunchBinding binding)
    {
        if (!WindowsFileSystemSafety.IsProcessElevated())
        {
            throw new NingRanException("可信联系人管理员请求只能由已提权的正式程序处理。");
        }

        ArgumentNullException.ThrowIfNull(binding);
        ArgumentException.ThrowIfNullOrWhiteSpace(binding.RequestPath);
        var fullPath = Path.GetFullPath(binding.RequestPath);
        var handle = WindowsFileSystemSafety.OpenExclusiveInputFile(fullPath);
        FileStream? requestStream = null;
        byte[]? publicIdentityBytes = null;
        try
        {
            requestStream = new FileStream(handle, FileAccess.Read);
            if (requestStream.Length is <= 0 or > MaximumRequestFileSize)
            {
                throw new NingRanException("可信联系人管理员请求大小不正确。");
            }

            var requestBytes = new byte[checked((int)requestStream.Length)];
            requestStream.ReadExactly(requestBytes);
            TrustedContactBrokerRequest request;
            try
            {
                VerifyRequestDigest(requestBytes, binding.RequestSha256);
                request = JsonSerializer.Deserialize<TrustedContactBrokerRequest>(requestBytes)
                    ?? throw new NingRanException("可信联系人管理员请求内容为空。");
            }
            catch (JsonException exception)
            {
                throw new NingRanException("可信联系人管理员请求格式不正确。", exception);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(requestBytes);
            }

            var targetSid = ValidateRequest(request, fullPath);
            ValidateLaunchBinding(request, binding, fullPath);
            ValidateRequestOwner(fullPath, requestStream, targetSid);
            var identityService = new NrIdentityService();
            var account = ResolveAccountName(targetSid);
            TrustedContactBrokerPreview preview;
            WindowsFileIdentity? legacyIdentity = null;
            if (request.Action == TrustedContactBrokerAction.Trust)
            {
                try
                {
                    publicIdentityBytes = Convert.FromBase64String(request.PublicIdentity!);
                }
                catch (FormatException exception)
                {
                    throw new NingRanException("管理员请求中的公开身份格式不正确。", exception);
                }

                if (publicIdentityBytes.Length is <= 0 or > MaximumPublicIdentityFileSize)
                {
                    throw new NingRanException("管理员请求中的公开身份大小不正确。");
                }

                using var identity = identityService.ReadPublicIdentityBytes(publicIdentityBytes);
                ValidateExpectedFingerprint(request, identity.Fingerprint);
                preview = new TrustedContactBrokerPreview(
                    request.Action,
                    identity.Name,
                    identity.Fingerprint,
                    NrIdentityService.CreateVerificationCode(identity.Fingerprint),
                    targetSid.Value,
                    account,
                    null,
                    false);
            }
            else if (request.IsLegacyRecord)
            {
                var legacyPath = NrTrustedContactService.ValidateLegacyPathForBroker(
                    request.ContactId!,
                    request.LegacyPath!,
                    targetSid);
                using var legacyHandle = WindowsFileSystemSafety.OpenExclusiveInputFile(legacyPath);
                legacyIdentity = WindowsFileSystemSafety.GetIdentity(legacyHandle);
                using var legacyStream = new FileStream(legacyHandle, FileAccess.Read);
                if (legacyStream.Length is <= 0 or > MaximumPublicIdentityFileSize)
                {
                    throw new NingRanException("旧可信联系人公开身份文件大小不正确。");
                }

                publicIdentityBytes = new byte[checked((int)legacyStream.Length)];
                legacyStream.ReadExactly(publicIdentityBytes);
                using var identity = identityService.ReadPublicIdentityBytes(publicIdentityBytes);
                ValidateExpectedFingerprint(request, identity.Fingerprint);
                preview = new TrustedContactBrokerPreview(
                    request.Action,
                    identity.Name,
                    identity.Fingerprint,
                    string.Empty,
                    targetSid.Value,
                    account,
                    File.GetCreationTimeUtc(legacyPath),
                    true);
            }
            else
            {
                var record = ProtectedTrustedContactStore.Read(
                    targetSid,
                    request.ContactId!,
                    identityService);
                try
                {
                    ValidateExpectedFingerprint(request, record.Fingerprint);
                    preview = new TrustedContactBrokerPreview(
                        request.Action,
                        record.Name,
                        record.Fingerprint,
                        string.Empty,
                        targetSid.Value,
                        account,
                        record.ConfirmedAtUtc.UtcDateTime,
                        false);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(record.PublicIdentityBytes);
                }
            }

            var operation = new TrustedContactBrokerOperation(
                requestStream,
                request,
                identityService,
                preview,
                publicIdentityBytes,
                legacyIdentity);
            requestStream = null;
            publicIdentityBytes = null;
            return operation;
        }
        catch
        {
            requestStream?.Dispose();
            if (requestStream is null)
            {
                handle.Dispose();
            }

            if (publicIdentityBytes is not null)
            {
                CryptographicOperations.ZeroMemory(publicIdentityBytes);
            }

            throw;
        }
    }

    public static void DeleteRequest(string? requestPath)
    {
        if (string.IsNullOrWhiteSpace(requestPath))
        {
            return;
        }

        try
        {
            var fullPath = Path.GetFullPath(requestPath);
            PendingLaunchBindings.TryRemove(fullPath, out _);
            var directory = Path.TrimEndingDirectorySeparator(GetRequestDirectory());
            if (!string.Equals(
                    Path.GetDirectoryName(fullPath),
                    directory,
                    StringComparison.OrdinalIgnoreCase) ||
                !Path.GetFileName(fullPath).StartsWith("request-", StringComparison.Ordinal) ||
                !string.Equals(Path.GetExtension(fullPath), ".json", StringComparison.OrdinalIgnoreCase) ||
                !File.Exists(fullPath))
            {
                return;
            }

            using var handle = WindowsFileSystemSafety.OpenInputFile(fullPath);
            var identity = WindowsFileSystemSafety.GetIdentity(handle);
            handle.Dispose();
            WindowsFileSystemSafety.DeleteVerifiedFile(fullPath, identity);
        }
        catch
        {
            // 请求中不含私密密钥；清理失败时由后续启动清理过期请求。
        }
    }

    private static SecurityIdentifier ValidateRequest(TrustedContactBrokerRequest request, string requestPath)
    {
        if (request.Version != RequestVersion ||
            !Guid.TryParseExact(request.RequestId, "N", out _) ||
            !IsCanonicalHex(request.RequestNonce, 64) ||
            !string.Equals(
                request.ExpectedFingerprint,
                NormalizeFingerprint(request.ExpectedFingerprint),
                StringComparison.Ordinal) ||
            !string.Equals(
                Path.GetFileName(requestPath),
                $"request-{request.RequestId}.json",
                StringComparison.Ordinal) ||
            request.CreatedAtUtc > DateTimeOffset.UtcNow.AddMinutes(1) ||
            DateTimeOffset.UtcNow - request.CreatedAtUtc > MaximumRequestAge)
        {
            throw new NingRanException("可信联系人管理员请求已经过期或不完整，请从主窗口重新开始。");
        }

        SecurityIdentifier targetSid;
        try
        {
            targetSid = new SecurityIdentifier(request.UserSid);
        }
        catch (ArgumentException exception)
        {
            throw new NingRanException("可信联系人请求中的 Windows 账户编号不正确。", exception);
        }

        if (request.Action == TrustedContactBrokerAction.Trust)
        {
            if (string.IsNullOrWhiteSpace(request.PublicIdentity) ||
                request.ContactId is not null ||
                request.LegacyPath is not null ||
                request.IsLegacyRecord)
            {
                throw new NingRanException("新增可信联系人的管理员请求不完整。");
            }
        }
        else if (request.Action == TrustedContactBrokerAction.Remove)
        {
            if (string.IsNullOrWhiteSpace(request.ContactId) ||
                request.PublicIdentity is not null ||
                (request.IsLegacyRecord && string.IsNullOrWhiteSpace(request.LegacyPath)) ||
                (!request.IsLegacyRecord && request.LegacyPath is not null))
            {
                throw new NingRanException("删除可信联系人的管理员请求不完整。");
            }
        }
        else
        {
            throw new NingRanException("不支持的可信联系人管理员操作。");
        }

        return targetSid;
    }

    private static void ValidateLaunchBinding(
        TrustedContactBrokerRequest request,
        TrustedContactBrokerLaunchBinding binding,
        string requestPath)
    {
        string bindingPath;
        try
        {
            bindingPath = Path.GetFullPath(binding.RequestPath);
        }
        catch (Exception exception) when (
            exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new NingRanException("可信联系人管理员请求路径不正确。", exception);
        }

        if (!string.Equals(bindingPath, requestPath, StringComparison.OrdinalIgnoreCase) ||
            !IsCanonicalHex(binding.RequestNonce, 64) ||
            !IsCanonicalHex(binding.RequestSha256, 64) ||
            !string.Equals(
                binding.ExpectedFingerprint,
                NormalizeFingerprint(binding.ExpectedFingerprint),
                StringComparison.Ordinal) ||
            !FixedTimeHexEquals(request.RequestNonce, binding.RequestNonce) ||
            request.Action != binding.Action ||
            !string.Equals(request.ContactId, binding.ContactId, StringComparison.Ordinal) ||
            !FixedTimeHexEquals(request.ExpectedFingerprint, binding.ExpectedFingerprint))
        {
            throw new NingRanException(
                "可信联系人管理员请求与主窗口启动时的联系人不一致，已拒绝处理。");
        }
    }

    private static void ValidateExpectedFingerprint(
        TrustedContactBrokerRequest request,
        string actualFingerprint)
    {
        var normalized = NormalizeFingerprint(actualFingerprint);
        if (!FixedTimeHexEquals(request.ExpectedFingerprint, normalized))
        {
            throw new NingRanException(
                "可信联系人身份与主窗口确认的身份不一致，可能已被替换，已拒绝处理。");
        }
    }

    private static void VerifyRequestDigest(byte[] requestBytes, string expectedDigest)
    {
        if (!IsCanonicalHex(expectedDigest, 64))
        {
            throw new NingRanException("可信联系人管理员请求的内容校验值不正确。");
        }

        var actualDigest = SHA256.HashData(requestBytes);
        byte[]? expectedDigestBytes = null;
        try
        {
            expectedDigestBytes = Convert.FromHexString(expectedDigest);
            if (expectedDigestBytes.Length != actualDigest.Length ||
                !CryptographicOperations.FixedTimeEquals(actualDigest, expectedDigestBytes))
            {
                throw new NingRanException(
                    "可信联系人管理员请求在启动确认窗口前已被替换或修改，已拒绝处理。");
            }
        }
        catch (FormatException exception)
        {
            throw new NingRanException("可信联系人管理员请求的内容校验值不正确。", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actualDigest);
            if (expectedDigestBytes is not null)
            {
                CryptographicOperations.ZeroMemory(expectedDigestBytes);
            }
        }
    }

    private static bool FixedTimeHexEquals(string? left, string? right)
    {
        if (!IsCanonicalHex(left, 64) || !IsCanonicalHex(right, 64))
        {
            return false;
        }

        byte[]? leftBytes = null;
        byte[]? rightBytes = null;
        try
        {
            leftBytes = Convert.FromHexString(left!);
            rightBytes = Convert.FromHexString(right!);
            return leftBytes.Length == 32 &&
                   rightBytes.Length == 32 &&
                   CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
        }
        catch (FormatException)
        {
            return false;
        }
        finally
        {
            if (leftBytes is not null)
            {
                CryptographicOperations.ZeroMemory(leftBytes);
            }

            if (rightBytes is not null)
            {
                CryptographicOperations.ZeroMemory(rightBytes);
            }
        }
    }

    private static bool IsCanonicalHex(string? value, int length) =>
        value is not null &&
        value.Length == length &&
        value.All(character =>
            character is >= '0' and <= '9' or >= 'A' and <= 'F');

    private static void ValidateRequestOwner(
        string path,
        FileStream lockedRequest,
        SecurityIdentifier expectedOwner)
    {
        WindowsFileSystemSafety.VerifyHandlePath(lockedRequest.SafeFileHandle, path);
        var expectedIdentity = WindowsFileSystemSafety.GetIdentity(lockedRequest.SafeFileHandle);
        var security = new FileInfo(path).GetAccessControl(AccessControlSections.Owner);
        WindowsFileSystemSafety.VerifyHandlePath(lockedRequest.SafeFileHandle, path);
        WindowsFileSystemSafety.VerifyIdentity(lockedRequest.SafeFileHandle, expectedIdentity);
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (owner is null || !owner.Equals(expectedOwner))
        {
            throw new NingRanException("管理员请求与发起请求的 Windows 账户不一致，已拒绝处理。");
        }
    }

    private static string WriteRequest(TrustedContactBrokerRequest request)
    {
        var directory = EnsureRequestDirectory();
        CleanupExpiredRequests(directory);
        var path = Path.GetFullPath(Path.Combine(directory, $"request-{request.RequestId}.json"));
        var bytes = JsonSerializer.SerializeToUtf8Bytes(request);
        Span<byte> digest = stackalloc byte[32];
        SHA256.HashData(bytes, digest);
        var binding = new TrustedContactBrokerLaunchBinding(
            path,
            request.RequestNonce,
            Convert.ToHexString(digest),
            request.Action,
            request.ContactId,
            NormalizeFingerprint(request.ExpectedFingerprint));
        var completed = false;
        try
        {
            using var file = WindowsFileSystemSafety.CreateNewTemporaryFile(path, 4 * 1024);
            file.Write(bytes);
            file.Flush(flushToDisk: true);
            if (!PendingLaunchBindings.TryAdd(path, binding))
            {
                throw new NingRanException("可信联系人管理员请求编号重复，请重新开始。");
            }

            completed = true;
            return path;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
            CryptographicOperations.ZeroMemory(digest);
            if (!completed)
            {
                DeleteRequest(path);
            }
        }
    }

    private static string CreateRequestNonce()
    {
        Span<byte> nonce = stackalloc byte[32];
        RandomNumberGenerator.Fill(nonce);
        var value = Convert.ToHexString(nonce);
        CryptographicOperations.ZeroMemory(nonce);
        return value;
    }

    private static string NormalizeFingerprint(string fingerprint)
    {
        var normalized = (fingerprint ?? string.Empty)
            .Replace("-", string.Empty, StringComparison.Ordinal)
            .ToUpperInvariant();
        if (!IsCanonicalHex(normalized, 64))
        {
            throw new NingRanException("可信联系人身份指纹格式不正确。");
        }

        return normalized;
    }

    private static string EnsureRequestDirectory()
    {
        var parent = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "NingRan");
        Directory.CreateDirectory(parent);
        var directory = GetRequestDirectory();
        var currentUser = GetCurrentUserSid();
        var localSystem = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(currentUser);
        security.AddAccessRule(new FileSystemAccessRule(
            currentUser,
            FileSystemRights.FullControl,
            inheritance,
            PropagationFlags.None,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            localSystem,
            FileSystemRights.FullControl,
            inheritance,
            PropagationFlags.None,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            administrators,
            FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize,
            inheritance,
            PropagationFlags.None,
            AccessControlType.Allow));

        var info = new DirectoryInfo(directory);
        if (!info.Exists)
        {
            info.Create(security);
        }
        else
        {
            info.Refresh();
            if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new NingRanException("可信联系人管理员请求目录不能是快捷链接或目录联接。");
            }

            info.SetAccessControl(security);
        }

        return directory;
    }

    private static void CleanupExpiredRequests(string directory)
    {
        foreach (var path in Directory.EnumerateFiles(directory, "request-*.json").Take(101))
        {
            try
            {
                if (File.GetCreationTimeUtc(path) < DateTime.UtcNow.Subtract(MaximumRequestAge))
                {
                    DeleteRequest(path);
                }
            }
            catch
            {
                // 单个异常请求不妨碍创建新请求。
            }
        }
    }

    private static string GetRequestDirectory() => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "NingRan",
        "TrustedContactBrokerRequests");

    private static SecurityIdentifier GetCurrentUserSid()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.User
            ?? throw new NingRanException("无法识别当前 Windows 账户，不能管理可信联系人。");
    }

    private static string ResolveAccountName(SecurityIdentifier sid)
    {
        try
        {
            return sid.Translate(typeof(NTAccount)).Value;
        }
        catch (IdentityNotMappedException)
        {
            return "无法解析账户名称";
        }
    }
}

internal sealed class TrustedContactBrokerRequest
{
    public int Version { get; init; }

    public required string RequestId { get; init; }

    public required string RequestNonce { get; init; }

    public required string UserSid { get; init; }

    public TrustedContactBrokerAction Action { get; init; }

    public string? PublicIdentity { get; init; }

    public string? LegacyPath { get; init; }

    public string? ContactId { get; init; }

    public required string ExpectedFingerprint { get; init; }

    public bool IsLegacyRecord { get; init; }

    public DateTimeOffset CreatedAtUtc { get; init; }
}
