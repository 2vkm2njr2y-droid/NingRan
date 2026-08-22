using System.Diagnostics;
using System.Security.Cryptography;
using NingRan.Core.Internal;

namespace NingRan.Core;

public sealed class NrArchiveService
{
    private readonly KdfParameters _kdfParameters;
    private readonly NrKeyFileService _keyFileService;
    private readonly NrIdentityService _identityService;
    private readonly NrTrustedContactService _trustedContactService;
    private readonly IPhysicalDeviceProvider _physicalDeviceProvider;
    private readonly bool _allowUnsignedArchivesForTesting;

    internal Action? BeforeVerifiedSourceDeleteForTesting { get; set; }

    public NrArchiveService(
        KdfParameters? kdfParameters = null,
        NrKeyFileService? keyFileService = null,
        NrIdentityService? identityService = null,
        NrTrustedContactService? trustedContactService = null,
        IPhysicalDeviceProvider? physicalDeviceProvider = null)
        : this(
            kdfParameters,
            keyFileService,
            identityService,
            trustedContactService,
            allowUnsignedArchivesForTesting: false,
            physicalDeviceProvider)
    {
    }

    internal NrArchiveService(
        KdfParameters? kdfParameters,
        NrKeyFileService? keyFileService,
        NrIdentityService? identityService,
        NrTrustedContactService? trustedContactService,
        bool allowUnsignedArchivesForTesting,
        IPhysicalDeviceProvider? physicalDeviceProvider = null)
    {
        _kdfParameters = kdfParameters ?? KdfParameters.Production;
        _kdfParameters.ValidateForReading();
        _keyFileService = keyFileService ?? new NrKeyFileService(_kdfParameters);
        _identityService = identityService ?? new NrIdentityService(_kdfParameters);
        _trustedContactService = trustedContactService ?? new NrTrustedContactService(_identityService);
        _physicalDeviceProvider = physicalDeviceProvider ?? new NrPhysicalDeviceService();
        _allowUnsignedArchivesForTesting = allowUnsignedArchivesForTesting;
    }

    public static TemporaryContentCleanupResult CleanupAbandonedTemporaryContent() =>
        MergeCleanupResults(
            SecureStagingArea.CleanupAbandoned(),
            TemporaryFileRegistry.CleanupAbandoned());

    public SizePaddingEstimate EstimateSizePadding(
        string sourcePath,
        SizePaddingMode sizePadding,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourcePath);
        WindowsFileSystemSafety.ThrowIfProcessIsElevated();
        using var manifest = PayloadManifest.Build(sourcePath, sizePadding, cancellationToken);
        return new SizePaddingEstimate(manifest.TotalFileBytes, manifest.PaddingLength);
    }

    public async Task<ArchiveInfo> InspectAsync(
        string archivePath,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(archivePath);
        var fullPath = Path.GetFullPath(archivePath);
        if (!File.Exists(fullPath))
        {
            throw new NingRanException("请选择存在的凝然加密文件。");
        }

        using var handle = WindowsFileSystemSafety.OpenInputFile(fullPath);
        await using var stream = new FileStream(handle, FileAccess.Read, 16 * 1024, isAsync: true);
        var info = await ArchiveEnvelope.InspectAsync(stream, cancellationToken).ConfigureAwait(false);
        var fileInfo = new FileInfo(fullPath);
        return info with
        {
            Mode = EncryptionMode.Standard,
            HidesExactSize = false,
            PhysicalDevices = [],
            FileSize = stream.Length,
            CreatedAtLocal = fileInfo.CreationTime,
        };
    }

    public async Task<EncryptionResult> EncryptAsync(
        EncryptRequest request,
        IProgress<CryptoProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        WindowsFileSystemSafety.ThrowIfProcessIsElevated();
        PasswordRules.ValidateForCreation(request.Password);
        if (!_allowUnsignedArchivesForTesting && string.IsNullOrWhiteSpace(request.SigningIdentityId))
        {
            throw new NingRanException("当前安全设置要求所有新加密文件都必须包含发送者身份证明。");
        }

        var sourcePath = Path.GetFullPath(request.SourcePath);
        var outputPath = NormalizeArchiveOutputPath(request.OutputPath);
        ValidateEncryptionPaths(sourcePath, outputPath);

        var outputDirectory = Path.GetDirectoryName(outputPath)
            ?? throw new NingRanException("加密文件保存位置不正确。");
        Directory.CreateDirectory(outputDirectory);
        using var outputDirectoryLock = WindowsFileSystemSafety.LockDirectoryPath(outputDirectory);
        if (File.Exists(outputPath) || Directory.Exists(outputPath))
        {
            throw new NingRanException("保存位置已经有同名内容，请更换名称。");
        }

        var reporter = new ProgressReporter(progress);
        reporter.Report(CryptoStage.Preparing, 0, 1, "正在检查文件与文件夹…");
        using var manifest = PayloadManifest.Build(sourcePath, request.SizePadding, cancellationToken);
        var totalWork = manifest.TotalFileBytes > 0
            ? checked(manifest.TotalFileBytes * 2)
            : 2;

        KeyFileSecret? keyFileSecret = null;
        SigningIdentity? signingIdentity = null;
        byte[]? dataKey = null;
        ArchiveHeader? archiveHeader = null;
        IReadOnlyList<PhysicalDeviceUnlock>? physicalUnlocks = null;
        PhysicalDeviceMonitor? physicalMonitor = null;
        var temporaryPath = Path.Combine(outputDirectory, $".ningran-{Guid.NewGuid():N}.part");
        Guid? temporaryRegistration = null;
        FileStream? temporaryFile = null;
        try
        {
            if (request.Mode == EncryptionMode.Advanced)
            {
                if (string.IsNullOrWhiteSpace(request.KeyFilePath))
                {
                    throw new NingRanException("高级模式必须选择一个普通文件或凝然专用密匙文件。");
                }

                reporter.Report(CryptoStage.DerivingKey, 0, totalWork, "正在读取并核验密匙文件…");
                keyFileSecret = await _keyFileService.UnlockAsync(
                    request.KeyFilePath,
                    request.Password,
                    cancellationToken).ConfigureAwait(false);
            }
            else if (request.Mode == EncryptionMode.PhysicalDevice)
            {
                if (request.PhysicalDevices.Count == 0)
                {
                    throw new NingRanException("物理设备模式必须至少选择一个已登记设备。 ");
                }
            }
            else if (request.Mode != EncryptionMode.Standard)
            {
                throw new NingRanException("不支持所选的加密模式。");
            }

            if (!string.IsNullOrWhiteSpace(request.SigningIdentityId))
            {
                if (request.SigningIdentityPassword is null || request.SigningIdentityPassword.IsEmpty)
                {
                    throw new NingRanException("请输入发送者身份密码。");
                }

                reporter.Report(CryptoStage.DerivingKey, 0, totalWork, "正在解锁发送者身份…");
                signingIdentity = await _identityService.UnlockLocalIdentityAsync(
                    request.SigningIdentityId,
                    request.SigningIdentityPassword,
                    cancellationToken).ConfigureAwait(false);
            }

            reporter.Report(CryptoStage.DerivingKey, 0, totalWork,
                request.Mode == EncryptionMode.PhysicalDevice
                    ? "正在逐一验证授权物理设备…"
                    : "正在加强密码保护…");
            if (request.Mode == EncryptionMode.PhysicalDevice)
            {
                var created = await ArchiveHeader.CreatePhysicalAsync(
                    request.Password,
                    request.PhysicalDevices,
                    _kdfParameters,
                    _physicalDeviceProvider,
                    request.OwnerWindowHandle,
                    cancellationToken).ConfigureAwait(false);
                archiveHeader = created.Header;
                dataKey = created.DataKey;
                physicalUnlocks = created.Unlocks;
                physicalMonitor = new PhysicalDeviceMonitor(physicalUnlocks, cancellationToken);
            }
            else
            {
                var created = await ArchiveHeader.CreateAsync(
                    request.Password,
                    keyFileSecret?.Memory ?? ReadOnlyMemory<byte>.Empty,
                    request.Mode,
                    request.HideExactSize,
                    _kdfParameters,
                    cancellationToken).ConfigureAwait(false);
                archiveHeader = created.Header;
                dataKey = created.DataKey;
            }

            var operationToken = physicalMonitor?.Token ?? cancellationToken;

            temporaryFile = WindowsFileSystemSafety.CreateNewTemporaryFile(temporaryPath);
            temporaryRegistration = TemporaryFileRegistry.Register(temporaryFile, temporaryPath);
            await temporaryFile.WriteAsync(archiveHeader.Bytes, operationToken).ConfigureAwait(false);
            using (var encryptedStream = new ChunkedAeadWriteStream(
                temporaryFile,
                dataKey,
                archiveHeader.PayloadNoncePrefix,
                archiveHeader.HeaderHash,
                leaveOpen: true))
            {
                await PayloadContainer.WriteAsync(
                    encryptedStream,
                    manifest,
                    signingIdentity,
                    (completed, message) => reporter.Report(
                        CryptoStage.Encrypting,
                        completed,
                        totalWork,
                        message),
                    operationToken).ConfigureAwait(false);
                await encryptedStream.CompleteAsync(operationToken).ConfigureAwait(false);
            }

            await temporaryFile.FlushAsync(operationToken).ConfigureAwait(false);
            temporaryFile.Flush(flushToDisk: true);

            reporter.Report(
                CryptoStage.Verifying,
                manifest.TotalFileBytes,
                totalWork,
                "正在验证刚生成的加密文件…");
            temporaryFile.Position = archiveHeader.Bytes.Length;
            using (var verificationStream = new ChunkedAeadReadStream(
                       temporaryFile,
                       dataKey,
                       archiveHeader.PayloadNoncePrefix,
                       archiveHeader.HeaderHash,
                       leaveOpen: true))
            using (var verifiedPayload = await PayloadContainer.ReadAsync(
                       verificationStream,
                       stagingDirectory: null,
                       (completed, _) => reporter.Report(
                           CryptoStage.Verifying,
                           manifest.TotalFileBytes + completed,
                           totalWork,
                           "正在验证加密内容…"),
                       operationToken).ConfigureAwait(false))
            {
                VerifyCreatedPayloadIdentity(verifiedPayload, signingIdentity);
            }

            if (dataKey is not null)
            {
                CryptographicOperations.ZeroMemory(dataKey);
                dataKey = null;
            }

            operationToken.ThrowIfCancellationRequested();
            reporter.Report(CryptoStage.Finalizing, totalWork, totalWork, "正在完成保存…");
            var finalTemporaryFile = temporaryFile;
            finalTemporaryFile.Position = 0;
            var archiveHash = await SHA256.HashDataAsync(finalTemporaryFile, operationToken)
                .ConfigureAwait(false);
            if (physicalUnlocks is not null)
            {
                reporter.Report(CryptoStage.Finalizing, totalWork, totalWork, "正在最终确认授权物理设备…");
                foreach (var unlock in physicalUnlocks)
                {
                    await unlock.RevalidateAsync(operationToken).ConfigureAwait(false);
                }
            }

            var archiveSize = finalTemporaryFile.Length;
            var archiveIdentity = WindowsFileSystemSafety.GetIdentity(finalTemporaryFile.SafeFileHandle);
            var sourceSnapshot = manifest.Entries.Select(entry => new SourceEntrySnapshot(
                entry.Kind,
                entry.FullPath,
                entry.RelativePath,
                entry.Length,
                entry.LastWriteUtcTicks,
                entry.Identity)).ToArray();
            var sourceParentPath = Path.GetDirectoryName(sourcePath);
            WindowsFileIdentity? sourceParentIdentity = null;
            if (!string.IsNullOrWhiteSpace(sourceParentPath))
            {
                using var sourceParentHandle = WindowsFileSystemSafety.OpenStableDirectory(sourceParentPath);
                sourceParentIdentity = WindowsFileSystemSafety.GetIdentity(sourceParentHandle);
            }

            WindowsFileSystemSafety.RenameOpenFile(
                temporaryFile.SafeFileHandle,
                temporaryPath,
                outputPath);
            TemporaryFileRegistry.Unregister(temporaryRegistration);
            temporaryFile.Dispose();
            temporaryFile = null;

            reporter.Report(CryptoStage.Finalizing, totalWork, totalWork, "加密完成并通过验证。");
            return new EncryptionResult(
                outputPath,
                archiveSize,
                sourceSnapshot,
                sourceParentPath,
                sourceParentIdentity,
                archiveIdentity,
                archiveHash);
        }
        catch (Exception exception)
        {
            var firstCleaned = TryDeleteTemporaryFile(ref temporaryFile, temporaryPath);
            if (firstCleaned)
            {
                TemporaryFileRegistry.Unregister(temporaryRegistration);
            }

            if (!firstCleaned)
            {
                throw new NingRanException(
                    "加密没有完成，并且部分临时文件未能自动删除。请关闭程序后重新打开以继续清理。",
                    exception);
            }

            physicalMonitor?.ThrowIfDeviceLost();
            if (exception is OperationCanceledException or NingRanException)
            {
                throw;
            }

            throw new NingRanException("加密过程中发生错误，未完成文件已经清理。", exception);
        }
        finally
        {
            if (physicalMonitor is not null)
            {
                await physicalMonitor.DisposeAsync().ConfigureAwait(false);
            }

            if (physicalUnlocks is not null)
            {
                foreach (var unlock in physicalUnlocks)
                {
                    unlock.Dispose();
                }
            }

            temporaryFile?.Dispose();
            keyFileSecret?.Dispose();
            signingIdentity?.Dispose();
            if (dataKey is not null)
            {
                CryptographicOperations.ZeroMemory(dataKey);
            }
        }
    }

    public async Task<DecryptionResult> DecryptAsync(
        DecryptRequest request,
        IProgress<CryptoProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        WindowsFileSystemSafety.ThrowIfProcessIsElevated();
        if (request.Password.IsEmpty)
        {
            throw new NingRanException("请输入密码。");
        }

        var archivePath = Path.GetFullPath(request.ArchivePath);
        if (!File.Exists(archivePath))
        {
            throw new NingRanException("请选择存在的凝然加密文件。");
        }

        var destinationDirectory = Path.GetFullPath(request.DestinationDirectory);
        var reporter = new ProgressReporter(progress);
        KeyFileSecret? keyFileSecret = null;
        PhysicalDeviceUnlock? physicalUnlock = null;
        PhysicalDeviceMonitor? physicalMonitor = null;
        byte[]? dataKey = null;
        StableDirectoryPath? destinationLock = null;
        SecureStagingArea? stagingArea = null;
        try
        {
            Directory.CreateDirectory(destinationDirectory);
            destinationLock = WindowsFileSystemSafety.LockDirectoryPath(destinationDirectory);
            using var archiveHandle = WindowsFileSystemSafety.OpenInputFile(archivePath);
            await using var archiveStream = new FileStream(
                archiveHandle,
                FileAccess.Read,
                1024 * 1024,
                isAsync: true);
            await ArchiveEnvelope.InspectAsync(archiveStream, cancellationToken).ConfigureAwait(false);
            var archiveLength = Math.Max(archiveStream.Length, 1);
            string? verifiedSenderName = null;
            PayloadReadResult? decryptedPayload = null;

            try
            {
                archiveStream.Position = 0;
                if (!string.IsNullOrWhiteSpace(request.KeyFilePath))
                {
                    reporter.Report(CryptoStage.DerivingKey, 0, archiveLength, "正在读取并核验密匙文件…");
                    keyFileSecret = await _keyFileService.UnlockAsync(
                        request.KeyFilePath,
                        request.Password,
                        cancellationToken).ConfigureAwait(false);
                }

                reporter.Report(CryptoStage.DerivingKey, 0, archiveLength, "正在验证密码和加密文件…");
                var unlocked = await ArchiveHeader.ReadAndUnlockAsync(
                    archiveStream,
                    request.Password,
                    keyFileSecret?.Memory ?? ReadOnlyMemory<byte>.Empty,
                    _physicalDeviceProvider,
                    request.OwnerWindowHandle,
                    cancellationToken).ConfigureAwait(false);
                dataKey = unlocked.DataKey;
                physicalUnlock = unlocked.PhysicalUnlock;
                if (physicalUnlock is not null)
                {
                    physicalMonitor = new PhysicalDeviceMonitor([physicalUnlock], cancellationToken);
                }

                var operationToken = physicalMonitor?.Token ?? cancellationToken;
                var payloadOffset = archiveStream.Position;

                reporter.Report(CryptoStage.Verifying, 0, archiveLength, "正在验证内容结构和发送者身份…");
                using (var validationStream = new ChunkedAeadReadStream(
                           archiveStream,
                           dataKey,
                           unlocked.Header.PayloadNoncePrefix,
                           unlocked.Header.HeaderHash,
                           leaveOpen: true))
                using (var validationPayload = await PayloadContainer.ReadAsync(
                           validationStream,
                           stagingDirectory: null,
                           (completed, _) => reporter.Report(
                               CryptoStage.Verifying,
                               Math.Min(completed, archiveLength),
                               archiveLength,
                               "正在验证加密内容，不创建文件…"),
                           operationToken).ConfigureAwait(false))
                {
                    verifiedSenderName = VerifyDecryptedPayloadIdentity(
                        validationPayload,
                        request.TrustedSenderId);
                }

                if (physicalUnlock is not null)
                {
                    await physicalUnlock.RevalidateAsync(operationToken).ConfigureAwait(false);
                    physicalMonitor!.ThrowIfDeviceLost();
                }

                operationToken.ThrowIfCancellationRequested();
                archiveStream.Position = payloadOffset;
                stagingArea = SecureStagingArea.Create(destinationDirectory);
                using (var restorationStream = new ChunkedAeadReadStream(
                           archiveStream,
                           dataKey,
                           unlocked.Header.PayloadNoncePrefix,
                           unlocked.Header.HeaderHash,
                           leaveOpen: true))
                {
                    decryptedPayload = await PayloadContainer.ReadAsync(
                        restorationStream,
                        stagingArea.PayloadDirectory,
                        (completed, message) => reporter.Report(
                            CryptoStage.Decrypting,
                            Math.Min(completed, archiveLength),
                            archiveLength,
                            message),
                        operationToken).ConfigureAwait(false);
                }

                var secondVerifiedSender = VerifyDecryptedPayloadIdentity(
                    decryptedPayload,
                    request.TrustedSenderId);
                if (!string.Equals(verifiedSenderName, secondVerifiedSender, StringComparison.Ordinal))
                {
                    throw new NingRanException("加密文件在两次验证之间发生了变化，已停止还原。");
                }

                var rootName = decryptedPayload.RootName;
                var isDirectory = decryptedPayload.IsDirectory;
                if (physicalUnlock is not null)
                {
                    await physicalUnlock.RevalidateAsync(operationToken).ConfigureAwait(false);
                    physicalMonitor!.ThrowIfDeviceLost();
                }

                operationToken.ThrowIfCancellationRequested();
                var stagedRoot = PathSafety.GetSafeDestination(stagingArea.PayloadDirectory, rootName);
                if (isDirectory ? !Directory.Exists(stagedRoot) : !File.Exists(stagedRoot))
                {
                    throw new NingRanException("还原后的内容不完整，未找到根文件或根文件夹。");
                }

                var finalPath = PathSafety.GetUniquePath(Path.Combine(destinationDirectory, rootName));
                reporter.Report(CryptoStage.Finalizing, archiveLength, archiveLength, "正在完成还原…");
                if (isDirectory)
                {
                    Directory.Move(stagedRoot, finalPath);
                }
                else
                {
                    File.Move(stagedRoot, finalPath);
                }

                stagingArea.MarkPayloadMoved();
                stagingArea.TryCleanup(out _);
                reporter.Report(CryptoStage.Finalizing, archiveLength, archiveLength, "解密完成并通过验证。");
                return new DecryptionResult(
                    finalPath,
                    isDirectory,
                    verifiedSenderName);
            }
            finally
            {
                decryptedPayload?.Dispose();
            }
        }
        catch (Exception exception)
        {
            if (stagingArea is not null && !stagingArea.TryCleanup(out var cleanupError))
            {
                throw new NingRanException(
                    "解密没有完成，而且临时明文未能自动删除。请关闭程序并重新打开，让程序再次尝试安全清理。",
                    new AggregateException(exception, cleanupError!));
            }

            physicalMonitor?.ThrowIfDeviceLost();
            if (exception is OperationCanceledException or NingRanException)
            {
                throw;
            }

            throw new NingRanException("解密过程中发生错误，未完成内容已经清理。", exception);
        }
        finally
        {
            if (physicalMonitor is not null)
            {
                await physicalMonitor.DisposeAsync().ConfigureAwait(false);
            }

            physicalUnlock?.Dispose();
            if (dataKey is not null)
            {
                CryptographicOperations.ZeroMemory(dataKey);
            }

            keyFileSecret?.Dispose();
            destinationLock?.Dispose();
        }
    }

    public async Task PermanentlyDeleteVerifiedSourceAsync(
        EncryptionResult result,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(result);
        WindowsFileSystemSafety.ThrowIfProcessIsElevated();
        if (result.SourceSnapshot.Count == 0)
        {
            throw new NingRanException("缺少原内容的安全记录，不能永久删除原内容。");
        }

        if (string.IsNullOrWhiteSpace(result.SourceParentPath) || result.SourceParentIdentity is null)
        {
            throw new NingRanException("不能自动删除磁盘或共享位置的根目录，请手动处理原内容。");
        }

        using var archiveHandle = WindowsFileSystemSafety.OpenExclusiveInputFile(result.ArchivePath);
        WindowsFileSystemSafety.VerifyIdentity(archiveHandle, result.ArchiveIdentity);
        await using var archiveStream = new FileStream(
            archiveHandle,
            FileAccess.Read,
            1024 * 1024,
            isAsync: true);
        var currentHash = await SHA256.HashDataAsync(archiveStream, cancellationToken)
            .ConfigureAwait(false);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(currentHash, result.ArchiveHash))
            {
                throw new NingRanException(
                    "正式加密文件在完成后发生了变化，为避免丢失原内容，已取消永久删除。");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(currentHash);
        }

        using var sourceParentHandle = WindowsFileSystemSafety.OpenStableDirectory(result.SourceParentPath);
        WindowsFileSystemSafety.VerifyIdentity(sourceParentHandle, result.SourceParentIdentity.Value);

        var sourcePath = result.SourcePath;
        using var currentManifest = PayloadManifest.Build(
            sourcePath,
            SizePaddingMode.None,
            cancellationToken);
        VerifySourceManifest(result, currentManifest);
        cancellationToken.ThrowIfCancellationRequested();

        for (var index = currentManifest.Entries.Count - 1; index >= 0; index--)
        {
            var current = currentManifest.Entries[index];
            var original = result.SourceSnapshot[index];
            current.SourceHandle.Dispose();
            if (index == 0)
            {
                BeforeVerifiedSourceDeleteForTesting?.Invoke();
            }

            if (original.Kind == PayloadEntryKind.File)
            {
                WindowsFileSystemSafety.DeleteFileWithoutFollowingLinks(
                    original.FullPath,
                    original.Identity);
            }
            else if (original.Kind == PayloadEntryKind.Directory)
            {
                WindowsFileSystemSafety.DeleteEmptyDirectoryWithoutFollowingLinks(
                    original.FullPath,
                    original.Identity);
            }
            else
            {
                throw new NingRanException("原内容包含不支持的类型，已停止永久删除。");
            }
        }
    }

    private static void VerifySourceManifest(EncryptionResult result, PayloadManifest currentManifest)
    {
        if (currentManifest.Entries.Count != result.SourceSnapshot.Count)
        {
            throw new NingRanException(
                "原内容在加密完成后发生了变化，为避免删错内容，已取消永久删除。");
        }

        for (var index = 0; index < currentManifest.Entries.Count; index++)
        {
            var current = currentManifest.Entries[index];
            var original = result.SourceSnapshot[index];
            if (current.Kind != original.Kind ||
                current.Length != original.Length ||
                current.LastWriteUtcTicks != original.LastWriteUtcTicks ||
                current.Identity != original.Identity ||
                !string.Equals(current.RelativePath, original.RelativePath, StringComparison.OrdinalIgnoreCase))
            {
                throw new NingRanException(
                    "原内容在加密完成后发生了变化，为避免删错内容，已取消永久删除。");
            }
        }
    }

    private static void VerifyCreatedPayloadIdentity(
        PayloadReadResult payload,
        SigningIdentity? signingIdentity)
    {
        if (signingIdentity is null)
        {
            if (payload.HasSenderSignature)
            {
                throw new NingRanException("加密内容包含了意外的发送者身份证明。");
            }

            return;
        }

        using var publicIdentity = signingIdentity.CreatePublicIdentity();
        if (!payload.HasSenderSignature ||
            !string.Equals(payload.SignerFingerprint, publicIdentity.Fingerprint, StringComparison.Ordinal) ||
            !publicIdentity.Key.VerifyHash(
                payload.AuthenticatedHash,
                payload.Signature!,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
        {
            throw new NingRanException("发送者身份证明生成后未能通过复验。");
        }
    }

    private string? VerifyDecryptedPayloadIdentity(PayloadReadResult payload, string? trustedSenderId)
    {
        if (!payload.HasSenderSignature)
        {
            if (_allowUnsignedArchivesForTesting)
            {
                return null;
            }

            throw new NingRanException("此文件没有发送者身份证明，当前安全设置禁止还原未签名文件。");
        }

        IReadOnlyList<TrustedContactSummary> candidates;
        if (string.IsNullOrWhiteSpace(trustedSenderId))
        {
            candidates = _trustedContactService.ListTrustedContacts();
        }
        else
        {
            var selected = _trustedContactService.FindTrustedContact(trustedSenderId)
                ?? throw new NingRanException("所选发送者尚未加入本机可信联系人。");
            candidates = [selected];
        }

        foreach (var contact in candidates)
        {
            using var identity = _trustedContactService.ReadTrustedIdentity(contact.Id);
            if (!string.Equals(payload.SignerFingerprint, identity.Fingerprint, StringComparison.Ordinal) ||
                !identity.Key.VerifyHash(
                    payload.AuthenticatedHash,
                    payload.Signature!,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            {
                continue;
            }

            return contact.Name;
        }

        throw new NingRanException(
            "发送者尚未加入本机可信联系人，或者加密文件已经被修改。请先导入公开身份并输入正确的安全码。");
    }

    private static string NormalizeArchiveOutputPath(string outputPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(outputPath);
        var fullPath = Path.GetFullPath(outputPath);
        return string.Equals(Path.GetExtension(fullPath), ".nrenc", StringComparison.OrdinalIgnoreCase)
            ? fullPath
            : fullPath + ".nrenc";
    }

    private static void ValidateEncryptionPaths(string sourcePath, string outputPath)
    {
        if (!File.Exists(sourcePath) && !Directory.Exists(sourcePath))
        {
            throw new NingRanException("请选择存在的文件或文件夹。");
        }

        if (string.Equals(sourcePath, outputPath, StringComparison.OrdinalIgnoreCase))
        {
            throw new NingRanException("加密文件不能覆盖原文件。");
        }

        if (Directory.Exists(sourcePath) && PathSafety.IsWithinDirectory(outputPath, sourcePath))
        {
            throw new NingRanException("加密文件不能保存在正在加密的文件夹里面。");
        }
    }

    private static bool TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }

            return !File.Exists(path);
        }
        catch
        {
            return false;
        }
    }

    private static bool TryDeleteTemporaryFile(ref FileStream? stream, string path)
    {
        if (stream is not null)
        {
            try
            {
                WindowsFileSystemSafety.DeleteOpenFile(stream.SafeFileHandle, path);
                stream.Dispose();
                stream = null;
                return !File.Exists(path);
            }
            catch
            {
                stream?.Dispose();
                stream = null;
            }
        }

        return TryDeleteFile(path);
    }

    private static TemporaryContentCleanupResult MergeCleanupResults(
        TemporaryContentCleanupResult first,
        TemporaryContentCleanupResult second) =>
        new(
            first.RemovedDirectoryCount + second.RemovedDirectoryCount,
            first.Failures.Concat(second.Failures).ToArray());

    private sealed class ProgressReporter
    {
        private readonly IProgress<CryptoProgress>? _progress;
        private readonly Stopwatch _stopwatch = Stopwatch.StartNew();

        public ProgressReporter(IProgress<CryptoProgress>? progress)
        {
            _progress = progress;
        }

        public void Report(CryptoStage stage, long completed, long total, string message)
        {
            TimeSpan? remaining = null;
            if (completed > 0 && total > completed && _stopwatch.Elapsed.TotalSeconds > 0.2)
            {
                var seconds = _stopwatch.Elapsed.TotalSeconds * (total - completed) / completed;
                if (double.IsFinite(seconds) && seconds >= 0)
                {
                    remaining = TimeSpan.FromSeconds(Math.Min(seconds, TimeSpan.MaxValue.TotalSeconds));
                }
            }

            _progress?.Report(new CryptoProgress(stage, completed, total, message, remaining));
        }
    }
}
