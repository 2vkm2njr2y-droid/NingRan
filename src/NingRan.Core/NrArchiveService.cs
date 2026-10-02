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
            MergeCleanupResults(
                TemporaryFileRegistry.CleanupAbandoned(),
                IncrementalArchiveRecovery.RecoverAbandoned()));

    public static bool IsSupportedArchiveFile(string path)
    {
        try
        {
            var fullPath = Path.GetFullPath(path);
            if (!File.Exists(fullPath))
            {
                return false;
            }

            if (NrSplitArchiveService.IsSupportedPartFile(fullPath))
            {
                return true;
            }

            if (string.Equals(Path.GetExtension(fullPath), ".nrenc", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return JpegArchiveContainer.IsEncryptedPhoto(fullPath);
        }
        catch (Exception exception) when (exception is ArgumentException or IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>
    /// 返回指定保存位置能否生成普通照片外观的加密文件。
    /// 该格式依赖 NTFS 的隐藏数据流；其他文件系统一律使用可移动的 .nrenc。
    /// </summary>
    public static bool SupportsPhotoArchiveOutput(string directory)
    {
        try
        {
            var fullDirectory = Path.GetFullPath(directory);
            return JpegArchiveContainer.IsPhotoArchivePath(
                Path.Combine(fullDirectory, ".ningran-photo-output.jpg"));
        }
        catch (Exception exception) when (exception is ArgumentException or IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

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

        if (NrSplitArchiveService.IsSupportedPartFile(fullPath))
        {
            await using var splitStream = NrSplitArchiveService.OpenReadStream(fullPath);
            var splitInfo = await ArchiveEnvelope.InspectAsync(splitStream, cancellationToken, 0)
                .ConfigureAwait(false);
            var splitFileInfo = new FileInfo(fullPath);
            return splitInfo with
            {
                Mode = EncryptionMode.Standard,
                HidesExactSize = false,
                PhysicalDevices = [],
                FormatVersion = "split-1",
                FileSize = splitStream.Length,
                CreatedAtLocal = splitFileInfo.CreationTime,
            };
        }

        var isPhotoArchive = JpegArchiveContainer.IsEncryptedPhoto(fullPath);
        await using var stream = JpegArchiveContainer.OpenArchiveReadStream(fullPath, exclusive: false);
        var region = JpegArchiveContainer.GetArchiveRegion(stream, isPhotoArchive);
        var info = await ArchiveEnvelope.InspectAsync(stream, cancellationToken, region.Offset).ConfigureAwait(false);
        var fileInfo = new FileInfo(fullPath);
        return info with
        {
            Mode = EncryptionMode.Standard,
            HidesExactSize = false,
            PhysicalDevices = [],
            FormatVersion = isPhotoArchive ? "7.0" : "6.1",
            FileSize = JpegArchiveContainer.GetStorageSize(fullPath),
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

        using var linkedSourceCancellation = request.SourceVault is { } sourceVault &&
                                             sourceVault.CancellationToken.CanBeCanceled
            ? CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, sourceVault.CancellationToken)
            : null;
        if (linkedSourceCancellation is not null)
        {
            cancellationToken = linkedSourceCancellation.Token;
        }
        using var sourceLease = request.SourceVault is null
            ? null
            : await request.SourceVault.AcquireExportLockAsync(cancellationToken).ConfigureAwait(false);

        var sourcePaths = request.IsVaultExport
            ? []
            : request.SourcePaths.Select(Path.GetFullPath).ToArray();
        var sourcePath = Path.GetFullPath(request.SourcePath);
        var isSplitArchive = request.SplitPartSizeBytes is not null;
        if (isSplitArchive && request.SplitPartSizeBytes is < NrSplitArchiveService.MinimumPartSize or > NrSplitArchiveService.MaximumPartSize)
        {
            throw new NingRanException("分片大小必须在 100 MB 到 64 GB 之间。");
        }
        var hasCoverImage = !string.IsNullOrWhiteSpace(request.CoverImagePath);
        var outputPath = isSplitArchive
            ? Path.ChangeExtension(Path.GetFullPath(request.OutputPath), NrSplitArchiveService.Extension)
            : JpegArchiveContainer.NormalizeOutputPath(request.OutputPath, hasCoverImage);
        if (isSplitArchive)
        {
            NrSplitArchiveService.EnsureOutputAvailable(outputPath);
        }
        var isPhotoArchive = !isSplitArchive && hasCoverImage && JpegArchiveContainer.IsPhotoArchivePath(outputPath);
        if (request.IsVaultExport && isPhotoArchive)
        {
            throw new NingRanException("保险箱只能导出为 .nrenc 加密包，不能使用照片外观。");
        }
        if (request.IsDelivery && isPhotoArchive)
        {
            throw new NingRanException("安全交付包必须保存为 .nrenc 文件，不能使用照片外观。");
        }
        foreach (var selectedSource in sourcePaths)
        {
            ValidateEncryptionPaths(selectedSource, outputPath);
        }

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
        request.DeliveryInfo?.ValidateForReading();
        using var manifest = request.SourceVault is { } vault
            ? PayloadManifest.BuildVault(vault, request.SizePadding, cancellationToken)
            : request.IsDelivery
            ? PayloadManifest.BuildMany(
                sourcePaths,
                CreateDeliveryRootName(request.DeliveryInfo!.Name),
                request.SizePadding,
                cancellationToken,
                request.Compression == ArchiveCompressionLevel.SmallestLossy)
            : PayloadManifest.Build(sourcePath, request.SizePadding, cancellationToken,
                request.Compression == ArchiveCompressionLevel.SmallestLossy);
        var totalWork = manifest.TotalFileBytes > 0
            ? checked(manifest.TotalFileBytes * 3)
            : 3;
        var verificationStart = manifest.TotalFileBytes > 0
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
        SplitArchivePartWriter? splitWriter = null;
        IReadOnlyList<string>? createdSplitPaths = null;
        var outputCreated = false;
        ArchiveSizeReport? sizeReport = null;
        try
        {
            if (request.Mode == EncryptionMode.Flexible)
            {
                request.ProtectionPolicy?.ValidateForCreation();
                if (request.ProtectionPolicy is null)
                    throw new NingRanException("新组合保护格式缺少解锁规则。 ");
                if (request.ProtectionPolicy.Requires(ProtectionFactor.KeyFile) &&
                    !string.IsNullOrWhiteSpace(request.KeyFilePath))
                {
                    reporter.Report(CryptoStage.DerivingKey, 0, totalWork, "正在读取并核验密匙文件…");
                    keyFileSecret = await _keyFileService.UnlockAsync(
                        request.KeyFilePath, request.Password, cancellationToken).ConfigureAwait(false);
                }
            }
            else if (request.Mode == EncryptionMode.Advanced)
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

            if (string.IsNullOrWhiteSpace(request.SigningIdentityId) ||
                request.SigningIdentityPassword is null || request.SigningIdentityPassword.IsEmpty)
            {
                if (!_allowUnsignedArchivesForTesting)
                {
                    throw new NingRanException("请输入发送者身份密码。");
                }

                signingIdentity = CreateEphemeralTestingIdentity();
            }

            if (request.Mode == EncryptionMode.Flexible)
            {
                if (signingIdentity is null)
                {
                    reporter.Report(CryptoStage.DerivingKey, 0, totalWork, "正在解锁发送者身份…");
                    signingIdentity = await _identityService.UnlockLocalIdentityAsync(
                        request.SigningIdentityId!, request.SigningIdentityPassword!, cancellationToken).ConfigureAwait(false);
                }
                reporter.Report(CryptoStage.DerivingKey, 0, totalWork, "正在验证组合解锁条件…");
                var flexible = await FlexibleArchiveHeader.CreateAsync(
                    request.Password,
                    keyFileSecret?.Memory ?? ReadOnlyMemory<byte>.Empty,
                    request.ProtectionPolicy!,
                    _kdfParameters,
                    _physicalDeviceProvider,
                    request.OwnerWindowHandle,
                    cancellationToken).ConfigureAwait(false);
                archiveHeader = flexible.Header;
                dataKey = flexible.DataKey;
                physicalUnlocks = flexible.Unlocks;
                physicalMonitor = physicalUnlocks.Count > 0
                    ? new PhysicalDeviceMonitor(
                        physicalUnlocks,
                        cancellationToken,
                        _physicalDeviceProvider is IPhysicalDevicePresence presence && flexible.Header.ForbiddenPhysicalLookupHashes.Count > 0
                            ? () => presence.IsAnyForbiddenStorageConnected(
                                flexible.Header.Bytes.AsMemory(24, 16), flexible.Header.ForbiddenPhysicalLookupHashes)
                            : null)
                    : null;
            }
            else if (request.Mode == EncryptionMode.PhysicalDevice)
            {
                if (signingIdentity is null)
                {
                    reporter.Report(CryptoStage.DerivingKey, 0, totalWork, "正在解锁发送者身份…");
                    signingIdentity = await _identityService.UnlockLocalIdentityAsync(
                        request.SigningIdentityId!,
                        request.SigningIdentityPassword!,
                        cancellationToken).ConfigureAwait(false);
                }
                reporter.Report(CryptoStage.DerivingKey, 0, totalWork, "正在逐一验证授权物理设备…");
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
            else if (signingIdentity is not null)
            {
                reporter.Report(CryptoStage.DerivingKey, 0, totalWork, "正在加强密码…");
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
            else
            {
                reporter.Report(CryptoStage.DerivingKey, 0, totalWork, "正在同时加强密码并解锁发送者身份…");
                var created = await UnlockIdentityAndCreateArchiveAsync(
                    request.SigningIdentityId!,
                    request.SigningIdentityPassword!,
                    request.Password,
                    keyFileSecret?.Memory ?? ReadOnlyMemory<byte>.Empty,
                    request.Mode,
                    request.HideExactSize,
                    _kdfParameters,
                    cancellationToken).ConfigureAwait(false);
                signingIdentity = created.Identity;
                archiveHeader = created.Header;
                dataKey = created.DataKey;
            }

            var operationToken = physicalMonitor?.Token ?? cancellationToken;

            const long archiveOffset = 0;
            Stream encryptionOutput;
            if (isSplitArchive)
            {
                splitWriter = NrSplitArchiveService.CreateWriter(outputPath, request.SplitPartSizeBytes!.Value);
                await splitWriter.WriteAsync(archiveHeader.Bytes, operationToken).ConfigureAwait(false);
                // 分片模式直接写入分片暂存文件，不再在同一磁盘上额外保留一份完整临时包。
                encryptionOutput = new SplitTeeWriteStream(splitWriter);
            }
            else
            {
                temporaryFile = WindowsFileSystemSafety.CreateNewTemporaryFile(temporaryPath);
                temporaryRegistration = TemporaryFileRegistry.Register(temporaryFile, temporaryPath);
                await temporaryFile.WriteAsync(archiveHeader.Bytes, operationToken).ConfigureAwait(false);
                encryptionOutput = temporaryFile;
            }
            var indexedPayload = await IndexedPayloadContainer.WriteAsync(
                encryptionOutput,
                manifest,
                archiveHeader,
                dataKey,
                signingIdentity ?? throw new NingRanException("缺少发送者身份，无法创建加密文件。"),
                request.Compression,
                request.DeliveryInfo,
                (stage, completed, message) => reporter.Report(
                    CryptoStage.Encrypting,
                    Math.Min(totalWork, stage == IndexedPayloadContainer.WriteStage.Planning
                        ? completed
                        : manifest.TotalFileBytes + completed),
                    totalWork,
                    message),
                operationToken).ConfigureAwait(false);

            if (temporaryFile is not null)
            {
                await temporaryFile.FlushAsync(operationToken).ConfigureAwait(false);
                temporaryFile.Flush(flushToDisk: true);
            }
            if (splitWriter is not null)
            {
                var splitFlush = splitWriter;
                await splitFlush.FlushAsync(operationToken).ConfigureAwait(false);
            }
            Stream? verificationInput = temporaryFile;
            if (splitWriter is not null)
            {
                // 先封存分片头，再通过分片读取流完成与单文件相同的结构和内容复验。
                createdSplitPaths = await splitWriter.CompleteAsync(operationToken).ConfigureAwait(false);
                splitWriter = null;
                verificationInput = NrSplitArchiveService.OpenReadStream(createdSplitPaths[0]);
            }

            var archiveLength = verificationInput?.Length
                ?? throw new NingRanException("未能打开刚生成的加密文件。");
            sizeReport = IndexedPayloadContainer.CreateSizeReport(indexedPayload, archiveLength);

            reporter.Report(
                CryptoStage.Verifying,
                verificationStart,
                totalWork,
                "正在验证刚生成的加密文件…");
            IndexedPayloadContainer.IndexedPayload? reopenedPayload = null;
            try
            {
                reopenedPayload = await IndexedPayloadContainer.OpenAsync(
                    verificationInput,
                    archiveHeader,
                    dataKey,
                    operationToken,
                    archiveOffset,
                    archiveLength).ConfigureAwait(false);
                await IndexedPayloadContainer.ValidateAllAsync(
                    verificationInput,
                    archiveHeader,
                    dataKey,
                    reopenedPayload,
                    (completed, _) => reporter.Report(
                        CryptoStage.Verifying,
                        Math.Min(totalWork, verificationStart + completed * IndexedPayloadContainer.BlockSize),
                        totalWork,
                        "正在验证加密内容…"),
                    operationToken,
                    archiveOffset).ConfigureAwait(false);
                VerifyCreatedIndexedPayloadIdentity(reopenedPayload, signingIdentity);
                if (!Equals(reopenedPayload.DeliveryInfo, request.DeliveryInfo))
                {
                    throw new NingRanException("生成后的安全交付规则复验失败，未完成文件不会被保留。");
                }
            }
            finally
            {
                reopenedPayload?.Dispose();
                indexedPayload.Dispose();
                if (!ReferenceEquals(verificationInput, temporaryFile))
                {
                    verificationInput?.Dispose();
                }
            }

            if (dataKey is not null)
            {
                CryptographicOperations.ZeroMemory(dataKey);
                dataKey = null;
            }

            operationToken.ThrowIfCancellationRequested();
            reporter.Report(CryptoStage.Finalizing, totalWork, totalWork, "正在完成保存…");
            if (splitWriter is not null)
            {
                createdSplitPaths = await splitWriter.CompleteAsync(operationToken).ConfigureAwait(false);
                splitWriter = null;
            }
            var archiveHash = Array.Empty<byte>();
            if (!request.IsVaultExport)
            {
                if (createdSplitPaths is not null)
                {
                    await using var splitHashInput = NrSplitArchiveService.OpenReadStream(createdSplitPaths[0]);
                    archiveHash = await SHA256.HashDataAsync(splitHashInput, operationToken)
                        .ConfigureAwait(false);
                }
                else
                {
                    temporaryFile!.Position = 0;
                    archiveHash = await SHA256.HashDataAsync(temporaryFile, operationToken)
                        .ConfigureAwait(false);
                }
            }
            if (physicalUnlocks is not null)
            {
                reporter.Report(CryptoStage.Finalizing, totalWork, totalWork, "正在最终确认授权物理设备…");
                foreach (var unlock in physicalUnlocks)
                {
                    await unlock.RevalidateAsync(operationToken).ConfigureAwait(false);
                }
            }

            var archiveSize = archiveLength;
            var sourceSnapshot = manifest.Entries.Where(entry => !string.IsNullOrWhiteSpace(entry.FullPath)).Select(entry => new SourceEntrySnapshot(
                entry.Kind,
                entry.FullPath,
                entry.RelativePath,
                entry.Length,
                entry.LastWriteUtcTicks,
                entry.Identity)).ToArray();
            var sourceParentPath = request.IsDelivery || request.IsVaultExport
                ? null
                : Path.GetDirectoryName(sourcePath);
            WindowsFileIdentity? sourceParentIdentity = null;
            if (!string.IsNullOrWhiteSpace(sourceParentPath))
            {
                using var sourceParentHandle = WindowsFileSystemSafety.OpenStableDirectory(sourceParentPath);
                sourceParentIdentity = WindowsFileSystemSafety.GetIdentity(sourceParentHandle);
            }

            WindowsFileIdentity archiveIdentity;
            var resultArchivePath = outputPath;
            if (isPhotoArchive)
            {
                // The temporary archive uses an exclusive write handle. Close it only after
                // verification and hashing so the finished bytes can be copied into the ADS.
                temporaryFile!.Dispose();
                temporaryFile = null;
                await JpegArchiveContainer.CopyCoverToNewFileAsync(
                    request.CoverImagePath!, outputPath, operationToken).ConfigureAwait(false);
                outputCreated = true;
                await JpegArchiveContainer.CopyArchiveToAlternateDataStreamAsync(
                    temporaryPath, outputPath, operationToken).ConfigureAwait(false);
                if (archiveHash.Length > 0)
                {
                    var copiedHash = await JpegArchiveContainer.ComputeArchiveHashAsync(
                        outputPath, operationToken).ConfigureAwait(false);
                    try
                    {
                        if (!CryptographicOperations.FixedTimeEquals(archiveHash, copiedHash))
                        {
                            throw new NingRanException("照片隐藏加密内容保存后的完整性检查失败，未完成文件会被清理。");
                        }
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(copiedHash);
                    }
                }
                archiveSize = JpegArchiveContainer.GetStorageSize(outputPath);
                using var archiveHandle = WindowsFileSystemSafety.OpenInputFile(outputPath);
                archiveIdentity = WindowsFileSystemSafety.GetIdentity(archiveHandle);
                if (!TryDeleteFile(temporaryPath))
                {
                    throw new NingRanException("加密内容已保存，但临时加密文件未能自动删除。请关闭程序后重新打开以继续清理。");
                }

                TemporaryFileRegistry.Unregister(temporaryRegistration);
            }
            else if (createdSplitPaths is not null)
            {
                using var splitHandle = WindowsFileSystemSafety.OpenInputFile(createdSplitPaths[0]);
                archiveIdentity = WindowsFileSystemSafety.GetIdentity(splitHandle);
                resultArchivePath = createdSplitPaths[0];
                if (temporaryFile is not null)
                {
                    temporaryFile.Dispose();
                    temporaryFile = null;
                    TryDeleteFile(temporaryPath);
                }
                TemporaryFileRegistry.Unregister(temporaryRegistration);
                outputCreated = true;
            }
            else
            {
                archiveIdentity = WindowsFileSystemSafety.GetIdentity(temporaryFile!.SafeFileHandle);
                WindowsFileSystemSafety.RenameOpenFile(
                    temporaryFile.SafeFileHandle,
                    temporaryPath,
                    outputPath);
                outputCreated = true;
                TemporaryFileRegistry.Unregister(temporaryRegistration);
                temporaryFile.Dispose();
                temporaryFile = null;
            }

            reporter.Report(CryptoStage.Finalizing, totalWork, totalWork, "加密完成并通过验证。");
            return new EncryptionResult(
                resultArchivePath,
                archiveSize,
                sizeReport ?? throw new NingRanException("未能生成压缩效果报告。"),
                sourceSnapshot,
                sourceParentPath,
                sourceParentIdentity,
                archiveIdentity,
                archiveHash);
        }
        catch (Exception exception)
        {
            if (splitWriter is not null)
            {
                await splitWriter.DisposeAsync().ConfigureAwait(false);
            }
            if (createdSplitPaths is not null && !outputCreated)
            {
                foreach (var splitPath in createdSplitPaths)
                {
                    TryDeleteFile(splitPath);
                }
            }
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

            if (outputCreated)
            {
                TryDeleteFile(outputPath);
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
        IReadOnlyList<PhysicalDeviceUnlock>? physicalUnlocks = null;
        PhysicalDeviceMonitor? physicalMonitor = null;
        byte[]? dataKey = null;
        StableDirectoryPath? destinationLock = null;
        SecureStagingArea? stagingArea = null;
        try
        {
            Directory.CreateDirectory(destinationDirectory);
            destinationLock = WindowsFileSystemSafety.LockDirectoryPath(destinationDirectory);
            var isPhotoArchive = JpegArchiveContainer.IsEncryptedPhoto(archivePath);
            await using var archiveStream = JpegArchiveContainer.OpenArchiveReadStream(archivePath, exclusive: false);
            var region = JpegArchiveContainer.GetArchiveRegion(archiveStream, isPhotoArchive);
            await ArchiveEnvelope.InspectAsync(archiveStream, cancellationToken, region.Offset).ConfigureAwait(false);
            var archiveLength = Math.Max(region.Length, 1);
            string? verifiedSenderName = null;
            IndexedPayloadContainer.IndexedPayload? decryptedPayload = null;

            try
            {
                archiveStream.Position = region.Offset;
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
                physicalUnlocks = unlocked.PhysicalUnlocks;
                if (physicalUnlocks.Count > 0)
                {
                    physicalMonitor = new PhysicalDeviceMonitor(
                        physicalUnlocks,
                        cancellationToken,
                        unlocked.Header.IsFlexible && _physicalDeviceProvider is IPhysicalDevicePresence presence && unlocked.Header.ForbiddenPhysicalLookupHashes.Count > 0
                            ? () => presence.IsAnyForbiddenStorageConnected(
                                unlocked.Header.Bytes.AsMemory(24, 16), unlocked.Header.ForbiddenPhysicalLookupHashes)
                            : null);
                }

                var operationToken = physicalMonitor?.Token ?? cancellationToken;
                reporter.Report(CryptoStage.Verifying, 0, archiveLength, "正在验证内容结构和发送者身份…");
                var basePayload = await IndexedPayloadContainer.OpenAsync(
                    archiveStream,
                    unlocked.Header,
                    dataKey,
                    operationToken,
                    region.Offset,
                    region.Length,
                    allowTrailingIncrementalData: true).ConfigureAwait(false);
                var incremental = await IncrementalArchiveContainer.OpenAsync(
                    archiveStream,
                    unlocked.Header,
                    dataKey,
                    basePayload,
                    region.Length,
                    operationToken).ConfigureAwait(false);
                decryptedPayload = incremental.Payload;
                archiveLength = Math.Max(incremental.EffectiveLength, 1);
                verifiedSenderName = VerifyDecryptedIndexedPayloadIdentity(decryptedPayload, request.TrustedSenderId).Name;
                EnsureDeliveryPlaintextExportAllowed(decryptedPayload.DeliveryInfo);
                await IndexedPayloadContainer.ValidateAllAsync(
                    archiveStream,
                    unlocked.Header,
                    dataKey,
                    decryptedPayload,
                    (completed, _) => reporter.Report(
                        CryptoStage.Verifying,
                        Math.Min(completed * IndexedPayloadContainer.BlockSize, archiveLength),
                        archiveLength,
                        "正在验证加密内容，不创建文件…"),
                    operationToken,
                    region.Offset).ConfigureAwait(false);

                if (physicalUnlock is not null)
                {
                    await physicalUnlock.RevalidateAsync(operationToken).ConfigureAwait(false);
                    physicalMonitor!.ThrowIfDeviceLost();
                }

                operationToken.ThrowIfCancellationRequested();
                stagingArea = SecureStagingArea.Create(destinationDirectory);
                await RestoreIndexedPayloadAsync(
                    archiveStream,
                    unlocked.Header,
                    dataKey,
                    decryptedPayload,
                    stagingArea.PayloadDirectory,
                    (completed, message) => reporter.Report(
                        CryptoStage.Decrypting,
                        Math.Min(completed, archiveLength),
                        archiveLength,
                        message),
                    operationToken,
                    region.Offset).ConfigureAwait(false);

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

            if (physicalUnlocks is not null)
            {
                foreach (var unlock in physicalUnlocks) unlock.Dispose();
            }
            else
            {
                physicalUnlock?.Dispose();
            }
            if (dataKey is not null)
            {
                CryptographicOperations.ZeroMemory(dataKey);
            }

            keyFileSecret?.Dispose();
            destinationLock?.Dispose();
        }
    }

    private async Task<SecureArchiveSession> OpenSplitForBrowsingAsync(
        DecryptRequest request,
        string archivePath,
        CancellationToken cancellationToken)
    {
        KeyFileSecret? keyFileSecret = null;
        Stream? input = null;
        ArchiveHeader? header = null;
        byte[]? dataKey = null;
        PhysicalDeviceUnlock? physicalUnlock = null;
        IReadOnlyList<PhysicalDeviceUnlock>? physicalUnlocks = null;
        PhysicalDeviceMonitor? physicalMonitor = null;
        IndexedPayloadContainer.IndexedPayload? payload = null;
        try
        {
            input = NrSplitArchiveService.OpenReadStream(archivePath);
            await ArchiveEnvelope.InspectAsync(input, cancellationToken, 0).ConfigureAwait(false);
            input.Position = 0;
            if (!string.IsNullOrWhiteSpace(request.KeyFilePath))
            {
                keyFileSecret = await _keyFileService.UnlockAsync(
                    request.KeyFilePath,
                    request.Password,
                    cancellationToken).ConfigureAwait(false);
            }

            var unlocked = await ArchiveHeader.ReadAndUnlockAsync(
                input,
                request.Password,
                keyFileSecret?.Memory ?? ReadOnlyMemory<byte>.Empty,
                _physicalDeviceProvider,
                request.OwnerWindowHandle,
                cancellationToken,
                request.ExpectedMode).ConfigureAwait(false);
            header = unlocked.Header;
            dataKey = unlocked.DataKey;
            physicalUnlock = unlocked.PhysicalUnlock;
            physicalUnlocks = unlocked.PhysicalUnlocks;
            if (physicalUnlocks.Count > 0)
            {
                physicalMonitor = new PhysicalDeviceMonitor(
                    physicalUnlocks,
                    cancellationToken,
                    unlocked.Header.IsFlexible && _physicalDeviceProvider is IPhysicalDevicePresence presence && unlocked.Header.ForbiddenPhysicalLookupHashes.Count > 0
                        ? () => presence.IsAnyForbiddenStorageConnected(
                            unlocked.Header.Bytes.AsMemory(24, 16), unlocked.Header.ForbiddenPhysicalLookupHashes)
                        : null);
            }

            var operationToken = physicalMonitor?.Token ?? cancellationToken;
            payload = await IndexedPayloadContainer.OpenAsync(
                input,
                header,
                dataKey,
                operationToken,
                0,
                input.Length,
                allowTrailingIncrementalData: false).ConfigureAwait(false);
            var sender = VerifyDecryptedIndexedPayloadIdentity(payload, request.TrustedSenderId);
            var session = new SecureArchiveSession(
                input,
                header,
                dataKey,
                payload,
                physicalUnlock,
                physicalMonitor,
                sender.Name,
                sender.IsTrusted,
                archivePath,
                0,
                Math.Max(input.Length, 1),
                isReadOnly: true,
                physicalUnlocks: physicalUnlocks);
            input = null;
            header = null;
            dataKey = null;
            payload = null;
            physicalUnlock = null;
            physicalUnlocks = null;
            physicalMonitor = null;
            return session;
        }
        catch
        {
            payload?.Dispose();
            if (dataKey is not null) CryptographicOperations.ZeroMemory(dataKey);
            if (header is not null)
            {
                CryptographicOperations.ZeroMemory(header.Bytes);
                CryptographicOperations.ZeroMemory(header.PayloadNoncePrefix);
                CryptographicOperations.ZeroMemory(header.HeaderHash);
            }
            if (physicalMonitor is not null)
            {
                await physicalMonitor.DisposeAsync().ConfigureAwait(false);
            }
            physicalUnlock?.Dispose();
            input?.Dispose();
            throw;
        }
        finally
        {
            keyFileSecret?.Dispose();
        }
    }

    /// <summary>
    /// 解锁加密文件并保留一个只在内存中读取内容的会话。调用方必须在关闭查看器时释放返回值。
    /// </summary>
    public async Task<SecureArchiveSession> OpenForBrowsingAsync(
        DecryptRequest request,
        bool allowElevated = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!allowElevated)
        {
            WindowsFileSystemSafety.ThrowIfProcessIsElevated();
        }
        if (request.Password.IsEmpty)
        {
            throw new NingRanException("请输入密码。");
        }

        var archivePath = Path.GetFullPath(request.ArchivePath);
        if (!File.Exists(archivePath))
        {
            throw new NingRanException("请选择存在的凝然加密文件。");
        }

        if (NrSplitArchiveService.IsSupportedPartFile(archivePath))
        {
            return await OpenSplitForBrowsingAsync(request, archivePath, cancellationToken).ConfigureAwait(false);
        }

        // 如果上一次增量提交在当前进程中断过，先处理同一加密包的登记，
        // 再建立新的独占读取会话，避免新修改覆盖尚未完成的恢复记录。
        var recovery = IncrementalArchiveRecovery.RecoverAbandoned(archivePath);
        if (recovery.Failures.Count > 0)
        {
            throw new NingRanException(
                $"这个加密包上次的增量修改还没有恢复完成：{recovery.Failures[0].Reason}");
        }

        KeyFileSecret? keyFileSecret = null;
        FileStream? input = null;
        ArchiveHeader? header = null;
        byte[]? dataKey = null;
        PhysicalDeviceUnlock? physicalUnlock = null;
        IReadOnlyList<PhysicalDeviceUnlock>? physicalUnlocks = null;
        PhysicalDeviceMonitor? physicalMonitor = null;
        IndexedPayloadContainer.IndexedPayload? payload = null;
        try
        {
            // 加密正文保持独占读取；照片主文件仍可由系统看图程序正常打开。
            input = JpegArchiveContainer.OpenArchiveReadStream(archivePath, exclusive: true);
            var region = JpegArchiveContainer.GetArchiveRegion(
                input,
                JpegArchiveContainer.IsEncryptedPhoto(archivePath));
            await ArchiveEnvelope.InspectAsync(input, cancellationToken, region.Offset).ConfigureAwait(false);
            input.Position = region.Offset;
            if (!string.IsNullOrWhiteSpace(request.KeyFilePath))
            {
                keyFileSecret = await _keyFileService.UnlockAsync(
                    request.KeyFilePath,
                    request.Password,
                    cancellationToken).ConfigureAwait(false);
            }

            var unlocked = await ArchiveHeader.ReadAndUnlockAsync(
                input,
                request.Password,
                keyFileSecret?.Memory ?? ReadOnlyMemory<byte>.Empty,
                _physicalDeviceProvider,
                request.OwnerWindowHandle,
                cancellationToken,
                request.ExpectedMode).ConfigureAwait(false);
            header = unlocked.Header;
            dataKey = unlocked.DataKey;
            physicalUnlock = unlocked.PhysicalUnlock;
            physicalUnlocks = unlocked.PhysicalUnlocks;
            if (physicalUnlocks.Count > 0)
            {
                physicalMonitor = new PhysicalDeviceMonitor(
                    physicalUnlocks,
                    cancellationToken,
                    unlocked.Header.IsFlexible && _physicalDeviceProvider is IPhysicalDevicePresence presence && unlocked.Header.ForbiddenPhysicalLookupHashes.Count > 0
                        ? () => presence.IsAnyForbiddenStorageConnected(
                            unlocked.Header.Bytes.AsMemory(24, 16), unlocked.Header.ForbiddenPhysicalLookupHashes)
                        : null);
            }

            var operationToken = physicalMonitor?.Token ?? cancellationToken;
            var basePayload = await IndexedPayloadContainer.OpenAsync(
                input,
                header,
                dataKey,
                operationToken,
                region.Offset,
                region.Length,
                allowTrailingIncrementalData: true).ConfigureAwait(false);
            var incremental = await IncrementalArchiveContainer.OpenAsync(
                input, header, dataKey, basePayload, region.Length, operationToken).ConfigureAwait(false);
            payload = incremental.Payload;
            var sender = VerifyDecryptedIndexedPayloadIdentity(payload, request.TrustedSenderId);
            var session = new SecureArchiveSession(
                input,
                header,
                dataKey,
                payload,
                physicalUnlock,
                physicalMonitor,
                sender.Name,
                sender.IsTrusted,
                archivePath,
                region.Offset,
                Math.Max(incremental.EffectiveLength, 1),
                incremental.BaseLength,
                incremental.NextBlockIndex,
                incremental.Generation,
                incremental.LastSegmentStart);
            input = null;
            header = null;
            dataKey = null;
            payload = null;
            physicalUnlock = null;
            physicalUnlocks = null;
            physicalMonitor = null;
            return session;
        }
        catch
        {
            payload?.Dispose();
            if (dataKey is not null) CryptographicOperations.ZeroMemory(dataKey);
            if (header is not null)
            {
                CryptographicOperations.ZeroMemory(header.Bytes);
                CryptographicOperations.ZeroMemory(header.PayloadNoncePrefix);
                CryptographicOperations.ZeroMemory(header.HeaderHash);
            }

            if (physicalMonitor is not null)
            {
                await physicalMonitor.DisposeAsync().ConfigureAwait(false);
            }

            physicalUnlock?.Dispose();
            input?.Dispose();
            throw;
        }
        finally
        {
            keyFileSecret?.Dispose();
        }
    }

    /// <summary>
    /// 将已验证的内容和新选择的内容重新写成一份全新的加密文件。
    /// 旧数据密钥和随机数绝不复用，成功前原文件不会被替换。
    /// </summary>
    public async Task RebuildArchiveAsync(
        SecureArchiveSession session,
        ArchiveUpdateRequest request,
        IProgress<CryptoProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        using var reopened = await RebuildAndOpenArchiveAsync(session, request, progress, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// 更新后直接返回已经复验的新会话，避免再次进行相同的密码加强步骤。
    /// </summary>
    public async Task<SecureArchiveSession> RebuildAndOpenArchiveAsync(
        SecureArchiveSession session,
        ArchiveUpdateRequest request,
        IProgress<CryptoProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(request);
        WindowsFileSystemSafety.ThrowIfProcessIsElevated();

        if (session.IsDelivery)
        {
            throw new NingRanException("安全交付包是只读资料，不能修改其中的文件、有效期或导出规则。");
        }

        var archivePath = Path.GetFullPath(request.ArchivePath);
        if (!string.Equals(archivePath, session.ArchivePath, StringComparison.OrdinalIgnoreCase) || !File.Exists(archivePath))
        {
            throw new NingRanException("当前打开的加密文件已经变化，请关闭后重新打开再修改。");
        }

        if (!session.IsDirectory)
        {
            throw new NingRanException("当前加密文件保存的是单个文件，不能向其中追加内容。");
        }

        if (session.Mode == EncryptionMode.PhysicalDevice)
        {
            throw new NingRanException("物理设备模式暂不支持安全修改。请导出内容后重新加密，以免改变授权设备。");
        }

        if (request.Password.IsEmpty || request.SigningIdentityPassword.IsEmpty || string.IsNullOrWhiteSpace(request.SigningIdentityId))
        {
            throw new NingRanException("修改加密文件需要加密文件密码、发送者身份和身份密码。");
        }

        if (session.Mode == EncryptionMode.Advanced && (string.IsNullOrWhiteSpace(request.KeyFilePath) || !File.Exists(request.KeyFilePath)))
        {
            throw new NingRanException("高级模式修改时需要重新选择原来的密匙文件。");
        }

        var reporter = new ProgressReporter(progress);
        var removePaths = new HashSet<string>(request.PathsToRemove.Select(PathSafety.NormalizeRelativePath), StringComparer.OrdinalIgnoreCase);
        var additionManifests = new List<(PayloadManifest Manifest, string TargetDirectory, string? TargetName)>();
        PayloadManifest? manifest = null;
        KeyFileSecret? keyFileSecret = null;
        SigningIdentity? signingIdentity = null;
        ArchiveHeader? header = null;
        byte[]? dataKey = null;
        FileStream? temporaryFile = null;
        FileStream? reopenedInput = null;
        IndexedPayloadContainer.IndexedPayload? reopenedPayload = null;
        Guid? temporaryRegistration = null;
        var archiveDirectory = Path.GetDirectoryName(archivePath) ?? throw new NingRanException("加密文件位置不正确。");
        var temporaryPath = Path.Combine(archiveDirectory, $".ningran-update-{Guid.NewGuid():N}.part");
        var isPhotoArchive = JpegArchiveContainer.IsEncryptedPhoto(archivePath);
        if (!isPhotoArchive)
        {
            return await AppendIncrementalAndOpenArchiveAsync(session, request, progress, cancellationToken)
                .ConfigureAwait(false);
        }
        var archiveReplaced = false;
        try
        {
            foreach (var addition in request.Additions)
            {
                if (string.IsNullOrWhiteSpace(addition.SourcePath) || string.IsNullOrWhiteSpace(addition.TargetDirectoryRelativePath))
                {
                    throw new NingRanException("追加位置不正确。");
                }

                var target = PathSafety.NormalizeRelativePath(addition.TargetDirectoryRelativePath);
                if (!session.Entries.Any(entry => entry.IsDirectory && string.Equals(entry.RelativePath, target, StringComparison.OrdinalIgnoreCase)))
                {
                    throw new NingRanException("追加目标文件夹已经不存在，请重新选择。");
                }

                additionManifests.Add((PayloadManifest.Build(addition.SourcePath, SizePaddingMode.None, cancellationToken,
                        request.Compression == ArchiveCompressionLevel.SmallestLossy), target,
                    addition.TargetName));
            }

            manifest = session.CreateRebuildManifest(removePaths, additionManifests, SizePaddingMode.None);
            additionManifests.Clear(); // 内容读取句柄的管理权已经交给合并后的清单。
            var totalWork = manifest.TotalFileBytes > 0
                ? checked(manifest.TotalFileBytes * 3)
                : 3;
            var verificationStart = manifest.TotalFileBytes > 0
                ? checked(manifest.TotalFileBytes * 2)
                : 2;

            if (session.Mode == EncryptionMode.Advanced)
            {
                reporter.Report(CryptoStage.DerivingKey, 0, totalWork, "正在读取并核验密匙文件…");
                keyFileSecret = await _keyFileService.UnlockAsync(request.KeyFilePath!, request.Password, cancellationToken)
                    .ConfigureAwait(false);
            }

            reporter.Report(CryptoStage.DerivingKey, 0, totalWork, "正在同时加强密码并解锁发送者身份…");
            var created = await UnlockIdentityAndCreateArchiveAsync(
                request.SigningIdentityId,
                request.SigningIdentityPassword,
                request.Password,
                keyFileSecret?.Memory ?? ReadOnlyMemory<byte>.Empty,
                session.Mode,
                hideExactSize: false,
                _kdfParameters,
                cancellationToken).ConfigureAwait(false);
            signingIdentity = created.Identity;
            header = created.Header;
            dataKey = created.DataKey;

            using var directoryLock = WindowsFileSystemSafety.LockDirectoryPath(archiveDirectory);
            temporaryFile = WindowsFileSystemSafety.CreateNewTemporaryFile(temporaryPath);
            temporaryRegistration = TemporaryFileRegistry.Register(temporaryFile, temporaryPath);
            const long archiveOffset = 0;
            await temporaryFile.WriteAsync(header.Bytes, cancellationToken).ConfigureAwait(false);
            var indexedPayload = await IndexedPayloadContainer.WriteAsync(
                temporaryFile, manifest, header, dataKey, signingIdentity,
                request.Compression,
                session.DeliveryInfo,
                (stage, completed, message) => reporter.Report(
                    CryptoStage.Encrypting,
                    Math.Min(totalWork, stage == IndexedPayloadContainer.WriteStage.Planning
                        ? completed
                        : manifest.TotalFileBytes + completed),
                    totalWork,
                    message),
                cancellationToken).ConfigureAwait(false);
            try
            {
                await temporaryFile.FlushAsync(cancellationToken).ConfigureAwait(false);
                temporaryFile.Flush(flushToDisk: true);
                reporter.Report(CryptoStage.Verifying, verificationStart, totalWork, "正在验证更新后的加密文件…");
                await IndexedPayloadContainer.ValidateAllAsync(
                    temporaryFile, header, dataKey, indexedPayload,
                    (completed, _) => reporter.Report(CryptoStage.Verifying,
                        Math.Min(totalWork, verificationStart + completed * IndexedPayloadContainer.BlockSize), totalWork,
                        "正在验证更新后的内容…"), cancellationToken, archiveOffset).ConfigureAwait(false);
                VerifyCreatedIndexedPayloadIdentity(indexedPayload, signingIdentity);
            }
            finally
            {
                indexedPayload.Dispose();
            }

            cancellationToken.ThrowIfCancellationRequested();
            reporter.Report(CryptoStage.Finalizing, totalWork, totalWork, "正在安全替换原加密文件…");
            temporaryFile.Dispose();
            temporaryFile = null;
            session.Dispose(); // 只在新文件完整验证通过后才释放旧文件的独占锁。
            if (isPhotoArchive)
            {
                await JpegArchiveContainer.ReplaceAlternateDataStreamAsync(
                    archivePath, temporaryPath, cancellationToken).ConfigureAwait(false);
                archiveReplaced = true;
                if (!TryDeleteFile(temporaryPath))
                {
                    throw new NingRanException("加密内容已更新，但临时加密文件未能自动删除。请关闭程序后重新打开以继续清理。");
                }
            }
            else
            {
                var backupPath = Path.Combine(archiveDirectory, $".ningran-update-backup-{Guid.NewGuid():N}.bak");
                try
                {
                    File.Replace(temporaryPath, archivePath, backupPath, ignoreMetadataErrors: true);
                    archiveReplaced = true;
                    TryDeleteFile(backupPath);
                }
                catch
                {
                    // File.Replace 失败时原文件仍在；临时文件会在 finally 中清理。
                    throw;
                }
            }

            TemporaryFileRegistry.Unregister(temporaryRegistration);
            reopenedInput = JpegArchiveContainer.OpenArchiveReadStream(archivePath, exclusive: true);
            var reopenedRegion = JpegArchiveContainer.GetArchiveRegion(reopenedInput, isPhotoArchive);
            await VerifyKnownHeaderAsync(reopenedInput, reopenedRegion.Offset, header, CancellationToken.None)
                .ConfigureAwait(false);
            reopenedPayload = await IndexedPayloadContainer.OpenAsync(
                reopenedInput,
                header,
                dataKey,
                CancellationToken.None,
                reopenedRegion.Offset,
                reopenedRegion.Length).ConfigureAwait(false);
            VerifyCreatedIndexedPayloadIdentity(reopenedPayload, signingIdentity);
            var reopenedSession = new SecureArchiveSession(
                reopenedInput,
                header,
                dataKey,
                reopenedPayload,
                physicalUnlock: null,
                physicalMonitor: null,
                signingIdentity.Name,
                senderIsTrusted: true,
                archivePath,
                reopenedRegion.Offset,
                reopenedRegion.Length);
            reopenedInput = null;
            reopenedPayload = null;
            header = null;
            dataKey = null;
            reporter.Report(CryptoStage.Finalizing, totalWork, totalWork, "加密文件已更新并重新签名。");
            return reopenedSession;
        }
        catch (Exception exception) when (exception is not NingRanException and not OperationCanceledException)
        {
            throw new NingRanException(
                archiveReplaced
                    ? "加密文件已经更新，但程序未能继续打开新内容。请关闭后重新打开该文件。"
                    : "修改加密文件时发生错误，原文件没有被替换。",
                exception);
        }
        finally
        {
            if (temporaryFile is not null)
            {
                TryDeleteTemporaryFile(ref temporaryFile, temporaryPath);
            }
            else if (File.Exists(temporaryPath))
            {
                TryDeleteFile(temporaryPath);
            }

            TemporaryFileRegistry.Unregister(temporaryRegistration);
            reopenedPayload?.Dispose();
            reopenedInput?.Dispose();
            manifest?.Dispose();
            foreach (var (addition, _, _) in additionManifests)
            {
                addition.Dispose();
            }

            keyFileSecret?.Dispose();
            signingIdentity?.Dispose();
            if (dataKey is not null) CryptographicOperations.ZeroMemory(dataKey);
            if (header is not null)
            {
                CryptographicOperations.ZeroMemory(header.Bytes);
                CryptographicOperations.ZeroMemory(header.PayloadNoncePrefix);
                CryptographicOperations.ZeroMemory(header.HeaderHash);
            }
        }
    }

    private async Task<SecureArchiveSession> AppendIncrementalAndOpenArchiveAsync(
        SecureArchiveSession session,
        ArchiveUpdateRequest request,
        IProgress<CryptoProgress>? progress,
        CancellationToken cancellationToken)
    {
        if (session.IsDelivery)
        {
            throw new NingRanException("安全交付包是只读资料，不能修改其中的文件。");
        }

        if (!session.IsDirectory)
        {
            throw new NingRanException("当前加密文件保存的是单个文件，不能向其中追加内容。");
        }

        if (session.IncrementalBaseLength <= 0)
        {
            throw new NingRanException("当前加密文件缺少增量修改所需的基础信息，请先用新版凝然打开后再试。");
        }

        if (request.PathsToRemove.Count == 0 && request.Additions.Count == 0)
        {
            throw new NingRanException("没有选择要添加或删除的内容。");
        }

        var archivePath = Path.GetFullPath(request.ArchivePath);
        var archiveDirectory = Path.GetDirectoryName(archivePath)
            ?? throw new NingRanException("加密文件位置不正确。");
        var temporaryPath = Path.Combine(archiveDirectory, $".ningran-increment-{Guid.NewGuid():N}.part");
        var removePaths = new HashSet<string>(
            request.PathsToRemove.Select(PathSafety.NormalizeRelativePath),
            StringComparer.OrdinalIgnoreCase);
        var effectiveEntries = session.Payload.Entries
            .Where(entry => !removePaths.Any(path =>
                string.Equals(entry.RelativePath, path, StringComparison.OrdinalIgnoreCase) ||
                entry.RelativePath.StartsWith(path + "/", StringComparison.OrdinalIgnoreCase)))
            .ToList();
        var effectivePaths = effectiveEntries
            .Select(entry => entry.RelativePath)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var plannedAdditions = new List<IncrementalArchiveContainer.PlannedAddition>();
        var manifests = new List<PayloadManifest>();
        SigningIdentity? signingIdentity = null;
        var committed = false;
        var commitStarted = false;
        var reopenSucceeded = false;
        Guid? recoveryRegistration = null;
        var reporter = new ProgressReporter(progress);
        try
        {
            reporter.Report(CryptoStage.Preparing, 0, 1, "正在准备增量修改…");
            signingIdentity = await _identityService.UnlockLocalIdentityAsync(
                request.SigningIdentityId,
                request.SigningIdentityPassword,
                cancellationToken).ConfigureAwait(false);

            var baseDataStart = IndexedPayloadContainer.DataStart(session.Header, session.Payload);
            var nextBlockIndex = session.IncrementalNextBlockIndex;
            var nextDataOffset = checked(session.ArchiveLength + IncrementalArchiveContainer.SegmentHeaderSize - baseDataStart);
            foreach (var addition in request.Additions)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var targetDirectory = PathSafety.NormalizeRelativePath(addition.TargetDirectoryRelativePath);
                if (!effectiveEntries.Any(entry => entry.Kind == PayloadEntryKind.Directory &&
                    string.Equals(entry.RelativePath, targetDirectory, StringComparison.OrdinalIgnoreCase)))
                {
                    throw new NingRanException("追加目标文件夹已经不存在，请重新选择。");
                }

                var manifest = PayloadManifest.Build(
                    addition.SourcePath,
                    SizePaddingMode.None,
                    cancellationToken,
                    request.Compression == ArchiveCompressionLevel.SmallestLossy);
                manifests.Add(manifest);
                var destinationRoot = PathSafety.NormalizeRelativePath(targetDirectory + "/" +
                    PathSafety.ValidateNameSegment(addition.TargetName ?? manifest.RootName));
                foreach (var sourceEntry in manifest.Entries)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var suffix = sourceEntry.RelativePath[manifest.RootName.Length..];
                    var destination = PathSafety.NormalizeRelativePath(destinationRoot + suffix);
                    if (!effectivePaths.Add(destination))
                    {
                        throw new NingRanException($"追加后的文件名重复：{destination}");
                    }

                    if (sourceEntry.Kind != PayloadEntryKind.File)
                    {
                        effectiveEntries.Add(new IndexedPayloadContainer.IndexedPayloadEntry(
                            sourceEntry.Kind,
                            destination,
                            0,
                            sourceEntry.LastWriteUtcTicks,
                            0,
                            0,
                            NrMediaFiles.TryGetKind(destination),
                            []));
                        continue;
                    }

                    var plannedBlocks = await IndexedPayloadContainer.PlanSourceFileAsync(
                        sourceEntry,
                        request.Compression,
                        bytes => reporter.Report(CryptoStage.Preparing, bytes, Math.Max(1, sourceEntry.Length),
                            $"正在分析压缩方式：{destination}"),
                        cancellationToken).ConfigureAwait(false);
                    var blockOffset = nextDataOffset;
                    var blocks = plannedBlocks.Select(block =>
                    {
                        var result = block with { DataOffset = blockOffset };
                        blockOffset = checked(blockOffset + block.StoredLength + CryptoSizes.Tag);
                        return result;
                    }).ToArray();
                    var indexedEntry = new IndexedPayloadContainer.IndexedPayloadEntry(
                        PayloadEntryKind.File,
                        destination,
                        sourceEntry.Length,
                        sourceEntry.LastWriteUtcTicks,
                        nextBlockIndex,
                        blocks.Length,
                        NrMediaFiles.TryGetKind(destination),
                        blocks);
                    var rewrittenSource = sourceEntry with { RelativePath = destination };
                    plannedAdditions.Add(new IncrementalArchiveContainer.PlannedAddition(rewrittenSource, indexedEntry));
                    effectiveEntries.Add(indexedEntry);
                    nextBlockIndex = checked(nextBlockIndex + blocks.Length);
                    nextDataOffset = blockOffset;
                }
            }

            if (!effectiveEntries.Any(entry => string.Equals(entry.RelativePath, session.RootName,
                StringComparison.OrdinalIgnoreCase)))
            {
                throw new NingRanException("不能删除加密文件的根目录。");
            }

            var previousHash = session.Payload.AuthenticatedHash.ToArray();
            var prefix = session.Payload.CreatePrefix();
            try
            {
                reporter.Report(CryptoStage.Encrypting, 0,
                    Math.Max(1, plannedAdditions.Sum(item => item.SourceEntry.Length)),
                    "正在追加新的加密分段…");
                var staged = await IncrementalArchiveContainer.WriteStagedAsync(
                    temporaryPath,
                    session.ArchiveLength,
                    session.IncrementalBaseLength,
                    checked(session.IncrementalGeneration + 1),
                    session.IncrementalLastSegmentStart,
                    previousHash,
                    session.IncrementalNextBlockIndex,
                    session.Header,
                    session.DataKey,
                    prefix,
                    plannedAdditions,
                    effectiveEntries,
                    session.IsDirectory,
                    session.RootName,
                    request.Compression,
                    signingIdentity,
                    cancellationToken).ConfigureAwait(false);

                reporter.Report(CryptoStage.Verifying, 0,
                    Math.Max(1, session.Entries.Count + plannedAdditions.Count),
                    "正在验证增量修改…");
                await session.ValidateAsync(cancellationToken).ConfigureAwait(false);
                await IncrementalArchiveContainer.ValidateStagedAsync(
                    temporaryPath,
                    staged,
                    session.Header,
                    session.DataKey,
                    prefix,
                    baseDataStart,
                    signingIdentity,
                    plannedAdditions,
                    cancellationToken).ConfigureAwait(false);

                EnsureIncrementalCommitSpace(archivePath, staged.SegmentLength);
                recoveryRegistration = IncrementalArchiveRecovery.Register(
                    session.ArchiveFile,
                    archivePath,
                    temporaryPath,
                    staged);
                // 复制一份密码对象，旧会话关闭后用于重新打开已提交的文件。
                using var reopenPassword = request.Password.Clone();
                commitStarted = true;
                session.Dispose();

                using var directoryLock = WindowsFileSystemSafety.LockDirectoryPath(archiveDirectory);
                await using (var target = new FileStream(
                                 archivePath,
                                 FileMode.Open,
                                 FileAccess.ReadWrite,
                                 FileShare.None,
                                 1024 * 1024,
                                 FileOptions.Asynchronous | FileOptions.WriteThrough))
                {
                    if (target.Length < session.ArchiveLength)
                        throw new NingRanException("加密文件在修改期间发生了变化，请关闭后重新打开再试。");
                    if (target.Length > session.ArchiveLength)
                    {
                        target.SetLength(session.ArchiveLength);
                    }

                    target.Position = session.ArchiveLength;
                    await using var source = new FileStream(
                        temporaryPath,
                        FileMode.Open,
                        FileAccess.Read,
                        FileShare.Read,
                        1024 * 1024,
                        FileOptions.Asynchronous | FileOptions.SequentialScan);
                    await source.CopyToAsync(target, 1024 * 1024, cancellationToken).ConfigureAwait(false);
                    await target.FlushAsync(cancellationToken).ConfigureAwait(false);
                    target.Flush(flushToDisk: true);

                    // The staged segment starts as provisional. Only after all
                    // bytes are durable do we publish the committed marker.
                    // A crash before this tiny final write leaves the old
                    // catalog readable and the staged file available for
                    // recovery.
                    var committedMarker = IncrementalArchiveContainer.GetCommittedSegmentMagic();
                    try
                    {
                        target.Position = session.ArchiveLength;
                        await target.WriteAsync(committedMarker, cancellationToken).ConfigureAwait(false);
                        await target.FlushAsync(cancellationToken).ConfigureAwait(false);
                        target.Flush(flushToDisk: true);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(committedMarker);
                    }
                }

                committed = true;
                using var reopenRequest = new DecryptRequest(
                    archivePath,
                    string.Empty,
                    reopenPassword,
                    request.KeyFilePath,
                    null,
                    request.OwnerWindowHandle,
                    session.Mode);
                var reopened = await OpenForBrowsingAsync(reopenRequest, allowElevated: false,
                    CancellationToken.None).ConfigureAwait(false);
                reopenSucceeded = true;
                reporter.Report(CryptoStage.Finalizing, 1, 1, "增量修改完成并通过验证。");
                return reopened;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(previousHash);
                CryptographicOperations.ZeroMemory(prefix);
            }
        }
        catch (OperationCanceledException) when (commitStarted && !committed)
        {
            // 用户主动取消时不应在下次启动悄悄完成这次修改；临时段
            // 会被删除，正式包中的临时标记也会继续代表旧版本。
            IncrementalArchiveRecovery.Unregister(recoveryRegistration);
            recoveryRegistration = null;
            commitStarted = false;
            throw;
        }
        catch (Exception exception) when (exception is not NingRanException and not OperationCanceledException)
        {
            throw new NingRanException(
                committed
                    ? "增量修改已经写入，但程序未能继续打开新内容。临时恢复文件已保留。"
                    : "修改加密文件时发生错误，原文件没有完成增量提交。",
                exception);
        }
        finally
        {
            foreach (var manifest in manifests) manifest.Dispose();
            signingIdentity?.Dispose();
            if (!commitStarted || reopenSucceeded)
            {
                if (TryDeleteFile(temporaryPath))
                {
                    IncrementalArchiveRecovery.Unregister(recoveryRegistration);
                    recoveryRegistration = null;
                }
            }
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
        var currentHash = await JpegArchiveContainer.ComputeArchiveHashAsync(result.ArchivePath, cancellationToken)
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
            current.SourceHandle!.Dispose();
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

    private static async Task RestoreIndexedPayloadAsync(
        FileStream archiveStream,
        ArchiveHeader header,
        byte[] dataKey,
        IndexedPayloadContainer.IndexedPayload payload,
        string stagingDirectory,
        Action<long, string>? reportProgress,
        CancellationToken cancellationToken,
        long archiveOffset = 0)
    {
        var directoryTimes = new List<(string Path, long Ticks)>();
        long completed = 0;
        foreach (var entry in payload.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var destination = PathSafety.GetSafeDestination(stagingDirectory, entry.RelativePath);
            if (entry.Kind == PayloadEntryKind.Directory)
            {
                Directory.CreateDirectory(destination);
                WindowsFileSystemSafety.VerifyDirectoryChain(stagingDirectory, destination);
                directoryTimes.Add((destination, entry.LastWriteUtcTicks));
                continue;
            }

            var parent = Path.GetDirectoryName(destination)!;
            Directory.CreateDirectory(parent);
            WindowsFileSystemSafety.VerifyDirectoryChain(stagingDirectory, parent);
            await using (var output = new FileStream(
                             destination,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             IndexedPayloadContainer.BlockSize,
                             FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await IndexedPayloadContainer.CopyEntryToStreamAsync(
                    archiveStream,
                    header,
                    dataKey,
                    payload,
                    entry,
                    output,
                    cancellationToken,
                    archiveOffset).ConfigureAwait(false);
                await output.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            File.SetLastWriteTimeUtc(destination, new DateTime(entry.LastWriteUtcTicks, DateTimeKind.Utc));
            completed = checked(completed + entry.Length);
            reportProgress?.Invoke(completed, $"正在还原：{entry.RelativePath}");
        }

        for (var index = directoryTimes.Count - 1; index >= 0; index--)
        {
            var directory = directoryTimes[index];
            Directory.SetLastWriteTimeUtc(directory.Path, new DateTime(directory.Ticks, DateTimeKind.Utc));
        }
    }

    private SenderVerificationResult VerifyDecryptedIndexedPayloadIdentity(
        IndexedPayloadContainer.IndexedPayload payload,
        string? trustedSenderId)
    {
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
                    payload.Signature,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            {
                continue;
            }

            return new SenderVerificationResult(contact.Name, true);
        }

        if (payload.DeliveryInfo is not null && string.IsNullOrWhiteSpace(trustedSenderId) &&
            payload.DeliverySenderPublicKey is { Length: > 0 } senderPublicKey &&
            !string.IsNullOrWhiteSpace(payload.DeliverySenderName))
        {
            try
            {
                using var key = ECDsa.Create();
                key.ImportSubjectPublicKeyInfo(senderPublicKey, out var read);
                if (read != senderPublicKey.Length || !key.VerifyHash(
                        payload.AuthenticatedHash,
                        payload.Signature,
                        DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                {
                    throw new NingRanException("安全交付包的发送者签名不正确，文件可能已被修改。");
                }

                return new SenderVerificationResult(payload.DeliverySenderName, false);
            }
            catch (CryptographicException exception)
            {
                throw new NingRanException("安全交付包的发送者公开验证信息不正确。", exception);
            }
        }

        throw new NingRanException(
            "发送者尚未加入本机可信联系人，或者加密文件已经被修改。请先导入公开身份并输入正确的安全码。");
    }

    private sealed record SenderVerificationResult(string Name, bool IsTrusted);

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

    private static void VerifyCreatedIndexedPayloadIdentity(
        IndexedPayloadContainer.IndexedPayload payload,
        SigningIdentity? signingIdentity)
    {
        if (signingIdentity is null)
        {
            throw new NingRanException("缺少发送者身份，无法验证新加密文件。");
        }

        using var publicIdentity = signingIdentity.CreatePublicIdentity();
        if (!string.Equals(payload.SignerFingerprint, publicIdentity.Fingerprint, StringComparison.Ordinal) ||
            !publicIdentity.Key.VerifyHash(
                payload.AuthenticatedHash,
                payload.Signature,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
        {
            throw new NingRanException("发送者身份证明生成后未能通过复验。");
        }
    }

    private static void EnsureDeliveryPlaintextExportAllowed(DeliveryPackageInfo? delivery)
    {
        if (delivery is null) return;
        if (delivery.IsExpiredAt(DateTimeOffset.UtcNow))
        {
            throw new NingRanException("此交付包已过期。你仍可查看交付信息和文件列表，但不能打开或导出文件。");
        }

        if (!delivery.AllowExport)
        {
            throw new NingRanException("发送方已禁止从此安全交付包导出明文文件。");
        }
    }

    private static SigningIdentity CreateEphemeralTestingIdentity()
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        try
        {
            var publicKey = key.ExportSubjectPublicKeyInfo();
            try
            {
                var fingerprint = Convert.ToHexString(SHA256.HashData(publicKey));
                return new SigningIdentity("自动检查发送者", fingerprint, key);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(publicKey);
            }
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }

    /// <summary>
    /// 身份密码和加密密码互不依赖，可同时完成各自的安全加固，
    /// 从而缩短等待时间而不减少任何一次密码计算。
    /// </summary>
    private async Task<(SigningIdentity Identity, ArchiveHeader Header, byte[] DataKey)>
        UnlockIdentityAndCreateArchiveAsync(
            string signingIdentityId,
            SensitivePassword signingIdentityPassword,
            SensitivePassword archivePassword,
            ReadOnlyMemory<byte> keyFileSecret,
            EncryptionMode mode,
            bool hideExactSize,
            KdfParameters kdfParameters,
            CancellationToken cancellationToken)
    {
        var identityTask = _identityService.UnlockLocalIdentityAsync(
            signingIdentityId, signingIdentityPassword, cancellationToken);
        var archiveTask = ArchiveHeader.CreateAsync(
            archivePassword, keyFileSecret, mode, hideExactSize, kdfParameters, cancellationToken);
        try
        {
            await Task.WhenAll(identityTask, archiveTask).ConfigureAwait(false);
            var archive = await archiveTask.ConfigureAwait(false);
            return (await identityTask.ConfigureAwait(false), archive.Header, archive.DataKey);
        }
        catch
        {
            if (identityTask.IsCompletedSuccessfully)
            {
                identityTask.Result.Dispose();
            }

            if (archiveTask.IsCompletedSuccessfully)
            {
                var archive = archiveTask.Result;
                CryptographicOperations.ZeroMemory(archive.DataKey);
                CryptographicOperations.ZeroMemory(archive.Header.Bytes);
                CryptographicOperations.ZeroMemory(archive.Header.PayloadNoncePrefix);
                CryptographicOperations.ZeroMemory(archive.Header.HeaderHash);
            }

            throw;
        }
    }

    private static async Task VerifyKnownHeaderAsync(
        FileStream input,
        long archiveOffset,
        ArchiveHeader expectedHeader,
        CancellationToken cancellationToken)
    {
        var storedHeader = new byte[expectedHeader.Bytes.Length];
        try
        {
            input.Position = archiveOffset;
            await BinaryFormat.ReadExactlyAsync(input, storedHeader, cancellationToken).ConfigureAwait(false);
            if (!CryptographicOperations.FixedTimeEquals(storedHeader, expectedHeader.Bytes))
            {
                throw new NingRanException("更新后的加密文件头部复验失败，请关闭后重新打开文件。");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(storedHeader);
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

    private static string CreateDeliveryRootName(string deliveryName)
    {
        var invalid = Path.GetInvalidFileNameChars().ToHashSet();
        var sanitized = new string(deliveryName.Trim()
            .Select(character => invalid.Contains(character) ? '＿' : character)
            .ToArray())
            .TrimEnd(' ', '.');
        if (string.IsNullOrWhiteSpace(sanitized))
        {
            sanitized = "安全交付资料";
        }

        if (sanitized.Length > 80)
        {
            sanitized = sanitized[..80].TrimEnd(' ', '.');
        }

        try
        {
            return PathSafety.ValidateNameSegment(sanitized);
        }
        catch (NingRanException)
        {
            return "安全交付资料";
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

    private static void EnsureIncrementalCommitSpace(string archivePath, long segmentLength)
    {
        if (segmentLength <= 0) return;
        try
        {
            var root = Path.GetPathRoot(Path.GetFullPath(archivePath));
            if (string.IsNullOrWhiteSpace(root)) return;
            var drive = new DriveInfo(root);
            if (drive.IsReady && drive.AvailableFreeSpace < segmentLength)
            {
                throw new NingRanException(
                    "磁盘剩余空间不足以完成这次增量修改。请至少再腾出与本次新增内容相近的空间后重试；原加密文件没有改变。");
            }
        }
        catch (NingRanException)
        {
            throw;
        }
        catch (Exception)
        {
            // 无法查询网络磁盘或特殊文件系统的剩余空间时，交给实际写入阶段处理。
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
        private CryptoStage? _currentStage;
        private long _stageStartCompleted;
        private TimeSpan _stageStartedAt;

        public ProgressReporter(IProgress<CryptoProgress>? progress)
        {
            _progress = progress;
        }

        public void Report(CryptoStage stage, long completed, long total, string message)
        {
            var elapsed = _stopwatch.Elapsed;
            if (_currentStage != stage || completed < _stageStartCompleted)
            {
                _currentStage = stage;
                _stageStartCompleted = completed;
                _stageStartedAt = elapsed;
            }

            var metrics = EstimateProgressMetrics(
                completed,
                total,
                _stageStartCompleted,
                elapsed - _stageStartedAt);
            _progress?.Report(new CryptoProgress(
                stage,
                completed,
                total,
                message,
                metrics.EstimatedRemaining,
                metrics.BytesPerSecond));
        }
    }

    internal static (TimeSpan? EstimatedRemaining, double? BytesPerSecond) EstimateProgressMetrics(
        long completed,
        long total,
        long stageStartCompleted,
        TimeSpan stageElapsed)
    {
        var stageCompleted = completed - stageStartCompleted;
        if (stageCompleted <= 0 || stageElapsed.TotalSeconds <= 0.2)
        {
            return (null, null);
        }

        var bytesPerSecond = stageCompleted / stageElapsed.TotalSeconds;
        if (!double.IsFinite(bytesPerSecond) || bytesPerSecond <= 0)
        {
            return (null, null);
        }

        TimeSpan? remaining = null;
        if (total > completed)
        {
            var seconds = (total - completed) / bytesPerSecond;
            if (double.IsFinite(seconds) && seconds >= 0)
            {
                remaining = TimeSpan.FromSeconds(Math.Min(seconds, TimeSpan.MaxValue.TotalSeconds));
            }
        }

        return (remaining, bytesPerSecond);
    }
}
