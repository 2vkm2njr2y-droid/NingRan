using System.Diagnostics;
using System.Security.Cryptography;
using NingRan.Core.Internal;

namespace NingRan.Core;

public sealed class NrVaultService
{
    private readonly KdfParameters _kdfParameters;
    private readonly NrKeyFileService _keyFileService;
    private readonly IPhysicalDeviceProvider _physicalDeviceProvider;

    public NrVaultService(
        KdfParameters? kdfParameters = null,
        NrKeyFileService? keyFileService = null,
        IPhysicalDeviceProvider? physicalDeviceProvider = null)
    {
        _kdfParameters = kdfParameters ?? KdfParameters.Production;
        _kdfParameters.ValidateForReading();
        _keyFileService = keyFileService ?? new NrKeyFileService(_kdfParameters);
        _physicalDeviceProvider = physicalDeviceProvider ?? new NrPhysicalDeviceService();
    }

    public static bool IsVaultFolder(string path)
    {
        try
        {
            var normalized = VaultFormat.NormalizeVaultPath(path);
            return Directory.Exists(normalized) &&
                   File.Exists(Path.Combine(normalized, "vault.info")) &&
                   File.Exists(Path.Combine(normalized, "vault.keys")) &&
                   File.Exists(Path.Combine(normalized, "catalog", "current.nrcat"));
        }
        catch (Exception exception) when (exception is ArgumentException or IOException or UnauthorizedAccessException or NingRanException)
        {
            return false;
        }
    }

    public static bool IsVaultFile(string path)
    {
        try
        {
            var normalized = VaultFormat.NormalizeVaultPath(path);
            return File.Exists(normalized) && Path.GetExtension(normalized).Length == 0;
        }
        catch (Exception exception) when (exception is ArgumentException or IOException or UnauthorizedAccessException or NingRanException)
        {
            return false;
        }
    }

    public async Task<VaultInfo> InspectAsync(string vaultPath, CancellationToken cancellationToken = default)
    {
        var normalized = VaultFormat.NormalizeVaultPath(vaultPath);
        if (Directory.Exists(normalized)) return await VaultFormat.ReadInfoAsync(normalized, cancellationToken).ConfigureAwait(false);
        if (!File.Exists(normalized)) throw new NingRanException("请选择存在的凝然保险箱文件。");
        if (FixedVaultContainer.IsFormat(normalized))
        {
            return await FixedVaultContainer.ReadInfoAsync(normalized, cancellationToken).ConfigureAwait(false);
        }
        return await VaultContainer.ReadInfoWithoutExtractingAsync(normalized, cancellationToken).ConfigureAwait(false);
    }

    public async Task<VaultCreationResult> CreateAsync(
        CreateVaultRequest request,
        IProgress<CryptoProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        WindowsFileSystemSafety.ThrowIfProcessIsElevated();
        PasswordRules.ValidateForCreation(request.Password);
        ValidateMode(request.Mode, request.KeyFilePath, request.PhysicalDevices);
        var finalPath = VaultFormat.NormalizeVaultPath(request.VaultPath);
        if (Directory.Exists(finalPath) || File.Exists(finalPath))
        {
            throw new NingRanException("保存位置已经有同名内容，请更换保险箱名称。");
        }

        var parent = Path.GetDirectoryName(finalPath)
            ?? throw new NingRanException("保险箱保存位置不正确。");
        Directory.CreateDirectory(parent);
        using var parentLock = WindowsFileSystemSafety.LockDirectoryPath(parent);
        ValidateSourcesOutsideVault(request.SourcePaths, finalPath);
        var temporaryPath = Path.Combine(parent, $".{Path.GetFileName(finalPath)}-{Guid.NewGuid():N}.part");
        KeyFileSecret? keyFileSecret = null;
        ArchiveHeader? keyHeader = null;
        ArchiveHeader? decoyKeyHeader = null;
        byte[]? dataKey = null;
        byte[]? decoyDataKey = null;
        SensitivePassword? decoyPassword = null;
        IReadOnlyList<PhysicalDeviceUnlock>? physicalUnlocks = null;
        var created = false;
        try
        {
            progress?.Report(new CryptoProgress(CryptoStage.DerivingKey, 0, 1, "正在保护保险箱数据钥匙…"));
            if (request.Mode == EncryptionMode.Advanced)
            {
                keyFileSecret = await _keyFileService.UnlockAsync(
                    request.KeyFilePath!, request.Password, cancellationToken).ConfigureAwait(false);
            }

            if (request.Mode == EncryptionMode.PhysicalDevice)
            {
                var physical = await ArchiveHeader.CreatePhysicalAsync(
                    request.Password,
                    request.PhysicalDevices,
                    _kdfParameters,
                    _physicalDeviceProvider,
                    request.OwnerWindowHandle,
                    cancellationToken).ConfigureAwait(false);
                keyHeader = physical.Header;
                dataKey = physical.DataKey;
                physicalUnlocks = physical.Unlocks;
            }
            else
            {
                var createdHeader = await ArchiveHeader.CreateAsync(
                    request.Password,
                    keyFileSecret?.Memory ?? ReadOnlyMemory<byte>.Empty,
                    request.Mode,
                    hideExactSize: false,
                    _kdfParameters,
                    cancellationToken).ConfigureAwait(false);
                keyHeader = createdHeader.Header;
                dataKey = createdHeader.DataKey;
            }

            decoyPassword = SensitivePassword.FromString($"{Guid.NewGuid():N}{Guid.NewGuid():N}");
            var decoyCreated = await ArchiveHeader.CreateAsync(
                decoyPassword,
                ReadOnlyMemory<byte>.Empty,
                EncryptionMode.Standard,
                hideExactSize: false,
                _kdfParameters,
                cancellationToken).ConfigureAwait(false);
            decoyKeyHeader = decoyCreated.Header;
            decoyDataKey = decoyCreated.DataKey;

            var plan = BuildSourcePlan(request.SourcePaths, []);
            var contentBytes = plan.Files.Sum(file => file.Entry.Length);
            var capacity = request.FixedCapacityBytes ?? WorkspaceVaultContainer.CalculateRecommendedCapacity(contentBytes);
            var requiredSlots = plan.Files.Sum(file => (long)file.Entry.ChunkCount);
            var dataSlotCount = WorkspaceVaultContainer.GetDataSlotCount(capacity);
            if (requiredSlots > dataSlotCount)
            {
                throw new NingRanException("所选资料超过保险箱的可用容量。请改用更大的固定容量。");
            }
            var driveRoot = Path.GetPathRoot(parent);
            if (!string.IsNullOrEmpty(driveRoot) && new DriveInfo(driveRoot).AvailableFreeSpace < capacity)
            {
                throw new NingRanException("保存磁盘的剩余空间不足，无法建立所选固定容量的保险箱。");
            }
            var temporaryInfo = new VaultInfo(
                temporaryPath,
                Guid.NewGuid(),
                request.Mode,
                request.SizeProtection,
                DateTimeOffset.UtcNow,
                WorkspaceVaultContainer.FormatVersion,
                capacity)
            {
                WorkspaceIndex = 0,
                WorkspaceRegion = new VaultWorkspaceRegion(Guid.NewGuid(), 0, dataSlotCount),
            };
            var total = Math.Max(checked(capacity + 2 * contentBytes), 1);
            long completed = 0;
            var operationClock = Stopwatch.StartNew();
            void ReportMeasured(CryptoStage stage, string message)
            {
                var seconds = operationClock.Elapsed.TotalSeconds;
                var speed = seconds > 0.25 ? completed / seconds : (double?)null;
                TimeSpan? remaining = speed is > 0 && completed < total
                    ? TimeSpan.FromSeconds((total - completed) / speed.Value)
                    : null;
                progress?.Report(new CryptoProgress(stage, completed, total, message, remaining, speed));
            }
            await WorkspaceVaultContainer.InitializeAsync(
                temporaryPath,
                temporaryInfo,
                capacity,
                keyHeader.Bytes,
                decoyKeyHeader.Bytes,
                (amount, message) =>
                {
                    completed = checked(completed + amount);
                    ReportMeasured(CryptoStage.Encrypting, message);
                },
                cancellationToken).ConfigureAwait(false);

            var entries = plan.Entries.Select(entry => entry with { }).ToList();
            ReportMeasured(CryptoStage.Encrypting, "正在建立加密保险箱…");
            foreach (var file in plan.Files)
            {
                await using var source = OpenVerifiedSource(file);
                var writtenEntry = await VaultFormat.WriteFileAsync(
                    temporaryPath,
                    temporaryInfo,
                    file.Entry,
                    source,
                    dataKey,
                    entries,
                    (amount, message) =>
                    {
                        completed = checked(completed + amount);
                        ReportMeasured(CryptoStage.Encrypting, message);
                    },
                    cancellationToken).ConfigureAwait(false);
                entries[entries.FindIndex(entry => entry.Id == writtenEntry.Id)] = writtenEntry;
                VerifySourceUnchanged(file, source);
            }

            await VaultFormat.WriteCatalogAsync(
                temporaryPath, temporaryInfo, entries, revision: 1, dataKey, cancellationToken).ConfigureAwait(false);
            ReportMeasured(CryptoStage.Verifying, "正在进行首次完整检查…");
            foreach (var entry in entries.Where(entry => !entry.IsDirectory))
            {
                await VaultFormat.VerifyFileAsync(
                    temporaryPath,
                    temporaryInfo,
                    entry,
                    dataKey,
                    (amount, message) =>
                    {
                        completed = Math.Min(total, checked(completed + amount));
                        ReportMeasured(CryptoStage.Verifying, message);
                    },
                    cancellationToken).ConfigureAwait(false);
            }

            cancellationToken.ThrowIfCancellationRequested();
            File.Move(temporaryPath, finalPath);
            created = true;
            completed = total;
            ReportMeasured(CryptoStage.Finalizing, "固定容量保险箱已创建。");
            return new VaultCreationResult(temporaryInfo with { VaultPath = finalPath }, entries.Count, contentBytes);
        }
        catch (NingRanException)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or CryptographicException)
        {
            throw new NingRanException("保险箱没有创建完成，未完成内容已经清理。", exception);
        }
        finally
        {
            if (!created)
            {
                TryDeleteTemporaryVault(temporaryPath);
            }
            if (physicalUnlocks is not null)
            {
                foreach (var unlock in physicalUnlocks) unlock.Dispose();
            }
            if (dataKey is not null) CryptographicOperations.ZeroMemory(dataKey);
            if (decoyDataKey is not null) CryptographicOperations.ZeroMemory(decoyDataKey);
            ClearArchiveHeader(keyHeader);
            ClearArchiveHeader(decoyKeyHeader);
            decoyPassword?.Dispose();
            keyFileSecret?.Dispose();
        }
    }

    public async Task<VaultDualCreationResult> CreateDualAsync(
        CreateDualVaultRequest request,
        IProgress<CryptoProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        WindowsFileSystemSafety.ThrowIfProcessIsElevated();
        PasswordRules.ValidateForCreation(request.DailyPassword);
        PasswordRules.ValidateForCreation(request.HiddenPassword);
        if (request.DailyPassword.FixedTimeEquals(request.HiddenPassword) || PasswordsAreTooSimilar(request.DailyPassword, request.HiddenPassword))
            throw new NingRanException("日常空间密码和秘密密码必须明显不同，不能相同或只相差末尾一个数字、符号。");
        if (request.DailyMode == EncryptionMode.PhysicalDevice)
            throw new NingRanException("为避免设备提示暴露空间差异，双层保险箱首版的日常空间暂不使用物理设备保护。请选择密码或密码加密匙。");
        if (request.DailyMode == EncryptionMode.Advanced && string.IsNullOrWhiteSpace(request.DailyKeyFilePath))
            throw new NingRanException("日常空间选择密码加密匙时，必须选择原始密匙文件。");
        if (request.DailyMode is not (EncryptionMode.Standard or EncryptionMode.Advanced))
            throw new NingRanException("双层保险箱不支持所选日常空间保护方式。");

        var finalPath = VaultFormat.NormalizeVaultPath(request.VaultPath);
        if (File.Exists(finalPath) || Directory.Exists(finalPath))
            throw new NingRanException("保存位置已经有同名内容，请更换保险箱名称。");
        var parent = Path.GetDirectoryName(finalPath) ?? throw new NingRanException("保险箱保存位置不正确。");
        Directory.CreateDirectory(parent);
        using var parentLock = WindowsFileSystemSafety.LockDirectoryPath(parent);
        ValidateSourcesOutsideVault(request.DailySourcePaths, finalPath);
        ValidateSourcesOutsideVault(request.HiddenSourcePaths, finalPath);
        var temporaryPath = Path.Combine(parent, $".{Path.GetFileName(finalPath)}-{Guid.NewGuid():N}.dual.part");

        KeyFileSecret? dailyKeyFileSecret = null;
        ArchiveHeader? dailyKeyHeader = null;
        ArchiveHeader? hiddenKeyHeader = null;
        byte[]? dailyDataKey = null;
        byte[]? hiddenDataKey = null;
        var created = false;
        try
        {
            if (request.DailyMode == EncryptionMode.Advanced)
            {
                dailyKeyFileSecret = await _keyFileService.UnlockAsync(
                    request.DailyKeyFilePath!, request.DailyPassword, cancellationToken).ConfigureAwait(false);
            }
            progress?.Report(new CryptoProgress(CryptoStage.DerivingKey, 0, 1, "正在建立两套互相独立的数据保护…"));
            var dailyCreated = await ArchiveHeader.CreateAsync(
                request.DailyPassword,
                dailyKeyFileSecret?.Memory ?? ReadOnlyMemory<byte>.Empty,
                request.DailyMode,
                hideExactSize: false,
                _kdfParameters,
                cancellationToken).ConfigureAwait(false);
            dailyKeyHeader = dailyCreated.Header;
            dailyDataKey = dailyCreated.DataKey;
            var hiddenCreated = await ArchiveHeader.CreateAsync(
                request.HiddenPassword,
                ReadOnlyMemory<byte>.Empty,
                EncryptionMode.Standard,
                hideExactSize: false,
                _kdfParameters,
                cancellationToken).ConfigureAwait(false);
            hiddenKeyHeader = hiddenCreated.Header;
            hiddenDataKey = hiddenCreated.DataKey;

            var dailyPlan = BuildSourcePlan(request.DailySourcePaths, []);
            var hiddenPlan = BuildSourcePlan(request.HiddenSourcePaths, []);
            var dailyContentBytes = dailyPlan.Files.Sum(file => file.Entry.Length);
            var hiddenContentBytes = hiddenPlan.Files.Sum(file => file.Entry.Length);
            var capacity = request.FixedCapacityBytes ?? WorkspaceVaultContainer.CalculateRecommendedCapacity(
                checked(dailyContentBytes + hiddenContentBytes));
            var totalSlots = WorkspaceVaultContainer.GetDataSlotCount(capacity);
            var dailySlots = request.DailyCapacityBytes is > 0
                ? checked((int)(request.DailyCapacityBytes.Value / VaultFormat.ChunkSize))
                : Math.Max(8, totalSlots * 55 / 100);
            var hiddenSlots = request.HiddenCapacityBytes is > 0
                ? checked((int)(request.HiddenCapacityBytes.Value / VaultFormat.ChunkSize))
                : Math.Max(8, totalSlots * 35 / 100);
            if (dailySlots < 1 || hiddenSlots < 1 || checked((long)dailySlots + hiddenSlots) > totalSlots)
                throw new NingRanException("日常空间和隐蔽空间的容量合计超过保险箱可用容量。");
            var requiredDailySlots = dailyPlan.Files.Sum(file => (long)file.Entry.ChunkCount);
            var requiredHiddenSlots = hiddenPlan.Files.Sum(file => (long)file.Entry.ChunkCount);
            if (requiredDailySlots > dailySlots)
                throw new NingRanException("日常空间初始资料超过所选日常空间容量。");
            if (requiredHiddenSlots > hiddenSlots)
                throw new NingRanException("隐蔽空间初始资料超过所选隐蔽空间容量。");
            var root = Path.GetPathRoot(parent);
            if (!string.IsNullOrEmpty(root) && new DriveInfo(root).AvailableFreeSpace < capacity)
                throw new NingRanException("保存磁盘的剩余空间不足，无法建立所选固定容量的保险箱。");

            var publicInfo = new VaultInfo(
                temporaryPath,
                Guid.NewGuid(),
                request.DailyMode,
                request.SizeProtection,
                DateTimeOffset.UtcNow,
                WorkspaceVaultContainer.FormatVersion,
                capacity);
            var dailyRegion = new VaultWorkspaceRegion(Guid.NewGuid(), 0, dailySlots);
            var hiddenRegion = new VaultWorkspaceRegion(Guid.NewGuid(), totalSlots - hiddenSlots, hiddenSlots);
            var dailyInfo = publicInfo with
            {
                WorkspaceIndex = 0,
                WorkspaceRegion = dailyRegion,
            };
            var hiddenInfo = publicInfo with
            {
                Mode = EncryptionMode.Standard,
                WorkspaceIndex = 1,
                WorkspaceRegion = hiddenRegion,
            };
            var totalWork = Math.Max(checked(capacity + 2 * (dailyContentBytes + hiddenContentBytes)), 1);
            long completed = 0;
            var operationClock = Stopwatch.StartNew();
            void ReportMeasured(CryptoStage stage, string message)
            {
                var seconds = operationClock.Elapsed.TotalSeconds;
                var speed = seconds > 0.25 ? completed / seconds : (double?)null;
                TimeSpan? remaining = speed is > 0 && completed < totalWork
                    ? TimeSpan.FromSeconds((totalWork - completed) / speed.Value)
                    : null;
                progress?.Report(new CryptoProgress(stage, completed, totalWork, message, remaining, speed));
            }

            await WorkspaceVaultContainer.InitializeAsync(
                temporaryPath,
                publicInfo,
                capacity,
                dailyKeyHeader.Bytes,
                hiddenKeyHeader.Bytes,
                (amount, message) =>
                {
                    completed = checked(completed + amount);
                    ReportMeasured(CryptoStage.Encrypting, message);
                },
                cancellationToken).ConfigureAwait(false);

            async Task<List<VaultCatalogEntry>> WriteWorkspaceAsync(
                SourcePlan plan,
                VaultInfo workspaceInfo,
                byte[] dataKey,
                string label)
            {
                var entries = plan.Entries.Select(entry => entry with { }).ToList();
                foreach (var file in plan.Files)
                {
                    await using var source = OpenVerifiedSource(file);
                    var written = await VaultFormat.WriteFileAsync(
                        temporaryPath,
                        workspaceInfo,
                        file.Entry,
                        source,
                        dataKey,
                        entries,
                        (amount, _) =>
                        {
                            completed = checked(completed + amount);
                            ReportMeasured(CryptoStage.Encrypting, $"正在写入{label}资料…");
                        },
                        cancellationToken).ConfigureAwait(false);
                    entries[entries.FindIndex(entry => entry.Id == written.Id)] = written;
                    VerifySourceUnchanged(file, source);
                }
                await VaultFormat.WriteCatalogAsync(
                    temporaryPath, workspaceInfo, entries, 1, dataKey, cancellationToken).ConfigureAwait(false);
                return entries;
            }

            var dailyEntries = await WriteWorkspaceAsync(dailyPlan, dailyInfo, dailyDataKey, "当前空间").ConfigureAwait(false);
            var hiddenEntries = await WriteWorkspaceAsync(hiddenPlan, hiddenInfo, hiddenDataKey, "当前空间").ConfigureAwait(false);

            async Task VerifyWorkspaceAsync(
                VaultInfo workspaceInfo,
                IReadOnlyList<VaultCatalogEntry> entries,
                byte[] dataKey)
            {
                foreach (var entry in entries.Where(entry => !entry.IsDirectory))
                {
                    await VaultFormat.VerifyFileAsync(
                        temporaryPath,
                        workspaceInfo,
                        entry,
                        dataKey,
                        (amount, _) =>
                        {
                            completed = Math.Min(totalWork, checked(completed + amount));
                            ReportMeasured(CryptoStage.Verifying, "正在重新检查保险箱内容…");
                        },
                        cancellationToken).ConfigureAwait(false);
                }
            }

            await VerifyWorkspaceAsync(dailyInfo, dailyEntries, dailyDataKey).ConfigureAwait(false);
            await VerifyWorkspaceAsync(hiddenInfo, hiddenEntries, hiddenDataKey).ConfigureAwait(false);

            var rereadDailyHeader = await WorkspaceVaultContainer.ReadKeyHeaderAsync(temporaryPath, 0, cancellationToken).ConfigureAwait(false);
            var rereadHiddenHeader = await WorkspaceVaultContainer.ReadKeyHeaderAsync(temporaryPath, 1, cancellationToken).ConfigureAwait(false);
            try
            {
                await VerifyWorkspaceUnlockAsync(
                    rereadDailyHeader, request.DailyPassword,
                    dailyKeyFileSecret?.Memory ?? ReadOnlyMemory<byte>.Empty,
                    request.DailyMode, dailyDataKey, cancellationToken).ConfigureAwait(false);
                await VerifyWorkspaceUnlockAsync(
                    rereadHiddenHeader, request.HiddenPassword,
                    ReadOnlyMemory<byte>.Empty,
                    EncryptionMode.Standard, hiddenDataKey, cancellationToken).ConfigureAwait(false);
                await VerifyWorkspaceRejectsPasswordAsync(
                    rereadHiddenHeader, request.DailyPassword, EncryptionMode.Standard, cancellationToken).ConfigureAwait(false);
                await VerifyWorkspaceRejectsPasswordAsync(
                    rereadDailyHeader, request.HiddenPassword, request.DailyMode, cancellationToken,
                    dailyKeyFileSecret?.Memory ?? ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(rereadDailyHeader);
                CryptographicOperations.ZeroMemory(rereadHiddenHeader);
            }

            var rereadDailyCatalog = await WorkspaceVaultContainer.ReadCatalogAsync(
                temporaryPath, dailyInfo, 0, dailyDataKey, cancellationToken).ConfigureAwait(false);
            var rereadHiddenCatalog = await WorkspaceVaultContainer.ReadCatalogAsync(
                temporaryPath, hiddenInfo, 1, hiddenDataKey, cancellationToken).ConfigureAwait(false);
            if (rereadDailyCatalog.Entries.Count != dailyEntries.Count ||
                rereadHiddenCatalog.Entries.Count != hiddenEntries.Count ||
                rereadDailyCatalog.Region != dailyRegion || rereadHiddenCatalog.Region != hiddenRegion)
                throw new NingRanException("双层保险箱重新读取后的空间目录或容量范围不一致。");

            cancellationToken.ThrowIfCancellationRequested();
            File.Move(temporaryPath, finalPath);
            created = true;
            completed = totalWork;
            ReportMeasured(CryptoStage.Finalizing, "双层保险箱已创建并完成两套独立检查。");
            return new VaultDualCreationResult(
                publicInfo with { VaultPath = finalPath },
                dailyEntries.Count,
                dailyContentBytes,
                hiddenEntries.Count,
                hiddenContentBytes);
        }
        catch (NingRanException) { throw; }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or CryptographicException)
        {
            throw new NingRanException("双层保险箱没有创建完成，未完成内容已经清理。", exception);
        }
        finally
        {
            if (!created) TryDeleteTemporaryVault(temporaryPath);
            if (dailyDataKey is not null) CryptographicOperations.ZeroMemory(dailyDataKey);
            if (hiddenDataKey is not null) CryptographicOperations.ZeroMemory(hiddenDataKey);
            ClearArchiveHeader(dailyKeyHeader);
            ClearArchiveHeader(hiddenKeyHeader);
            dailyKeyFileSecret?.Dispose();
        }
    }

    public async Task<VaultSession> UnlockAsync(
        UnlockVaultRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        WindowsFileSystemSafety.ThrowIfProcessIsElevated();
        if (request.Password.IsEmpty) throw new NingRanException("请输入保险箱密码。");
        var requestedPath = VaultFormat.NormalizeVaultPath(request.VaultPath);
        string? workingPath = null;
        var fixedContainer = File.Exists(requestedPath) && FixedVaultContainer.IsFormat(requestedPath);
        if (File.Exists(requestedPath) && !fixedContainer)
        {
            workingPath = VaultContainer.CreateWorkingDirectory(requestedPath);
            try { VaultContainer.Extract(requestedPath, workingPath); }
            catch { VaultContainer.DeleteWorkingDirectory(workingPath); throw; }
        }
        VaultInfo info;
        try
        {
            info = fixedContainer
                ? await FixedVaultContainer.ReadInfoAsync(requestedPath, cancellationToken).ConfigureAwait(false)
                : await VaultFormat.ReadInfoFromDirectoryAsync(workingPath ?? requestedPath, cancellationToken).ConfigureAwait(false);
            if (workingPath is not null) info = info with { VaultPath = workingPath };
        }
        catch
        {
            if (workingPath is not null) VaultContainer.DeleteWorkingDirectory(workingPath);
            throw;
        }
        if (info.FormatVersion == WorkspaceVaultContainer.FormatVersion)
        {
            return await UnlockWorkspaceContainerAsync(request, info, cancellationToken).ConfigureAwait(false);
        }
        KeyFileSecret? keyFileSecret = null;
        Stream? keyInput = null;
        byte[]? fixedKeyBytes = null;
        ArchiveHeader? keyHeader = null;
        byte[]? dataKey = null;
        PhysicalDeviceUnlock? physicalUnlock = null;
        PhysicalDeviceMonitor? physicalMonitor = null;
        try
        {
            if (info.Mode == EncryptionMode.Advanced)
            {
                if (string.IsNullOrWhiteSpace(request.KeyFilePath))
                {
                    throw new NingRanException("此保险箱需要同时选择原来的密匙文件。");
                }
                keyFileSecret = await _keyFileService.UnlockAsync(
                    request.KeyFilePath, request.Password, cancellationToken).ConfigureAwait(false);
            }
            if (fixedContainer)
            {
                fixedKeyBytes = await FixedVaultContainer.ReadKeyHeaderAsync(requestedPath, cancellationToken).ConfigureAwait(false);
                keyInput = new MemoryStream(fixedKeyBytes, writable: false);
            }
            else
            {
                keyInput = new FileStream(Path.Combine(info.VaultPath, "vault.keys"), FileMode.Open, FileAccess.Read,
                    FileShare.Read, 4096, FileOptions.Asynchronous | FileOptions.SequentialScan);
            }
            var unlocked = await ArchiveHeader.ReadAndUnlockAsync(
                keyInput,
                request.Password,
                keyFileSecret?.Memory ?? ReadOnlyMemory<byte>.Empty,
                _physicalDeviceProvider,
                request.OwnerWindowHandle,
                cancellationToken,
                info.Mode).ConfigureAwait(false);
            keyHeader = unlocked.Header;
            dataKey = unlocked.DataKey;
            physicalUnlock = unlocked.PhysicalUnlock;
            keyInput.Dispose();
            keyInput = null;
            if (physicalUnlock is not null)
            {
                physicalMonitor = new PhysicalDeviceMonitor([physicalUnlock], cancellationToken);
            }
            var operationToken = physicalMonitor?.Token ?? cancellationToken;
            var catalog = await VaultFormat.ReadCatalogAsync(info.VaultPath, info, dataKey, operationToken)
                .ConfigureAwait(false);
            var session = new VaultSession(
                info, keyHeader, dataKey, catalog.Entries, catalog.Revision,
                physicalUnlock, physicalMonitor, workingPath is not null);
            if (workingPath is not null) session.AttachSingleFileContainer(requestedPath, workingPath);
            keyHeader = null;
            dataKey = null;
            physicalUnlock = null;
            physicalMonitor = null;
            return session;
        }
        catch
        {
            if (workingPath is not null) VaultContainer.DeleteWorkingDirectory(workingPath);
            if (physicalMonitor is not null) await physicalMonitor.DisposeAsync().ConfigureAwait(false);
            physicalUnlock?.Dispose();
            if (dataKey is not null) CryptographicOperations.ZeroMemory(dataKey);
            if (keyHeader is not null)
            {
                CryptographicOperations.ZeroMemory(keyHeader.Bytes);
                CryptographicOperations.ZeroMemory(keyHeader.PayloadNoncePrefix);
                CryptographicOperations.ZeroMemory(keyHeader.HeaderHash);
            }
            throw;
        }
        finally
        {
            keyInput?.Dispose();
            if (fixedKeyBytes is not null) CryptographicOperations.ZeroMemory(fixedKeyBytes);
            keyFileSecret?.Dispose();
        }
    }

    private async Task<VaultSession> UnlockWorkspaceContainerAsync(
        UnlockVaultRequest request,
        VaultInfo publicInfo,
        CancellationToken cancellationToken)
    {
        byte[]? firstHeaderBytes = null;
        byte[]? secondHeaderBytes = null;
        KeyFileSecret? keyFileSecret = null;
        WorkspaceUnlockAttempt? first = null;
        WorkspaceUnlockAttempt? second = null;
        try
        {
            firstHeaderBytes = await WorkspaceVaultContainer.ReadKeyHeaderAsync(
                publicInfo.VaultPath, 0, cancellationToken).ConfigureAwait(false);
            secondHeaderBytes = await WorkspaceVaultContainer.ReadKeyHeaderAsync(
                publicInfo.VaultPath, 1, cancellationToken).ConfigureAwait(false);
            if (publicInfo.Mode == EncryptionMode.Advanced && !string.IsNullOrWhiteSpace(request.KeyFilePath))
            {
                try
                {
                    keyFileSecret = await _keyFileService.UnlockAsync(
                        request.KeyFilePath, request.Password, cancellationToken).ConfigureAwait(false);
                }
                catch (NingRanException)
                {
                    // Continue with an empty secret so the second password-only envelope is still attempted.
                }
            }

            first = await TryUnlockWorkspaceHeaderAsync(
                firstHeaderBytes,
                request.Password,
                keyFileSecret?.Memory ?? ReadOnlyMemory<byte>.Empty,
                publicInfo.Mode,
                request.OwnerWindowHandle,
                cancellationToken).ConfigureAwait(false);
            second = await TryUnlockWorkspaceHeaderAsync(
                secondHeaderBytes,
                request.Password,
                ReadOnlyMemory<byte>.Empty,
                EncryptionMode.Standard,
                request.OwnerWindowHandle,
                cancellationToken).ConfigureAwait(false);

            if ((first is null) == (second is null))
                throw new NingRanException("无法解锁保险箱。密码条件不正确，或保险箱已经损坏。");
            var selected = first ?? second!;
            var workspaceIndex = first is not null ? 0 : 1;
            VaultWorkspaceCatalog catalog;
            try
            {
                catalog = await WorkspaceVaultContainer.ReadCatalogAsync(
                    publicInfo.VaultPath,
                    publicInfo,
                    workspaceIndex,
                    selected.DataKey,
                    cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                throw new NingRanException("无法解锁保险箱。密码条件不正确，或保险箱已经损坏。");
            }
            var sessionInfo = publicInfo with
            {
                Mode = selected.Header.Mode,
                WorkspaceIndex = workspaceIndex,
                WorkspaceRegion = catalog.Region,
            };
            PhysicalDeviceMonitor? monitor = null;
            try
            {
                if (selected.PhysicalUnlock is not null)
                    monitor = new PhysicalDeviceMonitor([selected.PhysicalUnlock], cancellationToken);
                var session = new VaultSession(
                    sessionInfo,
                    selected.Header,
                    selected.DataKey,
                    catalog.Entries,
                    catalog.Revision,
                    selected.PhysicalUnlock,
                    monitor,
                    embeddedContainer: false);
                selected.Detach();
                if (ReferenceEquals(selected, first)) first = null; else second = null;
                return session;
            }
            catch
            {
                if (monitor is not null) await monitor.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (NingRanException exception) when (exception.Message == "无法解锁保险箱。密码条件不正确，或保险箱已经损坏。")
        {
            throw;
        }
        catch
        {
            throw new NingRanException("无法解锁保险箱。密码条件不正确，或保险箱已经损坏。");
        }
        finally
        {
            first?.Dispose();
            second?.Dispose();
            keyFileSecret?.Dispose();
            if (firstHeaderBytes is not null) CryptographicOperations.ZeroMemory(firstHeaderBytes);
            if (secondHeaderBytes is not null) CryptographicOperations.ZeroMemory(secondHeaderBytes);
        }
    }

    private async Task<WorkspaceUnlockAttempt?> TryUnlockWorkspaceHeaderAsync(
        byte[] headerBytes,
        SensitivePassword password,
        ReadOnlyMemory<byte> keyFileSecret,
        EncryptionMode expectedMode,
        nint ownerWindowHandle,
        CancellationToken cancellationToken)
    {
        try
        {
            using var input = new MemoryStream(headerBytes, writable: false);
            var unlocked = await ArchiveHeader.ReadAndUnlockAsync(
                input,
                password,
                keyFileSecret,
                _physicalDeviceProvider,
                ownerWindowHandle,
                cancellationToken,
                expectedMode).ConfigureAwait(false);
            return new WorkspaceUnlockAttempt(unlocked.Header, unlocked.DataKey, unlocked.PhysicalUnlock);
        }
        catch (OperationCanceledException) { throw; }
        catch (NingRanException) { return null; }
    }

    public async Task<VaultUpgradeResult> UpgradeLegacyAsync(
        UpgradeVaultRequest request,
        IProgress<CryptoProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        WindowsFileSystemSafety.ThrowIfProcessIsElevated();
        if (request.Password.IsEmpty) throw new NingRanException("请输入旧保险箱密码。");
        var sourcePath = VaultFormat.NormalizeVaultPath(request.SourceVaultPath);
        var targetPath = VaultFormat.NormalizeVaultPath(request.TargetVaultPath);
        if (!File.Exists(sourcePath) || FixedVaultContainer.IsFormat(sourcePath))
            throw new NingRanException("请选择旧版单文件保险箱进行升级。");
        if (string.Equals(sourcePath, targetPath, StringComparison.OrdinalIgnoreCase))
            throw new NingRanException("新版保险箱必须另存为新文件，不能覆盖原保险箱。");
        if (File.Exists(targetPath) || Directory.Exists(targetPath))
            throw new NingRanException("新版保存位置已经存在同名内容，请更换名称。");

        var sourceInfo = await VaultContainer.ReadInfoWithoutExtractingAsync(sourcePath, cancellationToken)
            .ConfigureAwait(false);
        var parent = Path.GetDirectoryName(targetPath) ?? throw new NingRanException("新版保险箱保存位置不正确。");
        Directory.CreateDirectory(parent);
        using var parentLock = WindowsFileSystemSafety.LockDirectoryPath(parent);
        var temporaryPath = Path.Combine(parent, $".{Path.GetFileName(targetPath)}-{Guid.NewGuid():N}.upgrade.part");
        KeyFileSecret? keyFileSecret = null;
        ArchiveHeader? keyHeader = null;
        byte[]? keyHeaderBytes = null;
        byte[]? dataKey = null;
        PhysicalDeviceUnlock? physicalUnlock = null;
        var finalPlaced = false;
        var completedSuccessfully = false;
        try
        {
            using var reader = new LegacyPackedVaultReader(sourcePath, sourceInfo);
            if (sourceInfo.Mode == EncryptionMode.Advanced)
            {
                if (string.IsNullOrWhiteSpace(request.KeyFilePath))
                    throw new NingRanException("此旧保险箱需要同时选择原来的密匙文件。");
                keyFileSecret = await _keyFileService.UnlockAsync(
                    request.KeyFilePath, request.Password, cancellationToken).ConfigureAwait(false);
            }

            progress?.Report(new CryptoProgress(CryptoStage.DerivingKey, 0, 1, "正在验证旧保险箱保护条件…"));
            keyHeaderBytes = await reader.ReadKeyHeaderAsync(cancellationToken).ConfigureAwait(false);
            using (var keyInput = new MemoryStream(keyHeaderBytes, writable: false))
            {
                var unlocked = await ArchiveHeader.ReadAndUnlockAsync(
                    keyInput,
                    request.Password,
                    keyFileSecret?.Memory ?? ReadOnlyMemory<byte>.Empty,
                    _physicalDeviceProvider,
                    request.OwnerWindowHandle,
                    cancellationToken,
                    sourceInfo.Mode).ConfigureAwait(false);
                keyHeader = unlocked.Header;
                dataKey = unlocked.DataKey;
                physicalUnlock = unlocked.PhysicalUnlock;
            }

            var legacyCatalog = await reader.ReadCatalogAsync(dataKey, cancellationToken).ConfigureAwait(false);
            var entries = legacyCatalog.Entries.Select(entry => entry with { BlockSlots = null }).ToList();
            SetRelativePaths(entries);
            var contentBytes = entries.Where(entry => !entry.IsDirectory).Sum(entry => entry.Length);
            var requiredSlots = entries.Where(entry => !entry.IsDirectory).Sum(entry => (long)entry.ChunkCount);
            var capacity = request.FixedCapacityBytes ?? FixedVaultContainer.CalculateRecommendedCapacity(contentBytes);
            if (requiredSlots > FixedVaultContainer.GetDataSlotCount(capacity))
                throw new NingRanException("旧保险箱内容超过所选新版固定容量，请选择更大的容量。");
            var driveRoot = Path.GetPathRoot(parent);
            if (!string.IsNullOrEmpty(driveRoot) && new DriveInfo(driveRoot).AvailableFreeSpace < capacity)
                throw new NingRanException("保存磁盘的剩余空间不足，无法生成所选固定容量的新版保险箱。");

            var upgradedTemporaryInfo = new VaultInfo(
                temporaryPath,
                sourceInfo.VaultId,
                sourceInfo.Mode,
                sourceInfo.SizeProtection,
                sourceInfo.CreatedAt,
                FixedVaultContainer.FormatVersion,
                capacity);
            var total = Math.Max(checked(capacity + 2 * contentBytes), 1);
            long progressed = 0;
            var upgradeClock = Stopwatch.StartNew();
            void ReportUpgrade(CryptoStage stage, string message)
            {
                var seconds = upgradeClock.Elapsed.TotalSeconds;
                var speed = seconds > 0.25 ? progressed / seconds : (double?)null;
                TimeSpan? remaining = speed is > 0 && progressed < total
                    ? TimeSpan.FromSeconds((total - progressed) / speed.Value)
                    : null;
                progress?.Report(new CryptoProgress(stage, progressed, total, message, remaining, speed));
            }
            await FixedVaultContainer.InitializeAsync(
                temporaryPath,
                upgradedTemporaryInfo,
                capacity,
                keyHeaderBytes,
                (amount, message) =>
                {
                    progressed = checked(progressed + amount);
                    ReportUpgrade(CryptoStage.Encrypting, message);
                },
                cancellationToken).ConfigureAwait(false);

            foreach (var legacyEntry in entries.Where(entry => !entry.IsDirectory).ToArray())
            {
                cancellationToken.ThrowIfCancellationRequested();
                await using var plaintext = reader.OpenPlaintextStream(legacyEntry, dataKey, cancellationToken);
                var written = await VaultFormat.WriteFileAsync(
                    temporaryPath,
                    upgradedTemporaryInfo,
                    legacyEntry,
                    plaintext,
                    dataKey,
                    entries,
                    (amount, message) =>
                    {
                        progressed = checked(progressed + amount);
                        ReportUpgrade(CryptoStage.Encrypting, $"正在升级：{legacyEntry.RelativePath}");
                    },
                    cancellationToken).ConfigureAwait(false);
                entries[entries.FindIndex(entry => entry.Id == written.Id)] = written;
            }

            await VaultFormat.WriteCatalogAsync(
                temporaryPath,
                upgradedTemporaryInfo,
                entries,
                revision: Math.Max(1, legacyCatalog.Revision),
                dataKey,
                cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            File.Move(temporaryPath, targetPath);
            finalPlaced = true;

            var finalInfo = await FixedVaultContainer.ReadInfoAsync(targetPath, cancellationToken).ConfigureAwait(false);
            var rereadKeyHeader = await FixedVaultContainer.ReadKeyHeaderAsync(targetPath, cancellationToken).ConfigureAwait(false);
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(rereadKeyHeader, keyHeaderBytes))
                    throw new NingRanException("新版保险箱的保护信息重新读取后不一致。");
            }
            finally { CryptographicOperations.ZeroMemory(rereadKeyHeader); }
            var rereadCatalog = await FixedVaultContainer.ReadCatalogAsync(
                targetPath, finalInfo, dataKey, cancellationToken).ConfigureAwait(false);
            foreach (var entry in rereadCatalog.Entries.Where(entry => !entry.IsDirectory))
            {
                await FixedVaultContainer.VerifyFileAsync(
                    targetPath,
                    finalInfo,
                    entry,
                    dataKey,
                    (amount, message) =>
                    {
                        progressed = Math.Min(total, checked(progressed + amount));
                        ReportUpgrade(CryptoStage.Verifying, $"正在重新检查：{entry.RelativePath}");
                    },
                    cancellationToken).ConfigureAwait(false);
            }
            if (rereadCatalog.Entries.Count != entries.Count || rereadCatalog.Revision != Math.Max(1, legacyCatalog.Revision))
                throw new NingRanException("新版保险箱重新读取后的目录数量或修改编号不一致。");

            completedSuccessfully = true;
            progressed = total;
            ReportUpgrade(CryptoStage.Finalizing, "旧保险箱已升级为新版，原文件保持不变。");
            return new VaultUpgradeResult(sourceInfo, finalInfo, entries.Count, contentBytes);
        }
        catch (NingRanException) { throw; }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or CryptographicException or InvalidDataException)
        {
            throw new NingRanException("旧保险箱没有升级完成，未完成的新版文件已经清理，原文件没有改变。", exception);
        }
        finally
        {
            if (!completedSuccessfully)
            {
                TryDeleteTemporaryVault(temporaryPath);
                if (finalPlaced) TryDeleteTemporaryVault(targetPath);
            }
            physicalUnlock?.Dispose();
            if (dataKey is not null) CryptographicOperations.ZeroMemory(dataKey);
            if (keyHeader is not null)
            {
                CryptographicOperations.ZeroMemory(keyHeader.Bytes);
                CryptographicOperations.ZeroMemory(keyHeader.PayloadNoncePrefix);
                CryptographicOperations.ZeroMemory(keyHeader.HeaderHash);
            }
            if (keyHeaderBytes is not null) CryptographicOperations.ZeroMemory(keyHeaderBytes);
            keyFileSecret?.Dispose();
        }
    }

    public async Task<VaultImportResult> AddSourcesAsync(
        VaultSession session,
        IReadOnlyList<string> sourcePaths,
        IProgress<CryptoProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(sourcePaths);
        if (!session.IsOpen) throw new NingRanException("保险箱已经锁定，请重新解锁。");
        ValidateSourcesOutsideVault(sourcePaths, session.VaultPath);
        var plan = BuildSourcePlan(sourcePaths, session.Catalog);
        if (plan.NewEntries.Count == 0) return new VaultImportResult(0, 0);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(session.CancellationToken, cancellationToken);
        var token = linked.Token;
        var total = Math.Max(plan.Files.Sum(file => file.Entry.Length), 1);
        var createdFiles = new List<Guid>();
        var entries = plan.Entries.Select(entry => entry with { }).ToList();
        long completed = 0;
        try
        {
            foreach (var file in plan.Files)
            {
                await using var source = OpenVerifiedSource(file);
                var writtenEntry = await VaultFormat.WriteFileAsync(
                    session.VaultPath,
                    session.Info,
                    file.Entry,
                    source,
                    session.DataKey,
                    entries,
                    (amount, message) =>
                    {
                        completed = checked(completed + amount);
                        progress?.Report(new CryptoProgress(CryptoStage.Encrypting, completed, total, message));
                    },
                    token).ConfigureAwait(false);
                entries[entries.FindIndex(entry => entry.Id == writtenEntry.Id)] = writtenEntry;
                VerifySourceUnchanged(file, source);
                createdFiles.Add(file.Entry.Id);
            }
            var revision = checked(session.Revision + 1);
            await VaultFormat.WriteCatalogAsync(
                session.VaultPath, session.Info, entries, revision, session.DataKey, token).ConfigureAwait(false);
            session.ReplaceCatalog(entries, revision);
            return new VaultImportResult(plan.NewEntries.Count, plan.Files.Sum(file => file.Entry.Length));
        }
        catch
        {
            foreach (var fileId in createdFiles)
            {
                try { VaultFormat.DeleteFileData(session.VaultPath, fileId); } catch { }
            }
            throw;
        }
    }

    public async Task<VaultImportResult> ImportArchiveAsync(
        VaultSession vault,
        SecureArchiveSession archive,
        IReadOnlyCollection<string>? selectedPaths = null,
        IProgress<CryptoProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(vault);
        ArgumentNullException.ThrowIfNull(archive);
        var selected = selectedPaths is null || selectedPaths.Count == 0
            ? archive.Entries
            : archive.Entries.Where(entry => selectedPaths.Any(path =>
                string.Equals(entry.RelativePath, path, StringComparison.OrdinalIgnoreCase) ||
                entry.RelativePath.StartsWith(path.TrimEnd('/') + "/", StringComparison.OrdinalIgnoreCase))).ToArray();
        if (selected.Count == 0) return new VaultImportResult(0, 0);

        var catalog = vault.Catalog.Select(entry => entry with { }).ToList();
        var rootName = GetUniqueRootName(archive.RootName, catalog);
        var rootId = Guid.NewGuid();
        var rootSource = selected.FirstOrDefault(entry =>
            string.Equals(entry.RelativePath, archive.RootName, StringComparison.OrdinalIgnoreCase));
        var rootIsDirectory = archive.IsDirectory || selected.Count > 1;
        catalog.Add(new VaultCatalogEntry(
            rootId, Guid.Empty, rootName, rootIsDirectory,
            rootIsDirectory ? 0 : rootSource?.Length ?? selected[0].Length,
            rootSource?.LastWriteUtcTicks ?? DateTime.UtcNow.Ticks,
            rootIsDirectory ? 0 : ChunkCount(rootSource?.Length ?? selected[0].Length)));

        var newEntries = new List<VaultCatalogEntry> { catalog[^1] };
        var sourceByEntry = new Dictionary<Guid, SecureArchiveEntry>();
        if (!rootIsDirectory)
        {
            sourceByEntry[rootId] = rootSource ?? selected[0];
        }
        else
        {
            var directoryIds = new Dictionary<string, Guid>(StringComparer.OrdinalIgnoreCase)
            {
                [archive.RootName] = rootId,
            };
            foreach (var source in selected.OrderBy(entry => entry.RelativePath.Count(character => character == '/')))
            {
                if (string.Equals(source.RelativePath, archive.RootName, StringComparison.OrdinalIgnoreCase)) continue;
                var relative = source.RelativePath;
                var prefix = archive.RootName + "/";
                if (relative.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) relative = relative[prefix.Length..];
                var parts = relative.Split('/', StringSplitOptions.RemoveEmptyEntries);
                var parentId = rootId;
                var parentPath = archive.RootName;
                for (var index = 0; index < parts.Length - 1; index++)
                {
                    parentPath += "/" + parts[index];
                    if (!directoryIds.TryGetValue(parentPath, out var directoryId))
                    {
                        directoryId = Guid.NewGuid();
                        directoryIds.Add(parentPath, directoryId);
                        var directory = new VaultCatalogEntry(
                            directoryId, parentId, parts[index], true, 0, source.LastWriteUtcTicks, 0);
                        catalog.Add(directory);
                        newEntries.Add(directory);
                    }
                    parentId = directoryId;
                }
                if (parts.Length == 0) continue;
                var entry = new VaultCatalogEntry(
                    Guid.NewGuid(), parentId, parts[^1], source.IsDirectory,
                    source.IsDirectory ? 0 : source.Length,
                    source.LastWriteUtcTicks,
                    source.IsDirectory ? 0 : ChunkCount(source.Length));
                catalog.Add(entry);
                newEntries.Add(entry);
                if (source.IsDirectory)
                {
                    directoryIds[source.RelativePath] = entry.Id;
                }
                else
                {
                    sourceByEntry[entry.Id] = source;
                }
            }
        }

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(
            vault.CancellationToken, archive.CancellationToken, cancellationToken);
        var total = Math.Max(sourceByEntry.Values.Sum(entry => entry.Length), 1);
        long completed = 0;
        var createdFiles = new List<Guid>();
        try
        {
            foreach (var pair in sourceByEntry)
            {
                var target = catalog.First(entry => entry.Id == pair.Key);
                await using var source = archive.OpenEntryReadStream(pair.Value.RelativePath);
                var writtenEntry = await VaultFormat.WriteFileAsync(
                    vault.VaultPath,
                    vault.Info,
                    target,
                    source,
                    vault.DataKey,
                    catalog,
                    (amount, message) =>
                    {
                        completed = checked(completed + amount);
                        progress?.Report(new CryptoProgress(CryptoStage.Encrypting, completed, total, message));
                    },
                    linked.Token).ConfigureAwait(false);
                catalog[catalog.FindIndex(entry => entry.Id == writtenEntry.Id)] = writtenEntry;
                createdFiles.Add(target.Id);
            }
            var revision = checked(vault.Revision + 1);
            await VaultFormat.WriteCatalogAsync(
                vault.VaultPath, vault.Info, catalog, revision, vault.DataKey, linked.Token).ConfigureAwait(false);
            vault.ReplaceCatalog(catalog, revision);
            return new VaultImportResult(newEntries.Count, sourceByEntry.Values.Sum(entry => entry.Length));
        }
        catch
        {
            foreach (var fileId in createdFiles)
            {
                try { VaultFormat.DeleteFileData(vault.VaultPath, fileId); } catch { }
            }
            throw;
        }
    }

    private static async Task WriteKeyFileAsync(string path, byte[] bytes, CancellationToken cancellationToken)
    {
        await using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None,
            4096, FileOptions.Asynchronous | FileOptions.WriteThrough);
        await output.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
        await output.FlushAsync(cancellationToken).ConfigureAwait(false);
        output.Flush(flushToDisk: true);
    }

    private async Task VerifyWorkspaceUnlockAsync(
        byte[] headerBytes,
        SensitivePassword password,
        ReadOnlyMemory<byte> keyFileSecret,
        EncryptionMode mode,
        byte[] expectedDataKey,
        CancellationToken cancellationToken)
    {
        ArchiveHeader? header = null;
        byte[]? dataKey = null;
        PhysicalDeviceUnlock? physicalUnlock = null;
        try
        {
            using var input = new MemoryStream(headerBytes, writable: false);
            var unlocked = await ArchiveHeader.ReadAndUnlockAsync(
                input, password, keyFileSecret, _physicalDeviceProvider, 0,
                cancellationToken, mode).ConfigureAwait(false);
            header = unlocked.Header;
            dataKey = unlocked.DataKey;
            physicalUnlock = unlocked.PhysicalUnlock;
            if (!CryptographicOperations.FixedTimeEquals(dataKey, expectedDataKey))
                throw new NingRanException("保险箱重新解锁后的数据钥匙不一致。");
        }
        finally
        {
            physicalUnlock?.Dispose();
            if (dataKey is not null) CryptographicOperations.ZeroMemory(dataKey);
            ClearArchiveHeader(header);
        }
    }

    private async Task VerifyWorkspaceRejectsPasswordAsync(
        byte[] headerBytes,
        SensitivePassword password,
        EncryptionMode mode,
        CancellationToken cancellationToken,
        ReadOnlyMemory<byte> keyFileSecret = default)
    {
        ArchiveHeader? header = null;
        byte[]? dataKey = null;
        PhysicalDeviceUnlock? physicalUnlock = null;
        try
        {
            using var input = new MemoryStream(headerBytes, writable: false);
            try
            {
                var unlocked = await ArchiveHeader.ReadAndUnlockAsync(
                    input, password, keyFileSecret, _physicalDeviceProvider, 0,
                    cancellationToken, mode).ConfigureAwait(false);
                header = unlocked.Header;
                dataKey = unlocked.DataKey;
                physicalUnlock = unlocked.PhysicalUnlock;
            }
            catch (NingRanException) { return; }
            throw new NingRanException("一套空间密码错误地解开了另一套空间保护。");
        }
        finally
        {
            physicalUnlock?.Dispose();
            if (dataKey is not null) CryptographicOperations.ZeroMemory(dataKey);
            ClearArchiveHeader(header);
        }
    }

    private static bool PasswordsAreTooSimilar(SensitivePassword first, SensitivePassword second)
    {
        var left = first.CopyCharacters();
        var right = second.CopyCharacters();
        try
        {
            if (left.AsSpan().SequenceEqual(right)) return true;
            static bool IsWeakSuffix(char value) => char.IsDigit(value) || "!@#$%^&*_-+=.?".Contains(value);
            if (Math.Abs(left.Length - right.Length) == 1)
            {
                var longer = left.Length > right.Length ? left : right;
                var shorter = left.Length > right.Length ? right : left;
                if (longer.AsSpan(0, shorter.Length).SequenceEqual(shorter) && IsWeakSuffix(longer[^1])) return true;
            }
            return left.Length == right.Length && left.Length > 0 &&
                   left.AsSpan(0, left.Length - 1).SequenceEqual(right.AsSpan(0, right.Length - 1)) &&
                   IsWeakSuffix(left[^1]) && IsWeakSuffix(right[^1]);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(System.Runtime.InteropServices.MemoryMarshal.AsBytes(left.AsSpan()));
            CryptographicOperations.ZeroMemory(System.Runtime.InteropServices.MemoryMarshal.AsBytes(right.AsSpan()));
        }
    }

    private static void ClearArchiveHeader(ArchiveHeader? header)
    {
        if (header is null) return;
        CryptographicOperations.ZeroMemory(header.Bytes);
        CryptographicOperations.ZeroMemory(header.PayloadNoncePrefix);
        CryptographicOperations.ZeroMemory(header.HeaderHash);
    }

    private static void ValidateMode(
        EncryptionMode mode,
        string? keyFilePath,
        IReadOnlyList<PhysicalDeviceDescriptor> physicalDevices)
    {
        if (mode == EncryptionMode.Advanced && string.IsNullOrWhiteSpace(keyFilePath))
        {
            throw new NingRanException("密码加密匙方式必须选择一个普通文件或凝然专用密匙文件。");
        }
        if (mode == EncryptionMode.PhysicalDevice && physicalDevices.Count == 0)
        {
            throw new NingRanException("密码加物理设备方式必须至少选择一个已登记设备。");
        }
        if (mode is not (EncryptionMode.Standard or EncryptionMode.Advanced or EncryptionMode.PhysicalDevice))
        {
            throw new NingRanException("不支持所选的保险箱保护方式。");
        }
    }

    private static void ValidateSourcesOutsideVault(IReadOnlyList<string> sourcePaths, string vaultPath)
    {
        foreach (var sourcePath in sourcePaths)
        {
            var source = Path.GetFullPath(sourcePath);
            if (Directory.Exists(source) && PathSafety.IsWithinDirectory(vaultPath, source) ||
                string.Equals(source, vaultPath, StringComparison.OrdinalIgnoreCase))
            {
                throw new NingRanException("保险箱不能创建在准备加入的文件夹内部，请更换保存位置。");
            }
        }
    }

    private static SourcePlan BuildSourcePlan(
        IReadOnlyList<string> sourcePaths,
        IReadOnlyList<VaultCatalogEntry> existing)
    {
        var entries = existing.Select(entry => entry with { }).ToList();
        var newEntries = new List<VaultCatalogEntry>();
        var files = new List<SourceFile>();
        var roots = entries.Where(entry => entry.ParentId == Guid.Empty)
            .Select(entry => entry.Name)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var normalizedSources = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var requestedPath in sourcePaths)
        {
            var fullPath = Path.GetFullPath(requestedPath);
            if (!normalizedSources.Add(fullPath)) continue;
            var isFile = File.Exists(fullPath);
            var isDirectory = Directory.Exists(fullPath);
            if (!isFile && !isDirectory)
            {
                throw new NingRanException("准备加入保险箱的文件或文件夹不存在。");
            }
            RejectReparsePoint(fullPath);
            var baseName = PathSafety.ValidateNameSegment(
                isFile ? Path.GetFileName(fullPath) : new DirectoryInfo(fullPath).Name);
            var rootName = GetUniqueName(baseName, roots);
            roots.Add(rootName);
            if (isFile)
            {
                AddSourceFile(fullPath, Guid.Empty, rootName, entries, newEntries, files);
                continue;
            }

            var rootInfo = new DirectoryInfo(fullPath);
            var rootEntry = new VaultCatalogEntry(
                Guid.NewGuid(), Guid.Empty, rootName, true, 0, rootInfo.LastWriteTimeUtc.Ticks, 0);
            entries.Add(rootEntry);
            newEntries.Add(rootEntry);
            var pending = new Stack<(DirectoryInfo Directory, Guid ParentId)>();
            pending.Push((rootInfo, rootEntry.Id));
            while (pending.Count > 0)
            {
                var current = pending.Pop();
                FileSystemInfo[] children;
                try
                {
                    children = current.Directory.GetFileSystemInfos()
                        .OrderBy(item => item is FileInfo)
                        .ThenBy(item => item.Name, StringComparer.OrdinalIgnoreCase)
                        .ToArray();
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                {
                    throw new NingRanException($"无法读取文件夹：{current.Directory.FullName}", exception);
                }
                foreach (var child in children)
                {
                    if (entries.Count >= VaultFormat.MaximumEntries)
                    {
                        throw new NingRanException($"保险箱最多支持 {VaultFormat.MaximumEntries:N0} 个文件和文件夹。");
                    }
                    RejectReparsePoint(child.FullName);
                    var name = PathSafety.ValidateNameSegment(child.Name);
                    if (child is DirectoryInfo directory)
                    {
                        var entry = new VaultCatalogEntry(
                            Guid.NewGuid(), current.ParentId, name, true, 0, directory.LastWriteTimeUtc.Ticks, 0);
                        entries.Add(entry);
                        newEntries.Add(entry);
                        pending.Push((directory, entry.Id));
                    }
                    else
                    {
                        AddSourceFile(child.FullName, current.ParentId, name, entries, newEntries, files);
                    }
                }
            }
        }

        SetRelativePaths(entries);
        return new SourcePlan(entries, newEntries, files);
    }

    private static void AddSourceFile(
        string fullPath,
        Guid parentId,
        string name,
        ICollection<VaultCatalogEntry> entries,
        ICollection<VaultCatalogEntry> newEntries,
        ICollection<SourceFile> files)
    {
        var info = new FileInfo(fullPath);
        var entry = new VaultCatalogEntry(
            Guid.NewGuid(), parentId, name, false, info.Length, info.LastWriteTimeUtc.Ticks, ChunkCount(info.Length));
        entries.Add(entry);
        newEntries.Add(entry);
        files.Add(new SourceFile(entry, fullPath));
    }

    private static FileStream OpenVerifiedSource(SourceFile source)
    {
        var handle = WindowsFileSystemSafety.OpenInputFile(source.FullPath);
        try
        {
            var stream = new FileStream(handle, FileAccess.Read, VaultFormat.ChunkSize, isAsync: true);
            if (stream.Length != source.Entry.Length || File.GetLastWriteTimeUtc(handle).Ticks != source.Entry.LastWriteUtcTicks)
            {
                stream.Dispose();
                throw new NingRanException($"文件在准备后发生了变化：{source.Entry.RelativePath}");
            }
            return stream;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private static void VerifySourceUnchanged(SourceFile source, FileStream stream)
    {
        if (stream.Length != source.Entry.Length ||
            stream.Position != stream.Length ||
            File.GetLastWriteTimeUtc(stream.SafeFileHandle).Ticks != source.Entry.LastWriteUtcTicks)
        {
            throw new NingRanException($"文件在加入保险箱时发生了变化：{source.Entry.RelativePath}");
        }
    }

    private static int ChunkCount(long length) =>
        length == 0 ? 0 : checked((int)((length + VaultFormat.ChunkSize - 1) / VaultFormat.ChunkSize));

    private static string GetUniqueRootName(string name, IReadOnlyList<VaultCatalogEntry> entries) =>
        GetUniqueName(name, entries.Where(entry => entry.ParentId == Guid.Empty).Select(entry => entry.Name));

    private static string GetUniqueName(string name, IEnumerable<string> existing)
    {
        var used = existing.ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (!used.Contains(name)) return name;
        var extension = Path.GetExtension(name);
        var stem = Path.GetFileNameWithoutExtension(name);
        for (var index = 1; ; index++)
        {
            var candidate = $"{stem} ({index}){extension}";
            if (!used.Contains(candidate)) return candidate;
        }
    }

    private static void SetRelativePaths(IReadOnlyList<VaultCatalogEntry> entries)
    {
        var byId = entries.ToDictionary(entry => entry.Id);
        string Build(VaultCatalogEntry entry) => entry.ParentId == Guid.Empty
            ? entry.Name
            : Build(byId[entry.ParentId]) + "/" + entry.Name;
        foreach (var entry in entries) entry.RelativePath = Build(entry);
    }

    private static void RejectReparsePoint(string path)
    {
        if (PathSafety.IsReparsePoint(path))
        {
            throw new NingRanException($"为避免读取到其他位置，保险箱暂不接受快捷连接或重定向路径：{path}");
        }
    }

    private static void TryDeleteTemporaryVault(string temporaryPath)
    {
        try
        {
            if (Directory.Exists(temporaryPath)) Directory.Delete(temporaryPath, recursive: true);
            else if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
        }
        catch
        {
            // 只清理由本次创建且带随机编号的临时目录；失败时保留，避免扩大删除范围。
        }
    }

    private sealed record SourceFile(VaultCatalogEntry Entry, string FullPath);
    private sealed record SourcePlan(
        IReadOnlyList<VaultCatalogEntry> Entries,
        IReadOnlyList<VaultCatalogEntry> NewEntries,
        IReadOnlyList<SourceFile> Files);

    private sealed class WorkspaceUnlockAttempt(
        ArchiveHeader header,
        byte[] dataKey,
        PhysicalDeviceUnlock? physicalUnlock) : IDisposable
    {
        private bool _detached;

        public ArchiveHeader Header { get; } = header;
        public byte[] DataKey { get; } = dataKey;
        public PhysicalDeviceUnlock? PhysicalUnlock { get; } = physicalUnlock;

        public void Detach() => _detached = true;

        public void Dispose()
        {
            if (_detached) return;
            PhysicalUnlock?.Dispose();
            CryptographicOperations.ZeroMemory(DataKey);
            ClearArchiveHeader(Header);
        }
    }
}
