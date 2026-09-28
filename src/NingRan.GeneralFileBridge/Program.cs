using NingRan.Core;
using NingRan.GeneralFileBridge;
using NingRan.Windows;

return await RunAsync(args).ConfigureAwait(false);

static async Task<int> RunAsync(string[] args)
{
    try
    {
        if (args.Length != 2 || args[0] != "--parent" || !int.TryParse(args[1], out var parentProcessId))
            throw new UnauthorizedAccessException("接口只能由弥尔通用文件系统启动。");
        using var security = BridgeSecurity.ValidateParent(parentProcessId);
        await security.AuthorizeConnectionAsync(parentProcessId).ConfigureAwait(false);
        var request = await BridgeConsole.ReadAsync<NingRanBridgeRequest>().ConfigureAwait(false)
            ?? throw new InvalidDataException("没有收到操作请求。");
        await ExecuteAsync(request).ConfigureAwait(false);
        return 0;
    }
    catch (Exception exception)
    {
        try { await BridgeConsole.WriteAsync(new BridgeResponse("error", false, exception.Message)).ConfigureAwait(false); }
        catch { }
        return 2;
    }
}

static async Task ExecuteAsync(NingRanBridgeRequest request)
{
    var archives = new NrArchiveService();
    var vaults = new NrVaultService();
    if (request.Command == "inspect")
    {
        var path = RequiredExistingPath(request.Path, "请选择要分析的凝然文件。");
        if (LooksLikeVault(path))
        {
            var info = await vaults.InspectAsync(path).ConfigureAwait(false);
            await BridgeConsole.WriteAsync(new BridgeResponse("result", true, "保险箱分析完成。", new
            {
                Type = "vault",
                info.Name,
                info.VaultId,
                Mode = info.Mode.ToString(),
                info.CreatedAt,
                Path = info.VaultPath,
                info.FormatVersion,
                info.CapacityBytes,
            })).ConfigureAwait(false);
            return;
        }

        var archive = await archives.InspectAsync(path).ConfigureAwait(false);
        await BridgeConsole.WriteAsync(new BridgeResponse("result", true, "凝然文件分析完成。", new
        {
            Type = "archive",
            Mode = archive.Mode.ToString(),
            archive.HidesExactSize,
            archive.HasSenderSignature,
            archive.LegacySenderMarker,
            archive.FormatVersion,
            archive.FileSize,
            archive.CreatedAtLocal,
            PhysicalDevices = archive.RequiredPhysicalDevices,
        })).ConfigureAwait(false);
        return;
    }

    if (request.Command == "identities")
    {
        var identities = new NrIdentityService().ListLocalIdentities();
        var devices = new NrPhysicalDeviceService().ListRegisteredDevices();
        await BridgeConsole.WriteAsync(new BridgeResponse("result", true, "身份与设备读取完成。", new
        {
            Identities = identities,
            Devices = devices,
        })).ConfigureAwait(false);
        return;
    }

    var archivePath = RequiredExistingPath(request.Path, "请选择要操作的凝然加密文件或保险箱。");
    if (LooksLikeVault(archivePath))
    {
        if (request.Command == "upgradeVault")
        {
            using var upgrade = new UpgradeVaultRequest(archivePath,
                RequiredText(request.OutputPath, "请选择新版保险箱保存位置。"),
                SensitivePassword.FromString(RequiredText(request.Password, "请输入旧保险箱密码。")),
                request.KeyFilePath, fixedCapacityBytes: request.FixedCapacityBytes);
            var result = await vaults.UpgradeLegacyAsync(upgrade, ProgressWriter()).ConfigureAwait(false);
            await BridgeConsole.WriteAsync(new BridgeResponse("result", true,
                "旧保险箱已升级并通过完整检查，原保险箱保持不变。", new
                {
                    OutputPath = result.UpgradedInfo.VaultPath,
                    result.EntryCount,
                    result.ContentBytes,
                    result.UpgradedInfo.CapacityBytes,
                    SourceRetained = true,
                })).ConfigureAwait(false);
            return;
        }
        using var vaultUnlock = new UnlockVaultRequest(archivePath,
            SensitivePassword.FromString(RequiredText(request.Password, "请输入凝然保险箱密码。")), request.KeyFilePath);
        using var vaultSession = await vaults.UnlockAsync(vaultUnlock).ConfigureAwait(false);
        switch (request.Command)
        {
            case "browse":
                await BridgeConsole.WriteAsync(new BridgeResponse("result", true,
                    "保险箱私密目录读取完成。", VaultSessionData(vaultSession))).ConfigureAwait(false);
                return;
            case "decrypt":
            {
                var outputPath = await ExportVaultAsync(vaultSession,
                    RequiredText(request.OutputPath, "请选择明文保存文件夹。"), ProgressWriter()).ConfigureAwait(false);
                if (request.DeleteSource) DeleteSourcePermanently(archivePath);
                await BridgeConsole.WriteAsync(new BridgeResponse("result", true,
                    request.DeleteSource ? "保险箱已完整解密，原保险箱已永久删除。" : "保险箱已完整解密，原保险箱仍然保留。",
                    new { OutputPath = outputPath, IsDirectory = true, SourceDeleted = request.DeleteSource }))
                    .ConfigureAwait(false);
                return;
            }
            case "play":
            {
                var selected = string.IsNullOrWhiteSpace(request.EntryPath)
                    ? vaultSession.Entries.FirstOrDefault(MediaPlaybackHost.CanOpenWithExternalViewer)
                    : vaultSession.Entries.FirstOrDefault(item => string.Equals(item.RelativePath,
                        request.EntryPath, StringComparison.OrdinalIgnoreCase));
                if (selected is null || !MediaPlaybackHost.CanOpenWithExternalViewer(selected))
                    throw new NingRanException("保险箱中没有找到可读取的图片、音频、视频或 PDF。");
                var playerPath = MediaPlaybackHost.FindExternalViewer()
                    ?? throw new FileNotFoundException("没有找到已安装的媒体查看器。");
                await using var host = new MediaPlaybackHost(vaultSession, vaultSession.Entries, selected);
                await host.StartAsync(playerPath).ConfigureAwait(false);
                await BridgeConsole.WriteAsync(new BridgeResponse("progress", true, "保险箱安全媒体通道已经打开。"))
                    .ConfigureAwait(false);
                _ = await host.WaitForExitAsync().ConfigureAwait(false);
                await BridgeConsole.WriteAsync(new BridgeResponse("result", true, "媒体查看已经结束。"))
                    .ConfigureAwait(false);
                return;
            }
            default:
                throw new NingRanException("保险箱兼容模式支持查看目录、读取媒体和完整解密；不会改写旧格式。");
        }
    }

    var mode = ParseMode(request.ExpectedMode);
    using var unlock = new DecryptRequest(archivePath, request.OutputPath ?? Path.GetTempPath(),
        RequiredText(request.Password, "请输入凝然密码。"), request.KeyFilePath, request.TrustedSenderId,
        ExpectedMode: mode);

    switch (request.Command)
    {
        case "browse":
        {
            using var session = await archives.OpenForBrowsingAsync(unlock).ConfigureAwait(false);
            await BridgeConsole.WriteAsync(new BridgeResponse("result", true, "私密信息读取完成。", SessionData(session)))
                .ConfigureAwait(false);
            break;
        }
        case "decrypt":
        {
            var progress = ProgressWriter();
            var result = await archives.DecryptAsync(unlock, progress).ConfigureAwait(false);
            if (request.DeleteSource) File.Delete(archivePath);
            await BridgeConsole.WriteAsync(new BridgeResponse("result", true,
                request.DeleteSource ? "解密完成，原加密文件已永久删除。" : "解密完成，原加密文件仍然保留。",
                new { result.OutputPath, result.IsDirectory, result.VerifiedSenderName, SourceDeleted = request.DeleteSource }))
                .ConfigureAwait(false);
            break;
        }
        case "exportEncrypted":
        {
            using var session = await archives.OpenForBrowsingAsync(unlock).ConfigureAwait(false);
            var output = RequiredText(request.OutputPath, "请选择加密包保存位置。");
            var exported = await session.ExportEncryptedArchiveAsync(output, ProgressWriter()).ConfigureAwait(false);
            await BridgeConsole.WriteAsync(new BridgeResponse("result", true,
                "凝然照片中的加密内容已转换为可移动加密包，没有生成明文。", new { OutputPath = exported }))
                .ConfigureAwait(false);
            break;
        }
        case "play":
        {
            using var session = await archives.OpenForBrowsingAsync(unlock).ConfigureAwait(false);
            var selected = string.IsNullOrWhiteSpace(request.EntryPath)
                ? session.Entries.FirstOrDefault(IsPlayable)
                : session.Entries.FirstOrDefault(item => string.Equals(item.RelativePath, request.EntryPath,
                    StringComparison.OrdinalIgnoreCase));
            if (selected is null || !IsPlayable(selected))
                throw new NingRanException("加密文件中没有找到可读取的图片、音频、视频或 PDF。");
            var playerPath = MediaPlaybackHost.FindExternalViewer()
                ?? throw new FileNotFoundException("没有找到已安装的媒体查看器。");
            await using var host = new MediaPlaybackHost(session, session.Entries, selected);
            await host.StartAsync(playerPath).ConfigureAwait(false);
            await BridgeConsole.WriteAsync(new BridgeResponse("progress", true, "安全媒体通道已经打开。"))
                .ConfigureAwait(false);
            _ = await host.WaitForExitAsync().ConfigureAwait(false);
            await BridgeConsole.WriteAsync(new BridgeResponse("result", true, "媒体查看已经结束。"))
                .ConfigureAwait(false);
            break;
        }
        case "change":
            await ChangeProtectionAsync(archives, unlock, request).ConfigureAwait(false);
            break;
        default:
            throw new InvalidDataException("凝然接口不支持这项操作。");
    }
}

static async Task ChangeProtectionAsync(NrArchiveService archives, DecryptRequest unlock,
    NingRanBridgeRequest request)
{
    var output = RequiredText(request.OutputPath, "请选择新加密文件的保存位置。");
    if (File.Exists(output) || Directory.Exists(output))
        throw new IOException("新加密文件的保存位置已经存在同名项目。");
    var newMode = ParseMode(request.NewMode) ?? EncryptionMode.Standard;
    var identities = new NrIdentityService().ListLocalIdentities();
    var identityId = RequiredText(request.SigningIdentityId, "请选择凝然发送者身份。");
    if (!identities.Any(item => string.Equals(item.Id, identityId, StringComparison.Ordinal)))
        throw new NingRanException("所选发送者身份不存在。");
    var devices = new NrPhysicalDeviceService().ListRegisteredDevices()
        .Where(item => request.PhysicalDeviceIds?.Contains(item.Id, StringComparer.Ordinal) == true)
        .ToArray();
    if (newMode == EncryptionMode.PhysicalDevice && devices.Length == 0)
        throw new NingRanException("物理设备保护至少需要选择一台已经登记的设备。");

    var stagingRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "MierGeneralFileSystem", "staging", Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(stagingRoot);
    var completed = false;
    try
    {
        using var session = await archives.OpenForBrowsingAsync(unlock).ConfigureAwait(false);
        if (session.IsDelivery)
            throw new NingRanException("安全交付包保持只读，不能修改密码或保护方式。");
        var exported = await session.ExportAllAsync(stagingRoot, ProgressWriter()).ConfigureAwait(false);
        using var encrypt = new EncryptRequest(exported.OutputPath, output,
            RequiredText(request.NewPassword, "请输入新密码。"), newMode, request.NewKeyFilePath,
            Compression: ParseCompression(request.Compression), SigningIdentityId: identityId,
            SigningIdentityPassword: RequiredText(request.SigningIdentityPassword, "请输入发送者身份密码。"),
            PhysicalDevices: devices);
        var result = await archives.EncryptAsync(encrypt, ProgressWriter()).ConfigureAwait(false);
        using var verify = new DecryptRequest(result.ArchivePath, stagingRoot,
            RequiredText(request.NewPassword, "请输入新密码。"), request.NewKeyFilePath, ExpectedMode: newMode);
        using var verifiedSession = await archives.OpenForBrowsingAsync(verify).ConfigureAwait(false);
        await verifiedSession.ValidateAsync().ConfigureAwait(false);
        await BridgeConsole.WriteAsync(new BridgeResponse("result", true,
            "新加密文件已经生成并通过完整验证，原文件仍然保留。", new
            {
                OutputPath = result.ArchivePath,
                Mode = newMode.ToString(),
                verifiedSession.RootName,
                EntryCount = verifiedSession.Entries.Count,
            })).ConfigureAwait(false);
        completed = true;
    }
    finally
    {
        SecureDeleteDirectory(stagingRoot);
        if (!completed)
        {
            try { if (File.Exists(output)) File.Delete(output); } catch { }
        }
    }
}

static object VaultSessionData(VaultSession session) => new
{
    RootName = session.Name,
    IsDirectory = true,
    Mode = session.Mode.ToString(),
    VerifiedSenderName = (string?)null,
    SenderIsTrusted = false,
    IsDelivery = false,
    IsExpired = false,
    CanExportPlaintext = true,
    DeliveryInfo = (object?)null,
    SizeReport = new { session.ContentBytes, session.StoredBytesEstimate },
    Entries = session.Entries.Select(item => new
    {
        item.RelativePath,
        item.Name,
        item.IsDirectory,
        item.Length,
        MediaKind = item.IsDirectory ? null : NrMediaFiles.TryGetKind(item.Name)?.ToString(),
        LastWriteUtcTicks = item.LastWriteTimeUtc.Ticks,
    }).ToArray(),
};

static async Task<string> ExportVaultAsync(VaultSession session, string outputDirectory,
    IProgress<CryptoProgress> progress)
{
    var outputRoot = Path.GetFullPath(outputDirectory);
    if (!Directory.Exists(outputRoot)) throw new DirectoryNotFoundException("明文保存文件夹不存在。");
    var name = Path.GetFileNameWithoutExtension(session.Name);
    if (string.IsNullOrWhiteSpace(name)) name = "保险箱内容";
    var finalRoot = Path.Combine(outputRoot, name);
    if (File.Exists(finalRoot) || Directory.Exists(finalRoot))
        throw new IOException($"保存位置已经存在“{name}”，请先改名或选择其他文件夹。");
    var temporaryRoot = Path.Combine(outputRoot, $".{name}-{Guid.NewGuid():N}.part");
    Directory.CreateDirectory(temporaryRoot);
    var total = Math.Max(1L, session.ContentBytes);
    long completed = 0;
    try
    {
        foreach (var entry in session.Entries.Where(item => item.IsDirectory)
                     .OrderBy(item => item.RelativePath.Count(character => character == '/')))
        {
            Directory.CreateDirectory(GetSafeExportPath(temporaryRoot, entry.RelativePath));
        }
        foreach (var entry in session.Entries.Where(item => !item.IsDirectory))
        {
            var target = GetSafeExportPath(temporaryRoot, entry.RelativePath);
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            var part = target + ".mufs-part";
            await using (var source = session.OpenReadStream(entry.RelativePath))
            await using (var destination = new FileStream(part, FileMode.CreateNew, FileAccess.Write,
                             FileShare.None, 128 * 1024, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                var buffer = new byte[128 * 1024];
                try
                {
                    int read;
                    while ((read = await source.ReadAsync(buffer).ConfigureAwait(false)) != 0)
                    {
                        await destination.WriteAsync(buffer.AsMemory(0, read)).ConfigureAwait(false);
                        completed += read;
                        progress.Report(new CryptoProgress(CryptoStage.Decrypting, completed, total,
                            $"正在解密保险箱内容：{entry.Name}"));
                    }
                    await destination.FlushAsync().ConfigureAwait(false);
                    destination.Flush(flushToDisk: true);
                }
                finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(buffer); }
            }
            File.Move(part, target);
            File.SetLastWriteTimeUtc(target, entry.LastWriteTimeUtc);
        }
        Directory.Move(temporaryRoot, finalRoot);
        progress.Report(new CryptoProgress(CryptoStage.Finalizing, total, total, "保险箱内容已完整写入并验证。"));
        return finalRoot;
    }
    catch
    {
        SecureDeleteDirectory(temporaryRoot);
        throw;
    }
}

static string GetSafeExportPath(string root, string relativePath)
{
    var normalized = relativePath.Replace('/', Path.DirectorySeparatorChar).TrimStart(Path.DirectorySeparatorChar);
    var target = Path.GetFullPath(Path.Combine(root, normalized));
    var prefix = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root)) + Path.DirectorySeparatorChar;
    if (!target.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        throw new NingRanException("保险箱中包含不安全的内部路径，已停止解密。");
    return target;
}

static void DeleteSourcePermanently(string path)
{
    if (File.Exists(path)) File.Delete(path);
    else if (Directory.Exists(path)) Directory.Delete(path, recursive: true);
}

static object SessionData(SecureArchiveSession session) => new
{
    session.RootName,
    session.IsDirectory,
    Mode = session.Mode.ToString(),
    session.VerifiedSenderName,
    session.SenderIsTrusted,
    session.IsDelivery,
    session.IsExpired,
    session.CanExportPlaintext,
    session.DeliveryInfo,
    session.SizeReport,
    Entries = session.Entries.Select(item => new
    {
        item.RelativePath,
        item.Name,
        item.IsDirectory,
        item.Length,
        MediaKind = item.MediaKind?.ToString(),
        item.LastWriteUtcTicks,
    }).ToArray(),
};

static bool IsPlayable(SecureArchiveEntry entry) => !entry.IsDirectory &&
    entry.MediaKind is SecureMediaKind.Audio or SecureMediaKind.Video or SecureMediaKind.Image or SecureMediaKind.Pdf;

static IProgress<CryptoProgress> ProgressWriter() => new InlineProgress<CryptoProgress>(value =>
    BridgeConsole.WriteAsync(new BridgeResponse("progress", true, value.Message, new
    {
        Stage = value.Stage.ToString(),
        value.Fraction,
        value.CompletedBytes,
        value.TotalBytes,
    })).GetAwaiter().GetResult());

static EncryptionMode? ParseMode(string? value) => string.IsNullOrWhiteSpace(value)
    ? null
    : Enum.TryParse<EncryptionMode>(value, true, out var mode)
        ? mode
        : throw new InvalidDataException("选择的凝然保护方式无效。");

static ArchiveCompressionLevel ParseCompression(string? value) =>
    Enum.TryParse<ArchiveCompressionLevel>(value, true, out var compression)
        ? compression
        : ArchiveCompressionLevel.Standard;

static string RequiredExistingPath(string? value, string message)
{
    var path = Path.GetFullPath(RequiredText(value, message));
    if (!File.Exists(path) && !Directory.Exists(path)) throw new FileNotFoundException(message, path);
    return path;
}

static bool LooksLikeVault(string path) => NrVaultService.IsVaultFolder(path) ||
    NrVaultService.IsVaultFile(path) ||
    File.Exists(path) && Path.GetExtension(path).Equals(".nrvault", StringComparison.OrdinalIgnoreCase);

static string RequiredText(string? value, string message) =>
    string.IsNullOrWhiteSpace(value) ? throw new InvalidDataException(message) : value;

static void SecureDeleteDirectory(string path)
{
    if (!Directory.Exists(path)) return;
    try
    {
        foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
        {
            try
            {
                File.SetAttributes(file, FileAttributes.Normal);
                var length = new FileInfo(file).Length;
                using var stream = new FileStream(file, FileMode.Open, FileAccess.Write, FileShare.None,
                    1024 * 1024, FileOptions.WriteThrough);
                var random = new byte[1024 * 1024];
                long written = 0;
                while (written < length)
                {
                    System.Security.Cryptography.RandomNumberGenerator.Fill(random);
                    var count = (int)Math.Min(random.Length, length - written);
                    stream.Write(random, 0, count);
                    written += count;
                }
                stream.Flush(flushToDisk: true);
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(random);
                stream.Dispose();
                File.Delete(file);
            }
            catch { }
        }
        Directory.Delete(path, recursive: true);
    }
    catch
    {
        // 尽最大努力覆写并清除；无法删除时不掩盖原操作结果。
    }
}

internal sealed record NingRanBridgeRequest(
    string Command,
    string? Path = null,
    string? OutputPath = null,
    string? Password = null,
    string? KeyFilePath = null,
    string? TrustedSenderId = null,
    string? ExpectedMode = null,
    string? EntryPath = null,
    bool DeleteSource = false,
    string? NewPassword = null,
    string? NewKeyFilePath = null,
    string? NewMode = null,
    string? SigningIdentityId = null,
    string? SigningIdentityPassword = null,
    IReadOnlyList<string>? PhysicalDeviceIds = null,
    string? Compression = null,
    long? FixedCapacityBytes = null);

internal sealed record BridgeResponse(string Kind, bool Success, string Message, object? Data = null);

internal sealed class InlineProgress<T>(Action<T> report) : IProgress<T>
{
    public void Report(T value) => report(value);
}
