using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using NingRan.Core;
using NingRan.Core.Internal;
using NingRan.Windows;
using System.Reflection;
using System.Windows;
using System.Windows.Threading;

namespace NingRan.DeliveryChecks;

internal static class Program
{
    private const string PasswordText = "Delivery check 8.0.1!";

    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length == 1 && string.Equals(args[0], "--winfsp-runtime-only", StringComparison.OrdinalIgnoreCase))
        {
            return VerifyInstalledTemporaryDriveRuntimeVersionOnly();
        }
        if (args.Length == 1 && string.Equals(args[0], "--winfsp-mount-only", StringComparison.OrdinalIgnoreCase))
        {
            return VerifyTemporaryDriveMountOnly();
        }

        var root = Path.Combine(Path.GetTempPath(), "NingRan.DeliveryChecks", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            VerifyTemporaryDriveVersionResolution();
            Console.WriteLine("临时磁盘版本判断回归检查通过。");
            VerifyExternalMediaViewerPathResolution(root);
            Console.WriteLine("独立播放器安装位置检查通过。");
            VerifyMediaPlayerSelection(root);
            Console.WriteLine("播放器选择和记忆检查通过。");
            VerifyWizardLayout();
            Console.WriteLine("安全交付向导界面检查通过。");
            VerifyVaultCreationLayout();
            Console.WriteLine("保险箱创建界面检查通过。");
            VerifyVaultWorkspaceLayout(root);
            Console.WriteLine("保险箱工作区界面检查通过。");
            RunAsync(root).GetAwaiter().GetResult();
            Console.WriteLine("安全交付自动检查全部通过。");
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(exception);
            return 1;
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { }
        }
    }

    private static void VerifyTemporaryDriveVersionResolution()
    {
        var apiVersion = new Version(2, 2);
        var resolved = VaultDriveService.ResolveRuntimeVersion(apiVersion, 2, 2, 26215, 0);
        Assert(resolved == new Version(2, 2, 26215),
            $"临时磁盘组件接口省略构建号时，没有使用文件中的完整版本：{resolved}。");

        var older = VaultDriveService.ResolveRuntimeVersion(apiVersion, 2, 2, 26100, 0);
        Assert(older < new Version(2, 2, 26215),
            $"低于最低要求的临时磁盘组件版本被错误接受：{older}。");

        var mismatched = VaultDriveService.ResolveRuntimeVersion(apiVersion, 2, 1, 99999, 0);
        Assert(mismatched == apiVersion,
            $"文件主次版本与已加载组件不一致时仍信任了文件构建号：{mismatched}。");

    }

    private static void VerifyExternalMediaViewerPathResolution(string root)
    {
        var programFiles = Path.Combine(root, "Program Files");
        var unifiedDirectory = Path.Combine(programFiles, "弥尔通用文件系统", "Media-Helper");
        var currentDirectory = Path.Combine(programFiles, "Mier", "Media-Helper");
        var legacyDirectory = Path.Combine(programFiles, "media-helper");
        var unifiedPlayer = Path.Combine(unifiedDirectory, "凝然媒体播放器.exe");
        var currentPlayer = Path.Combine(currentDirectory, "凝然媒体播放器.exe");
        var legacyPlayer = Path.Combine(legacyDirectory, "凝然媒体播放器.exe");
        Directory.CreateDirectory(unifiedDirectory);
        Directory.CreateDirectory(currentDirectory);
        Directory.CreateDirectory(legacyDirectory);
        File.WriteAllBytes(unifiedPlayer, []);
        File.WriteAllBytes(currentPlayer, []);
        File.WriteAllBytes(legacyPlayer, []);

        Assert(string.Equals(
                MediaPlaybackHost.FindExternalViewer(programFiles),
                unifiedPlayer,
                StringComparison.OrdinalIgnoreCase),
            "同时存在弥尔通用文件系统和旧安装位置时，没有优先找到通用文件管理系统播放器。");

        File.Delete(unifiedPlayer);
        Assert(string.Equals(
                MediaPlaybackHost.FindExternalViewer(programFiles),
                currentPlayer,
                StringComparison.OrdinalIgnoreCase),
            "通用文件管理系统播放器不存在时，没有回退到 Mier\\Media-Helper。");

        File.Delete(currentPlayer);
        Assert(string.Equals(
                MediaPlaybackHost.FindExternalViewer(programFiles),
                legacyPlayer,
                StringComparison.OrdinalIgnoreCase),
            "没有兼容旧 media-helper 安装位置中的播放器。");

        File.Delete(legacyPlayer);
        Assert(MediaPlaybackHost.FindExternalViewer(programFiles) is null,
            "固定安全安装位置没有播放器时仍返回了外部程序。");

        var installedRoot = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var installedPlayer = new[]
            {
                Path.Combine(installedRoot, "弥尔通用文件系统", "Media-Helper", "凝然媒体播放器.exe"),
                Path.Combine(installedRoot, "Mier", "Media-Helper", "凝然媒体播放器.exe"),
                Path.Combine(installedRoot, "media-helper", "凝然媒体播放器.exe"),
            }
            .FirstOrDefault(File.Exists);
        if (installedPlayer is not null)
        {
            Assert(string.Equals(
                    MediaPlaybackHost.FindExternalViewer(),
                    installedPlayer,
                    StringComparison.OrdinalIgnoreCase),
                "没有识别这台电脑上实际安装的 Mier Media-Helper 播放器。");
        }
    }

    private static void VerifyMediaPlayerSelection(string root)
    {
        var application = Application.Current as App;
        if (application is null)
        {
            application = new App();
            application.InitializeComponent();
        }

        var settingsPath = Path.Combine(root, "Settings", "media-player-settings.json");
        var defaults = MediaPlayerPreferences.Load(settingsPath);
        Assert(defaults.AudioVideoPlayer == AudioVideoPlayerChoice.NingRanPlayer,
            "首次使用时没有默认选择凝然播放器。");

        var builtIn = new MediaPlayerPreferences { AudioVideoPlayer = AudioVideoPlayerChoice.BuiltInPlayer };
        builtIn.Save(settingsPath);
        var loaded = MediaPlayerPreferences.Load(settingsPath);
        Assert(loaded.AudioVideoPlayer == AudioVideoPlayerChoice.BuiltInPlayer,
            "内置播放器选择没有被保存并重新读取。");

        Assert(!MediaPlayerSelection.ShouldUseExternalViewer(SecureMediaKind.Audio, loaded, externalViewersBlocked: false) &&
               !MediaPlayerSelection.ShouldUseExternalViewer(SecureMediaKind.Video, loaded, externalViewersBlocked: false),
            "选择内置播放器后仍会把音频或视频交给外部播放器。");
        Assert(MediaPlayerSelection.ShouldUseExternalViewer(SecureMediaKind.Image, loaded, externalViewersBlocked: false) &&
               MediaPlayerSelection.ShouldUseExternalViewer(SecureMediaKind.Pdf, loaded, externalViewersBlocked: false),
            "播放器选择错误改变了图片或 PDF 的原有打开方式。");
        Assert(!MediaPlayerSelection.ShouldUseExternalViewer(SecureMediaKind.Image, defaults, externalViewersBlocked: true) &&
               !MediaPlayerSelection.ShouldUseExternalViewer(SecureMediaKind.Video, defaults, externalViewersBlocked: true),
            "严格防护开启时仍可能启动外部查看器。");

        File.WriteAllText(settingsPath, "{broken setting");
        Assert(MediaPlayerPreferences.Load(settingsPath).AudioVideoPlayer == AudioVideoPlayerChoice.NingRanPlayer,
            "播放器设置损坏后没有安全恢复到原有默认行为。");

        var dialog = new MediaPlayerSettingsWindow(defaults, externalPlayerAvailable: false);
        try
        {
            var content = dialog.Content as FrameworkElement
                ?? throw new InvalidOperationException("播放器设置窗口缺少可测量的内容区域。");
            content.Measure(new Size(600, 430));
            content.Arrange(new Rect(0, 0, 600, 430));
            content.UpdateLayout();
            Assert(dialog.NingRanPlayerRadio.ActualWidth > 100 &&
                   dialog.BuiltInPlayerRadio.ActualWidth > 100 &&
                   dialog.SaveChoiceButton.ActualWidth > 0,
                "播放器设置窗口的选择项或保存按钮没有正常布局。");
        }
        finally
        {
            dialog.Close();
        }
    }

    private static int VerifyInstalledTemporaryDriveRuntimeVersionOnly()
    {
        try
        {
            VerifyInstalledTemporaryDriveRuntimeVersion();
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(exception);
            return 1;
        }
    }

    private static void VerifyInstalledTemporaryDriveRuntimeVersion()
    {
        var installedCandidates = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "WinFsp", "bin", "winfsp-x64.dll"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WinFsp", "bin", "winfsp-x64.dll"),
        };
        Assert(installedCandidates.Any(File.Exists), "这台电脑没有找到已安装的临时磁盘组件。");
        Assert(VaultDriveService.TryGetRuntimeVersion(out var installedVersion, out var message),
            $"已安装的临时磁盘组件未通过运行时版本检查：{message}");
        Assert(installedVersion is not null && installedVersion >= new Version(2, 2, 26215),
            $"运行时版本检查没有返回已安装组件的完整版本：{installedVersion}。");
        Console.WriteLine($"临时磁盘组件完整版本检查通过：{installedVersion}。");
    }

    private static int VerifyTemporaryDriveMountOnly()
    {
        var root = Path.Combine(Path.GetTempPath(), "NingRan.DeliveryChecks", "WinFspMount", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            const string passwordText = "Mount check daily 8.0.1!";
            const string hiddenPasswordText = "Mount check hidden 9.6.2#";
            const string expectedText = "凝然日常空间临时磁盘实际挂载检查";
            const string hiddenExpectedText = "凝然隐蔽空间临时磁盘实际挂载检查";
            var sourcePath = Path.Combine(root, "日常挂载验证.txt");
            var hiddenSourcePath = Path.Combine(root, "隐蔽挂载验证.txt");
            var keyFilePath = Path.Combine(root, "日常空间密匙.nrkey");
            var vaultPath = Path.Combine(root, "挂载验证保险箱");
            File.WriteAllText(sourcePath, expectedText, Encoding.UTF8);
            File.WriteAllText(hiddenSourcePath, hiddenExpectedText, Encoding.UTF8);

            var keyFileService = new NrKeyFileService(KdfParameters.Testing);
            keyFileService.CreateAsync(keyFilePath, passwordText).GetAwaiter().GetResult();
            var service = new NrVaultService(KdfParameters.Testing, keyFileService);
            using (var password = SensitivePassword.FromString(passwordText))
            using (var hiddenPassword = SensitivePassword.FromString(hiddenPasswordText))
            using (var request = new CreateDualVaultRequest(
                       vaultPath,
                       password,
                       hiddenPassword,
                       dailyMode: EncryptionMode.Advanced,
                       dailyKeyFilePath: keyFilePath,
                       dailySourcePaths: [sourcePath],
                       hiddenSourcePaths: [hiddenSourcePath],
                       fixedCapacityBytes: 128L * 1024 * 1024,
                       dailyCapacityBytes: 8L * 1024 * 1024,
                       hiddenCapacityBytes: 8L * 1024 * 1024))
            {
                service.CreateDualAsync(request).GetAwaiter().GetResult();
            }

            VerifyMountedVaultSpace(service, vaultPath, passwordText, keyFilePath, sourcePath, expectedText, "日常空间");
            VerifyMountedVaultSpace(service, vaultPath, hiddenPasswordText, null, hiddenSourcePath, hiddenExpectedText, "隐蔽空间");
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(exception);
            return 1;
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { }
        }
    }

    private static void VerifyMountedVaultSpace(
        NrVaultService service,
        string vaultPath,
        string passwordText,
        string? keyFilePath,
        string sourcePath,
        string expectedText,
        string spaceName)
    {
        using var unlockPassword = SensitivePassword.FromString(passwordText);
        using var unlock = new UnlockVaultRequest(vaultPath, unlockPassword, keyFilePath);
        using var session = service.UnlockAsync(unlock).GetAwaiter().GetResult();
        Assert(session.TemporaryDriveAllowed, $"{spaceName}没有允许建立临时磁盘。");

        string mountRoot;
        using (var mount = VaultDriveService.Mount(session))
        {
            Assert(mount.IsMounted && !string.IsNullOrWhiteSpace(mount.MountPoint),
                $"{spaceName}的临时磁盘组件返回成功，但没有提供可用盘符。");
            mountRoot = mount.MountPoint.TrimEnd('\\') + "\\";
            Assert(WaitUntil(() => Directory.Exists(mountRoot), TimeSpan.FromSeconds(5)),
                $"{spaceName}的临时磁盘 {mount.MountPoint} 没有出现在系统中。");
            var mountedFile = Path.Combine(mountRoot, Path.GetFileName(sourcePath));
            Assert(WaitUntil(() => File.Exists(mountedFile), TimeSpan.FromSeconds(5)),
                $"{spaceName}的测试文件没有出现在临时磁盘中。");
            Assert(File.ReadAllText(mountedFile, Encoding.UTF8) == expectedText,
                $"从{spaceName}临时磁盘读取到的测试文件内容不正确。");
            Console.WriteLine($"{spaceName}临时磁盘实际挂载和读取检查通过：{mount.MountPoint}。");
        }
        Assert(WaitUntil(() => !Directory.Exists(mountRoot), TimeSpan.FromSeconds(5)),
            $"{spaceName}检查结束后临时磁盘 {mountRoot} 没有卸载。");
    }

    private static bool WaitUntil(Func<bool> condition, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            if (condition()) return true;
            Thread.Sleep(100);
        }
        return condition();
    }

    private static async Task RunAsync(string root)
    {
        var sourceA = Path.Combine(root, "项目资料 A");
        var sourceB = Path.Combine(root, "资料-B");
        Directory.CreateDirectory(Path.Combine(sourceA, "空目录", "第二层"));
        Directory.CreateDirectory(sourceB);
        await File.WriteAllTextAsync(Path.Combine(sourceA, "说明 中文 & symbols (1).txt"), "受保护的交付内容", Encoding.UTF8);
        await File.WriteAllBytesAsync(Path.Combine(sourceA, "空文件.bin"), []);
        var largeBytes = new byte[9 * 1024 * 1024 + 137];
        for (var index = 0; index < largeBytes.Length; index++) largeBytes[index] = (byte)(index % 251);
        await File.WriteAllBytesAsync(Path.Combine(sourceB, "数据.dat"), largeBytes);
        CryptographicOperations.ZeroMemory(largeBytes);
        var singleFile = Path.Combine(root, "顶层文件.txt");
        await File.WriteAllTextAsync(singleFile, "top-level", Encoding.UTF8);
        var originalHashes = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
            .ToDictionary(path => path, ComputeFileHash, StringComparer.OrdinalIgnoreCase);
        VerifyProtectedRecentDeliveryHistory(root);

        var created = DateTimeOffset.UtcNow;
        var recipient = new TrustedContactSummary(
            "contact-check",
            "自动检查接收方",
            DateTime.UtcNow,
            new string('A', 64),
            "S-1-5-21-check",
            false);
        var delivery = DeliveryPackageInfo.Create(
            "季度资料：安全交付",
            "用于自动检查的说明",
            created,
            created.AddDays(30),
            allowExport: false,
            recipient);
        var archivePath = Path.Combine(root, "安全交付.nrenc");
        await CreatePackageAsync([sourceA, sourceB, singleFile], archivePath, delivery);

        using (var session = await OpenSessionAsync(archivePath))
        {
            Assert(session.IsDelivery, "新包没有识别为安全交付包。");
            Assert(session.DeliveryInfo == delivery, "生成后重新读取的交付规则不一致。");
            Assert(session.DeliveryInfo?.RecipientName == "自动检查接收方", "接收方确认信息没有随交付规则保存。");
            Assert(!session.CanExportPlaintext, "禁止导出规则没有进入底层会话。");
            Assert(session.Entries.Any(entry => entry.RelativePath.EndsWith("空目录/第二层", StringComparison.Ordinal)),
                "没有保留多层空文件夹。");
            Assert(session.Entries.Any(entry => entry.RelativePath.EndsWith("空文件.bin", StringComparison.Ordinal) && entry.Length == 0),
                "没有保留空文件。");
            Assert(session.Entries.Any(entry => entry.RelativePath.EndsWith("说明 中文 & symbols (1).txt", StringComparison.Ordinal)),
                "没有保留中文、空格和常见符号文件名。");
            Assert(session.Entries.Where(entry => entry.RelativePath.Contains('/'))
                    .Select(entry => entry.RelativePath.Split('/')[1])
                    .Distinct(StringComparer.OrdinalIgnoreCase).Count() == 3,
                "没有保留三个顶层项目。");

            var textEntry = session.Entries.Single(entry => entry.RelativePath.EndsWith("说明 中文 & symbols (1).txt", StringComparison.Ordinal));
            await using var content = session.OpenEntryReadStream(textEntry.RelativePath);
            using var reader = new StreamReader(content, Encoding.UTF8);
            Assert(await reader.ReadToEndAsync() == "受保护的交付内容", "安全查看读取的内容不正确。");

            await ExpectNingRanFailureAsync(
                () => session.ExportEntryAsync(textEntry.RelativePath, Path.Combine(root, "不应导出.txt")),
                "禁止导出时底层仍导出了单个文件。");
            await ExpectNingRanFailureAsync(
                () => session.ExportAllAsync(Path.Combine(root, "不应导出全部")),
                "禁止导出时底层仍导出了全部内容。");
        }

        var localIdentityService = new NrIdentityService(KdfParameters.Testing);
        var contactService = new NrTrustedContactService(localIdentityService);
        var publicOpenService = new NrArchiveService(
            KdfParameters.Testing,
            keyFileService: null,
            identityService: localIdentityService,
            trustedContactService: contactService,
            allowUnsignedArchivesForTesting: false);
        using (var openRequest = new DecryptRequest(
                   archivePath,
                   string.Empty,
                   PasswordText,
                   ExpectedMode: EncryptionMode.Standard))
        using (var session = await publicOpenService.OpenForBrowsingAsync(openRequest))
        {
            Assert(!session.SenderIsTrusted && session.VerifiedSenderName == "自动检查发送者",
                "没有预建联系人时，安全交付包未能以“签名有效但未确认发送者”状态打开。");
        }

        using (var wrongPassword = new DecryptRequest(
                   archivePath,
                   string.Empty,
                   "wrong delivery password",
                   ExpectedMode: EncryptionMode.Standard))
        {
            await ExpectNingRanFailureAsync(
                () => publicOpenService.OpenForBrowsingAsync(wrongPassword),
                "错误密码仍然打开了安全交付包。");
        }

        await VerifyTamperedPackageIsRejectedAsync(root, archivePath, publicOpenService);
        await VerifyFutureFormatRequestsUpdateAsync(root, archivePath, publicOpenService);

        var prohibitedExportDirectory = Path.Combine(root, "禁止直接还原");
        using (var directExport = new DecryptRequest(
                   archivePath,
                   prohibitedExportDirectory,
                   PasswordText,
                   ExpectedMode: EncryptionMode.Standard))
        {
            await ExpectNingRanFailureAsync(
                () => publicOpenService.DecryptAsync(directExport),
                "旧的直接还原入口绕过了安全交付的禁止导出规则。");
            Assert(!Directory.Exists(prohibitedExportDirectory) ||
                   !Directory.EnumerateFileSystemEntries(prohibitedExportDirectory).Any(),
                "禁止直接还原失败后留下了明文内容。");
        }

        var allowedDelivery = DeliveryPackageInfo.Create(
            "允许导出交付",
            null,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddDays(7),
            allowExport: true);
        var allowedPath = Path.Combine(root, "允许导出.nrenc");
        await CreatePackageAsync([singleFile], allowedPath, allowedDelivery);
        using (var session = await OpenSessionAsync(allowedPath))
        {
            var entry = session.Entries.Single(item => !item.IsDirectory);
            var exported = Path.Combine(root, "允许导出副本.txt");
            await session.ExportEntryAsync(entry.RelativePath, exported);
            Assert(await File.ReadAllTextAsync(exported, Encoding.UTF8) == "top-level",
                "允许导出时单文件导出没有保持原内容。");
        }
        var allowedDirectDirectory = Path.Combine(root, "允许直接还原");
        using (var allowedDirectExport = new DecryptRequest(
                   allowedPath,
                   allowedDirectDirectory,
                   PasswordText,
                   ExpectedMode: EncryptionMode.Standard))
        {
            var directResult = await publicOpenService.DecryptAsync(allowedDirectExport);
            Assert(Directory.Exists(directResult.OutputPath) &&
                   Directory.EnumerateFiles(directResult.OutputPath, "顶层文件.txt", SearchOption.AllDirectories).Any(),
                "允许导出时原有完整还原流程发生回归。");
        }

        var expired = new DeliveryPackageInfo(
            DeliveryPackageInfo.CurrentVersion,
            "已过期交付",
            string.Empty,
            DateTimeOffset.UtcNow.AddDays(-2),
            DateTimeOffset.UtcNow.AddDays(-1),
            true,
            null,
            null,
            null);
        var expiredPath = Path.Combine(root, "已过期.nrenc");
        await CreatePackageAsync([singleFile], expiredPath, expired);
        using (var session = await OpenSessionAsync(expiredPath))
        {
            Assert(session.IsExpired, "已过期交付包没有显示过期状态。");
            Assert(session.CancellationToken.IsCancellationRequested, "已过期交付包没有结束现有查看会话。");
            Assert(session.Entries.Count >= 2, "过期后无法读取交付文件树。");
            var entry = session.Entries.Single(item => !item.IsDirectory);
            await ExpectNingRanFailureAsync(
                () => Task.Run(() => session.OpenEntryReadStream(entry.RelativePath).Dispose()),
                "过期后仍能建立内容读取会话。");
        }
        using (var expiredDirectExport = new DecryptRequest(
                   expiredPath,
                   Path.Combine(root, "过期直接还原"),
                   PasswordText,
                   ExpectedMode: EncryptionMode.Standard))
        {
            await ExpectNingRanFailureAsync(
                () => publicOpenService.DecryptAsync(expiredDirectExport),
                "旧的直接还原入口绕过了过期限制。");
        }

        var soonExpired = new DeliveryPackageInfo(
            DeliveryPackageInfo.CurrentVersion,
            "即将过期交付",
            string.Empty,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddSeconds(1.2),
            true,
            null,
            null,
            null);
        var soonExpiredPath = Path.Combine(root, "即将过期.nrenc");
        await CreatePackageAsync([singleFile], soonExpiredPath, soonExpired);
        using (var session = await OpenSessionAsync(soonExpiredPath))
        {
            var entry = session.Entries.Single(item => !item.IsDirectory);
            await using var stream = session.OpenEntryReadStream(entry.RelativePath);
            var first = new byte[1];
            Assert(await stream.ReadAsync(first) == 1, "有效期内无法读取内容。");
            await Task.Delay(TimeSpan.FromSeconds(1.5));
            Assert(session.CancellationToken.IsCancellationRequested, "到期时没有结束已建立的读取会话。");
            await ExpectNingRanFailureAsync(async () =>
            {
                var next = new byte[1];
                _ = await stream.ReadAsync(next);
            }, "到期前建立的读取流在到期后仍能继续读取。");
        }

        var legacyPath = Path.Combine(root, "普通包.nrenc");
        await CreatePackageAsync([singleFile], legacyPath, null);
        using (var session = await OpenSessionAsync(legacyPath))
        {
            Assert(!session.IsDelivery && session.DeliveryInfo is null, "普通旧式加密包被错误识别为安全交付包。");
            Assert(session.CanExportPlaintext, "普通加密包的原有导出能力发生回归。");
        }

        await VerifyDuplicateTopLevelNamesAreRejectedAsync(root);
        await VerifyNestedSelectionIsRejectedAsync(root, sourceA);
        await VerifyIncrementalArchiveUpdatesAsync(root);
        var unverifiedRecipient = recipient with { RequiresReverification = true };
        await ExpectNingRanFailureAsync(() => Task.Run(() => DeliveryPackageInfo.Create(
            "不应创建", null, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1), true,
            unverifiedRecipient)), "未重新核对的联系人被错误显示为可确认接收方。");
        foreach (var original in originalHashes)
        {
            Assert(File.Exists(original.Key) && ComputeFileHash(original.Key).AsSpan().SequenceEqual(original.Value),
                $"生成或失败处理改动了原始资料：{Path.GetFileName(original.Key)}");
        }
    }

    private static void VerifyWizardLayout()
    {
        var application = Application.Current as App;
        if (application is null)
        {
            application = new App();
            application.InitializeComponent();
        }
        var wizard = new DeliveryWizardWindow(loadChoices: false);
        try
        {
            var layoutRoot = wizard.Content as FrameworkElement
                ?? throw new InvalidOperationException("安全交付向导缺少可测量的内容区域。");
            var pages = new FrameworkElement[]
            {
                wizard.SourcePage,
                wizard.InfoPage,
                wizard.ProtectionPage,
                wizard.RulesPage,
                wizard.ReviewPage,
                wizard.ResultPage,
            };
            var showPage = typeof(DeliveryWizardWindow).GetMethod("ShowPage",
                BindingFlags.Instance | BindingFlags.NonPublic)
                ?? throw new InvalidOperationException("安全交付向导缺少页面切换方法。");
            for (var page = 0; page < pages.Length; page++)
            {
                showPage.Invoke(wizard, [page]);
                layoutRoot.Measure(new Size(900, 700));
                layoutRoot.Arrange(new Rect(0, 0, 900, 700));
                layoutRoot.UpdateLayout();
                Assert(pages.Count(item => item.Visibility == Visibility.Visible) == 1 &&
                       pages[page].Visibility == Visibility.Visible,
                    $"安全交付向导第 {page + 1} 页的显示状态不正确。");
                Assert(pages[page].ActualWidth > 100 && pages[page].ActualHeight > 100,
                    $"安全交付向导第 {page + 1} 页没有获得可用布局空间。");
                Assert(wizard.NextButton.ActualWidth > 0 && wizard.StepTitle.ActualWidth > 0,
                    "安全交付向导的主要导航控件没有正常布局。");
            }
        }
        finally
        {
            wizard.Close();
        }
    }

    private static void VerifyVaultCreationLayout()
    {
        var entry = new VaultEntryWindow();
        try
        {
            var entryRoot = entry.Content as FrameworkElement
                ?? throw new InvalidOperationException("保险箱入口窗口缺少可测量的内容区域。");
            entryRoot.Measure(new Size(720, 430));
            entryRoot.Arrange(new Rect(0, 0, 720, 430));
            entryRoot.UpdateLayout();
            Assert(entry.CreateVaultButton.ActualWidth > 120 && entry.OpenVaultButton.ActualWidth > 120,
                "创建保险箱和打开保险箱的独立入口没有获得可用布局空间。");
        }
        finally { entry.Close(); }

        var keyFiles = new NrKeyFileService(KdfParameters.Testing);
        var devices = new NrPhysicalDeviceService();
        var window = new VaultWindow(
            new NrVaultService(KdfParameters.Testing, keyFiles, devices),
            new NrArchiveService(KdfParameters.Testing, keyFileService: keyFiles, physicalDeviceProvider: devices),
            keyFiles,
            devices);
        try
        {
            Assert(window.CreateSetupPanel.Visibility == Visibility.Visible &&
                   window.OpenSetupPanel.Visibility == Visibility.Collapsed,
                "创建界面仍然混入了打开已有保险箱的控件。");
            Assert(window.CreateHiddenSpaceCheckBox.IsChecked != true,
                "建立隐蔽空间选项没有默认关闭。");
            Assert(window.HiddenSpacePanel.Visibility == Visibility.Collapsed &&
                   window.HiddenSourcesPanel.Visibility == Visibility.Collapsed,
                "默认创建页错误显示了秘密密码或隐蔽资料区域。");
            window.CreateHiddenSpaceCheckBox.IsChecked = true;
            Assert(window.HiddenSpacePanel.Visibility == Visibility.Visible &&
                   window.HiddenSourcesPanel.Visibility == Visibility.Visible,
                "开启建立隐蔽空间后没有显示秘密密码、容量和初始资料区域。");
            Assert(window.ModeCombo.Items[2] is System.Windows.Controls.ComboBoxItem { IsEnabled: false },
                "开启隐蔽空间后仍允许选择会暴露空间差异的物理设备方式。");
            window.LocationPage.Visibility = Visibility.Collapsed;
            window.ActionsPage.Visibility = Visibility.Collapsed;
            window.ProtectionPage.Visibility = Visibility.Visible;
            var root = window.Content as FrameworkElement
                ?? throw new InvalidOperationException("保险箱窗口缺少可测量的内容区域。");
            root.Measure(new Size(920, 760));
            root.Arrange(new Rect(0, 0, 920, 760));
            root.UpdateLayout();
            Assert(window.HiddenPasswordInput.ActualWidth > 100 &&
                   window.ConfirmHiddenPasswordInput.ActualWidth > 100 &&
                   window.DailyCapacityInput.ActualWidth > 100 &&
                   window.HiddenCapacityInput.ActualWidth > 100,
                "双层保险箱的密码或容量输入框没有获得可用布局空间。");
        }
        finally { window.Close(); }

        var openWindow = new VaultWindow(
            new NrVaultService(KdfParameters.Testing, keyFiles, devices),
            new NrArchiveService(KdfParameters.Testing, keyFileService: keyFiles, physicalDeviceProvider: devices),
            keyFiles,
            devices,
            VaultWindowMode.Open);
        try
        {
            var openRoot = openWindow.Content as FrameworkElement
                ?? throw new InvalidOperationException("打开保险箱窗口缺少可测量的内容区域。");
            openRoot.Measure(new Size(920, 760));
            openRoot.Arrange(new Rect(0, 0, 920, 760));
            openRoot.UpdateLayout();
            Assert(openWindow.OpenSetupPanel.Visibility == Visibility.Visible &&
                   openWindow.CreateSetupPanel.Visibility == Visibility.Collapsed &&
                   openWindow.LocationNavButton.Visibility == Visibility.Collapsed &&
                   openWindow.ProtectionNavButton.Visibility == Visibility.Collapsed,
                "打开界面仍然显示了创建保险箱的设置或导航。");
            Assert(openWindow.OpenPasswordInput.ActualWidth > 200 && openWindow.OpenButton.ActualWidth > 0,
                "打开保险箱的独立密码框或挂载按钮没有获得可用布局空间。");
        }
        finally { openWindow.Close(); }

    }

    private static void VerifyVaultWorkspaceLayout(string root)
    {
        const string dailyPasswordText = "Delivery daily space 8.0.1!";
        const string secondPasswordText = "Delivery second space 9.6.2#";
        var path = Path.Combine(root, "内部浏览布局保险箱");
        var service = new NrVaultService(KdfParameters.Testing);
        using (var dailyPassword = SensitivePassword.FromString(dailyPasswordText))
        using (var secondPassword = SensitivePassword.FromString(secondPasswordText))
        using (var request = new CreateDualVaultRequest(
                   path,
                   dailyPassword,
                   secondPassword,
                   fixedCapacityBytes: 128L * 1024 * 1024,
                   dailyCapacityBytes: 8L * 1024 * 1024,
                   hiddenCapacityBytes: 8L * 1024 * 1024))
        {
            service.CreateDualAsync(request).GetAwaiter().GetResult();
        }
        Console.WriteLine("保险箱工作区检查：测试保险箱已建立。");
        using var unlockPassword = SensitivePassword.FromString(secondPasswordText);
        using var unlock = new UnlockVaultRequest(path, unlockPassword);
        using var session = service.UnlockAsync(unlock).GetAwaiter().GetResult();
        Console.WriteLine("保险箱工作区检查：隐蔽空间已解锁。");
        Assert(session.TemporaryDriveAllowed, "第二套密码打开后没有允许建立临时磁盘。");
        using (var mediaOutput = session.OpenWriteStream("内部播放检查.wav", createNew: true))
        {
            var wave = CreateSilentWave();
            try
            {
                mediaOutput.Write(wave);
                mediaOutput.CommitAsync().GetAwaiter().GetResult();
            }
            finally { CryptographicOperations.ZeroMemory(wave); }
        }
        Console.WriteLine("保险箱工作区检查：内部媒体样本已保存。");
        var window = new VaultWorkspaceWindow(service, session);
        try
        {
            var content = window.Content as FrameworkElement
                ?? throw new InvalidOperationException("内部浏览窗口缺少可测量的内容区域。");
            content.Measure(new Size(900, 650));
            content.Arrange(new Rect(0, 0, 900, 650));
            content.UpdateLayout();
            Assert(window.FileTree.ActualWidth > 180 && window.PreviewHint.ActualWidth > 100 &&
                   window.AddFilesButton.ActualWidth > 0 && window.ReplaceButton.ActualWidth > 0 && window.ExportButton.ActualWidth > 0,
                "程序内部浏览的文件树、查看区或主要操作没有获得可用布局空间。");

            var mediaEntry = session.Entries.Single(entry => entry.RelativePath == "内部播放检查.wav");
            var mediaWindow = new VaultMediaViewerWindow(session, mediaEntry);
            try
            {
                mediaWindow.Show();
                Console.WriteLine("保险箱工作区检查：媒体查看窗口已打开。");
                PumpDispatcher(TimeSpan.FromSeconds(2));
                Console.WriteLine("保险箱工作区检查：媒体查看窗口等待完成。");
                var mediaContent = mediaWindow.Content as FrameworkElement
                    ?? throw new InvalidOperationException("保险箱媒体查看窗口缺少可测量的内容区域。");
                mediaContent.Measure(new Size(920, 620));
                mediaContent.Arrange(new Rect(0, 0, 920, 620));
                mediaContent.UpdateLayout();
                Assert(mediaWindow.MediaView.ActualWidth > 300 && mediaWindow.ProgressSlider.ActualWidth > 100 &&
                       mediaWindow.CloseButton.ActualWidth > 0 && mediaWindow.PlayButton.IsEnabled &&
                       mediaWindow.LoadingText.Visibility == Visibility.Collapsed,
                    $"保险箱媒体查看没有从加密内容开始播放，或主要操作没有获得可用布局空间。" +
                    $" 画面={mediaWindow.MediaView.ActualWidth:0.##}，进度={mediaWindow.ProgressSlider.ActualWidth:0.##}，" +
                    $"播放可用={mediaWindow.PlayButton.IsEnabled}，提示={mediaWindow.LoadingText.Visibility}，内容={mediaWindow.LoadingText.Text}");
            }
            finally { mediaWindow.Close(); }

            var help = new HelpWindow();
            try
            {
                var helpText = help.VaultText.Text;
                Assert(UiLanguage.IsEnglish
                        ? helpText.Contains("Create concealed space", StringComparison.Ordinal) &&
                          helpText.Contains("cannot guarantee", StringComparison.OrdinalIgnoreCase) &&
                          helpText.Contains("fallback browser", StringComparison.OrdinalIgnoreCase)
                        : helpText.Contains("建立隐蔽空间", StringComparison.Ordinal) &&
                          helpText.Contains("不能保证", StringComparison.Ordinal) &&
                          helpText.Contains("备用查看", StringComparison.Ordinal),
                    "保险箱帮助没有完整说明双空间入口、真实边界或临时磁盘备用流程。");
            }
            finally { help.Close(); }
        }
        finally { window.Close(); }

        using var lockPassword = SensitivePassword.FromString(secondPasswordText);
        using var lockRequest = new UnlockVaultRequest(path, lockPassword);
        using var lockSession = service.UnlockAsync(lockRequest).GetAwaiter().GetResult();
        Console.WriteLine("保险箱工作区检查：锁定测试会话已解锁。");
        var lockWindow = new VaultWindow(
            service,
            new NrArchiveService(KdfParameters.Testing),
            new NrKeyFileService(KdfParameters.Testing),
            new NrPhysicalDeviceService());
        using var activeOperation = new CancellationTokenSource();
        try
        {
            const BindingFlags privateInstance = BindingFlags.Instance | BindingFlags.NonPublic;
            Assert(!VaultWindow.ShouldLockForIdle(15 * 60 * 1000, 0, vaultArchiveExportInProgress: true),
                "保险箱导出超过 15 分钟时仍会触发无人操作自动锁定。");
            Assert(VaultWindow.ShouldLockForIdle(15 * 60 * 1000, 0, vaultArchiveExportInProgress: false),
                "保险箱导出结束后没有恢复 15 分钟无人操作自动锁定。");
            typeof(VaultWindow).GetField("_vaultSession", privateInstance)!.SetValue(lockWindow, lockSession);
            typeof(VaultWindow).GetField("_operationCancellation", privateInstance)!.SetValue(lockWindow, activeOperation);
            typeof(VaultWindow).GetField("_busy", privateInstance)!.SetValue(lockWindow, true);
            typeof(VaultWindow).GetMethod("RequestImmediateLock", privateInstance)!.Invoke(lockWindow, null);
            Assert(activeOperation.IsCancellationRequested && !lockSession.IsOpen,
                "正在执行操作时请求锁定，没有同时取消操作并清除当前保险箱会话。");
        }
        finally { lockWindow.Close(); }
    }

    private static byte[] CreateSilentWave()
    {
        const int sampleRate = 8000;
        const int seconds = 1;
        const short channels = 1;
        const short bitsPerSample = 16;
        var dataLength = sampleRate * seconds * channels * bitsPerSample / 8;
        var bytes = new byte[44 + dataLength];
        "RIFF"u8.CopyTo(bytes);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(4, 4), 36 + dataLength);
        "WAVEfmt "u8.CopyTo(bytes.AsSpan(8));
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(16, 4), 16);
        BinaryPrimitives.WriteInt16LittleEndian(bytes.AsSpan(20, 2), 1);
        BinaryPrimitives.WriteInt16LittleEndian(bytes.AsSpan(22, 2), channels);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(24, 4), sampleRate);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(28, 4), sampleRate * channels * bitsPerSample / 8);
        BinaryPrimitives.WriteInt16LittleEndian(bytes.AsSpan(32, 2), (short)(channels * bitsPerSample / 8));
        BinaryPrimitives.WriteInt16LittleEndian(bytes.AsSpan(34, 2), bitsPerSample);
        "data"u8.CopyTo(bytes.AsSpan(36));
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(40, 4), dataLength);
        return bytes;
    }

    private static void PumpDispatcher(TimeSpan duration)
    {
        var frame = new DispatcherFrame();
        var timer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = duration,
        };
        timer.Tick += (_, _) =>
        {
            timer.Stop();
            frame.Continue = false;
        };
        timer.Start();
        Dispatcher.PushFrame(frame);
    }

    private static void VerifyProtectedRecentDeliveryHistory(string root)
    {
        var storagePath = Path.Combine(root, "history", "recent-deliveries.dat");
        var packagePath = Path.Combine(root, "只应出现在加密记录中.nrenc");
        var created = DateTimeOffset.UtcNow;
        var expires = created.AddDays(30);
        var history = new RecentDeliveryHistory(storagePath);
        history.Add(packagePath, created, expires, verificationPassed: true);
        var storedBytes = File.ReadAllBytes(storagePath);
        var plaintextPathBytes = Encoding.UTF8.GetBytes(packagePath);
        Assert(storedBytes.AsSpan().IndexOf(plaintextPathBytes) < 0,
            "最近交付记录在磁盘中泄露了交付包完整路径明文。");
        var loaded = history.Load();
        Assert(loaded.Count == 1 && loaded[0].Path == Path.GetFullPath(packagePath) &&
               loaded[0].ExpiresAtUtc == expires && loaded[0].VerificationPassed,
            "受保护的最近交付记录无法由当前 Windows 用户正确读回。");
        var recordProperties = typeof(RecentDeliveryItem).GetProperties().Select(property => property.Name).ToArray();
        Assert(!recordProperties.Any(name => name.Contains("Password", StringComparison.OrdinalIgnoreCase) ||
                                             name.Contains("Key", StringComparison.OrdinalIgnoreCase) ||
                                             name.Contains("FileList", StringComparison.OrdinalIgnoreCase)),
            "最近交付记录模型包含不应保存的敏感字段。");
    }

    private static async Task CreatePackageAsync(
        IReadOnlyList<string> sources,
        string archivePath,
        DeliveryPackageInfo? delivery)
    {
        using var manifest = delivery is null
            ? PayloadManifest.Build(sources[0], SizePaddingMode.None, CancellationToken.None)
            : PayloadManifest.BuildMany(sources, "安全交付资料", SizePaddingMode.None, CancellationToken.None);
        using var password = SensitivePassword.FromString(PasswordText);
        var createdHeader = await ArchiveHeader.CreateAsync(password, ReadOnlyMemory<byte>.Empty,
            EncryptionMode.Standard, false, KdfParameters.Testing, CancellationToken.None);
        var header = createdHeader.Header;
        var dataKey = createdHeader.DataKey;
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = key.ExportSubjectPublicKeyInfo();
        var fingerprint = Convert.ToHexString(SHA256.HashData(publicKey));
        CryptographicOperations.ZeroMemory(publicKey);
        using var identity = new SigningIdentity("自动检查发送者", fingerprint, key);
        try
        {
            await using var output = new FileStream(archivePath, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None,
                IndexedPayloadContainer.BlockSize, FileOptions.Asynchronous | FileOptions.WriteThrough);
            await output.WriteAsync(header.Bytes);
            using var payload = await IndexedPayloadContainer.WriteAsync(
                output, manifest, header, dataKey, identity, ArchiveCompressionLevel.Standard, delivery, null,
                CancellationToken.None);
            await output.FlushAsync();
            output.Flush(flushToDisk: true);
            using var reopened = await IndexedPayloadContainer.OpenAsync(output, header, dataKey, CancellationToken.None,
                archiveOffset: 0, archiveLength: output.Length);
            await IndexedPayloadContainer.ValidateAllAsync(output, header, dataKey, reopened, null, CancellationToken.None);
            Assert(Equals(reopened.DeliveryInfo, delivery), "写入后重新读取的交付信息不一致。");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dataKey);
            CryptographicOperations.ZeroMemory(header.Bytes);
            CryptographicOperations.ZeroMemory(header.PayloadNoncePrefix);
            CryptographicOperations.ZeroMemory(header.HeaderHash);
        }
    }

    private static async Task<SecureArchiveSession> OpenSessionAsync(string archivePath)
    {
        var input = new FileStream(archivePath, FileMode.Open, FileAccess.Read, FileShare.Read,
            IndexedPayloadContainer.BlockSize, FileOptions.Asynchronous | FileOptions.RandomAccess);
        using var password = SensitivePassword.FromString(PasswordText);
        ArchiveHeader? header = null;
        byte[]? dataKey = null;
        IndexedPayloadContainer.IndexedPayload? payload = null;
        try
        {
            var unlocked = await ArchiveHeader.ReadAndUnlockAsync(input, password, ReadOnlyMemory<byte>.Empty,
                new NrPhysicalDeviceService(), 0, CancellationToken.None, EncryptionMode.Standard);
            header = unlocked.Header;
            dataKey = unlocked.DataKey;
            payload = await IndexedPayloadContainer.OpenAsync(input, header, dataKey, CancellationToken.None,
                0, input.Length);
            var session = new SecureArchiveSession(input, header, dataKey, payload, null, null,
                "自动检查发送者", false, archivePath, 0, input.Length);
            input = null!;
            header = null;
            dataKey = null;
            payload = null;
            return session;
        }
        finally
        {
            input?.Dispose();
            payload?.Dispose();
            if (dataKey is not null) CryptographicOperations.ZeroMemory(dataKey);
            if (header is not null)
            {
                CryptographicOperations.ZeroMemory(header.Bytes);
                CryptographicOperations.ZeroMemory(header.PayloadNoncePrefix);
                CryptographicOperations.ZeroMemory(header.HeaderHash);
            }
        }
    }

    private static Task VerifyDuplicateTopLevelNamesAreRejectedAsync(string root)
    {
        var first = Path.Combine(root, "重复一", "相同名称");
        var second = Path.Combine(root, "重复二", "相同名称");
        Directory.CreateDirectory(first);
        Directory.CreateDirectory(second);
        return ExpectNingRanFailureAsync(() => Task.Run(() =>
        {
            using var ignored = PayloadManifest.BuildMany([first, second], "交付", SizePaddingMode.None,
                CancellationToken.None);
        }), "同名顶层项目没有被明确拒绝。");
    }

    private static Task VerifyNestedSelectionIsRejectedAsync(string root, string parent)
    {
        var nested = Path.Combine(parent, "说明 中文 & symbols (1).txt");
        return ExpectNingRanFailureAsync(() => Task.Run(() =>
        {
            using var ignored = PayloadManifest.BuildMany([parent, nested], "交付", SizePaddingMode.None,
                CancellationToken.None);
        }), "重复选择文件夹和其内部文件时没有明确拒绝。");
    }

    private static async Task VerifyIncrementalArchiveUpdatesAsync(string root)
    {
        var workspace = Path.Combine(root, "增量修改检查");
        Directory.CreateDirectory(workspace);
        var sourceRoot = Path.Combine(workspace, "原始资料");
        Directory.CreateDirectory(sourceRoot);
        await File.WriteAllTextAsync(Path.Combine(sourceRoot, "删除后不可见.txt"), "old", Encoding.UTF8);
        await File.WriteAllTextAsync(Path.Combine(sourceRoot, "保留内容.txt"), "keep", Encoding.UTF8);
        var firstAddition = Path.Combine(workspace, "第一次追加.txt");
        var secondAddition = Path.Combine(workspace, "第二次追加.txt");
        await File.WriteAllTextAsync(firstAddition, "first", Encoding.UTF8);
        await File.WriteAllTextAsync(secondAddition, "second", Encoding.UTF8);
        var archivePath = Path.Combine(workspace, "增量测试.nrenc");
        const string passwordText = "Incremental archive check 8.0.1!";

        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = signingKey.ExportSubjectPublicKeyInfo();
        var fingerprint = Convert.ToHexString(SHA256.HashData(publicKey));
        CryptographicOperations.ZeroMemory(publicKey);
        using var identity = new SigningIdentity("增量检查身份", fingerprint, signingKey);

        await CreateEditableArchiveAsync(sourceRoot, archivePath, passwordText, identity);
        await ApplyIncrementalUpdateForCheckAsync(
            archivePath,
            passwordText,
            identity,
            Path.Combine(Path.GetFileName(sourceRoot), "删除后不可见.txt"),
            firstAddition);

        var firstState = await ReadIncrementalStateForCheckAsync(archivePath, passwordText);
        try
        {
            Assert(firstState.Generation == 1, "第一次增量修改没有生成第一个修改版本。");
            Assert(!firstState.Payload.Entries.Any(entry => entry.RelativePath.EndsWith("删除后不可见.txt", StringComparison.Ordinal)),
                "增量删除后原文件仍然出现在目录中。");
            var firstEntry = firstState.Payload.Entries.Single(entry => entry.RelativePath.EndsWith("第一次追加.txt", StringComparison.Ordinal));
            await using var firstStream = new SecureArchiveReadStreamForCheck(
                firstState.Input,
                firstState.Header,
                firstState.DataKey,
                firstState.Payload,
                firstEntry);
            using var firstReader = new StreamReader(firstStream, Encoding.UTF8);
            Assert(await firstReader.ReadToEndAsync() == "first", "第一次增量追加的内容读取不正确。");
        }
        finally
        {
            firstState.Dispose();
        }

        await ApplyIncrementalUpdateForCheckAsync(
            archivePath,
            passwordText,
            identity,
            Path.Combine(Path.GetFileName(sourceRoot), "第一次追加.txt"),
            secondAddition,
            simulateRecovery: true);

        var secondState = await ReadIncrementalStateForCheckAsync(archivePath, passwordText);
        try
        {
            Assert(secondState.Generation == 2, "第二次增量修改没有正确接续上一版本。");
            Assert(!secondState.Payload.Entries.Any(entry => entry.RelativePath.EndsWith("第一次追加.txt", StringComparison.Ordinal)),
                "第二次增量删除没有移除上一版本追加的文件。");
            Assert(secondState.Payload.Entries.Any(entry => entry.RelativePath.EndsWith("第二次追加.txt", StringComparison.Ordinal)),
                "第二次增量追加的文件没有出现在目录中。");
        }
        finally
        {
            secondState.Dispose();
        }

        Console.WriteLine("凝然加密包增量追加、删除和连续版本检查通过。");
    }

    private static async Task CreateEditableArchiveAsync(
        string sourceRoot,
        string archivePath,
        string passwordText,
        SigningIdentity identity)
    {
        using var manifest = PayloadManifest.Build(sourceRoot, SizePaddingMode.None, CancellationToken.None);
        using var password = SensitivePassword.FromString(passwordText);
        var created = await ArchiveHeader.CreateAsync(
            password,
            ReadOnlyMemory<byte>.Empty,
            EncryptionMode.Standard,
            false,
            KdfParameters.Testing,
            CancellationToken.None);
        var header = created.Header;
        var dataKey = created.DataKey;
        try
        {
            await using var output = new FileStream(
                archivePath,
                FileMode.CreateNew,
                FileAccess.ReadWrite,
                FileShare.None,
                IndexedPayloadContainer.BlockSize,
                FileOptions.Asynchronous | FileOptions.WriteThrough);
            await output.WriteAsync(header.Bytes);
            using var payload = await IndexedPayloadContainer.WriteAsync(
                output,
                manifest,
                header,
                dataKey,
                identity,
                ArchiveCompressionLevel.Standard,
                null,
                null,
                CancellationToken.None);
            await output.FlushAsync();
            output.Flush(flushToDisk: true);
            using var reopened = await IndexedPayloadContainer.OpenAsync(
                output,
                header,
                dataKey,
                CancellationToken.None,
                archiveOffset: 0,
                archiveLength: output.Length);
            await IndexedPayloadContainer.ValidateAllAsync(output, header, dataKey, reopened, null, CancellationToken.None);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dataKey);
            CryptographicOperations.ZeroMemory(header.Bytes);
            CryptographicOperations.ZeroMemory(header.PayloadNoncePrefix);
            CryptographicOperations.ZeroMemory(header.HeaderHash);
        }
    }

    private static async Task ApplyIncrementalUpdateForCheckAsync(
        string archivePath,
        string passwordText,
        SigningIdentity identity,
        string removePath,
        string additionPath,
        bool simulateRecovery = false)
    {
        await using var input = new FileStream(
            archivePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            IndexedPayloadContainer.BlockSize,
            FileOptions.Asynchronous | FileOptions.RandomAccess);
        using var password = SensitivePassword.FromString(passwordText);
        var unlocked = await ArchiveHeader.ReadAndUnlockAsync(
            input,
            password,
            ReadOnlyMemory<byte>.Empty,
            new NrPhysicalDeviceService(),
            0,
            CancellationToken.None,
            EncryptionMode.Standard);
        var header = unlocked.Header;
        var dataKey = unlocked.DataKey;
        IndexedPayloadContainer.IndexedPayload? basePayload = null;
        IncrementalArchiveContainer.OpenResult? incremental = null;
        PayloadManifest? manifest = null;
        var stagedPath = Path.Combine(
            Path.GetDirectoryName(archivePath)!,
            $".ningran-increment-check-{Guid.NewGuid():N}.part");
        try
        {
            basePayload = await IndexedPayloadContainer.OpenAsync(
                input,
                header,
                dataKey,
                CancellationToken.None,
                archiveOffset: 0,
                archiveLength: input.Length,
                allowTrailingIncrementalData: true);
            incremental = await IncrementalArchiveContainer.OpenAsync(
                input,
                header,
                dataKey,
                basePayload,
                input.Length,
                CancellationToken.None);
            var payload = incremental.Payload;
            var remove = PathSafety.NormalizeRelativePath(removePath);
            var entries = payload.Entries
                .Where(entry => !string.Equals(entry.RelativePath, remove, StringComparison.OrdinalIgnoreCase) &&
                                !entry.RelativePath.StartsWith(remove + "/", StringComparison.OrdinalIgnoreCase))
                .ToList();
            manifest = PayloadManifest.Build(additionPath, SizePaddingMode.None, CancellationToken.None);
            var destination = PathSafety.NormalizeRelativePath(payload.RootName + "/" + manifest.RootName);
            var sourceEntry = manifest.Entries.Single(entry => entry.Kind == PayloadEntryKind.File);
            var plannedBlocks = await IndexedPayloadContainer.PlanSourceFileAsync(
                sourceEntry,
                ArchiveCompressionLevel.Standard,
                null,
                CancellationToken.None);
            var baseDataStart = IndexedPayloadContainer.DataStart(header, payload);
            var nextDataOffset = checked(incremental.EffectiveLength + IncrementalArchiveContainer.SegmentHeaderSize - baseDataStart);
            var nextBlockIndex = incremental.NextBlockIndex;
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
            entries.Add(indexedEntry);
            var rewrittenSource = sourceEntry with { RelativePath = destination };
            var addition = new IncrementalArchiveContainer.PlannedAddition(rewrittenSource, indexedEntry);
            var previousHash = payload.AuthenticatedHash.ToArray();
            var prefix = payload.CreatePrefix();
            try
            {
                var staged = await IncrementalArchiveContainer.WriteStagedAsync(
                    stagedPath,
                    incremental.EffectiveLength,
                    incremental.BaseLength,
                    incremental.Generation + 1,
                    incremental.LastSegmentStart,
                    previousHash,
                    incremental.NextBlockIndex,
                    header,
                    dataKey,
                    prefix,
                    [addition],
                    entries,
                    payload.IsDirectory,
                    payload.RootName,
                    ArchiveCompressionLevel.Standard,
                    identity,
                    CancellationToken.None);
                await IncrementalArchiveContainer.ValidateStagedAsync(
                    stagedPath,
                    staged,
                    header,
                    dataKey,
                    prefix,
                    baseDataStart,
                    identity,
                    [addition],
                    CancellationToken.None);

                if (simulateRecovery)
                {
                    await input.DisposeAsync();
                    await using var registrationInput = new FileStream(
                        archivePath,
                        FileMode.Open,
                        FileAccess.ReadWrite,
                        FileShare.None,
                        IndexedPayloadContainer.BlockSize,
                        FileOptions.Asynchronous | FileOptions.WriteThrough);
                    IncrementalArchiveRecovery.Register(
                        registrationInput,
                        archivePath,
                        stagedPath,
                        staged);
                    await registrationInput.DisposeAsync();
                    var recovery = IncrementalArchiveRecovery.RecoverAbandoned(archivePath);
                    Assert(recovery.Failures.Count == 0 && recovery.RemovedDirectoryCount == 1,
                        $"中断的增量提交没有被安全恢复：{string.Join("；", recovery.Failures.Select(item => item.Reason))}（已处理 {recovery.RemovedDirectoryCount} 项）。");
                }
                else
                {
                    var committedMarker = IncrementalArchiveContainer.GetCommittedSegmentMagic();
                    try
                    {
                        await input.DisposeAsync();
                        await using var target = new FileStream(
                            archivePath,
                            FileMode.Open,
                            FileAccess.ReadWrite,
                            FileShare.None,
                            IndexedPayloadContainer.BlockSize,
                            FileOptions.Asynchronous | FileOptions.WriteThrough);
                        target.Position = incremental.EffectiveLength;
                        await using (var stagedInput = new FileStream(
                                         stagedPath,
                                         FileMode.Open,
                                         FileAccess.Read,
                                         FileShare.Read,
                                         IndexedPayloadContainer.BlockSize,
                                         FileOptions.Asynchronous | FileOptions.SequentialScan))
                        {
                            await stagedInput.CopyToAsync(target, IndexedPayloadContainer.BlockSize, CancellationToken.None);
                        }

                        await target.FlushAsync();
                        target.Flush(flushToDisk: true);
                        target.Position = incremental.EffectiveLength;
                        await target.WriteAsync(committedMarker);
                        await target.FlushAsync();
                        target.Flush(flushToDisk: true);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(committedMarker);
                    }
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(previousHash);
                CryptographicOperations.ZeroMemory(prefix);
            }
        }
        finally
        {
            manifest?.Dispose();
            incremental?.Payload.Dispose();
            if (basePayload is not null && !ReferenceEquals(incremental?.Payload, basePayload))
            {
                basePayload.Dispose();
            }
            CryptographicOperations.ZeroMemory(dataKey);
            CryptographicOperations.ZeroMemory(header.Bytes);
            CryptographicOperations.ZeroMemory(header.PayloadNoncePrefix);
            CryptographicOperations.ZeroMemory(header.HeaderHash);
            try { if (File.Exists(stagedPath)) File.Delete(stagedPath); } catch { }
        }
    }

    private static async Task<IncrementalCheckState> ReadIncrementalStateForCheckAsync(
        string archivePath,
        string passwordText)
    {
        var input = new FileStream(
            archivePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            IndexedPayloadContainer.BlockSize,
            FileOptions.Asynchronous | FileOptions.RandomAccess);
        using var password = SensitivePassword.FromString(passwordText);
        ArchiveHeader? header = null;
        byte[]? dataKey = null;
        IndexedPayloadContainer.IndexedPayload? basePayload = null;
        try
        {
            var unlocked = await ArchiveHeader.ReadAndUnlockAsync(
                input,
                password,
                ReadOnlyMemory<byte>.Empty,
                new NrPhysicalDeviceService(),
                0,
                CancellationToken.None,
                EncryptionMode.Standard);
            header = unlocked.Header;
            dataKey = unlocked.DataKey;
            basePayload = await IndexedPayloadContainer.OpenAsync(
                input,
                header,
                dataKey,
                CancellationToken.None,
                0,
                input.Length,
                allowTrailingIncrementalData: true);
            var incremental = await IncrementalArchiveContainer.OpenAsync(
                input,
                header,
                dataKey,
                basePayload,
                input.Length,
                CancellationToken.None);
            var state = new IncrementalCheckState(input, header, dataKey, incremental.Payload, incremental.Generation);
            input = null!;
            header = null;
            dataKey = null;
            basePayload = null;
            return state;
        }
        finally
        {
            input?.Dispose();
            basePayload?.Dispose();
            if (dataKey is not null) CryptographicOperations.ZeroMemory(dataKey);
            if (header is not null)
            {
                CryptographicOperations.ZeroMemory(header.Bytes);
                CryptographicOperations.ZeroMemory(header.PayloadNoncePrefix);
                CryptographicOperations.ZeroMemory(header.HeaderHash);
            }
        }
    }

    private sealed class IncrementalCheckState(
        FileStream input,
        ArchiveHeader header,
        byte[] dataKey,
        IndexedPayloadContainer.IndexedPayload payload,
        long generation) : IDisposable
    {
        public FileStream Input { get; } = input;
        public ArchiveHeader Header { get; } = header;
        public byte[] DataKey { get; } = dataKey;
        public IndexedPayloadContainer.IndexedPayload Payload { get; } = payload;
        public long Generation { get; } = generation;

        public void Dispose()
        {
            Input.Dispose();
            Payload.Dispose();
            CryptographicOperations.ZeroMemory(DataKey);
            CryptographicOperations.ZeroMemory(Header.Bytes);
            CryptographicOperations.ZeroMemory(Header.PayloadNoncePrefix);
            CryptographicOperations.ZeroMemory(Header.HeaderHash);
        }
    }

    private sealed class SecureArchiveReadStreamForCheck(
        FileStream input,
        ArchiveHeader header,
        byte[] dataKey,
        IndexedPayloadContainer.IndexedPayload payload,
        IndexedPayloadContainer.IndexedPayloadEntry entry) : Stream
    {
        private readonly MemoryStream _buffer = new();

        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => _buffer.Length;
        public override long Position { get => _buffer.Position; set => _buffer.Position = value; }

        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => _buffer.Read(buffer, offset, count);
        public override long Seek(long offset, SeekOrigin origin) => _buffer.Seek(offset, origin);
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_buffer.Length == 0)
            {
                await using var content = new MemoryStream();
                await IndexedPayloadContainer.CopyEntryToStreamAsync(
                    input,
                    header,
                    dataKey,
                    payload,
                    entry,
                    content,
                    cancellationToken);
                content.Position = 0;
                await content.CopyToAsync(_buffer, cancellationToken);
                _buffer.Position = 0;
            }

            return await _buffer.ReadAsync(buffer, cancellationToken);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) _buffer.Dispose();
            base.Dispose(disposing);
        }
    }

    private static async Task VerifyTamperedPackageIsRejectedAsync(
        string root,
        string archivePath,
        NrArchiveService archiveService)
    {
        var tamperedPath = Path.Combine(root, "被改动的交付.nrenc");
        File.Copy(archivePath, tamperedPath);
        await using (var stream = new FileStream(tamperedPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            var position = Math.Max(1, stream.Length / 2);
            stream.Position = position;
            var original = stream.ReadByte();
            Assert(original >= 0, "无法为篡改检查读取交付包内容。");
            stream.Position = position;
            stream.WriteByte((byte)(original ^ 0x5A));
            stream.Flush(flushToDisk: true);
        }

        using var request = new DecryptRequest(
            tamperedPath,
            string.Empty,
            PasswordText,
            ExpectedMode: EncryptionMode.Standard);
        await ExpectNingRanFailureAsync(async () =>
        {
            using var session = await archiveService.OpenForBrowsingAsync(request);
            await session.ValidateAsync();
        }, "交付包内容被改动后仍然通过了完整性检查。");
    }

    private static async Task VerifyFutureFormatRequestsUpdateAsync(
        string root,
        string archivePath,
        NrArchiveService archiveService)
    {
        var futurePath = Path.Combine(root, "未来格式交付.nrenc");
        File.Copy(archivePath, futurePath);
        long prefixOffset;
        await using (var input = new FileStream(futurePath, FileMode.Open, FileAccess.Read, FileShare.Read))
        using (var password = SensitivePassword.FromString(PasswordText))
        {
            var unlocked = await ArchiveHeader.ReadAndUnlockAsync(
                input,
                password,
                ReadOnlyMemory<byte>.Empty,
                new NrPhysicalDeviceService(),
                0,
                CancellationToken.None,
                EncryptionMode.Standard);
            prefixOffset = unlocked.Header.Bytes.Length;
            CryptographicOperations.ZeroMemory(unlocked.DataKey);
            CryptographicOperations.ZeroMemory(unlocked.Header.Bytes);
            CryptographicOperations.ZeroMemory(unlocked.Header.PayloadNoncePrefix);
            CryptographicOperations.ZeroMemory(unlocked.Header.HeaderHash);
        }

        await using (var output = new FileStream(futurePath, FileMode.Open, FileAccess.Write, FileShare.None))
        {
            output.Position = prefixOffset + 7;
            output.WriteByte((byte)'9');
            output.Flush(flushToDisk: true);
        }

        using var request = new DecryptRequest(
            futurePath,
            string.Empty,
            PasswordText,
            ExpectedMode: EncryptionMode.Standard);
        try
        {
            using var ignored = await archiveService.OpenForBrowsingAsync(request);
        }
        catch (NingRanException exception)
        {
            Assert(exception.Message.Contains("更新", StringComparison.Ordinal),
                "遇到较新交付格式时没有给出清晰的更新提示。");
            return;
        }

        throw new InvalidOperationException("较新交付格式被错误地当作当前格式打开。");
    }

    private static async Task ExpectNingRanFailureAsync(Func<Task> action, string message)
    {
        try
        {
            await action();
        }
        catch (NingRanException)
        {
            return;
        }

        throw new InvalidOperationException(message);
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    private static byte[] ComputeFileHash(string path)
    {
        using var stream = File.OpenRead(path);
        return SHA256.HashData(stream);
    }
}
