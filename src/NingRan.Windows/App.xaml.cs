using System.IO;
using System.Windows;
using System.Windows.Threading;
using NingRan.Core;
using NingRan.Security;

namespace NingRan.Windows;

public partial class App : Application
{
    private SingleInstanceCoordinator? _singleInstance;
    private NativeElevationBinding? _nativeElevationBinding;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        EventManager.RegisterClassHandler(typeof(Window), FrameworkElement.LoadedEvent,
            new RoutedEventHandler(Window_Loaded), handledEventsToo: true);
        if (!NativeElevationBinding.TryConsume(
                e.Args,
                out var applicationArguments,
                out var nativeBinding,
                out var bindingError))
        {
            MessageBox.Show(
                $"管理员组件没有通过原生安全引导验证，已停止运行。\n\n{bindingError}",
                "凝然加密",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            Shutdown(2);
            return;
        }
        _nativeElevationBinding = nativeBinding;

        if (StrictProtectionSettings.IsManagementArgumentPresent(applicationArguments))
        {
            if (nativeBinding?.IsMode(NativeElevationBinding.Modes.StrictSettings) != true)
            {
                Shutdown(2);
                return;
            }
            var exitCode = RunStrictProtectionSettingsEditor(applicationArguments);
            Shutdown(exitCode);
            return;
        }

        if (TrustedContactBrokerClient.IsBrokerArgumentPresent(applicationArguments))
        {
            if (nativeBinding?.IsMode(NativeElevationBinding.Modes.TrustedContact) != true)
            {
                Shutdown(2);
                return;
            }
            var exitCode = RunTrustedContactBroker(applicationArguments);
            Shutdown(exitCode);
            return;
        }

        var processElevated = NingRanRuntime.IsProcessElevated();
        CrashReportService.CleanupPreviousReports();
        DispatcherUnhandledException += App_DispatcherUnhandledException;
        TaskScheduler.UnobservedTaskException += App_UnobservedTaskException;
        var highSecurityOpen = HighSecurityLaunch.TryReadPath(applicationArguments, out var highSecurityArchivePath);
        if (highSecurityOpen && nativeBinding?.IsMode(NativeElevationBinding.Modes.HighSecurity) != true)
        {
            MessageBox.Show(
                "高安全查看没有通过原生安全引导验证，已停止运行。",
                "凝然加密",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            Shutdown(2);
            return;
        }
        if (!highSecurityOpen && nativeBinding is not null)
        {
            Shutdown(2);
            return;
        }
        var associatedFile = highSecurityArchivePath ?? applicationArguments.FirstOrDefault(File.Exists);
        if (highSecurityOpen && !HighSecurityLaunch.IsTrustedInstalledComponent(
                Environment.ProcessPath ?? string.Empty,
                "NingRan.exe"))
        {
            MessageBox.Show(
                "高安全查看只能从受保护的正式安装位置启动，已拒绝当前请求。",
                "凝然加密",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            Shutdown(-1);
            return;
        }

        if (processElevated && !highSecurityOpen)
        {
            var notice = new SecurityNoticeWindow();
            notice.ShowDialog();
            Shutdown(-1);
            return;
        }

        if (highSecurityOpen && !processElevated)
        {
            MessageBox.Show("高安全查看必须经 Windows 管理员确认启动。请从普通窗口的“高安全打开”按钮重新开始。",
                "凝然加密", MessageBoxButton.OK, MessageBoxImage.Warning);
            Shutdown(-1);
            return;
        }

        if (!highSecurityOpen)
        {
            _singleInstance = new SingleInstanceCoordinator(Dispatcher);
            if (!_singleInstance.IsPrimaryInstance)
            {
                if (associatedFile is not null)
                {
                    // 文件路径只由本次启动的受信进程处理，不交给已经运行的进程。
                    // 这样即使旧进程已被同一账户中的恶意程序劫持，也无法获得待打开文件的路径。
                    _singleInstance.Dispose();
                    _singleInstance = null;
                }
                else
                {
                    var delivered = await _singleInstance.NotifyPrimaryAsync();
                    if (!delivered)
                    {
                        MessageBox.Show(
                            "凝然加密已经在运行，但暂时无法联系现有窗口。请切换到已打开的窗口后重试。",
                            "凝然加密",
                            MessageBoxButton.OK,
                            MessageBoxImage.Warning);
                    }

                    Shutdown(delivered ? 0 : 2);
                    return;
                }
            }

            _singleInstance?.StartListening();
        }

        TemporaryContentCleanupResult cleanupResult;
        if (processElevated)
        {
            // 高安全窗口绝不读取、创建或清理普通用户的 LocalAppData 恢复登记。
            // 这些登记会由下次普通权限启动负责清理。
            cleanupResult = new TemporaryContentCleanupResult(0, []);
        }
        else
        {
            try
            {
                cleanupResult = NrArchiveService.CleanupAbandonedTemporaryContent();
            }
            catch (Exception exception)
            {
                cleanupResult = new TemporaryContentCleanupResult(
                    0,
                    new[]
                    {
                        new TemporaryContentCleanupFailure(
                            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                            exception.Message),
                    });
            }
        }

        var splash = new SplashWindow();
        splash.Show();

        var minimumDisplay = Task.Delay(TimeSpan.FromSeconds(2));
        var mainWindow = new MainWindow(allowElevatedMediaBrowsing: highSecurityOpen);
        await minimumDisplay;

        MainWindow = mainWindow;
        ShutdownMode = ShutdownMode.OnMainWindowClose;
        mainWindow.Show();
        splash.Close();

        if (associatedFile is not null)
        {
            await mainWindow.OpenAssociatedFileAsync(associatedFile);
        }

        _singleInstance?.SetRequestHandler(mainWindow.HandleExternalLaunch);

        if (cleanupResult.Failures.Count > 0)
        {
            MessageBox.Show(
                mainWindow,
                $"发现上次异常退出留下的临时内容，但有 {cleanupResult.Failures.Count} 项无法自动删除。程序下次启动时会继续尝试清理。",
                "凝然加密 - 安全清理提醒",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
        else if (cleanupResult.RemovedDirectoryCount > 0)
        {
            MessageBox.Show(
                mainWindow,
                $"已自动清理上次异常退出留下的 {cleanupResult.RemovedDirectoryCount} 个临时项目。",
                "凝然加密",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
    }

    private static void Window_Loaded(object sender, RoutedEventArgs e)
    {
        if (sender is Window window)
        {
            UiLanguage.Apply(window);
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        TaskScheduler.UnobservedTaskException -= App_UnobservedTaskException;
        CrashReportService.CleanupPreviousReports();
        _singleInstance?.Dispose();
        _singleInstance = null;
        _nativeElevationBinding?.Dispose();
        _nativeElevationBinding = null;
        base.OnExit(e);
    }

    private void App_DispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        e.Handled = true;
        CrashReportDialog.ShowTemporary(MainWindow, "程序遇到错误", "程序遇到未处理的错误，当前操作已停止。", "主窗口", e.Exception);
    }

    private static void App_UnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
    {
        try { CrashReportService.Create("后台任务", "后台任务发生错误。", e.Exception); } catch { }
        e.SetObserved();
    }

    private static int RunTrustedContactBroker(IReadOnlyList<string> arguments)
    {
        if (!TrustedContactBrokerClient.TryReadRequestBinding(arguments, out var requestBinding) ||
            requestBinding is null)
        {
            MessageBox.Show(
                UiLanguage.IsEnglish
                    ? "The trusted-contact administrator request is incomplete. Close this window and restart it from the NingRan Encryption main window."
                    : "可信联系人管理员请求不完整。请关闭此窗口并从凝然加密主窗口重新开始。",
                "凝然加密 - 管理员确认",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return 1;
        }

        if (!NingRanRuntime.IsProcessElevated() ||
            !HighSecurityLaunch.IsTrustedInstalledComponent(
                Environment.ProcessPath ?? string.Empty,
                "NingRan.exe"))
        {
            MessageBox.Show(
                UiLanguage.IsEnglish
                    ? "This request must be handled by NingRan Encryption from a protected installation location after Windows administrator confirmation."
                    : "该请求必须由受保护安装位置中的凝然加密，经 Windows 管理员确认后处理。",
                "凝然加密 - 管理员确认",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return 1;
        }

        try
        {
            using var operation = TrustedContactBroker.OpenRequest(requestBinding);
            var preview = operation.Preview;
            if (preview.Action == TrustedContactBrokerAction.Trust)
            {
                var dialog = new PublicIdentityVerificationDialog(
                    preview.Name,
                    preview.VerificationCode,
                    preview.TargetAccount,
                    preview.TargetUserSid);
                if (dialog.ShowDialog() != true)
                {
                    return TrustedContactBrokerClient.CancelledExitCode;
                }

                var contact = operation.Commit()
                    ?? throw new NingRanException("未能建立受保护的可信联系人记录。");
                MessageBox.Show(
                    UiLanguage.IsEnglish
                        ? $"Trusted contact “{contact.Name}” was saved for Windows account “{preview.TargetAccount}”."
                        : $"已为 Windows 账户“{preview.TargetAccount}”保存可信联系人“{contact.Name}”。",
                    "凝然加密 - 管理员确认",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                return 0;
            }

            var legacyNotice = preview.IsLegacyRecord
                ? (UiLanguage.IsEnglish
                    ? "\n\nThis record was left by an earlier version and is currently not trusted."
                    : "\n\n这是升级前留下、当前已暂停信任的旧记录。")
                : string.Empty;
            var answer = MessageBox.Show(
                UiLanguage.IsEnglish
                    ? $"Remove this contact from Windows account:\n{preview.TargetAccount}\nSID: {preview.TargetUserSid}\n\nContact: {preview.Name}\nIdentity fingerprint: {FormatFingerprint(preview.Fingerprint)}{legacyNotice}\n\nTo trust it again after removal, the security code must be entered again. Continue?"
                    : $"将从以下 Windows 账户删除联系人：\n{preview.TargetAccount}\nSID：{preview.TargetUserSid}\n\n联系人：{preview.Name}\n身份指纹：{FormatFingerprint(preview.Fingerprint)}{legacyNotice}\n\n删除后，如需再次信任，必须重新输入安全码。确定继续吗？",
                "凝然加密 - 管理员确认删除",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning,
                MessageBoxResult.No);
            if (answer != MessageBoxResult.Yes)
            {
                return TrustedContactBrokerClient.CancelledExitCode;
            }

            operation.Commit();
            return 0;
        }
        catch (Exception exception)
        {
            MessageBox.Show(
                UiLanguage.IsEnglish
                    ? $"The trusted-contact administrator operation did not complete:\n\n{exception.Message}"
                    : $"可信联系人管理员操作未完成：\n\n{exception.Message}",
                "凝然加密 - 管理员确认",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return 1;
        }
    }

    private static int RunStrictProtectionSettingsEditor(IReadOnlyList<string> arguments)
    {
        if (arguments.Count != 1 ||
            !string.Equals(arguments[0], StrictProtectionSettings.ManagementArgument, StringComparison.Ordinal) ||
            !NingRanRuntime.IsProcessElevated() ||
            !HighSecurityLaunch.IsTrustedInstalledComponent(
                Environment.ProcessPath ?? string.Empty,
                "NingRan.exe"))
        {
            MessageBox.Show(
                "严格防护设置必须由受保护安装位置中的凝然加密，经 Windows 管理员确认后修改。",
                "凝然加密 - 管理员确认",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return 1;
        }

        try
        {
            var settings = StrictProtectionSettings.Load();
            if (!string.IsNullOrWhiteSpace(settings.LoadFailureReason))
            {
                MessageBox.Show(
                    UiLanguage.IsEnglish
                        ? $"{settings.LoadFailureReason}\n\nSaving will recreate settings that only administrators can modify."
                        : settings.LoadFailureReason + "\n\n保存后会重新建立只有管理员可修改的设置。",
                    "凝然加密 - 严格防护设置需要修复",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }

            var dialog = new StrictProtectionDialog(settings);
            if (dialog.ShowDialog() != true)
            {
                return 2;
            }

            dialog.Settings.Save();
            return 0;
        }
        catch (Exception exception)
        {
            MessageBox.Show(
                UiLanguage.IsEnglish
                    ? $"Strict Protection settings were not saved:\n\n{exception.Message}"
                    : $"严格防护设置没有保存：\n\n{exception.Message}",
                "凝然加密 - 管理员确认",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return 1;
        }
    }

    private static string FormatFingerprint(string fingerprint)
    {
        if (fingerprint.Length != 64)
        {
            return fingerprint;
        }

        return string.Join("-", Enumerable.Range(0, 8).Select(index =>
            fingerprint.Substring(index * 8, 8)));
    }

}
