using System.IO;
using System.Windows;
using NingRan.Core;

namespace NingRan.Windows;

public partial class App : Application
{
    private SingleInstanceCoordinator? _singleInstance;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        var associatedFile = e.Args.FirstOrDefault(File.Exists);
        _singleInstance = new SingleInstanceCoordinator(Dispatcher);
        if (!_singleInstance.IsPrimaryInstance)
        {
            var delivered = await _singleInstance.NotifyPrimaryAsync(associatedFile);
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

        _singleInstance.StartListening();
        if (NingRanRuntime.IsProcessElevated())
        {
            var notice = new SecurityNoticeWindow();
            notice.ShowDialog();
            Shutdown(-1);
            return;
        }

        TemporaryContentCleanupResult cleanupResult;
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

        var splash = new SplashWindow();
        splash.Show();

        var minimumDisplay = Task.Delay(TimeSpan.FromSeconds(2));
        var mainWindow = new MainWindow();
        await minimumDisplay;

        MainWindow = mainWindow;
        ShutdownMode = ShutdownMode.OnMainWindowClose;
        mainWindow.Show();
        splash.Close();

        if (associatedFile is not null)
        {
            await mainWindow.OpenAssociatedFileAsync(associatedFile);
        }

        _singleInstance.SetRequestHandler(mainWindow.HandleExternalLaunch);

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

    protected override void OnExit(ExitEventArgs e)
    {
        _singleInstance?.Dispose();
        _singleInstance = null;
        base.OnExit(e);
    }
}
