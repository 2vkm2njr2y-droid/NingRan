using System.Windows;
using System.Windows.Threading;

namespace NingRan.MediaPlayer;

public partial class App : Application
{
    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        if (e.Args is ["--ningran-protocol-self-test"])
        {
            Shutdown(await ProtocolSelfTest.RunAsync().ConfigureAwait(true));
            return;
        }

        if (PlayerLaunchOptions.TryParse(e.Args, out var secureLaunch))
        {
            PlayerOptions options;
            try
            {
                options = await MediaPipeClient.OpenSessionAsync(secureLaunch).ConfigureAwait(true);
            }
            catch
            {
                Shutdown(4);
                return;
            }

            DispatcherUnhandledException += (_, exception) =>
            {
                exception.Handled = true;
                try { (MainWindow as MediaPlayerWindow)?.MarkProblem($"播放器窗口错误：{exception.Exception.GetType().Name}：{exception.Exception.Message}"); }
                catch { }
                Shutdown(3);
            };
            MainWindow = new MediaPlayerWindow(options);
            MainWindow.Show();
            return;
        }

        if (!LocalMediaLaunchOptions.TryParse(e.Args, out var localLaunch))
        {
            MessageBox.Show(
                "请选择一个受支持的音频或视频文件打开。",
                "凝然媒体播放器",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            Shutdown(2);
            return;
        }

        DispatcherUnhandledException += (_, exception) =>
        {
            exception.Handled = true;
            try { (MainWindow as MediaPlayerWindow)?.MarkProblem($"播放器窗口错误：{exception.Exception.GetType().Name}：{exception.Exception.Message}"); }
            catch { }
            Shutdown(3);
        };
        MainWindow = new MediaPlayerWindow(localLaunch.Files);
        MainWindow.Show();
    }
}
