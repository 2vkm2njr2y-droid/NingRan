using System.Windows;
using System.Windows.Threading;

namespace NingRan.MediaPlayer;

public partial class App : Application
{
    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        var token = await Console.In.ReadLineAsync().ConfigureAwait(true);
        if (!PlayerOptions.TryParse(e.Args, token, out var options))
        {
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
        MainWindow = new MediaPlayerWindow(options);
        MainWindow.Show();
    }
}
