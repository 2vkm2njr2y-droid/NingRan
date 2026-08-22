using System.IO;
using System.Reflection;
using System.Security.Principal;
using System.Windows;
using NingRan.Setup;

namespace NingRan.Setup.Windows;

public partial class App : Application
{
    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        if (e.Args.Contains("--verify-payload", StringComparer.OrdinalIgnoreCase))
        {
            var exitCode = await VerifyPayloadAsync();
            Shutdown(exitCode);
            return;
        }

        if (IsProcessElevated())
        {
            MessageBox.Show(
                "凝然加密采用当前用户安装，不需要管理员权限。\n\n请关闭窗口后直接双击安装包，不要选择“以管理员身份运行”。",
                "凝然加密安装程序",
                MessageBoxButton.OK,
                MessageBoxImage.Stop);
            Shutdown(-1);
            return;
        }

        var executableDirectory = Path.GetDirectoryName(Environment.ProcessPath)
            ?? AppContext.BaseDirectory;
        var uninstall = SetupModeDetector.ShouldUninstall(e.Args, executableDirectory);
        var installPath = uninstall ? executableDirectory : null;
        if (uninstall && InstallState.TryLoad(installPath!) is null)
        {
            MessageBox.Show(
                "没有在这个位置找到有效的安装记录。请从 Windows 的“已安装的应用”中卸载，或重新安装后再卸载。",
                "无法开始卸载",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            Shutdown(-1);
            return;
        }

        var window = new InstallerWindow(uninstall, installPath);
        MainWindow = window;
        ShutdownMode = ShutdownMode.OnMainWindowClose;
        window.Show();
    }

    internal static Stream OpenPayload()
    {
        return Assembly.GetExecutingAssembly().GetManifestResourceStream("NingRan.Setup.Payload.zip")
            ?? throw new InvalidDataException("安装包中没有找到离线程序文件，请重新下载安装包。");
    }

    private static async Task<int> VerifyPayloadAsync()
    {
        var temporary = Path.Combine(Path.GetTempPath(), $"NingRan-Verify-{Guid.NewGuid():N}");
        try
        {
            await using var payload = OpenPayload();
            await PayloadExtractor.ExtractAndVerifyAsync(payload, temporary);
            return 0;
        }
        catch
        {
            return 2;
        }
        finally
        {
            SafeDirectoryTree.Delete(temporary);
        }
    }

    private static bool IsProcessElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}
