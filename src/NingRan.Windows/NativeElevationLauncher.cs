using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using NingRan.Security;

namespace NingRan.Windows;

internal static class NativeElevationLauncher
{
    private const string PublicLaunchArgument = "--ningran-launch";
    private const string ChildPidPrefix = "NINGRAN_CHILD_PID=";
    private const string CancelledResponse = "NINGRAN_CANCELLED";

    public static NativeElevatedProcess Start(string mode, IEnumerable<string> arguments) =>
        StartAsync(mode, arguments, CancellationToken.None).GetAwaiter().GetResult();

    public static async Task<NativeElevatedProcess> StartAsync(
        string mode,
        IEnumerable<string> arguments,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(mode);
        ArgumentNullException.ThrowIfNull(arguments);
        var launcherPath = Path.Combine(AppContext.BaseDirectory, "NingRan.SecurityLauncher.exe");
        if (!HighSecurityLaunch.IsTrustedInstalledComponent(launcherPath, "NingRan.SecurityLauncher.exe"))
        {
            throw new UnauthorizedAccessException(
                "原生安全引导器不在受保护的正式安装位置。请重新安装最新版凝然加密。");
        }

        var info = new ProcessStartInfo(launcherPath)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = AppContext.BaseDirectory,
        };
        info.ArgumentList.Add(PublicLaunchArgument);
        info.ArgumentList.Add(mode);
        foreach (var argument in arguments) info.ArgumentList.Add(argument);

        var relay = Process.Start(info)
            ?? throw new InvalidOperationException("Windows 没有启动原生安全引导器。");
        try
        {
            var response = await relay.StandardOutput.ReadLineAsync(cancellationToken)
                .AsTask()
                .WaitAsync(TimeSpan.FromSeconds(95), cancellationToken)
                .ConfigureAwait(false);
            if (string.Equals(response, CancelledResponse, StringComparison.Ordinal))
            {
                await relay.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
                throw new Win32Exception(1223, "用户取消了 Windows 管理员确认。");
            }
            if (response is null || !response.StartsWith(ChildPidPrefix, StringComparison.Ordinal) ||
                !int.TryParse(response.AsSpan(ChildPidPrefix.Length), NumberStyles.None,
                    CultureInfo.InvariantCulture, out var childPid) || childPid <= 0)
            {
                await relay.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
                var detail = await relay.StandardError.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
                throw new InvalidOperationException(string.IsNullOrWhiteSpace(detail)
                    ? "原生安全引导器没有返回可信的管理员组件。"
                    : "原生安全引导器启动失败。请重新安装最新版凝然加密。");
            }

            var child = Process.GetProcessById(childPid);
            return new NativeElevatedProcess(relay, child);
        }
        catch
        {
            relay.Dispose();
            throw;
        }
    }
}

internal sealed class NativeElevatedProcess : IDisposable
{
    private readonly Process _relay;

    internal NativeElevatedProcess(Process relay, Process child)
    {
        _relay = relay;
        Child = child;
    }

    public Process Child { get; }
    public int ExitCode => _relay.ExitCode;

    public Task WaitForExitAsync(CancellationToken cancellationToken = default) =>
        _relay.WaitForExitAsync(cancellationToken);

    public void Dispose()
    {
        Child.Dispose();
        _relay.Dispose();
    }
}
