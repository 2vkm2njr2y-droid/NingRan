using System.ComponentModel;
using System.Diagnostics;
using System.IO;

namespace NingRan.Windows;

internal static class HighSecurityLaunch
{
    public const string ArgumentName = "--high-security-open";

    public static bool TryReadPath(IReadOnlyList<string> arguments, out string? archivePath)
    {
        archivePath = null;
        if (arguments.Count != 2 || !string.Equals(arguments[0], ArgumentName, StringComparison.Ordinal))
        {
            return false;
        }

        try
        {
            var fullPath = Path.GetFullPath(arguments[1]);
            if (!File.Exists(fullPath) || !string.Equals(Path.GetExtension(fullPath), ".nrenc", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            archivePath = fullPath;
            return true;
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }

    public static void Start(string archivePath)
    {
        var executablePath = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(executablePath))
        {
            throw new InvalidOperationException("无法确定当前程序的位置，无法启动高安全查看。");
        }

        if (!IsTrustedInstalledComponent(executablePath, "NingRan.exe"))
        {
            throw new InvalidOperationException("当前程序不是从受保护的正式安装位置启动，已拒绝管理员启动。");
        }

        using var launched = NativeElevationLauncher.Start(
            NingRan.Security.NativeElevationBinding.Modes.HighSecurity,
            [ArgumentName, Path.GetFullPath(archivePath)]);
    }

    internal static bool IsTrustedInstalledComponent(string path, string fileName)
    {
        try
        {
            var expected = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "凝然加密",
                fileName);
            return string.Equals(
                Path.GetFullPath(path),
                Path.GetFullPath(expected),
                StringComparison.OrdinalIgnoreCase) &&
                File.Exists(expected);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }

    public static bool WasCancelled(Exception exception) => exception is Win32Exception { NativeErrorCode: 1223 };
}
