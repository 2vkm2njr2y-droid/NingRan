using System.Diagnostics;
using System.IO;
using System.Text;
using NingRan.Setup;

namespace NingRan.Setup.Windows;

internal static class CleanupScheduler
{
    public static void ScheduleInstalledDirectoryCleanup(string installPath)
    {
        var validated = SetupPathSafety.ValidateFixedInstallPath(installPath);
        SetupPathSafety.VerifyInstallDirectoryPermissions(validated);
        var uninstaller = Path.Combine(validated, SetupProduct.UninstallerName);
        if (!File.Exists(uninstaller))
        {
            throw new InvalidOperationException("没有找到正在运行的卸载程序，无法安排最后清理。");
        }

        var scriptPath = Path.Combine(Path.GetTempPath(), $"NingRan-Cleanup-{Guid.NewGuid():N}.ps1");
        const string script = """
            param(
                [int]$WaitForProcessId,
                [string]$UninstallerPath,
                [string]$InstallDirectory,
                [string]$CleanupScriptPath
            )
            Wait-Process -Id $WaitForProcessId -Timeout 120 -ErrorAction SilentlyContinue
            for ($attempt = 0; $attempt -lt 20; $attempt++) {
                Remove-Item -LiteralPath $UninstallerPath -Force -ErrorAction SilentlyContinue
                if (-not (Test-Path -LiteralPath $UninstallerPath)) { break }
                Start-Sleep -Milliseconds 250
            }
            Remove-Item -LiteralPath $InstallDirectory -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $CleanupScriptPath -Force -ErrorAction SilentlyContinue
            """;
        File.WriteAllText(scriptPath, script, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));

        var powershell = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32",
            "WindowsPowerShell",
            "v1.0",
            "powershell.exe");
        var startInfo = new ProcessStartInfo
        {
            FileName = powershell,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
        };
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-ExecutionPolicy");
        startInfo.ArgumentList.Add("Bypass");
        startInfo.ArgumentList.Add("-WindowStyle");
        startInfo.ArgumentList.Add("Hidden");
        startInfo.ArgumentList.Add("-File");
        startInfo.ArgumentList.Add(scriptPath);
        startInfo.ArgumentList.Add(Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture));
        startInfo.ArgumentList.Add(uninstaller);
        startInfo.ArgumentList.Add(validated);
        startInfo.ArgumentList.Add(scriptPath);
        Process.Start(startInfo)?.Dispose();
    }
}
