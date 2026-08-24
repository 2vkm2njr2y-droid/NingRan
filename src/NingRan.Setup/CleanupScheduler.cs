using System.Diagnostics;
using System.IO;
using System.Text;
using NingRan.Setup;

namespace NingRan.Setup.Windows;

internal static class CleanupScheduler
{
    public static void ScheduleInstalledDirectoryCleanup(string installPath)
    {
        var validated = SetupPathSafety.ValidateUninstallPath(installPath);
        if (SetupPathSafety.IsLegacyInstallPath(validated))
        {
            SetupPathSafety.HardenLegacyInstallDirectory(validated);
        }
        else
        {
            SetupPathSafety.VerifyInstallDirectoryPermissions(validated);
        }

        if (!File.Exists(Path.Combine(validated, SetupProduct.UninstallerName)))
        {
            throw new InvalidOperationException("没有找到正在运行的卸载程序，无法安排最后清理。");
        }

        var scriptPath = Path.Combine(validated, $".NingRan-Cleanup-{Guid.NewGuid():N}.ps1");
        const string script = """
            param(
                [int]$WaitForProcessId,
                [string]$InstallDirectory
            )
            Wait-Process -Id $WaitForProcessId -Timeout 120 -ErrorAction SilentlyContinue
            $escapedDirectory = $InstallDirectory.Replace("'", "''")
            $cleanupCommand = "`$target = '$escapedDirectory'; for (`$attempt = 0; `$attempt -lt 120; `$attempt++) { Remove-Item -LiteralPath `$target -Recurse -Force -ErrorAction SilentlyContinue; if (-not (Test-Path -LiteralPath `$target)) { foreach (`$regPath in @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\NingRan','HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\NingRan')) { `$recorded = (Get-ItemProperty -LiteralPath `$regPath -Name InstallLocation -ErrorAction SilentlyContinue).InstallLocation; if ([string]::Equals([string]`$recorded, `$target, [StringComparison]::OrdinalIgnoreCase)) { Remove-Item -LiteralPath `$regPath -Recurse -Force -ErrorAction SilentlyContinue } }; exit 0 }; Start-Sleep -Milliseconds 500 }"
            $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cleanupCommand))
            Start-Process -FilePath (Join-Path $PSHome 'powershell.exe') -ArgumentList @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encodedCommand) -WorkingDirectory $env:WINDIR -WindowStyle Hidden
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
        startInfo.ArgumentList.Add(validated);
        using var cleanupProcess = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Windows 未能启动最后清理程序，卸载记录将保留以便重试。");
    }
}
