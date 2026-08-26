using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32;

namespace NingRan.Security;

/// <summary>
/// WebView2 accepts per-user environment and registry overrides before the
/// host receives a CoreWebView2 instance. A viewer handling decrypted content
/// must reject those overrides and use the protected per-machine runtime.
/// </summary>
internal static class SecureWebView2Policy
{
    private const string RuntimeClientId = "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}";
    private static readonly string[] OverrideEnvironmentVariables =
    [
        "WEBVIEW2_BROWSER_EXECUTABLE_FOLDER",
        "WEBVIEW2_USER_DATA_FOLDER",
        "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS",
        "WEBVIEW2_RELEASE_CHANNEL_PREFERENCE",
        "WEBVIEW2_CHANNEL_SEARCH_KIND",
        "WEBVIEW2_RELEASE_CHANNELS",
        "WEBVIEW2_WAIT_FOR_SCRIPT_DEBUGGER",
        "WEBVIEW2_PIPE_FOR_SCRIPT_DEBUGGER",
    ];

    public static void AssertSafeBeforeCreate()
    {
        foreach (var variable in OverrideEnvironmentVariables)
        {
            if (Environment.GetEnvironmentVariable(variable, EnvironmentVariableTarget.Process) is not null)
            {
                throw new InvalidOperationException(
                    $"检测到可能替换或调试安全查看器的环境设置（{variable}），已拒绝打开内容。请清除该设置并重新启动凝然加密。");
            }
        }

        AssertNoRegistryOverrides();
        AssertMachineRuntimeInstalled();
    }

    public static void AssertTrustedBrowserProcess(uint processId)
    {
        try
        {
            if (processId == 0 || processId > int.MaxValue)
            {
                throw new InvalidOperationException("浏览组件没有返回有效的进程编号。");
            }
            using var process = Process.GetProcessById((int)processId);
            var path = Path.GetFullPath(process.MainModule?.FileName ?? string.Empty);
            if (!string.Equals(Path.GetFileName(path), "msedgewebview2.exe", StringComparison.OrdinalIgnoreCase) ||
                !IsInProtectedSystemLocation(path) || !HasValidMicrosoftSignature(path))
            {
                throw new InvalidOperationException("实际启动的浏览组件不是受保护的 Microsoft WebView2 Runtime。");
            }
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or
                                             System.ComponentModel.Win32Exception or IOException or
                                             UnauthorizedAccessException or CryptographicException)
        {
            throw new InvalidOperationException(
                "无法确认浏览组件来自受保护的 Microsoft 安装位置，已在提供解密内容前停止。", exception);
        }
    }

    private static void AssertNoRegistryOverrides()
    {
        var executableName = Path.GetFileName(Environment.ProcessPath ?? string.Empty);
        var appIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "*",
            executableName,
            Path.GetFileNameWithoutExtension(executableName),
        };

        foreach (var hive in new[] { RegistryHive.LocalMachine, RegistryHive.CurrentUser })
        {
            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                using var policyRoot = baseKey.OpenSubKey(@"Software\Policies\Microsoft\Edge\WebView2", writable: false);
                if (policyRoot is null) continue;
                foreach (var subKeyName in policyRoot.GetSubKeyNames())
                {
                    using var policy = policyRoot.OpenSubKey(subKeyName, writable: false);
                    if (policy is null) continue;
                    if (policy.GetValueNames().Any(appIds.Contains))
                    {
                        throw new InvalidOperationException(
                            "Windows 中存在会替换或附加参数到 WebView2 的策略，安全查看器已拒绝打开解密内容。");
                    }
                }
            }
        }
    }

    private static void AssertMachineRuntimeInstalled()
    {
        var registryPaths = new[]
        {
            $@"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{RuntimeClientId}",
            $@"SOFTWARE\Microsoft\EdgeUpdate\Clients\{RuntimeClientId}",
        };
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            using var localMachine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            foreach (var registryPath in registryPaths)
            {
                using var runtime = localMachine.OpenSubKey(registryPath, writable: false);
                var versionText = runtime?.GetValue("pv") as string;
                if (Version.TryParse(versionText, out var version) && version > new Version(0, 0, 0, 0))
                {
                    return;
                }
            }
        }

        throw new InvalidOperationException(
            "未找到由 Windows 管理员安装的 Microsoft WebView2 Runtime。为避免加载当前账户可替换的组件，已拒绝打开内容。");
    }

    private static bool IsInProtectedSystemLocation(string path)
    {
        var roots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
        }.Where(value => !string.IsNullOrWhiteSpace(value))
         .Select(Path.GetFullPath)
         .Distinct(StringComparer.OrdinalIgnoreCase);
        foreach (var root in roots)
        {
            var relative = Path.GetRelativePath(root, path);
            if (Path.IsPathRooted(relative) || string.Equals(relative, "..", StringComparison.Ordinal) ||
                relative.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal) ||
                relative.StartsWith($"..{Path.AltDirectorySeparatorChar}", StringComparison.Ordinal))
            {
                continue;
            }

            var current = new FileInfo(path) as FileSystemInfo;
            while (current is not null)
            {
                current.Refresh();
                if (!current.Exists || (current.Attributes & FileAttributes.ReparsePoint) != 0)
                {
                    return false;
                }
                if (string.Equals(Path.TrimEndingDirectorySeparator(current.FullName),
                        Path.TrimEndingDirectorySeparator(root), StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
                current = current switch
                {
                    FileInfo file => file.Directory,
                    DirectoryInfo directory => directory.Parent,
                    _ => null,
                };
            }
        }

        return false;
    }

    private static bool HasValidMicrosoftSignature(string path)
    {
        if (!VerifyAuthenticodeSignature(path)) return false;
#pragma warning disable SYSLIB0057
        using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
        var publisher = certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
        var subjectParts = certificate.SubjectName
            .Decode(X500DistinguishedNameFlags.UseNewLines)
            .Split(["\r\n", "\n"], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return string.Equals(publisher, "Microsoft Corporation", StringComparison.Ordinal) &&
               subjectParts.Contains("O=Microsoft Corporation", StringComparer.Ordinal);
    }

    private static bool VerifyAuthenticodeSignature(string path)
    {
        var fileInfo = new WinTrustFileInfo
        {
            StructSize = (uint)Marshal.SizeOf<WinTrustFileInfo>(),
            FilePath = path,
        };
        var fileInfoPointer = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
        try
        {
            Marshal.StructureToPtr(fileInfo, fileInfoPointer, fDeleteOld: false);
            var trustData = new WinTrustData
            {
                StructSize = (uint)Marshal.SizeOf<WinTrustData>(),
                UiChoice = 2,
                RevocationChecks = 0,
                UnionChoice = 1,
                FileInfo = fileInfoPointer,
                StateAction = 0,
            };
            var action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
            return WinVerifyTrust(new nint(-1), ref action, ref trustData) == 0;
        }
        finally
        {
            Marshal.DestroyStructure<WinTrustFileInfo>(fileInfoPointer);
            Marshal.FreeHGlobal(fileInfoPointer);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustFileInfo
    {
        public uint StructSize;
        [MarshalAs(UnmanagedType.LPWStr)] public string FilePath;
        public nint FileHandle;
        public nint KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustData
    {
        public uint StructSize;
        public nint PolicyCallbackData;
        public nint SipClientData;
        public uint UiChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public nint FileInfo;
        public uint StateAction;
        public nint StateData;
        [MarshalAs(UnmanagedType.LPWStr)] public string? UrlReference;
        public uint ProviderFlags;
        public uint UiContext;
    }

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern int WinVerifyTrust(nint windowHandle, ref Guid action, ref WinTrustData trustData);
}
