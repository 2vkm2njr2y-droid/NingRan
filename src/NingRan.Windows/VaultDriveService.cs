using Fsp;
using NingRan.Core;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace NingRan.Windows;

internal sealed class VaultDriveMount : IDisposable
{
    private FileSystemHost? _host;

    internal VaultDriveMount(FileSystemHost host)
    {
        _host = host;
        MountPoint = host.MountPoint() ?? string.Empty;
    }

    public string MountPoint { get; }
    public bool IsMounted => _host is not null;

    public void Dispose()
    {
        var host = Interlocked.Exchange(ref _host, null);
        host?.Dispose();
    }
}

internal static class VaultDriveService
{
    public const string RequiredRuntimeVersion = "2.2.26215";
    private static readonly Version MinimumRuntimeVersion = new(2, 2, 26215);

    public static bool TryGetRuntimeVersion(out Version? version, out string message)
    {
        try
        {
            var runtimePath = EnsureWinFspNativeDllSearchPath();
            var apiVersion = FileSystemHost.Version();
            version = ResolveRuntimeVersion(apiVersion, runtimePath);
            if (version < MinimumRuntimeVersion)
            {
                message = UiLanguage.IsEnglish
                    ? $"Temporary-drive component {version} is too old. Version {RequiredRuntimeVersion} or later is required. Run the NingRan installer to repair it."
                    : $"临时磁盘组件版本 {version} 过低，需要 {RequiredRuntimeVersion} 或更高版本。请运行凝然安装程序修复。";
                return false;
            }
            message = UiLanguage.IsEnglish
                ? $"Temporary-drive component {version} is available."
                : $"临时磁盘组件 {version} 已可用。";
            return true;
        }
        catch (Exception exception) when (exception is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException or TypeInitializationException)
        {
            version = null;
            message = UiLanguage.IsEnglish
                ? "The temporary-drive component is not installed. Run the NingRan installer to add or repair it."
                : "尚未安装临时磁盘组件，请运行凝然安装程序进行安装或修复。";
            return false;
        }
    }

    private static string? EnsureWinFspNativeDllSearchPath()
    {
        var candidates = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "WinFsp", "bin"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WinFsp", "bin"),
        };
        foreach (var directory in candidates)
        {
            var nativePath = Path.Combine(directory, "winfsp-x64.dll");
            if (File.Exists(nativePath))
            {
                SetDllDirectory(directory);
                return nativePath;
            }
        }
        return null;
    }

    private static Version ResolveRuntimeVersion(Version apiVersion, string? runtimePath)
    {
        if (string.IsNullOrWhiteSpace(runtimePath) || !File.Exists(runtimePath)) return apiVersion;
        try
        {
            var fileVersion = FileVersionInfo.GetVersionInfo(runtimePath);
            return ResolveRuntimeVersion(
                apiVersion,
                fileVersion.FileMajorPart,
                fileVersion.FileMinorPart,
                fileVersion.FileBuildPart,
                fileVersion.FilePrivatePart);
        }
        catch (Exception exception) when (exception is FileNotFoundException or IOException or UnauthorizedAccessException)
        {
            return apiVersion;
        }
    }

    internal static Version ResolveRuntimeVersion(
        Version apiVersion,
        int fileMajor,
        int fileMinor,
        int fileBuild,
        int filePrivate)
    {
        ArgumentNullException.ThrowIfNull(apiVersion);
        if (fileMajor != apiVersion.Major || fileMinor != apiVersion.Minor || fileBuild < 0)
        {
            return apiVersion;
        }
        return filePrivate > 0
            ? new Version(fileMajor, fileMinor, fileBuild, filePrivate)
            : new Version(fileMajor, fileMinor, fileBuild);
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool SetDllDirectory(string? lpPathName);

    public static VaultDriveMount Mount(VaultSession session, string? driveLetter = null)
    {
        ArgumentNullException.ThrowIfNull(session);
        if (!TryGetRuntimeVersion(out _, out var message))
        {
            throw new NingRanException(message);
        }

        var mountPoint = string.IsNullOrWhiteSpace(driveLetter)
            ? null
            : driveLetter.Trim().TrimEnd('\\').TrimEnd(':') + ":";
        var fileSystem = new VaultFileSystem(session);
        var host = new FileSystemHost(fileSystem);
        try
        {
            var status = host.Mount(mountPoint, null, false);
            if (status < 0)
            {
                throw new NingRanException($"临时磁盘没有成功显示（结果 0x{status:X8}）。请更换盘符或修复临时磁盘组件。");
            }
            return new VaultDriveMount(host);
        }
        catch
        {
            host.Dispose();
            throw;
        }
    }
}
