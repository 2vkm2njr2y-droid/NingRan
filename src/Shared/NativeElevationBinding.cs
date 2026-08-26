using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace NingRan.Security;

internal sealed class NativeElevationBinding : IDisposable
{
    private const string ParentArgument = "--ningran-native-parent";
    private const string NonceArgument = "--ningran-native-nonce";
    private const string ModeArgument = "--ningran-native-mode";
    private const string InstallDirectoryName = "凝然加密";
    private const string LauncherName = "NingRan.SecurityLauncher.exe";
    private readonly Process _parent;

    private NativeElevationBinding(string mode, IReadOnlyList<string> businessArguments, Process parent)
    {
        Mode = mode;
        BusinessArguments = businessArguments;
        _parent = parent;
    }

    public string Mode { get; }
    public IReadOnlyList<string> BusinessArguments { get; }

    public static bool TryConsume(
        IReadOnlyList<string> arguments,
        out IReadOnlyList<string> businessArguments,
        out NativeElevationBinding? binding,
        out string? error)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        businessArguments = arguments;
        binding = null;
        error = null;
        var hasBindingMarker = arguments.Any(argument =>
            string.Equals(argument, ParentArgument, StringComparison.Ordinal) ||
            string.Equals(argument, NonceArgument, StringComparison.Ordinal) ||
            string.Equals(argument, ModeArgument, StringComparison.Ordinal));
        if (!hasBindingMarker)
        {
            return true;
        }

        try
        {
            if (arguments.Count < 6 ||
                !string.Equals(arguments[^6], ParentArgument, StringComparison.Ordinal) ||
                !int.TryParse(arguments[^5], System.Globalization.NumberStyles.None,
                    System.Globalization.CultureInfo.InvariantCulture, out var claimedParentId) ||
                claimedParentId <= 0 ||
                !string.Equals(arguments[^4], NonceArgument, StringComparison.Ordinal) ||
                !IsCanonicalNonce(arguments[^3]) ||
                !string.Equals(arguments[^2], ModeArgument, StringComparison.Ordinal) ||
                !IsKnownMode(arguments[^1]))
            {
                throw new UnauthorizedAccessException("原生管理员启动绑定不完整。");
            }

            var actualParentId = GetActualParentProcessId();
            if (actualParentId != claimedParentId)
            {
                throw new UnauthorizedAccessException("管理员组件的真实父进程与原生启动绑定不一致。");
            }

            var parent = Process.GetProcessById(actualParentId);
            try
            {
                var expectedParentPath = GetInstalledPath(LauncherName);
                var actualParentPath = Path.GetFullPath(parent.MainModule?.FileName
                    ?? throw new InvalidOperationException("Windows 无法确认原生安全引导器的位置。"));
                var mode = arguments[^1];
                var expectedSelfPath = GetInstalledPath(
                    string.Equals(mode, Modes.StrictMonitor, StringComparison.Ordinal)
                        ? "NingRan.StrictMonitor.exe"
                        : "NingRan.exe");
                var actualSelfPath = Path.GetFullPath(Environment.ProcessPath
                    ?? throw new InvalidOperationException("Windows 无法确认管理员组件的位置。"));
                if (parent.HasExited ||
                    !PathsEqual(actualParentPath, expectedParentPath) ||
                    !PathsEqual(actualSelfPath, expectedSelfPath) ||
                    !IsOrdinaryPath(actualParentPath) ||
                    !IsOrdinaryPath(actualSelfPath))
                {
                    throw new UnauthorizedAccessException(
                        "管理员组件不是由受保护安装目录中的原生安全引导器直接启动。");
                }

                businessArguments = arguments.Take(arguments.Count - 6).ToArray();
                binding = new NativeElevationBinding(mode, businessArguments, parent);
                parent = null!;
                return true;
            }
            finally
            {
                parent?.Dispose();
            }
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or
                                             UnauthorizedAccessException or Win32Exception or IOException or
                                             NotSupportedException)
        {
            error = exception.Message;
            return false;
        }
    }

    public bool IsMode(string mode) => string.Equals(Mode, mode, StringComparison.Ordinal);

    public void Dispose() => _parent.Dispose();

    private static int GetActualParentProcessId()
    {
        var status = NtQueryInformationProcess(GetCurrentProcess(), 0, out var information,
            Marshal.SizeOf<ProcessBasicInformation>(), out _);
        var value = information.InheritedFromUniqueProcessId.ToInt64();
        if (status != 0 || value is <= 0 or > int.MaxValue)
        {
            throw new Win32Exception(status, "Windows 无法确认管理员组件的真实父进程。");
        }
        return (int)value;
    }

    private static string GetInstalledPath(string name) => Path.GetFullPath(Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), InstallDirectoryName, name));

    private static bool IsOrdinaryPath(string path)
    {
        var full = Path.GetFullPath(path);
        if (!File.Exists(full) || (File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
        {
            return false;
        }
        var root = Path.GetPathRoot(full);
        if (string.IsNullOrWhiteSpace(root)) return false;
        var current = Path.TrimEndingDirectorySeparator(root);
        foreach (var segment in Path.GetRelativePath(root, Path.GetDirectoryName(full)!).Split(
                     [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) return false;
        }
        return true;
    }

    private static bool PathsEqual(string left, string right) => string.Equals(
        Path.GetFullPath(left), Path.GetFullPath(right), StringComparison.OrdinalIgnoreCase);

    private static bool IsCanonicalNonce(string? value) => value is not null && value.Length == 64 &&
        value.All(character => character is >= '0' and <= '9' or >= 'A' and <= 'F');

    private static bool IsKnownMode(string? mode) => mode is Modes.HighSecurity or Modes.StrictSettings or
        Modes.TrustedContact or Modes.StrictMonitor;

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessBasicInformation
    {
        public nint Reserved1;
        public nint PebBaseAddress;
        public nint Reserved2_0;
        public nint Reserved2_1;
        public nint UniqueProcessId;
        public nint InheritedFromUniqueProcessId;
    }

    [DllImport("kernel32.dll")]
    private static extern nint GetCurrentProcess();

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(nint processHandle, int informationClass,
        out ProcessBasicInformation information, int informationLength, out int returnLength);

    internal static class Modes
    {
        public const string HighSecurity = "high-security";
        public const string StrictSettings = "strict-settings";
        public const string TrustedContact = "trusted-contact";
        public const string StrictMonitor = "strict-monitor";
    }
}
