using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace NingRan.Setup.Windows;

internal static class SetupBootstrap
{
    private const string OriginArgument = "--ningran-bootstrap-origin";
    private const string ParentArgument = "--ningran-bootstrap-parent";
    private const string PayloadHashArgument = "--ningran-bootstrap-payload-sha256";
    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint OpenExisting = 3;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagSequentialScan = 0x08000000;
    private const uint FileAttributeReparsePoint = 0x00000400;
    private static readonly byte[] FooterMagic = "NRSETUP1"u8.ToArray();
    private static readonly object Sync = new();
    private static FileStream? _originStream;
    private static Process? _parentProcess;
    private static string? _originExecutablePath;
    private static string? _payloadSha256;

    public static bool IsBound => _originStream is not null && _parentProcess is not null;
    public static string OriginExecutablePath => _originExecutablePath
        ?? throw new InvalidOperationException("安装程序没有通过原生安全引导器启动。");
    public static int ParentProcessId => _parentProcess?.Id
        ?? throw new InvalidOperationException("安装程序没有可验证的原生父进程。");
    public static string PayloadSha256 => _payloadSha256
        ?? throw new InvalidOperationException("安装程序载荷没有通过原生安全引导器验证。");

    public static IReadOnlyList<string> InitializeAndGetApplicationArguments(IReadOnlyList<string> arguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        if (IsBound)
        {
            throw new InvalidOperationException("原生安装引导绑定不能重复初始化。");
        }

        if (arguments.Count < 6 ||
            !string.Equals(arguments[^6], OriginArgument, StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(arguments[^5]) ||
            !string.Equals(arguments[^4], ParentArgument, StringComparison.Ordinal) ||
            !int.TryParse(arguments[^3], NumberStyles.None, CultureInfo.InvariantCulture, out var claimedParentId) ||
            claimedParentId <= 0 ||
            !string.Equals(arguments[^2], PayloadHashArgument, StringComparison.Ordinal) ||
            !IsCanonicalSha256(arguments[^1]))
        {
            throw new UnauthorizedAccessException(
                $"安装或卸载必须由{SetupProduct.Name}的原生安全引导器启动；当前请求缺少可信绑定。");
        }

        var claimedOrigin = Path.GetFullPath(arguments[^5]);
        var actualParentId = GetActualParentProcessId();
        if (actualParentId != claimedParentId)
        {
            throw new UnauthorizedAccessException("安装程序的真实父进程与原生引导绑定不一致。");
        }

        var parent = Process.GetProcessById(actualParentId);
        FileStream? originStream = null;
        try
        {
            if (parent.HasExited)
            {
                throw new UnauthorizedAccessException("原生安装引导器已经退出。");
            }

            var parentPath = Path.GetFullPath(parent.MainModule?.FileName
                ?? throw new InvalidOperationException("Windows 无法确认原生安装引导器的位置。"));
            originStream = OpenLockedOrigin(claimedOrigin);
            var finalOriginPath = GetFinalPath(originStream.SafeFileHandle);
            if (!PathsEqual(parentPath, finalOriginPath) || !PathsEqual(claimedOrigin, finalOriginPath))
            {
                throw new UnauthorizedAccessException("原生安装引导器的进程和文件不是同一个对象。");
            }

            var footer = ReadAndValidateFooter(originStream);
            var claimedHash = arguments[^1];
            if (!string.Equals(Convert.ToHexString(footer.PayloadSha256), claimedHash, StringComparison.Ordinal))
            {
                throw new UnauthorizedAccessException("原生安装引导器中的载荷指纹与启动绑定不一致。");
            }

            var workerPath = Path.GetFullPath(Environment.ProcessPath
                ?? throw new InvalidOperationException("Windows 无法确认托管安装程序的位置。"));
            using (var worker = new FileStream(workerPath, FileMode.Open, FileAccess.Read,
                       FileShare.Read | FileShare.Delete, 1024 * 1024, FileOptions.SequentialScan))
            {
                if (worker.Length != footer.PayloadLength ||
                    !CryptographicOperations.FixedTimeEquals(SHA256.HashData(worker), footer.PayloadSha256))
                {
                    throw new UnauthorizedAccessException("正在运行的安装程序不是原生引导器认证的载荷。");
                }
            }

            originStream.Position = footer.PayloadOffset;
            using (var payloadHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
            {
                var buffer = new byte[1024 * 1024];
                var remaining = footer.PayloadLength;
                while (remaining > 0)
                {
                    var read = originStream.Read(buffer, 0, (int)Math.Min(buffer.Length, remaining));
                    if (read <= 0)
                    {
                        throw new EndOfStreamException("原生安装引导器的载荷被截断。");
                    }
                    payloadHash.AppendData(buffer, 0, read);
                    remaining -= read;
                }
                if (!CryptographicOperations.FixedTimeEquals(payloadHash.GetHashAndReset(), footer.PayloadSha256))
                {
                    throw new UnauthorizedAccessException("原生安装引导器的内嵌载荷校验失败。");
                }
            }

            lock (Sync)
            {
                _originStream = originStream;
                _parentProcess = parent;
                _originExecutablePath = finalOriginPath;
                _payloadSha256 = claimedHash;
            }
            originStream = null;
            parent = null!;
            return arguments.Take(arguments.Count - 6).ToArray();
        }
        finally
        {
            originStream?.Dispose();
            parent?.Dispose();
        }
    }

    public static void CopyAuthenticatedOriginTo(string destination)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(destination);
        lock (Sync)
        {
            var source = _originStream
                ?? throw new InvalidOperationException("原生安装引导器尚未完成认证。");
            if (_parentProcess is null || _parentProcess.HasExited)
            {
                throw new UnauthorizedAccessException("认证过的原生安装引导器已退出，不能复制卸载程序。");
            }

            var targetPath = Path.GetFullPath(destination);
            source.Position = 0;
            using var target = new FileStream(targetPath, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                1024 * 1024, FileOptions.SequentialScan | FileOptions.WriteThrough);
            source.CopyTo(target, 1024 * 1024);
            target.Flush(flushToDisk: true);
            if (target.Length != source.Length)
            {
                throw new IOException("原生卸载引导器没有完整复制到目标位置。");
            }
        }
    }

    private static FileStream OpenLockedOrigin(string path)
    {
        var handle = CreateFileW(path, GenericRead, FileShareRead, 0, OpenExisting,
            FileFlagOpenReparsePoint | FileFlagSequentialScan, 0);
        if (handle.IsInvalid)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "无法锁定原生安装引导器。");
        }

        try
        {
            if (!GetFileInformationByHandle(handle, out var information))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "无法读取原生安装引导器属性。");
            }
            if ((information.FileAttributes & FileAttributeReparsePoint) != 0)
            {
                throw new UnauthorizedAccessException("原生安装引导器不能通过文件链接运行。");
            }
            return new FileStream(handle, FileAccess.Read, 1024 * 1024, isAsync: false);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private static FooterInfo ReadAndValidateFooter(FileStream source)
    {
        const int footerSize = 48;
        if (source.Length <= footerSize)
        {
            throw new InvalidDataException("原生安装引导器没有内嵌安装载荷。");
        }
        Span<byte> footer = stackalloc byte[footerSize];
        source.Position = source.Length - footerSize;
        source.ReadExactly(footer);
        if (!footer[..8].SequenceEqual(FooterMagic))
        {
            throw new InvalidDataException("原生安装引导器的载荷标记不正确。");
        }
        var payloadLength = BitConverter.ToInt64(footer.Slice(8, 8));
        var payloadOffset = source.Length - footerSize - payloadLength;
        if (payloadLength <= 0 || payloadOffset <= 0)
        {
            throw new InvalidDataException("原生安装引导器的载荷长度不正确。");
        }
        return new FooterInfo(payloadOffset, payloadLength, footer.Slice(16, 32).ToArray());
    }

    private static string GetFinalPath(SafeFileHandle handle)
    {
        var capacity = 1024;
        while (capacity <= 32768)
        {
            var buffer = new char[capacity];
            var length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Length, 0);
            if (length == 0)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "无法确认原生安装引导器的最终路径。");
            }
            if (length < buffer.Length)
            {
                var value = new string(buffer, 0, (int)length);
                return Path.GetFullPath(value.StartsWith("\\\\?\\", StringComparison.Ordinal)
                    ? value[4..]
                    : value);
            }
            capacity = checked((int)length + 1);
        }
        throw new PathTooLongException("原生安装引导器的路径过长。");
    }

    private static int GetActualParentProcessId()
    {
        var status = NtQueryInformationProcess(GetCurrentProcess(), 0, out var information,
            Marshal.SizeOf<ProcessBasicInformation>(), out _);
        var value = information.InheritedFromUniqueProcessId.ToInt64();
        if (status != 0 || value is <= 0 or > int.MaxValue)
        {
            throw new Win32Exception(status, "Windows 无法确认托管安装程序的真实父进程。");
        }
        return (int)value;
    }

    private static bool IsCanonicalSha256(string? value) => value is not null && value.Length == 64 &&
        value.All(character => character is >= '0' and <= '9' or >= 'A' and <= 'F');

    private static bool PathsEqual(string left, string right) => string.Equals(
        Path.TrimEndingDirectorySeparator(Path.GetFullPath(left)),
        Path.TrimEndingDirectorySeparator(Path.GetFullPath(right)),
        StringComparison.OrdinalIgnoreCase);

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

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll")]
    private static extern nint GetCurrentProcess();

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(nint processHandle, int informationClass,
        out ProcessBasicInformation information, int informationLength, out int returnLength);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string fileName, uint desiredAccess, uint shareMode,
        nint securityAttributes, uint creationDisposition, uint flagsAndAttributes, nint templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle file, out ByHandleFileInformation information);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, [Out] char[] path,
        uint pathLength, uint flags);

    private sealed record FooterInfo(long PayloadOffset, long PayloadLength, byte[] PayloadSha256);
}
