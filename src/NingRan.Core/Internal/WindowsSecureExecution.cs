using System.Runtime.InteropServices;

/// <summary>
/// Reports whether Windows exposes the hardware-backed isolation capability required by a VBS enclave.
/// A regular desktop application cannot turn itself into an enclave without a separately signed native component.
/// </summary>
namespace NingRan.Core
{
    public static class WindowsSecureExecution
    {
        private const uint VbsEnclaveType = 0x00000010;

        public static WindowsSecureExecutionStatus GetStatus()
        {
        if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 17763))
        {
            return new WindowsSecureExecutionStatus(false,
                "此 Windows 版本不提供虚拟化安全区。密码和正在查看时的数据密钥仍会尝试使用锁定内存，并在使用后立即清除。");
        }

        try
        {
            return IsEnclaveTypeSupported(VbsEnclaveType)
                ? new WindowsSecureExecutionStatus(true,
                    "此电脑支持 Windows 虚拟化安全区。密码和正在查看时的数据密钥会尝试使用锁定内存，并在使用后立即清除。")
                : new WindowsSecureExecutionStatus(false,
                    "此电脑未启用 Windows 虚拟化安全区。密码和正在查看时的数据密钥仍会尝试使用锁定内存，并在使用后立即清除。");
        }
        catch (Exception exception) when (exception is EntryPointNotFoundException or DllNotFoundException)
        {
            return new WindowsSecureExecutionStatus(false,
                "此 Windows 版本无法确认虚拟化安全区。密码和正在查看时的数据密钥仍会尝试使用锁定内存，并在使用后立即清除。");
        }
        }

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsEnclaveTypeSupported(uint enclaveType);
    }

    public sealed record WindowsSecureExecutionStatus(bool VbsEnclaveAvailable, string Message);
}

/// <summary>Prevents a short secret from being paged to disk while the current process uses it.</summary>
namespace NingRan.Core.Internal
{
    internal sealed class SensitiveMemoryLock : IDisposable
    {
    private GCHandle _pin;
    private nint _address;
    private nuint _length;
    private bool _locked;
    private bool _disposed;

    private SensitiveMemoryLock(byte[] bytes)
    {
        if (bytes.Length == 0 || !OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            _pin = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            _address = _pin.AddrOfPinnedObject();
            _length = checked((nuint)bytes.Length);
            _locked = VirtualLock(_address, _length);
        }
        catch
        {
            if (_pin.IsAllocated)
            {
                _pin.Free();
            }

            _address = 0;
            _length = 0;
        }
    }

    public static SensitiveMemoryLock Create(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        return new SensitiveMemoryLock(bytes);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        if (_locked)
        {
            _ = VirtualUnlock(_address, _length);
        }

        if (_pin.IsAllocated)
        {
            _pin.Free();
        }

        _address = 0;
        _length = 0;
        _locked = false;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool VirtualLock(nint address, nuint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool VirtualUnlock(nint address, nuint size);
    }
}
