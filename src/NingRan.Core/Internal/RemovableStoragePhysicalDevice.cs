using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace NingRan.Core.Internal;

internal sealed record ConnectedStorageDevice(
    string RootPath,
    string Model,
    long CapacityBytes,
    byte[] HardwareFingerprint);

internal static class RemovableStoragePhysicalDevice
{
    private const uint IoctlStorageQueryProperty = 0x002D1400;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint OpenExisting = 3;
    private const int BusTypeScsi = 1;
    private const int BusTypeUsb = 7;
    private const int BusTypeMmc = 13;
    private const int BusTypeSd = 12;

    public static IReadOnlyList<ConnectedStorageDevice> Discover()
    {
        if (!OperatingSystem.IsWindows())
        {
            return [];
        }

        var result = new List<ConnectedStorageDevice>();
        foreach (var drive in DriveInfo.GetDrives())
        {
            try
            {
                if (!drive.IsReady || drive.DriveType is DriveType.CDRom or DriveType.Network or DriveType.Ram)
                {
                    continue;
                }

                var descriptor = ReadDescriptor(drive.Name);
                var isSupportedBus = descriptor.BusType is BusTypeUsb or BusTypeSd or BusTypeMmc;
                var removableScsi = descriptor.BusType == BusTypeScsi && descriptor.RemovableMedia;
                if (!isSupportedBus && !removableScsi)
                {
                    continue;
                }

                var volumeSerial = ReadVolumeSerial(drive.Name);
                var capacity = drive.TotalSize;
                var model = string.Join(' ', new[] { descriptor.Vendor, descriptor.Product }
                    .Where(value => !string.IsNullOrWhiteSpace(value))).Trim();
                if (string.IsNullOrWhiteSpace(model))
                {
                    model = drive.VolumeLabel.Length > 0 ? drive.VolumeLabel : "外接存储设备";
                }

                var fingerprintInput = string.Join('|',
                    descriptor.BusType,
                    descriptor.Vendor,
                    descriptor.Product,
                    descriptor.Serial,
                    capacity,
                    volumeSerial);
                var fingerprint = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(fingerprintInput));
                result.Add(new ConnectedStorageDevice(
                    NormalizeRoot(drive.Name),
                    model,
                    capacity,
                    fingerprint));
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or Win32Exception)
            {
                // A device can disappear while Windows is enumerating it. Ignore that stale entry.
            }
        }

        return result;
    }

    public static ConnectedStorageDevice GetRequired(string path)
    {
        var root = NormalizeRoot(Path.GetPathRoot(Path.GetFullPath(path))
            ?? throw new NingRanException("请选择移动存储设备的盘符。"));
        var found = Discover().FirstOrDefault(device =>
            string.Equals(device.RootPath, root, StringComparison.OrdinalIgnoreCase));
        return found ?? throw new NingRanException(
            "所选位置不是受支持的外接存储设备。仅支持 U 盘、移动硬盘/固态硬盘和读卡器存储，不支持内置磁盘、网络盘或手机文件传输。 ");
    }

    private static StorageDescriptor ReadDescriptor(string rootPath)
    {
        var devicePath = $@"\\.\{rootPath.TrimEnd('\\')}";
        using var handle = CreateFileW(
            devicePath,
            0,
            FileShareRead | FileShareWrite,
            nint.Zero,
            OpenExisting,
            0,
            nint.Zero);
        if (handle.IsInvalid)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        var query = new byte[12];
        var output = new byte[4096];
        if (!DeviceIoControl(
                handle,
                IoctlStorageQueryProperty,
                query,
                query.Length,
                output,
                output.Length,
                out var returned,
                nint.Zero) || returned < 36)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        var size = BinaryPrimitives.ReadUInt32LittleEndian(output.AsSpan(4, 4));
        var usable = (int)Math.Min(Math.Min(size, (uint)returned), (uint)output.Length);
        return new StorageDescriptor(
            ReadAnsiString(output, usable, BinaryPrimitives.ReadUInt32LittleEndian(output.AsSpan(12, 4))),
            ReadAnsiString(output, usable, BinaryPrimitives.ReadUInt32LittleEndian(output.AsSpan(16, 4))),
            ReadAnsiString(output, usable, BinaryPrimitives.ReadUInt32LittleEndian(output.AsSpan(24, 4))),
            BinaryPrimitives.ReadInt32LittleEndian(output.AsSpan(28, 4)),
            output[10] != 0);
    }

    private static string ReadAnsiString(byte[] buffer, int usableLength, uint offset)
    {
        if (offset == 0 || offset >= usableLength)
        {
            return string.Empty;
        }

        var start = checked((int)offset);
        var end = Array.IndexOf(buffer, (byte)0, start, usableLength - start);
        if (end < 0)
        {
            end = usableLength;
        }

        return System.Text.Encoding.ASCII.GetString(buffer, start, end - start).Trim();
    }

    private static uint ReadVolumeSerial(string rootPath)
    {
        if (!GetVolumeInformationW(
                rootPath,
                null,
                0,
                out var serial,
                out _,
                out _,
                null,
                0))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        return serial;
    }

    private static string NormalizeRoot(string root) =>
        Path.TrimEndingDirectorySeparator(Path.GetFullPath(root)) + Path.DirectorySeparatorChar;

    private sealed record StorageDescriptor(
        string Vendor,
        string Product,
        string Serial,
        int BusType,
        bool RemovableMedia);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        nint lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        nint hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        byte[] lpInBuffer,
        int nInBufferSize,
        byte[] lpOutBuffer,
        int nOutBufferSize,
        out uint lpBytesReturned,
        nint lpOverlapped);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumeInformationW(
        string lpRootPathName,
        char[]? lpVolumeNameBuffer,
        uint nVolumeNameSize,
        out uint lpVolumeSerialNumber,
        out uint lpMaximumComponentLength,
        out uint lpFileSystemFlags,
        char[]? lpFileSystemNameBuffer,
        uint nFileSystemNameSize);
}
