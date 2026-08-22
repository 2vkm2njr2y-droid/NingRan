using System.Security.Cryptography;
using System.Text.Json;
using NingRan.Core.Internal;

namespace NingRan.Core;

public sealed class NrPhysicalDeviceService : IPhysicalDeviceProvider
{
    private static ReadOnlySpan<byte> TokenMagic => "NRDEV001"u8;
    private static readonly byte[] RegistryEntropy = "NINGRAN-PHYSICAL-DEVICES-V1"u8.ToArray();
    private const int TokenSize = 120;
    private const string TokenDirectoryName = ".ningran-physical-key";
    private const string TokenFileName = "device.nrk";
    private readonly string _registryPath;
    private readonly Fido2PhysicalDevice _fido2;

    public NrPhysicalDeviceService()
        : this(GetDefaultRegistryPath(), new Fido2PhysicalDevice())
    {
    }

    internal NrPhysicalDeviceService(string registryPath, Fido2PhysicalDevice fido2)
    {
        _registryPath = registryPath;
        _fido2 = fido2;
    }

    public IReadOnlyList<PhysicalDeviceDescriptor> ListRegisteredDevices() =>
        ReadRegistry().OrderBy(device => device.Name, StringComparer.CurrentCultureIgnoreCase).ToArray();

    public IReadOnlyList<PhysicalDeviceDescriptor> ListConnectedStorageDevices() =>
        RemovableStoragePhysicalDevice.Discover().Select(device =>
        {
            var token = TryReadValidToken(device);
            try
            {
                return new PhysicalDeviceDescriptor(
                    PhysicalDeviceKind.RemovableStorage,
                    token?.RegistrationId ?? $"未登记-{Convert.ToHexString(device.HardwareFingerprint.AsSpan(0, 4))}",
                    token is null ? "未登记的移动存储" : "已登记的移动存储",
                    device.Model,
                    device.CapacityBytes);
            }
            finally
            {
                token?.Clear();
            }
        }).ToArray();

    public PhysicalDeviceDescriptor PreviewStorageDevice(string path)
    {
        var connected = RemovableStoragePhysicalDevice.GetRequired(path);
        var token = TryReadValidToken(connected);
        try
        {
            return new PhysicalDeviceDescriptor(
                PhysicalDeviceKind.RemovableStorage,
                token?.RegistrationId ?? Convert.ToHexString(connected.HardwareFingerprint),
                token is null ? "准备登记的移动存储" : "已登记的移动存储",
                connected.Model,
                connected.CapacityBytes);
        }
        finally
        {
            token?.Clear();
        }
    }

    public PhysicalDeviceDescriptor RegisterStorageDevice(string path, string userName)
    {
        ValidateName(userName);
        var connected = RemovableStoragePhysicalDevice.GetRequired(path);
        var tokenDirectory = Path.Combine(connected.RootPath, TokenDirectoryName);
        var tokenPath = Path.Combine(tokenDirectory, TokenFileName);
        StorageToken token;

        if (Directory.Exists(tokenDirectory))
        {
            var attributes = File.GetAttributes(tokenDirectory);
            if ((attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new NingRanException("移动存储内的物理密钥目录不是普通文件夹，已拒绝使用。 ");
            }
        }

        if (File.Exists(tokenPath))
        {
            token = ReadToken(tokenPath);
            if (!CryptographicOperations.FixedTimeEquals(token.HardwareFingerprint, connected.HardwareFingerprint))
            {
                token.Clear();
                throw new NingRanException("这块移动存储中的物理密钥凭证属于另一设备或已被修改，不能覆盖。 ");
            }
        }
        else
        {
            Directory.CreateDirectory(tokenDirectory);
            if ((File.GetAttributes(tokenDirectory) & FileAttributes.ReparsePoint) != 0)
            {
                throw new NingRanException("移动存储内的物理密钥目录不是普通文件夹，已拒绝使用。 ");
            }

            token = CreateToken(connected.HardwareFingerprint);
            var bytes = token.Serialize();
            try
            {
                using var stream = WindowsFileSystemSafety.CreateNewTemporaryFile(tokenPath, 4096);
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
                try
                {
                    File.SetAttributes(tokenDirectory, File.GetAttributes(tokenDirectory) | FileAttributes.Hidden);
                    File.SetAttributes(tokenPath, File.GetAttributes(tokenPath) | FileAttributes.Hidden | FileAttributes.ReadOnly);
                }
                catch (IOException)
                {
                    // Some removable file systems do not support every Windows attribute.
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }

        try
        {
            var descriptor = new PhysicalDeviceDescriptor(
                PhysicalDeviceKind.RemovableStorage,
                token.RegistrationId,
                userName.Trim(),
                connected.Model,
                connected.CapacityBytes);
            Upsert(descriptor);
            return descriptor;
        }
        finally
        {
            token.Clear();
        }
    }

    public async Task<PhysicalDeviceDescriptor> RegisterFido2DeviceAsync(
        string userName,
        nint ownerWindowHandle,
        CancellationToken cancellationToken = default)
    {
        ValidateName(userName);
        var descriptor = await _fido2.RegisterAsync(
            userName.Trim(),
            ownerWindowHandle,
            cancellationToken).ConfigureAwait(false);
        Upsert(descriptor);
        return descriptor;
    }

    public void RenameDevice(string id, string newName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        ValidateName(newName);
        var devices = ReadRegistry();
        var index = devices.FindIndex(device => string.Equals(device.Id, id, StringComparison.Ordinal));
        if (index < 0)
        {
            throw new NingRanException("没有找到要重命名的物理设备。 ");
        }

        devices[index] = devices[index] with { Name = newName.Trim() };
        WriteRegistry(devices);
    }

    public void ForgetDevice(string id)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        var devices = ReadRegistry();
        if (devices.RemoveAll(device => string.Equals(device.Id, id, StringComparison.Ordinal)) == 0)
        {
            throw new NingRanException("没有找到要移除的物理设备。 ");
        }

        WriteRegistry(devices);
    }

    public async Task<PhysicalDeviceUnlock> UnlockAnyAsync(
        IReadOnlyList<PhysicalDeviceRequirement> devices,
        nint ownerWindowHandle,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(devices);
        foreach (var requirement in devices.Where(device =>
                     device.Device.Kind == PhysicalDeviceKind.RemovableStorage))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var unlock = TryUnlockStorage(requirement);
            if (unlock is not null)
            {
                return unlock;
            }
        }

        var fidoRequirements = devices.Where(device =>
            device.Device.Kind == PhysicalDeviceKind.Fido2SecurityKey).ToArray();
        if (fidoRequirements.Length > 0)
        {
            return await _fido2.UnlockAnyAsync(
                fidoRequirements,
                ownerWindowHandle,
                cancellationToken).ConfigureAwait(false);
        }

        throw new NingRanException("没有检测到此文件授权的物理设备，请插入设备后重试。 ");
    }

    public Task<PhysicalDeviceUnlock> UnlockAnonymousAsync(
        IReadOnlyList<AnonymousPhysicalDeviceRequirement> requirements,
        ReadOnlyMemory<byte> archiveSalt,
        nint ownerWindowHandle,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requirements);
        if (archiveSalt.Length != 16 || requirements.Count == 0 ||
            requirements.Any(requirement =>
                requirement.DeviceLookupHash.Length != 32 || requirement.SecretSalt.Length != 32))
        {
            throw new NingRanException("匿名物理设备授权信息不正确或文件已损坏。 ");
        }

        var matches = new List<PhysicalDeviceRequirement>();
        foreach (var device in ReadRegistry())
        {
            cancellationToken.ThrowIfCancellationRequested();
            var lookup = PhysicalDevicePrivacy.ComputeLookupHash(device, archiveSalt.Span);
            try
            {
                foreach (var requirement in requirements)
                {
                    if (CryptographicOperations.FixedTimeEquals(
                            requirement.DeviceLookupHash,
                            lookup))
                    {
                        matches.Add(new PhysicalDeviceRequirement(
                            device,
                            requirement.SecretSalt.ToArray()));
                    }
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(lookup);
            }
        }

        if (matches.Count == 0)
        {
            throw new NingRanException("本机没有与此文件匿名授权记录匹配的物理设备。 ");
        }

        return UnlockAnyAsync(matches, ownerWindowHandle, cancellationToken);
    }

    private PhysicalDeviceUnlock? TryUnlockStorage(PhysicalDeviceRequirement requirement)
    {
        if (requirement.SecretSalt.Length != 32)
        {
            throw new NingRanException("物理设备开锁信息不正确或文件已损坏。 ");
        }

        foreach (var connected in RemovableStoragePhysicalDevice.Discover())
        {
            var token = TryReadValidToken(connected);
            if (token is null)
            {
                continue;
            }

            try
            {
                if (!string.Equals(token.RegistrationId, requirement.Device.Id, StringComparison.Ordinal))
                {
                    continue;
                }

                var secret = DeriveStorageSecret(token, requirement.SecretSalt);
                var expectedTokenHash = token.TokenHash.ToArray();
                bool IsPresent()
                {
                    try
                    {
                        var current = RemovableStoragePhysicalDevice.GetRequired(connected.RootPath);
                        if (!CryptographicOperations.FixedTimeEquals(
                                current.HardwareFingerprint,
                                connected.HardwareFingerprint))
                        {
                            return false;
                        }

                        var reread = TryReadValidToken(current);
                        if (reread is null)
                        {
                            return false;
                        }

                        try
                        {
                            return string.Equals(reread.RegistrationId, token.RegistrationId, StringComparison.Ordinal) &&
                                CryptographicOperations.FixedTimeEquals(reread.TokenHash, expectedTokenHash);
                        }
                        finally
                        {
                            reread.Clear();
                        }
                    }
                    catch
                    {
                        return false;
                    }
                }

                async Task Revalidate(CancellationToken cancellationToken)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (!IsPresent())
                    {
                        throw new NingRanException("物理设备已被拔出或发生变化，操作已经取消。 ");
                    }

                    await Task.CompletedTask;
                }

                return new PhysicalDeviceUnlock(requirement.Device, secret, IsPresent, Revalidate);
            }
            finally
            {
                token.Clear();
            }
        }

        return null;
    }

    private static StorageToken? TryReadValidToken(ConnectedStorageDevice device)
    {
        try
        {
            var token = ReadToken(Path.Combine(device.RootPath, TokenDirectoryName, TokenFileName));
            if (!CryptographicOperations.FixedTimeEquals(token.HardwareFingerprint, device.HardwareFingerprint))
            {
                token.Clear();
                return null;
            }

            return token;
        }
        catch
        {
            return null;
        }
    }

    private static StorageToken ReadToken(string path)
    {
        var bytes = BoundedFileReader.ReadAllBytes(path, TokenSize, "移动存储物理密钥凭证");
        try
        {
            if (bytes.Length != TokenSize || !bytes.AsSpan(0, 8).SequenceEqual(TokenMagic))
            {
                throw new NingRanException("移动存储内的物理密钥凭证不完整或已损坏。 ");
            }

            var secret = bytes.AsSpan(56, 32).ToArray();
            var expectedTag = HMACSHA256.HashData(secret, bytes.AsSpan(0, 88));
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(expectedTag, bytes.AsSpan(88, 32)))
                {
                    CryptographicOperations.ZeroMemory(secret);
                    throw new NingRanException("移动存储内的物理密钥凭证已被修改。 ");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(expectedTag);
            }

            return new StorageToken(
                new Guid(bytes.AsSpan(8, 16)).ToString("N"),
                bytes.AsSpan(24, 32).ToArray(),
                secret,
                SHA256.HashData(bytes));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static StorageToken CreateToken(byte[] hardwareFingerprint) =>
        new(
            Guid.NewGuid().ToString("N"),
            hardwareFingerprint.ToArray(),
            RandomNumberGenerator.GetBytes(32),
            []);

    private static byte[] DeriveStorageSecret(StorageToken token, ReadOnlySpan<byte> secretSalt)
    {
        var info = new byte["NINGRAN-STORAGE-DEVICE-V1"u8.Length + 32 + 16];
        try
        {
            "NINGRAN-STORAGE-DEVICE-V1"u8.CopyTo(info);
            token.HardwareFingerprint.CopyTo(info.AsSpan("NINGRAN-STORAGE-DEVICE-V1"u8.Length));
            new Guid(token.RegistrationId).TryWriteBytes(info.AsSpan(info.Length - 16));
            var result = new byte[32];
            HKDF.DeriveKey(HashAlgorithmName.SHA256, token.Secret, result, secretSalt, info);
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(info);
        }
    }

    private void Upsert(PhysicalDeviceDescriptor descriptor)
    {
        var devices = ReadRegistry();
        devices.RemoveAll(device => string.Equals(device.Id, descriptor.Id, StringComparison.Ordinal));
        devices.Add(descriptor);
        WriteRegistry(devices);
    }

    private List<PhysicalDeviceDescriptor> ReadRegistry()
    {
        if (!File.Exists(_registryPath))
        {
            return [];
        }

        var protectedBytes = BoundedFileReader.ReadAllBytes(
            _registryPath,
            256 * 1024,
            "本机物理设备清单");
        byte[]? plain = null;
        try
        {
            plain = ProtectedData.Unprotect(protectedBytes, RegistryEntropy, DataProtectionScope.CurrentUser);
            var registry = JsonSerializer.Deserialize<DeviceRegistry>(plain)
                ?? throw new NingRanException("本机物理设备清单不完整。 ");
            if (registry.Version != 1 || registry.Devices is null || registry.Devices.Count > 128)
            {
                throw new NingRanException("本机物理设备清单版本不正确或已损坏。 ");
            }

            return registry.Devices;
        }
        catch (CryptographicException exception)
        {
            throw new NingRanException("本机物理设备清单无法由当前 Windows 用户读取。 ", exception);
        }
        catch (JsonException exception)
        {
            throw new NingRanException("本机物理设备清单已损坏。 ", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedBytes);
            if (plain is not null)
            {
                CryptographicOperations.ZeroMemory(plain);
            }
        }
    }

    private void WriteRegistry(List<PhysicalDeviceDescriptor> devices)
    {
        var directory = Path.GetDirectoryName(_registryPath)!;
        Directory.CreateDirectory(directory);
        var plain = JsonSerializer.SerializeToUtf8Bytes(new DeviceRegistry(1, devices));
        byte[]? protectedBytes = null;
        var temporaryPath = _registryPath + $".{Guid.NewGuid():N}.tmp";
        try
        {
            protectedBytes = ProtectedData.Protect(plain, RegistryEntropy, DataProtectionScope.CurrentUser);
            using (var stream = new FileStream(
                       temporaryPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       4096,
                       FileOptions.WriteThrough))
            {
                stream.Write(protectedBytes);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporaryPath, _registryPath, overwrite: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
            if (protectedBytes is not null)
            {
                CryptographicOperations.ZeroMemory(protectedBytes);
            }

            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private static void ValidateName(string name)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Trim().Length > 50 || name.IndexOfAny(['\r', '\n', '\0']) >= 0)
        {
            throw new NingRanException("请填写 1 至 50 个字符的设备名称，且不要换行。 ");
        }
    }

    private static string GetDefaultRegistryPath() => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "NingRan",
        "physical-devices.dat");

    private sealed record DeviceRegistry(int Version, List<PhysicalDeviceDescriptor> Devices);

    private sealed class StorageToken
    {
        public StorageToken(string registrationId, byte[] hardwareFingerprint, byte[] secret, byte[] tokenHash)
        {
            RegistrationId = registrationId;
            HardwareFingerprint = hardwareFingerprint;
            Secret = secret;
            TokenHash = tokenHash;
        }

        public string RegistrationId { get; }
        public byte[] HardwareFingerprint { get; }
        public byte[] Secret { get; }
        public byte[] TokenHash { get; private set; }

        public byte[] Serialize()
        {
            var bytes = new byte[TokenSize];
            TokenMagic.CopyTo(bytes);
            new Guid(RegistrationId).TryWriteBytes(bytes.AsSpan(8, 16));
            HardwareFingerprint.CopyTo(bytes.AsSpan(24, 32));
            Secret.CopyTo(bytes.AsSpan(56, 32));
            var tag = HMACSHA256.HashData(Secret, bytes.AsSpan(0, 88));
            tag.CopyTo(bytes.AsSpan(88, 32));
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(TokenHash);
            TokenHash = SHA256.HashData(bytes);
            return bytes;
        }

        public void Clear()
        {
            CryptographicOperations.ZeroMemory(HardwareFingerprint);
            CryptographicOperations.ZeroMemory(Secret);
            CryptographicOperations.ZeroMemory(TokenHash);
        }
    }
}
