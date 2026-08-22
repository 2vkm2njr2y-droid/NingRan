using System.Buffers.Binary;
using System.Security.Cryptography;

namespace NingRan.Core.Internal;

internal sealed class ArchiveHeader
{
    private static ReadOnlySpan<byte> Magic => "NRARC008"u8;
    private const int PrefixSize = 56;
    private const int PasswordSlotSize = 12 + KeyDerivation.KeySize + CryptoSizes.Tag;
    private const int PhysicalSlotSize = 32 + 32 + PasswordSlotSize;
    private const int StandardSlotOffset = PrefixSize;
    private const int AdvancedSlotOffset = StandardSlotOffset + PasswordSlotSize;
    private const int PhysicalSlotsOffset = AdvancedSlotOffset + PasswordSlotSize;
    private const int MaxPhysicalDevices = 16;
    private const int HeaderSize = PhysicalSlotsOffset + (MaxPhysicalDevices * PhysicalSlotSize);

    private ArchiveHeader(byte[] bytes, EncryptionMode mode)
    {
        Bytes = bytes;
        Mode = mode;
        PayloadNoncePrefix = bytes.AsSpan(40, 4).ToArray();
        HeaderHash = SHA256.HashData(bytes);
    }

    public byte[] Bytes { get; }
    public EncryptionMode Mode { get; }
    public byte[] PayloadNoncePrefix { get; }
    public byte[] HeaderHash { get; }

    public static bool IsMagic(ReadOnlySpan<byte> magic) => magic.SequenceEqual(Magic);

    public static async Task InspectAsync(Stream stream, CancellationToken cancellationToken)
    {
        var bytes = await ReadHeaderBytesAsync(stream, cancellationToken).ConfigureAwait(false);
        CryptographicOperations.ZeroMemory(bytes);
    }

    public static async Task<(ArchiveHeader Header, byte[] DataKey)> CreateAsync(
        SensitivePassword password,
        ReadOnlyMemory<byte> keyFileSecret,
        EncryptionMode mode,
        bool hideExactSize,
        KdfParameters kdfParameters,
        CancellationToken cancellationToken)
    {
        _ = hideExactSize;
        if (mode is not (EncryptionMode.Standard or EncryptionMode.Advanced))
        {
            throw new NingRanException("此处只支持普通模式或高级模式。");
        }

        if (mode == EncryptionMode.Advanced && keyFileSecret.Length != KeyDerivation.KeySize)
        {
            throw new NingRanException("高级模式需要选择有效的普通文件或凝然专用密匙文件。");
        }

        var bytes = CreateBaseHeader(kdfParameters);
        var dataKey = RandomNumberGenerator.GetBytes(KeyDerivation.KeySize);
        byte[]? passwordKey = null;
        byte[]? wrapKey = null;
        try
        {
            passwordKey = await KeyDerivation.DerivePasswordKeyAsync(
                password, bytes.AsMemory(24, 16), kdfParameters, cancellationToken).ConfigureAwait(false);
            wrapKey = KeyDerivation.DeriveArchiveWrapKey(
                passwordKey, keyFileSecret.Span, mode, bytes.AsSpan(24, 16));
            EncryptPasswordSlot(
                bytes,
                mode == EncryptionMode.Standard ? StandardSlotOffset : AdvancedSlotOffset,
                mode,
                wrapKey,
                dataKey);
            return (new ArchiveHeader(bytes, mode), dataKey);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(bytes);
            CryptographicOperations.ZeroMemory(dataKey);
            throw;
        }
        finally
        {
            if (passwordKey is not null) CryptographicOperations.ZeroMemory(passwordKey);
            if (wrapKey is not null) CryptographicOperations.ZeroMemory(wrapKey);
        }
    }

    public static async Task<(
        ArchiveHeader Header,
        byte[] DataKey,
        IReadOnlyList<PhysicalDeviceUnlock> Unlocks)> CreatePhysicalAsync(
        SensitivePassword password,
        IReadOnlyList<PhysicalDeviceDescriptor> devices,
        KdfParameters kdfParameters,
        IPhysicalDeviceProvider deviceProvider,
        nint ownerWindowHandle,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(devices);
        ArgumentNullException.ThrowIfNull(deviceProvider);
        if (devices.Count is < 1 or > MaxPhysicalDevices)
        {
            throw new NingRanException($"物理设备模式必须选择 1 至 {MaxPhysicalDevices} 个设备。");
        }

        if (devices.Select(device => $"{(byte)device.Kind}:{device.Id}")
            .Distinct(StringComparer.Ordinal).Count() != devices.Count)
        {
            throw new NingRanException("不能重复选择同一个物理设备。");
        }

        var bytes = CreateBaseHeader(kdfParameters);
        var dataKey = RandomNumberGenerator.GetBytes(KeyDerivation.KeySize);
        byte[]? passwordKey = null;
        var unlocks = new List<PhysicalDeviceUnlock>(devices.Count);
        try
        {
            passwordKey = await KeyDerivation.DerivePasswordKeyAsync(
                password, bytes.AsMemory(24, 16), kdfParameters, cancellationToken).ConfigureAwait(false);
            var slotIndexes = Enumerable.Range(0, MaxPhysicalDevices)
                .OrderBy(_ => RandomNumberGenerator.GetInt32(int.MaxValue))
                .Take(devices.Count)
                .ToArray();
            for (var index = 0; index < devices.Count; index++)
            {
                var device = devices[index];
                var validatedIdentifier = PhysicalDevicePrivacy.GetIdentifierBytes(device);
                CryptographicOperations.ZeroMemory(validatedIdentifier);
                var secretSalt = RandomNumberGenerator.GetBytes(32);
                try
                {
                    var unlock = await deviceProvider.UnlockAnyAsync(
                        [new PhysicalDeviceRequirement(device, secretSalt)],
                        ownerWindowHandle,
                        cancellationToken).ConfigureAwait(false);
                    if (!PhysicalDevicePrivacy.DeviceMatches(unlock.Device, device))
                    {
                        unlock.Dispose();
                        throw new NingRanException("物理设备返回了与所选设备不一致的凭证。");
                    }

                    unlocks.Add(unlock);
                    var identifier = PhysicalDevicePrivacy.GetIdentifierBytes(device);
                    var wrapKey = KeyDerivation.DerivePhysicalDeviceWrapKey(
                        passwordKey, unlock.Secret.Span, bytes.AsSpan(24, 16), identifier);
                    try
                    {
                        EncryptPhysicalSlot(
                            bytes, slotIndexes[index], device, secretSalt, wrapKey, dataKey);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(identifier);
                        CryptographicOperations.ZeroMemory(wrapKey);
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(secretSalt);
                }
            }

            return (new ArchiveHeader(bytes, EncryptionMode.PhysicalDevice), dataKey, unlocks);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(bytes);
            CryptographicOperations.ZeroMemory(dataKey);
            foreach (var unlock in unlocks) unlock.Dispose();
            throw;
        }
        finally
        {
            if (passwordKey is not null) CryptographicOperations.ZeroMemory(passwordKey);
        }
    }

    public static async Task<(
        ArchiveHeader Header,
        byte[] DataKey,
        PhysicalDeviceUnlock? PhysicalUnlock)> ReadAndUnlockAsync(
        Stream stream,
        SensitivePassword password,
        ReadOnlyMemory<byte> keyFileSecret,
        IPhysicalDeviceProvider deviceProvider,
        nint ownerWindowHandle,
        CancellationToken cancellationToken)
    {
        var bytes = await ReadHeaderBytesAsync(stream, cancellationToken).ConfigureAwait(false);
        var kdfParameters = ReadKdfParameters(bytes);
        byte[]? passwordKey = null;
        try
        {
            passwordKey = await KeyDerivation.DerivePasswordKeyAsync(
                password, bytes.AsMemory(24, 16), kdfParameters, cancellationToken).ConfigureAwait(false);

            var standardKey = KeyDerivation.DeriveArchiveWrapKey(
                passwordKey, ReadOnlySpan<byte>.Empty, EncryptionMode.Standard, bytes.AsSpan(24, 16));
            try
            {
                if (TryDecryptPasswordSlot(
                        bytes, StandardSlotOffset, EncryptionMode.Standard, standardKey, out var dataKey))
                {
                    return (new ArchiveHeader(bytes, EncryptionMode.Standard), dataKey, null);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(standardKey);
            }

            if (keyFileSecret.Length == KeyDerivation.KeySize)
            {
                var advancedKey = KeyDerivation.DeriveArchiveWrapKey(
                    passwordKey, keyFileSecret.Span, EncryptionMode.Advanced, bytes.AsSpan(24, 16));
                try
                {
                    if (TryDecryptPasswordSlot(
                            bytes, AdvancedSlotOffset, EncryptionMode.Advanced, advancedKey, out var dataKey))
                    {
                        return (new ArchiveHeader(bytes, EncryptionMode.Advanced), dataKey, null);
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(advancedKey);
                }
            }

            var requirements = ReadAnonymousRequirements(bytes);
            PhysicalDeviceUnlock? unlock = null;
            try
            {
                unlock = await deviceProvider.UnlockAnonymousAsync(
                    requirements,
                    bytes.AsMemory(24, 16),
                    ownerWindowHandle,
                    cancellationToken).ConfigureAwait(false);
                var lookup = PhysicalDevicePrivacy.ComputeLookupHash(unlock.Device, bytes.AsSpan(24, 16));
                int slotIndex;
                try
                {
                    slotIndex = requirements.ToList().FindIndex(requirement =>
                        CryptographicOperations.FixedTimeEquals(requirement.DeviceLookupHash, lookup));
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(lookup);
                }

                if (slotIndex < 0)
                {
                    throw new NingRanException("物理设备没有匹配此文件的匿名授权记录。");
                }

                var identifier = PhysicalDevicePrivacy.GetIdentifierBytes(unlock.Device);
                var physicalKey = KeyDerivation.DerivePhysicalDeviceWrapKey(
                    passwordKey, unlock.Secret.Span, bytes.AsSpan(24, 16), identifier);
                try
                {
                    if (TryDecryptPhysicalSlot(bytes, slotIndex, physicalKey, out var dataKey))
                    {
                        return (new ArchiveHeader(bytes, EncryptionMode.PhysicalDevice), dataKey, unlock);
                    }

                    unlock.Dispose();
                    unlock = null;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(identifier);
                    CryptographicOperations.ZeroMemory(physicalKey);
                }
            }
            catch (NingRanException)
            {
                unlock?.Dispose();
            }

            throw new NingRanException(
                "密码或解锁条件不正确，或者加密文件已损坏。若文件使用高级模式，请同时选择原密匙文件；若使用物理设备，请插入获授权设备。");
        }
        catch
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw;
        }
        finally
        {
            if (passwordKey is not null) CryptographicOperations.ZeroMemory(passwordKey);
        }
    }

    private static byte[] CreateBaseHeader(KdfParameters kdfParameters)
    {
        kdfParameters.ValidateForReading();
        var bytes = RandomNumberGenerator.GetBytes(HeaderSize);
        Magic.CopyTo(bytes);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(8, 4), HeaderSize);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(12, 4), kdfParameters.MemoryKib);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(16, 4), kdfParameters.Iterations);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(20, 4), kdfParameters.Parallelism);
        RandomNumberGenerator.Fill(bytes.AsSpan(24, 20));
        bytes.AsSpan(44, 12).Clear();
        return bytes;
    }

    private static async Task<byte[]> ReadHeaderBytesAsync(Stream stream, CancellationToken cancellationToken)
    {
        var bytes = new byte[HeaderSize];
        try
        {
            await BinaryFormat.ReadExactlyAsync(stream, bytes, cancellationToken).ConfigureAwait(false);
        }
        catch (EndOfStreamException exception)
        {
            throw new NingRanException("这不是完整的凝然加密文件。", exception);
        }

        if (!bytes.AsSpan(0, Magic.Length).SequenceEqual(Magic) ||
            BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(8, 4)) != HeaderSize ||
            bytes.AsSpan(44, 12).IndexOfAnyExcept((byte)0) >= 0)
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw new NingRanException("这不是当前版本支持的凝然加密文件，或文件头已经损坏。");
        }

        _ = ReadKdfParameters(bytes);
        return bytes;
    }

    private static KdfParameters ReadKdfParameters(byte[] bytes)
    {
        var parameters = new KdfParameters(
            BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(12, 4)),
            BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(16, 4)),
            BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(20, 4)));
        try
        {
            parameters.ValidateForReading();
            return parameters;
        }
        catch (InvalidDataException exception)
        {
            throw new NingRanException(exception.Message, exception);
        }
    }

    private static void EncryptPasswordSlot(
        byte[] bytes, int offset, EncryptionMode mode, byte[] wrapKey, byte[] dataKey)
    {
        RandomNumberGenerator.Fill(bytes.AsSpan(offset, 12));
        var aad = CreatePasswordSlotAad(bytes, offset, mode);
        try
        {
            using var cipher = new ChaCha20Poly1305(wrapKey);
            cipher.Encrypt(
                bytes.AsSpan(offset, 12),
                dataKey,
                bytes.AsSpan(offset + 12, KeyDerivation.KeySize),
                bytes.AsSpan(offset + 12 + KeyDerivation.KeySize, CryptoSizes.Tag),
                aad);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aad);
        }
    }

    private static bool TryDecryptPasswordSlot(
        byte[] bytes, int offset, EncryptionMode mode, byte[] wrapKey, out byte[] dataKey)
    {
        dataKey = new byte[KeyDerivation.KeySize];
        var aad = CreatePasswordSlotAad(bytes, offset, mode);
        try
        {
            using var cipher = new ChaCha20Poly1305(wrapKey);
            cipher.Decrypt(
                bytes.AsSpan(offset, 12),
                bytes.AsSpan(offset + 12, KeyDerivation.KeySize),
                bytes.AsSpan(offset + 12 + KeyDerivation.KeySize, CryptoSizes.Tag),
                dataKey,
                aad);
            return true;
        }
        catch (CryptographicException)
        {
            CryptographicOperations.ZeroMemory(dataKey);
            dataKey = [];
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aad);
        }
    }

    private static byte[] CreatePasswordSlotAad(byte[] bytes, int offset, EncryptionMode mode)
    {
        var aad = new byte[PrefixSize + 1 + 12];
        bytes.AsSpan(0, PrefixSize).CopyTo(aad);
        aad[PrefixSize] = (byte)mode;
        bytes.AsSpan(offset, 12).CopyTo(aad.AsSpan(PrefixSize + 1));
        return aad;
    }

    private static void EncryptPhysicalSlot(
        byte[] bytes,
        int slotIndex,
        PhysicalDeviceDescriptor device,
        byte[] secretSalt,
        byte[] wrapKey,
        byte[] dataKey)
    {
        var offset = PhysicalSlotsOffset + (slotIndex * PhysicalSlotSize);
        var lookup = PhysicalDevicePrivacy.ComputeLookupHash(device, bytes.AsSpan(24, 16));
        try
        {
            lookup.CopyTo(bytes.AsSpan(offset, 32));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(lookup);
        }

        secretSalt.CopyTo(bytes.AsSpan(offset + 32, 32));
        RandomNumberGenerator.Fill(bytes.AsSpan(offset + 64, 12));
        var aad = CreatePhysicalSlotAad(bytes, slotIndex);
        try
        {
            using var cipher = new ChaCha20Poly1305(wrapKey);
            cipher.Encrypt(
                bytes.AsSpan(offset + 64, 12),
                dataKey,
                bytes.AsSpan(offset + 76, KeyDerivation.KeySize),
                bytes.AsSpan(offset + 76 + KeyDerivation.KeySize, CryptoSizes.Tag),
                aad);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aad);
        }
    }

    private static bool TryDecryptPhysicalSlot(byte[] bytes, int slotIndex, byte[] wrapKey, out byte[] dataKey)
    {
        var offset = PhysicalSlotsOffset + (slotIndex * PhysicalSlotSize);
        dataKey = new byte[KeyDerivation.KeySize];
        var aad = CreatePhysicalSlotAad(bytes, slotIndex);
        try
        {
            using var cipher = new ChaCha20Poly1305(wrapKey);
            cipher.Decrypt(
                bytes.AsSpan(offset + 64, 12),
                bytes.AsSpan(offset + 76, KeyDerivation.KeySize),
                bytes.AsSpan(offset + 76 + KeyDerivation.KeySize, CryptoSizes.Tag),
                dataKey,
                aad);
            return true;
        }
        catch (CryptographicException)
        {
            CryptographicOperations.ZeroMemory(dataKey);
            dataKey = [];
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aad);
        }
    }

    private static byte[] CreatePhysicalSlotAad(byte[] bytes, int slotIndex)
    {
        var offset = PhysicalSlotsOffset + (slotIndex * PhysicalSlotSize);
        var aad = new byte[PrefixSize + 1 + 76];
        bytes.AsSpan(0, PrefixSize).CopyTo(aad);
        aad[PrefixSize] = checked((byte)slotIndex);
        bytes.AsSpan(offset, 76).CopyTo(aad.AsSpan(PrefixSize + 1));
        return aad;
    }

    private static IReadOnlyList<AnonymousPhysicalDeviceRequirement> ReadAnonymousRequirements(byte[] bytes)
    {
        var requirements = new AnonymousPhysicalDeviceRequirement[MaxPhysicalDevices];
        for (var index = 0; index < requirements.Length; index++)
        {
            var offset = PhysicalSlotsOffset + (index * PhysicalSlotSize);
            requirements[index] = new AnonymousPhysicalDeviceRequirement(
                bytes.AsSpan(offset, 32).ToArray(),
                bytes.AsSpan(offset + 32, 32).ToArray());
        }

        return requirements;
    }
}
