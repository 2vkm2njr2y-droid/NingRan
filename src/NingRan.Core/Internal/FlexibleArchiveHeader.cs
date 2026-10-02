using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace NingRan.Core.Internal;

internal static class FlexibleArchiveHeader
{
    internal static ReadOnlySpan<byte> FlexibleMagic => "NRARC009"u8;

    private const int PrefixSize = 64;
    private const int PhysicalRecordSize = 126;
    private const int EnvelopeSize = CryptoSizes.Nonce + KeyDerivation.KeySize + CryptoSizes.Tag;
    private const byte RequiredFlag = 1;
    private const byte ForbiddenFlag = 2;
    private const byte HelloAccountBoundSecretFlag = 1;

    public static byte[] ComputePayloadHeaderHash(ReadOnlySpan<byte> bytes)
    {
        var immutable = new byte[8 + 32];
        bytes[..8].CopyTo(immutable);
        bytes.Slice(12, 32).CopyTo(immutable.AsSpan(8));
        try { return SHA256.HashData(immutable); }
        finally { CryptographicOperations.ZeroMemory(immutable); }
    }

    public static async Task<(
        ArchiveHeader Header,
        byte[] DataKey,
        IReadOnlyList<PhysicalDeviceUnlock> Unlocks)> CreateAsync(
        SensitivePassword password,
        ReadOnlyMemory<byte> keyFileSecret,
        ProtectionPolicy policy,
        KdfParameters kdfParameters,
        IPhysicalDeviceProvider deviceProvider,
        nint ownerWindowHandle,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(deviceProvider);
        policy.ValidateForCreation();
        policy.WindowsHello?.Validate();

        var archiveSalt = RandomNumberGenerator.GetBytes(16);
        var payloadNoncePrefix = RandomNumberGenerator.GetBytes(4);
        var dataKey = RandomNumberGenerator.GetBytes(KeyDerivation.KeySize);
        var physicalSecret = policy.Requires(ProtectionFactor.PhysicalDevice)
            ? RandomNumberGenerator.GetBytes(KeyDerivation.KeySize)
            : null;
        var physicalUnlocks = new List<PhysicalDeviceUnlock>();
        var physicalRecords = new List<PhysicalRecord>();
        var forbiddenLookups = new List<byte[]>();
        byte[]? helloSecret = null;
        byte[]? primaryWrapKey = null;
        byte[]? recoveryWrapKey = null;
        try
        {
            if (policy.Requires(ProtectionFactor.KeyFile) && keyFileSecret.Length != KeyDerivation.KeySize)
                throw new NingRanException("当前保护方式需要有效的密匙文件。 ");

            if (policy.Requires(ProtectionFactor.Password) && password.IsEmpty)
                throw new NingRanException("当前保护方式需要设置密码。 ");

            if (policy.Requires(ProtectionFactor.PhysicalDevice))
            {
                var physicalPolicy = policy.PhysicalDevices!;
                if (deviceProvider is not IPhysicalDevicePresence presence)
                    throw new NingRanException("当前设备接口无法持续检测禁止插入的物理密匙。 ");
                foreach (var forbiddenDevice in physicalPolicy.ForbiddenDevices)
                    forbiddenLookups.Add(PhysicalDevicePrivacy.ComputeLookupHash(forbiddenDevice, archiveSalt));
                if (presence.IsAnyForbiddenStorageConnected(archiveSalt, forbiddenLookups))
                    throw new NingRanException("检测到禁止插入的物理密匙，已拒绝创建。 ");

                var shares = ThresholdSecretSharing.Split(
                    physicalSecret!, physicalPolicy.Devices.Count, physicalPolicy.MinimumRequired);
                try
                {
                    for (var index = 0; index < physicalPolicy.Devices.Count; index++)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        var device = physicalPolicy.Devices[index];
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
                                throw new NingRanException("物理密匙返回了与所选设备不一致的凭证。 ");
                            }

                            physicalUnlocks.Add(unlock);
                            var lookup = PhysicalDevicePrivacy.ComputeLookupHash(device, archiveSalt);
                            var encryptedShare = EncryptShare(
                                shares[index], unlock.Secret.Span, archiveSalt, lookup, secretSalt);
                            physicalRecords.Add(new PhysicalRecord(
                                lookup,
                                secretSalt.ToArray(),
                                encryptedShare,
                                physicalPolicy.RequiredDeviceIds.Contains(device.Id, StringComparer.Ordinal),
                                forbidden: false));
                        }
                        finally
                        {
                            CryptographicOperations.ZeroMemory(secretSalt);
                        }
                    }
                }
                finally
                {
                    foreach (var share in shares) CryptographicOperations.ZeroMemory(share);
                }
            }

            if (policy.Requires(ProtectionFactor.WindowsHello))
            {
                helloSecret = await new Fido2PhysicalDevice().UnlockWindowsHelloAsync(
                    policy.WindowsHello!, ownerWindowHandle, cancellationToken).ConfigureAwait(false);
            }

            primaryWrapKey = await DeriveCompositeKeyAsync(
                password,
                keyFileSecret,
                policy.Factors,
                physicalSecret,
                helloSecret,
                archiveSalt,
                kdfParameters,
                cancellationToken).ConfigureAwait(false);
            var primaryEnvelope = EncryptEnvelope(dataKey, primaryWrapKey);

            Envelope? recoveryEnvelope = null;
            if (policy.RecoveryFactors != ProtectionFactor.None)
            {
                recoveryWrapKey = await DeriveCompositeKeyAsync(
                    password,
                    keyFileSecret,
                    policy.RecoveryFactors,
                    null,
                    null,
                    archiveSalt,
                    kdfParameters,
                    cancellationToken).ConfigureAwait(false);
                recoveryEnvelope = EncryptEnvelope(dataKey, recoveryWrapKey);
            }

            var bytes = BuildHeader(
                policy,
                archiveSalt,
                payloadNoncePrefix,
                physicalRecords,
                forbiddenLookups,
                primaryEnvelope,
                recoveryEnvelope,
                kdfParameters);
            var header = new ArchiveHeader(bytes, EncryptionMode.Flexible, policy, forbiddenLookups);
            return (header, dataKey, physicalUnlocks);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(dataKey);
            foreach (var unlock in physicalUnlocks) unlock.Dispose();
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(archiveSalt);
            CryptographicOperations.ZeroMemory(payloadNoncePrefix);
            if (physicalSecret is not null) CryptographicOperations.ZeroMemory(physicalSecret);
            if (helloSecret is not null) CryptographicOperations.ZeroMemory(helloSecret);
            if (primaryWrapKey is not null) CryptographicOperations.ZeroMemory(primaryWrapKey);
            if (recoveryWrapKey is not null) CryptographicOperations.ZeroMemory(recoveryWrapKey);
            foreach (var record in physicalRecords) record.Clear();
            foreach (var lookup in forbiddenLookups) CryptographicOperations.ZeroMemory(lookup);
        }
    }

    public static async Task<(
        ArchiveHeader Header,
        byte[] DataKey,
        IReadOnlyList<PhysicalDeviceUnlock> Unlocks)> ReadAndUnlockAsync(
        Stream stream,
        SensitivePassword password,
        ReadOnlyMemory<byte> keyFileSecret,
        IPhysicalDeviceProvider deviceProvider,
        nint ownerWindowHandle,
        CancellationToken cancellationToken)
    {
        var bytes = await ReadFlexibleHeaderAsync(stream, cancellationToken).ConfigureAwait(false);
        var parsed = Parse(bytes);
        byte[]? physicalSecret = null;
        byte[]? helloSecret = null;
        byte[]? primaryWrapKey = null;
        byte[]? recoveryWrapKey = null;
        var unlocks = new List<PhysicalDeviceUnlock>();
        try
        {
            if ((parsed.Policy.Factors & ProtectionFactor.KeyFile) != 0 &&
                keyFileSecret.Length != KeyDerivation.KeySize)
                throw new NingRanException("当前保险箱需要选择原密匙文件。 ");

            if ((parsed.Policy.Factors & ProtectionFactor.Password) != 0 && password.IsEmpty)
                throw new NingRanException("当前保险箱需要输入密码。 ");

            if ((parsed.Policy.Factors & ProtectionFactor.PhysicalDevice) != 0)
            {
                if (deviceProvider is not IPhysicalDevicePresence presence)
                    throw new NingRanException("当前设备接口无法持续检查物理密匙规则。 ");
                if (presence.IsAnyForbiddenStorageConnected(parsed.ArchiveSalt, parsed.ForbiddenLookups))
                    throw new NingRanException("检测到禁止插入的物理密匙，已拒绝解锁。 ");
                var shares = await UnlockPhysicalSharesAsync(
                    parsed, deviceProvider, ownerWindowHandle, cancellationToken, unlocks).ConfigureAwait(false);
                try
                {
                    physicalSecret = ThresholdSecretSharing.Combine(shares, parsed.MinimumPhysicalDevices);
                }
                finally
                {
                    foreach (var share in shares) CryptographicOperations.ZeroMemory(share);
                }
            }

            if ((parsed.Policy.Factors & ProtectionFactor.WindowsHello) != 0)
            {
                helloSecret = await new Fido2PhysicalDevice().UnlockWindowsHelloAsync(
                    parsed.Hello ?? throw new NingRanException("保险箱缺少 Windows Hello 凭据。 "),
                    ownerWindowHandle,
                    cancellationToken).ConfigureAwait(false);
            }

            primaryWrapKey = await DeriveCompositeKeyAsync(
                password,
                keyFileSecret,
                parsed.Policy.Factors,
                physicalSecret,
                helloSecret,
                parsed.ArchiveSalt,
                parsed.KdfParameters,
                cancellationToken).ConfigureAwait(false);
            if (TryDecryptEnvelope(parsed.PrimaryEnvelope, primaryWrapKey, out var dataKey))
            {
                return (new ArchiveHeader(bytes, EncryptionMode.Flexible, parsed.Policy, parsed.ForbiddenLookups), dataKey, unlocks);
            }

            if (parsed.RecoveryEnvelope is not null && parsed.Policy.RecoveryFactors != ProtectionFactor.None)
            {
                recoveryWrapKey = await DeriveCompositeKeyAsync(
                    password,
                    keyFileSecret,
                    parsed.Policy.RecoveryFactors,
                    null,
                    null,
                    parsed.ArchiveSalt,
                    parsed.KdfParameters,
                    cancellationToken).ConfigureAwait(false);
                if (TryDecryptEnvelope(parsed.RecoveryEnvelope.Value, recoveryWrapKey, out dataKey))
                    return (new ArchiveHeader(bytes, EncryptionMode.Flexible, parsed.Policy, parsed.ForbiddenLookups), dataKey, unlocks);
            }

            throw new NingRanException("密码、密匙文件、物理密匙或 Windows Hello 条件不正确，无法解锁保险箱。 ");
        }
        catch
        {
            foreach (var unlock in unlocks) unlock.Dispose();
            CryptographicOperations.ZeroMemory(bytes);
            throw;
        }
        finally
        {
            if (physicalSecret is not null) CryptographicOperations.ZeroMemory(physicalSecret);
            if (helloSecret is not null) CryptographicOperations.ZeroMemory(helloSecret);
            if (primaryWrapKey is not null) CryptographicOperations.ZeroMemory(primaryWrapKey);
            if (recoveryWrapKey is not null) CryptographicOperations.ZeroMemory(recoveryWrapKey);
        }
    }

    internal static byte[] DeriveFlexibleShareKey(
        ReadOnlySpan<byte> deviceSecret,
        ReadOnlySpan<byte> archiveSalt,
        ReadOnlySpan<byte> lookupHash)
    {
        var info = new byte["NINGRAN-FLEX-PHYSICAL-SHARE"u8.Length + lookupHash.Length];
        try
        {
            "NINGRAN-FLEX-PHYSICAL-SHARE"u8.CopyTo(info);
            lookupHash.CopyTo(info.AsSpan("NINGRAN-FLEX-PHYSICAL-SHARE"u8.Length));
            var result = new byte[KeyDerivation.KeySize];
            HKDF.DeriveKey(HashAlgorithmName.SHA256, deviceSecret, result, archiveSalt, info);
            return result;
        }
        finally { CryptographicOperations.ZeroMemory(info); }
    }

    private static async Task<byte[]> DeriveCompositeKeyAsync(
        SensitivePassword password,
        ReadOnlyMemory<byte> keyFileSecret,
        ProtectionFactor factors,
        ReadOnlyMemory<byte> physicalSecret,
        ReadOnlyMemory<byte> helloSecret,
        ReadOnlyMemory<byte> archiveSalt,
        KdfParameters kdfParameters,
        CancellationToken cancellationToken)
    {
        var pieces = new List<byte[]>();
        try
        {
            if ((factors & ProtectionFactor.Password) != 0)
                pieces.Add(await KeyDerivation.DerivePasswordKeyAsync(
                    password, archiveSalt, kdfParameters, cancellationToken).ConfigureAwait(false));
            if ((factors & ProtectionFactor.KeyFile) != 0)
                pieces.Add(keyFileSecret.ToArray());
            if ((factors & ProtectionFactor.PhysicalDevice) != 0)
                pieces.Add(physicalSecret.ToArray());
            if ((factors & ProtectionFactor.WindowsHello) != 0)
                pieces.Add(helloSecret.ToArray());

            if (pieces.Count == 0 || pieces.Any(piece => piece.Length != KeyDerivation.KeySize))
                throw new NingRanException("解锁条件资料不完整。 ");

            var input = new byte[pieces.Count * KeyDerivation.KeySize];
            try
            {
                for (var index = 0; index < pieces.Count; index++)
                    pieces[index].CopyTo(input, index * KeyDerivation.KeySize);
                var output = new byte[KeyDerivation.KeySize];
                HKDF.DeriveKey(
                    HashAlgorithmName.SHA256,
                    input,
                    output,
                    archiveSalt.Span,
                    "NINGRAN-ARCHIVE-V5-FLEXIBLE-WRAP"u8);
                return output;
            }
            finally { CryptographicOperations.ZeroMemory(input); }
        }
        finally
        {
            foreach (var piece in pieces) CryptographicOperations.ZeroMemory(piece);
        }
    }

    private static byte[] BuildHeader(
        ProtectionPolicy policy,
        byte[] archiveSalt,
        byte[] payloadNoncePrefix,
        IReadOnlyList<PhysicalRecord> physicalRecords,
        IReadOnlyList<byte[]> forbiddenLookups,
        Envelope primary,
        Envelope? recovery,
        KdfParameters kdfParameters)
    {
        var helloId = policy.WindowsHello?.CredentialId ?? [];
        var helloProtectedSecret = policy.WindowsHello?.ProtectedSecret;
        var length = checked(PrefixSize + physicalRecords.Count * PhysicalRecordSize +
            forbiddenLookups.Count * 32 + (helloId.Length == 0 ? 0 : 2 + helloId.Length + 32 +
                (helloProtectedSecret is null ? 0 : 2 + helloProtectedSecret.Length)) +
            EnvelopeSize + (recovery is null ? 0 : EnvelopeSize));
        var bytes = RandomNumberGenerator.GetBytes(length);
        FlexibleMagic.CopyTo(bytes);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(8, 4), length);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(12, 4), kdfParameters.MemoryKib);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(16, 4), kdfParameters.Iterations);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(20, 4), kdfParameters.Parallelism);
        archiveSalt.CopyTo(bytes.AsSpan(24, 16));
        payloadNoncePrefix.CopyTo(bytes.AsSpan(40, 4));
        bytes[44] = (byte)policy.Factors;
        bytes[45] = (byte)policy.RecoveryFactors;
        bytes[46] = checked((byte)(policy.PhysicalDevices?.MinimumRequired ?? 0));
        bytes[47] = checked((byte)physicalRecords.Count);
        bytes[48] = checked((byte)(policy.PhysicalDevices?.RequiredDeviceIds.Count ?? 0));
        bytes[49] = checked((byte)forbiddenLookups.Count);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(50, 2), checked((ushort)helloId.Length));
        bytes.AsSpan(52, 12).Clear();
        if (helloProtectedSecret is not null) bytes[52] = HelloAccountBoundSecretFlag;

        var offset = PrefixSize;
        foreach (var record in physicalRecords)
        {
            record.Lookup.CopyTo(bytes.AsSpan(offset, 32));
            record.Salt.CopyTo(bytes.AsSpan(offset + 32, 32));
            record.Nonce.CopyTo(bytes.AsSpan(offset + 64, 12));
            record.Ciphertext.CopyTo(bytes.AsSpan(offset + 76, 33));
            record.Tag.CopyTo(bytes.AsSpan(offset + 109, 16));
            bytes[offset + 125] = (byte)((record.Required ? RequiredFlag : 0) | (record.Forbidden ? ForbiddenFlag : 0));
            offset += PhysicalRecordSize;
        }

        foreach (var lookup in forbiddenLookups)
        {
            lookup.CopyTo(bytes.AsSpan(offset, 32));
            offset += 32;
        }

        if (helloId.Length > 0)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(offset, 2), checked((ushort)helloId.Length));
            helloId.CopyTo(bytes.AsSpan(offset + 2));
            policy.WindowsHello!.Salt.CopyTo(bytes.AsSpan(offset + 2 + helloId.Length, 32));
            offset += 2 + helloId.Length + 32;
            if (helloProtectedSecret is not null)
            {
                BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(offset, 2), checked((ushort)helloProtectedSecret.Length));
                helloProtectedSecret.CopyTo(bytes.AsSpan(offset + 2));
                offset += 2 + helloProtectedSecret.Length;
            }
        }

        WriteEnvelope(bytes.AsSpan(offset, EnvelopeSize), primary);
        offset += EnvelopeSize;
        if (recovery is not null) WriteEnvelope(bytes.AsSpan(offset, EnvelopeSize), recovery.Value);
        return bytes;
    }

    private static async Task<byte[]> ReadFlexibleHeaderAsync(Stream stream, CancellationToken cancellationToken)
    {
        stream.Position = 0;
        var prefix = new byte[12];
        await BinaryFormat.ReadExactlyAsync(stream, prefix, cancellationToken).ConfigureAwait(false);
        if (!prefix.AsSpan(0, 8).SequenceEqual(FlexibleMagic))
            throw new NingRanException("这不是新组合保护格式。 ");
        var length = BinaryPrimitives.ReadInt32LittleEndian(prefix.AsSpan(8, 4));
        if (length is < PrefixSize or > 1024 * 1024)
            throw new NingRanException("组合保护文件头大小不正确。 ");
        var bytes = new byte[length];
        prefix.CopyTo(bytes, 0);
        await BinaryFormat.ReadExactlyAsync(stream, bytes.AsMemory(12), cancellationToken).ConfigureAwait(false);
        return ValidateAndReturn(bytes);
    }

    internal static byte[] ValidateAndReturn(byte[] bytes)
    {
        if (!bytes.AsSpan(0, 8).SequenceEqual(FlexibleMagic) ||
            BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(8, 4)) != bytes.Length ||
            bytes[44] == 0 || bytes[47] > 16 || bytes[49] > bytes[47])
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw new NingRanException("组合保护文件头已经损坏。 ");
        }

        var parameters = new KdfParameters(
            BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(12, 4)),
            BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(16, 4)),
            BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(20, 4)));
        parameters.ValidateForReading();
        return bytes;
    }

    private static ParsedHeader Parse(byte[] bytes)
    {
        var factors = (ProtectionFactor)bytes[44];
        var recovery = (ProtectionFactor)bytes[45];
        if ((factors & ~(
                ProtectionFactor.Password | ProtectionFactor.KeyFile |
                ProtectionFactor.PhysicalDevice | ProtectionFactor.WindowsHello)) != 0 ||
            (recovery & ~(ProtectionFactor.Password | ProtectionFactor.KeyFile)) != 0 ||
            factors == ProtectionFactor.None)
            throw new NingRanException("组合保护方式记录不正确。 ");

        var minimum = bytes[46];
        var count = bytes[47];
        var requiredCount = bytes[48];
        var forbiddenCount = bytes[49];
        if ((factors & ProtectionFactor.PhysicalDevice) != 0 &&
            (count == 0 || minimum == 0 || minimum > count || requiredCount > minimum))
            throw new NingRanException("组合保护中的物理密匙规则不正确。 ");

        var records = new List<PhysicalRecord>(count);
        var offset = PrefixSize;
        for (var index = 0; index < count; index++)
        {
            if (offset + PhysicalRecordSize > bytes.Length) throw new NingRanException("组合保护记录不完整。 ");
            records.Add(new PhysicalRecord(
                bytes.AsSpan(offset, 32).ToArray(),
                bytes.AsSpan(offset + 32, 32).ToArray(),
                bytes.AsSpan(offset + 76, 33).ToArray(),
                (bytes[offset + 125] & RequiredFlag) != 0,
                (bytes[offset + 125] & ForbiddenFlag) != 0,
                bytes.AsSpan(offset + 64, 12).ToArray(),
                bytes.AsSpan(offset + 109, 16).ToArray()));
            offset += PhysicalRecordSize;
        }

        var forbiddenLookups = new List<byte[]>(forbiddenCount);
        for (var index = 0; index < forbiddenCount; index++)
        {
            if (offset + 32 > bytes.Length) throw new NingRanException("禁止插入名单记录不完整。 ");
            forbiddenLookups.Add(bytes.AsSpan(offset, 32).ToArray());
            offset += 32;
        }

        WindowsHelloCredential? hello = null;
        var helloLength = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(50, 2));
        if (helloLength > 0)
        {
            var helloRecordOffset = offset;
            if (offset + 2 + helloLength + 32 > bytes.Length) throw new NingRanException("Windows Hello 记录不完整。 ");
            var storedLength = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(offset, 2));
            if (storedLength != helloLength) throw new NingRanException("Windows Hello 记录长度不一致。 ");
            offset += 2 + helloLength + 32;
            byte[]? protectedSecret = null;
            if ((bytes[52] & HelloAccountBoundSecretFlag) != 0)
            {
                if (offset + 2 > bytes.Length) throw new NingRanException("Windows Hello 本机恢复记录不完整。 ");
                var protectedLength = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(offset, 2));
                if (protectedLength is 0 or > 4096 || offset + 2 + protectedLength > bytes.Length)
                    throw new NingRanException("Windows Hello 本机恢复记录长度不正确。 ");
                protectedSecret = bytes.AsSpan(offset + 2, protectedLength).ToArray();
                offset += 2 + protectedLength;
            }
            hello = new WindowsHelloCredential(
                bytes.AsSpan(helloRecordOffset + 2, helloLength).ToArray(),
                bytes.AsSpan(helloRecordOffset + 2 + helloLength, 32).ToArray(),
                protectedSecret);
            hello.Validate();
        }

        if (offset + EnvelopeSize > bytes.Length) throw new NingRanException("组合保护主密匙记录不完整。 ");
        var primary = ReadEnvelope(bytes.AsSpan(offset, EnvelopeSize));
        offset += EnvelopeSize;
        Envelope? recoveryEnvelope = null;
        if (recovery != ProtectionFactor.None)
        {
            if (offset + EnvelopeSize > bytes.Length) throw new NingRanException("组合保护恢复记录不完整。 ");
            recoveryEnvelope = ReadEnvelope(bytes.AsSpan(offset, EnvelopeSize));
            offset += EnvelopeSize;
        }

        if (offset != bytes.Length ||
            ((factors & ProtectionFactor.WindowsHello) != 0) != (hello is not null) ||
            ((bytes[52] & HelloAccountBoundSecretFlag) != 0) && hello is null)
            throw new NingRanException("组合保护文件头中包含无法识别的内容。 ");

        var descriptors = records.Select((record, index) => new PhysicalDeviceDescriptor(
            PhysicalDeviceKind.Fido2SecurityKey,
            Convert.ToHexString(record.Lookup),
            "匿名物理密匙",
            record.Forbidden ? "禁止插入" : record.Required ? "必需" : "候选",
            0)).ToArray();
        // Public policy metadata stores salted device lookups, not real device IDs.
        // It is informational only; the authenticated envelope validates the unlock.
        var policy = new ProtectionPolicy(factors, null, hello, recovery);
        var parameters = new KdfParameters(
            BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(12, 4)),
            BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(16, 4)),
            BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(20, 4)));
        return new ParsedHeader(
            policy,
            parameters,
            bytes.AsSpan(24, 16).ToArray(),
            records,
            forbiddenLookups,
            primary,
            recoveryEnvelope,
            minimum);
    }

    private static async Task<IReadOnlyList<byte[]>> UnlockPhysicalSharesAsync(
        ParsedHeader parsed,
        IPhysicalDeviceProvider provider,
        nint ownerWindowHandle,
        CancellationToken cancellationToken,
        List<PhysicalDeviceUnlock> unlocks)
    {
        var remaining = parsed.Records.ToList();
        var shares = new List<byte[]>();
        var acquired = new HashSet<string>(StringComparer.Ordinal);
        try
        {
            while (remaining.Count > 0 && shares.Count < parsed.MinimumPhysicalDevices)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var requirements = remaining.Select(record => new AnonymousPhysicalDeviceRequirement(
                    record.Lookup.ToArray(), record.Salt.ToArray())).ToArray();
                PhysicalDeviceUnlock unlock;
                try
                {
                    unlock = await provider.UnlockAnonymousAsync(
                        requirements,
                        parsed.ArchiveSalt,
                        ownerWindowHandle,
                        cancellationToken).ConfigureAwait(false);
                }
                catch (NingRanException)
                {
                    break;
                }

                var lookup = PhysicalDevicePrivacy.ComputeLookupHash(unlock.Device, parsed.ArchiveSalt);
                var record = remaining.FirstOrDefault(item => CryptographicOperations.FixedTimeEquals(item.Lookup, lookup));
                if (record is null)
                {
                    unlock.Dispose();
                    CryptographicOperations.ZeroMemory(lookup);
                    throw new NingRanException("检测到未经此文件授权的物理密匙。 ");
                }

                remaining.Remove(record);
                var lookupKey = Convert.ToHexString(record.Lookup);
                if (!acquired.Add(lookupKey))
                {
                    unlock.Dispose();
                    CryptographicOperations.ZeroMemory(lookup);
                    continue;
                }

                if (record.Forbidden)
                {
                    unlock.Dispose();
                    CryptographicOperations.ZeroMemory(lookup);
                    throw new NingRanException("检测到禁止插入的物理密匙，已拒绝解锁。 ");
                }

                var shareKey = DeriveFlexibleShareKey(unlock.Secret.Span, parsed.ArchiveSalt, lookup);
                try
                {
                    shares.Add(DecryptShare(record, shareKey));
                    unlocks.Add(unlock);
                }
                catch
                {
                    unlock.Dispose();
                    throw;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(shareKey);
                    CryptographicOperations.ZeroMemory(lookup);
                }
            }

            if (shares.Count < parsed.MinimumPhysicalDevices ||
                parsed.Records.Where(record => record.Required).Any(record =>
                    !acquired.Contains(Convert.ToHexString(record.Lookup))))
                throw new NingRanException("没有同时插入满足规则的物理密匙。 ");
            return shares;
        }
        catch
        {
            foreach (var share in shares) CryptographicOperations.ZeroMemory(share);
            throw;
        }
    }

    private static byte[] EncryptShare(
        byte[] share,
        ReadOnlySpan<byte> deviceSecret,
        ReadOnlySpan<byte> archiveSalt,
        ReadOnlySpan<byte> lookup,
        ReadOnlySpan<byte> secretSalt)
    {
        var key = DeriveFlexibleShareKey(deviceSecret, archiveSalt, lookup);
        try
        {
            var nonce = RandomNumberGenerator.GetBytes(CryptoSizes.Nonce);
            var ciphertext = new byte[share.Length];
            var tag = new byte[CryptoSizes.Tag];
            using var cipher = new ChaCha20Poly1305(key);
            cipher.Encrypt(nonce, share, ciphertext, tag, secretSalt);
            var result = new byte[12 + share.Length + tag.Length];
            nonce.CopyTo(result, 0);
            ciphertext.CopyTo(result, 12);
            tag.CopyTo(result, 12 + share.Length);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
            return result;
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    private static byte[] DecryptShare(PhysicalRecord record, ReadOnlySpan<byte> key)
    {
        var result = new byte[record.Ciphertext.Length];
        using var cipher = new ChaCha20Poly1305(key);
        try
        {
            cipher.Decrypt(record.Nonce, record.Ciphertext, record.Tag, result, record.Salt);
            return result;
        }
        catch (CryptographicException exception)
        {
            CryptographicOperations.ZeroMemory(result);
            throw new NingRanException("物理密匙凭证无法通过校验。 ", exception);
        }
    }

    private static Envelope EncryptEnvelope(ReadOnlySpan<byte> dataKey, ReadOnlySpan<byte> wrapKey)
    {
        var nonce = RandomNumberGenerator.GetBytes(CryptoSizes.Nonce);
        var ciphertext = new byte[KeyDerivation.KeySize];
        var tag = new byte[CryptoSizes.Tag];
        using var cipher = new ChaCha20Poly1305(wrapKey);
        cipher.Encrypt(nonce, dataKey, ciphertext, tag, "NRARC009-DATA-KEY"u8);
        return new Envelope(nonce, ciphertext, tag);
    }

    private static bool TryDecryptEnvelope(Envelope envelope, ReadOnlySpan<byte> wrapKey, out byte[] dataKey)
    {
        dataKey = new byte[KeyDerivation.KeySize];
        try
        {
            using var cipher = new ChaCha20Poly1305(wrapKey);
            cipher.Decrypt(envelope.Nonce, envelope.Ciphertext, envelope.Tag, dataKey, "NRARC009-DATA-KEY"u8);
            return true;
        }
        catch (CryptographicException)
        {
            CryptographicOperations.ZeroMemory(dataKey);
            dataKey = [];
            return false;
        }
    }

    private static void WriteEnvelope(Span<byte> destination, Envelope envelope)
    {
        envelope.Nonce.CopyTo(destination);
        envelope.Ciphertext.CopyTo(destination[CryptoSizes.Nonce..]);
        envelope.Tag.CopyTo(destination[(CryptoSizes.Nonce + KeyDerivation.KeySize)..]);
    }

    private static Envelope ReadEnvelope(ReadOnlySpan<byte> source) => new(
        source[..CryptoSizes.Nonce].ToArray(),
        source.Slice(CryptoSizes.Nonce, KeyDerivation.KeySize).ToArray(),
        source.Slice(CryptoSizes.Nonce + KeyDerivation.KeySize, CryptoSizes.Tag).ToArray());

    private readonly record struct Envelope(byte[] Nonce, byte[] Ciphertext, byte[] Tag);

    private sealed class PhysicalRecord
    {
        public PhysicalRecord(
            byte[] lookup,
            byte[] salt,
            byte[] encryptedShare,
            bool required,
            bool forbidden,
            byte[]? nonce = null,
            byte[]? tag = null)
        {
            Lookup = lookup;
            Salt = salt;
            Required = required;
            Forbidden = forbidden;
            Nonce = nonce ?? encryptedShare[..CryptoSizes.Nonce].ToArray();
            Ciphertext = nonce is null ? encryptedShare[CryptoSizes.Nonce..^CryptoSizes.Tag].ToArray() : encryptedShare;
            Tag = tag ?? encryptedShare[^CryptoSizes.Tag..].ToArray();
        }

        public byte[] Lookup { get; }
        public byte[] Salt { get; }
        public byte[] Nonce { get; }
        public byte[] Ciphertext { get; }
        public byte[] Tag { get; }
        public bool Required { get; }
        public bool Forbidden { get; }

        public void Clear()
        {
            CryptographicOperations.ZeroMemory(Lookup);
            CryptographicOperations.ZeroMemory(Salt);
            CryptographicOperations.ZeroMemory(Nonce);
            CryptographicOperations.ZeroMemory(Ciphertext);
            CryptographicOperations.ZeroMemory(Tag);
        }
    }

    private sealed record ParsedHeader(
        ProtectionPolicy Policy,
        KdfParameters KdfParameters,
        byte[] ArchiveSalt,
        IReadOnlyList<PhysicalRecord> Records,
        IReadOnlyList<byte[]> ForbiddenLookups,
        Envelope PrimaryEnvelope,
        Envelope? RecoveryEnvelope,
        int MinimumPhysicalDevices)
    {
        public WindowsHelloCredential? Hello => Policy.WindowsHello;
    }
}
