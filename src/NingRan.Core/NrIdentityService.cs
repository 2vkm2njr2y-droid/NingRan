using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using NingRan.Core.Internal;

namespace NingRan.Core;

public sealed class NrIdentityService
{
    private static ReadOnlySpan<byte> PrivateMagic => "NRID0002"u8;
    private static ReadOnlySpan<byte> PublicMagic => "NRPUB002"u8;

    private const int PrivateFixedHeaderSize = 60;
    private const int MaximumPrivateFileSize = 16 * 1024;
    private const int MaximumPublicFileSize = 4 * 1024;
    private const int MaximumNameBytes = 256;
    private const int MaximumPublicKeyBytes = 1024;
    private const int MaximumPrivateKeyBytes = 8 * 1024;
    private const int PublicSignatureSize = 64;
    private const int MaximumLocalIdentities = 1_000;
    private const int VerificationCodeLength = 7;

    private readonly KdfParameters _kdfParameters;

    public NrIdentityService(KdfParameters? kdfParameters = null)
    {
        _kdfParameters = kdfParameters ?? KdfParameters.Production;
        _kdfParameters.ValidateForReading();
    }

    public IReadOnlyList<IdentitySummary> ListLocalIdentities()
    {
        var directory = EnsureIdentityDirectory();
        var identities = new List<IdentitySummary>();
        var paths = Directory.EnumerateFiles(directory, "*.nrid")
            .Take(MaximumLocalIdentities + 1)
            .ToArray();
        if (paths.Length > MaximumLocalIdentities)
        {
            throw new NingRanException("本机发送者身份数量超过 1000 个安全上限。");
        }

        foreach (var path in paths)
        {
            byte[]? bytes = null;
            try
            {
                bytes = BoundedFileReader.ReadAllBytes(path, MaximumPrivateFileSize, "私密身份文件");
                using var metadata = ReadPrivateMetadata(bytes);
                var identityId = GetOrMigrateStoredIdentityId(path, metadata.Fingerprint);
                identities.Add(new IdentitySummary(identityId, metadata.Name));
            }
            catch
            {
                // 单个损坏的本地身份不应阻止其他身份显示；使用时仍会完整验证。
            }
            finally
            {
                if (bytes is not null)
                {
                    CryptographicOperations.ZeroMemory(bytes);
                }
            }
        }

        return identities
            .OrderBy(identity => identity.Name, StringComparer.CurrentCultureIgnoreCase)
            .ThenBy(identity => identity.Id, StringComparer.Ordinal)
            .ToArray();
    }

    public async Task<IdentityCreationResult> CreateAsync(
        string name,
        string password,
        CancellationToken cancellationToken = default)
    {
        using var sensitivePassword = SensitivePassword.FromString(password);
        return await CreateAsync(name, sensitivePassword, cancellationToken).ConfigureAwait(false);
    }

    public async Task<IdentityCreationResult> CreateAsync(
        string name,
        SensitivePassword password,
        CancellationToken cancellationToken = default)
    {
        var normalizedName = ValidateIdentityName(name);
        PasswordRules.ValidateForCreation(password);
        using var identity = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = Array.Empty<byte>();
        var privateKey = Array.Empty<byte>();
        var publicContent = Array.Empty<byte>();
        var publicHash = Array.Empty<byte>();
        var publicSignature = Array.Empty<byte>();
        byte[]? privateFile = null;
        try
        {
            publicKey = identity.ExportSubjectPublicKeyInfo();
            privateKey = identity.ExportPkcs8PrivateKey();
            publicContent = CreatePublicContent(normalizedName, publicKey);
            publicHash = SHA256.HashData(publicContent);
            publicSignature = identity.SignHash(
                publicHash,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            privateFile = await CreatePrivateFileAsync(
                normalizedName,
                publicKey,
                publicSignature,
                privateKey,
                password,
                cancellationToken).ConfigureAwait(false);
            var fingerprint = ComputeFingerprint(publicKey);
            var identityDirectory = EnsureIdentityDirectory();
            var identityId = CreateRandomRecordId();
            var storePath = Path.Combine(identityDirectory, identityId + ".nrid");

            var createdPaths = new List<string>();
            try
            {
                await WriteNewFileSafelyAsync(storePath, privateFile, cancellationToken).ConfigureAwait(false);
                createdPaths.Add(storePath);
                var summary = new IdentitySummary(identityId, normalizedName);
                return new IdentityCreationResult(summary);
            }
            catch (Exception exception)
            {
                var cleanupFailed = createdPaths.Any(path => !TryDeleteFile(path));
                if (cleanupFailed)
                {
                    throw new NingRanException(
                        "身份创建失败，并且部分临时身份文件未能自动删除。请关闭程序后重试清理。",
                        exception);
                }

                throw;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKey);
            CryptographicOperations.ZeroMemory(privateKey);
            CryptographicOperations.ZeroMemory(publicContent);
            CryptographicOperations.ZeroMemory(publicHash);
            CryptographicOperations.ZeroMemory(publicSignature);
            if (privateFile is not null)
            {
                CryptographicOperations.ZeroMemory(privateFile);
            }
        }
    }

    public async Task<IdentitySummary> ImportAsync(
        string backupPath,
        string password,
        CancellationToken cancellationToken = default)
    {
        using var sensitivePassword = SensitivePassword.FromString(password);
        return await ImportAsync(backupPath, sensitivePassword, cancellationToken).ConfigureAwait(false);
    }

    public async Task<IdentitySummary> ImportAsync(
        string backupPath,
        SensitivePassword password,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(backupPath);
        var bytes = await ReadPrivateFileAsync(backupPath, cancellationToken).ConfigureAwait(false);
        try
        {
            using var unlocked = await UnlockBytesAsync(bytes, password, cancellationToken).ConfigureAwait(false);
            var existing = FindLocalIdentityByFingerprint(unlocked.Fingerprint);
            if (existing is not null)
            {
                return existing;
            }

            var identityId = CreateRandomRecordId();
            var storePath = Path.Combine(EnsureIdentityDirectory(), identityId + ".nrid");
            await WriteNewFileSafelyAsync(storePath, bytes, cancellationToken).ConfigureAwait(false);
            return new IdentitySummary(identityId, unlocked.Name);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    public async Task ExportPublicIdentityAsync(
        string identityId,
        string outputPath,
        CancellationToken cancellationToken = default)
    {
        var bytes = await ReadStoredPrivateFileAsync(identityId, cancellationToken).ConfigureAwait(false);
        try
        {
            using var metadata = ReadPrivateMetadata(bytes);
            var publicContent = CreatePublicContent(metadata.Name, metadata.PublicKey);
            var publicFile = CreatePublicFile(publicContent, metadata.PublicSignature);
            try
            {
                await WriteNewFileSafelyAsync(outputPath, publicFile, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(publicContent);
                CryptographicOperations.ZeroMemory(publicFile);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    public async Task ExportPrivateIdentityBackupAsync(
        string identityId,
        string outputPath,
        SensitivePassword password,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(outputPath);
        var bytes = await ReadStoredPrivateFileAsync(identityId, cancellationToken).ConfigureAwait(false);
        try
        {
            using var unlocked = await UnlockBytesAsync(bytes, password, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            await WriteNewFileSafelyAsync(outputPath, bytes, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    public PublicIdentityInfo ReadPublicIdentityInfo(string path)
    {
        using var identity = ReadPublicIdentity(path);
        return new PublicIdentityInfo(identity.Name, CreateVerificationCode(identity.Fingerprint));
    }

    public async Task DeleteLocalIdentityAsync(
        string identityId,
        SensitivePassword password,
        CancellationToken cancellationToken = default)
    {
        var path = GetStoredIdentityPath(identityId);
        using var identityHandle = WindowsFileSystemSafety.OpenInputFile(path);
        var expectedIdentity = WindowsFileSystemSafety.GetIdentity(identityHandle);
        identityHandle.Dispose();

        var bytes = await ReadPrivateFileAsync(path, cancellationToken).ConfigureAwait(false);
        try
        {
            using var unlocked = await UnlockBytesAsync(bytes, password, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            WindowsFileSystemSafety.DeleteVerifiedFile(path, expectedIdentity);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    internal async Task<SigningIdentity> UnlockLocalIdentityAsync(
        string identityId,
        SensitivePassword password,
        CancellationToken cancellationToken)
    {
        var bytes = await ReadStoredPrivateFileAsync(identityId, cancellationToken).ConfigureAwait(false);
        try
        {
            return await UnlockBytesAsync(bytes, password, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    internal PublicSigningIdentity ReadPublicIdentity(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        byte[] bytes;
        try
        {
            var fullPath = Path.GetFullPath(path);
            using var handle = WindowsFileSystemSafety.OpenInputFile(fullPath);
            using var stream = new FileStream(handle, FileAccess.Read);
            if (stream.Length is <= 0 or > MaximumPublicFileSize)
            {
                throw new NingRanException("发送者公开身份文件大小不正确。");
            }

            bytes = new byte[checked((int)stream.Length)];
            stream.ReadExactly(bytes);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new NingRanException("无法读取发送者公开身份文件。", exception);
        }

        try
        {
            return ReadPublicIdentityBytes(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    internal PublicSigningIdentity ReadPublicIdentityBytes(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < PublicMagic.Length + sizeof(ushort) * 2 + PublicSignatureSize ||
            bytes.Length > MaximumPublicFileSize ||
            !bytes[..PublicMagic.Length].SequenceEqual(PublicMagic))
        {
            throw new NingRanException("这不是有效的凝然发送者公开身份文件。");
        }

        var nameLength = BinaryPrimitives.ReadUInt16LittleEndian(bytes.Slice(8, 2));
        var publicKeyLength = BinaryPrimitives.ReadUInt16LittleEndian(bytes.Slice(10, 2));
        var contentLength = checked(12 + nameLength + publicKeyLength);
        if (nameLength is 0 or > MaximumNameBytes ||
            publicKeyLength is 0 or > MaximumPublicKeyBytes ||
            bytes.Length != contentLength + PublicSignatureSize)
        {
            throw new NingRanException("发送者公开身份文件格式不正确或已损坏。");
        }

        var name = DecodeName(bytes.Slice(12, nameLength));
        var publicKey = bytes.Slice(12 + nameLength, publicKeyLength).ToArray();
        try
        {
            var key = ECDsa.Create();
            try
            {
                key.ImportSubjectPublicKeyInfo(publicKey, out var read);
                if (read != publicKey.Length || key.KeySize != 256)
                {
                    throw new CryptographicException("公开身份算法不正确。");
                }

                var hash = SHA256.HashData(bytes[..contentLength]);
                try
                {
                    if (!key.VerifyHash(
                            hash,
                            bytes.Slice(contentLength, PublicSignatureSize),
                            DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                    {
                        throw new CryptographicException("公开身份名称或验证数据已被修改。");
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(hash);
                }

                var fingerprint = ComputeFingerprint(publicKey);
                return new PublicSigningIdentity(name, fingerprint, key);
            }
            catch
            {
                key.Dispose();
                throw;
            }
        }
        catch (CryptographicException exception)
        {
            throw new NingRanException("发送者公开身份文件中的验证数据不正确。", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKey);
        }
    }

    internal static string CreateVerificationCode(string fingerprint)
    {
        byte[] bytes;
        try
        {
            bytes = Convert.FromHexString(fingerprint);
        }
        catch (FormatException exception)
        {
            throw new NingRanException("身份核对信息不正确。", exception);
        }

        if (bytes.Length != 32)
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw new NingRanException("身份核对信息长度不正确。");
        }

        try
        {
            Span<char> code = stackalloc char[VerificationCodeLength];
            var uppercaseMask = bytes[VerificationCodeLength] & 0x7F;
            if (uppercaseMask == 0)
            {
                uppercaseMask = 1;
            }
            else if (uppercaseMask == 0x7F)
            {
                uppercaseMask = 0x7E;
            }

            for (var index = 0; index < code.Length; index++)
            {
                var letter = (char)('a' + (bytes[index] % 26));
                code[index] = (uppercaseMask & (1 << index)) != 0
                    ? char.ToUpperInvariant(letter)
                    : letter;
            }

            return new string(code);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private async Task<byte[]> CreatePrivateFileAsync(
        string name,
        byte[] publicKey,
        byte[] publicSignature,
        byte[] privateKey,
        SensitivePassword password,
        CancellationToken cancellationToken)
    {
        var nameBytes = Encoding.UTF8.GetBytes(name);
        if (publicSignature.Length != PublicSignatureSize)
        {
            throw new NingRanException("发送者公开身份签名长度不正确。");
        }

        var headerSize = checked(
            PrivateFixedHeaderSize + nameBytes.Length + publicKey.Length + publicSignature.Length);
        var file = new byte[checked(headerSize + privateKey.Length + CryptoSizes.Tag)];
        PrivateMagic.CopyTo(file);
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(8, 2), checked((ushort)headerSize));
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(10, 2), PublicSignatureSize);
        BinaryPrimitives.WriteInt32LittleEndian(file.AsSpan(12, 4), _kdfParameters.MemoryKib);
        BinaryPrimitives.WriteInt32LittleEndian(file.AsSpan(16, 4), _kdfParameters.Iterations);
        BinaryPrimitives.WriteInt32LittleEndian(file.AsSpan(20, 4), _kdfParameters.Parallelism);
        RandomNumberGenerator.Fill(file.AsSpan(24, 16));
        RandomNumberGenerator.Fill(file.AsSpan(40, 12));
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(52, 2), checked((ushort)nameBytes.Length));
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(54, 2), checked((ushort)publicKey.Length));
        BinaryPrimitives.WriteInt32LittleEndian(file.AsSpan(56, 4), privateKey.Length);
        nameBytes.CopyTo(file.AsSpan(PrivateFixedHeaderSize));
        publicKey.CopyTo(file.AsSpan(PrivateFixedHeaderSize + nameBytes.Length));
        publicSignature.CopyTo(file.AsSpan(PrivateFixedHeaderSize + nameBytes.Length + publicKey.Length));

        byte[]? passwordKey = null;
        byte[]? wrapKey = null;
        try
        {
            passwordKey = await KeyDerivation.DerivePasswordKeyAsync(
                password,
                file.AsMemory(24, 16),
                _kdfParameters,
                cancellationToken).ConfigureAwait(false);
            wrapKey = DeriveIdentityWrapKey(passwordKey, file.AsSpan(24, 16));
            using var cipher = new ChaCha20Poly1305(wrapKey);
            cipher.Encrypt(
                file.AsSpan(40, 12),
                privateKey,
                file.AsSpan(headerSize, privateKey.Length),
                file.AsSpan(headerSize + privateKey.Length, CryptoSizes.Tag),
                file.AsSpan(0, headerSize));
            return file;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(file);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nameBytes);
            if (passwordKey is not null)
            {
                CryptographicOperations.ZeroMemory(passwordKey);
            }

            if (wrapKey is not null)
            {
                CryptographicOperations.ZeroMemory(wrapKey);
            }
        }
    }

    private async Task<SigningIdentity> UnlockBytesAsync(
        byte[] bytes,
        SensitivePassword password,
        CancellationToken cancellationToken)
    {
        if (password.IsEmpty)
        {
            throw new NingRanException("请输入发送者身份密码。");
        }

        using var metadata = ReadPrivateMetadata(bytes);
        var parameters = new KdfParameters(
            BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(12, 4)),
            BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(16, 4)),
            BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(20, 4)));
        try
        {
            parameters.ValidateForReading();
        }
        catch (InvalidDataException exception)
        {
            throw new NingRanException(exception.Message, exception);
        }

        var headerSize = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(8, 2));
        var privateLength = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(56, 4));
        var privateKey = new byte[privateLength];
        byte[]? passwordKey = null;
        byte[]? wrapKey = null;
        try
        {
            passwordKey = await KeyDerivation.DerivePasswordKeyAsync(
                password,
                bytes.AsMemory(24, 16),
                parameters,
                cancellationToken).ConfigureAwait(false);
            wrapKey = DeriveIdentityWrapKey(passwordKey, bytes.AsSpan(24, 16));
            using (var cipher = new ChaCha20Poly1305(wrapKey))
            {
                cipher.Decrypt(
                    bytes.AsSpan(40, 12),
                    bytes.AsSpan(headerSize, privateLength),
                    bytes.AsSpan(headerSize + privateLength, CryptoSizes.Tag),
                    privateKey,
                    bytes.AsSpan(0, headerSize));
            }

            var key = ECDsa.Create();
            try
            {
                key.ImportPkcs8PrivateKey(privateKey, out var read);
                if (read != privateKey.Length || key.KeySize != 256)
                {
                    throw new CryptographicException("私密身份算法不正确。");
                }

                var exportedPublic = key.ExportSubjectPublicKeyInfo();
                try
                {
                    if (!exportedPublic.AsSpan().SequenceEqual(metadata.PublicKey))
                    {
                        throw new CryptographicException("私密身份与公开身份不匹配。");
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(exportedPublic);
                }

                return new SigningIdentity(metadata.Name, metadata.Fingerprint, key);
            }
            catch
            {
                key.Dispose();
                throw;
            }
        }
        catch (CryptographicException exception)
        {
            throw new NingRanException("发送者身份密码不正确，或者身份文件已经损坏。", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
            if (passwordKey is not null)
            {
                CryptographicOperations.ZeroMemory(passwordKey);
            }

            if (wrapKey is not null)
            {
                CryptographicOperations.ZeroMemory(wrapKey);
            }
        }
    }

    private static PrivateIdentityMetadata ReadPrivateMetadata(byte[] bytes)
    {
        if (bytes.Length < PrivateFixedHeaderSize + 1 + CryptoSizes.Tag ||
            bytes.Length > MaximumPrivateFileSize ||
            !bytes.AsSpan(0, PrivateMagic.Length).SequenceEqual(PrivateMagic))
        {
            throw new NingRanException("这不是有效的凝然私密身份文件。");
        }

        var headerSize = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(8, 2));
        var publicSignatureLength = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(10, 2));
        var nameLength = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(52, 2));
        var publicKeyLength = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(54, 2));
        var privateKeyLength = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(56, 4));
        if (nameLength is 0 or > MaximumNameBytes ||
            publicKeyLength is 0 or > MaximumPublicKeyBytes ||
            publicSignatureLength != PublicSignatureSize ||
            privateKeyLength is <= 0 or > MaximumPrivateKeyBytes ||
            headerSize != PrivateFixedHeaderSize + nameLength + publicKeyLength + publicSignatureLength ||
            bytes.Length != headerSize + privateKeyLength + CryptoSizes.Tag)
        {
            throw new NingRanException("私密身份文件格式不正确或已损坏。");
        }

        var name = DecodeName(bytes.AsSpan(PrivateFixedHeaderSize, nameLength));
        var publicKey = bytes.AsSpan(PrivateFixedHeaderSize + nameLength, publicKeyLength).ToArray();
        var publicSignature = bytes.AsSpan(
            PrivateFixedHeaderSize + nameLength + publicKeyLength,
            publicSignatureLength).ToArray();
        try
        {
            var fingerprint = ComputeFingerprint(publicKey);
            VerifyPublicMetadata(name, publicKey, publicSignature);
            return new PrivateIdentityMetadata(name, fingerprint, publicKey, publicSignature);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(publicKey);
            CryptographicOperations.ZeroMemory(publicSignature);
            throw;
        }
    }

    private static byte[] CreatePublicContent(string name, byte[] publicKey)
    {
        var nameBytes = Encoding.UTF8.GetBytes(name);
        var contentLength = checked(12 + nameBytes.Length + publicKey.Length);
        var bytes = new byte[contentLength];
        PublicMagic.CopyTo(bytes);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(8, 2), checked((ushort)nameBytes.Length));
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(10, 2), checked((ushort)publicKey.Length));
        nameBytes.CopyTo(bytes.AsSpan(12));
        publicKey.CopyTo(bytes.AsSpan(12 + nameBytes.Length));
        CryptographicOperations.ZeroMemory(nameBytes);
        return bytes;
    }

    private static byte[] CreatePublicFile(byte[] content, byte[] signature)
    {
        if (signature.Length != PublicSignatureSize)
        {
            throw new NingRanException("发送者公开身份签名长度不正确。");
        }

        var bytes = new byte[checked(content.Length + signature.Length)];
        content.CopyTo(bytes, 0);
        signature.CopyTo(bytes, content.Length);
        return bytes;
    }

    private static void VerifyPublicMetadata(string name, byte[] publicKey, byte[] signature)
    {
        var content = CreatePublicContent(name, publicKey);
        var hash = SHA256.HashData(content);
        try
        {
            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(publicKey, out var read);
            if (read != publicKey.Length || key.KeySize != 256 ||
                !key.VerifyHash(
                    hash,
                    signature,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            {
                throw new NingRanException("发送者身份名称或公开验证数据已经损坏。");
            }
        }
        catch (CryptographicException exception)
        {
            throw new NingRanException("发送者身份公开验证数据不正确。", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(content);
            CryptographicOperations.ZeroMemory(hash);
        }
    }

    private static byte[] DeriveIdentityWrapKey(ReadOnlySpan<byte> passwordKey, ReadOnlySpan<byte> salt)
    {
        var key = new byte[KeyDerivation.KeySize];
        HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            passwordKey,
            key,
            salt,
            "NINGRAN-IDENTITY-V1-PRIVATE-WRAP"u8);
        return key;
    }

    private static string ValidateIdentityName(string name)
    {
        string normalized;
        try
        {
            normalized = (name ?? string.Empty).Normalize(NormalizationForm.FormKC).Trim();
        }
        catch (ArgumentException exception)
        {
            throw new NingRanException("身份名称包含无效文字。", exception);
        }

        var bytes = Encoding.UTF8.GetByteCount(normalized);
        if (bytes is 0 or > MaximumNameBytes || normalized.Any(character =>
                char.IsControl(character) ||
                char.GetUnicodeCategory(character) is UnicodeCategory.Format or
                    UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator or
                    UnicodeCategory.Surrogate))
        {
            throw new NingRanException(
                "身份名称不能为空，不能包含隐藏文字、方向控制符或控制字符，且长度不能超过 256 字节。");
        }

        return normalized;
    }

    private static string DecodeName(ReadOnlySpan<byte> bytes)
    {
        try
        {
            return ValidateIdentityName(new UTF8Encoding(false, true).GetString(bytes));
        }
        catch (DecoderFallbackException exception)
        {
            throw new NingRanException("身份名称编码不正确或已损坏。", exception);
        }
    }

    private static string ComputeFingerprint(ReadOnlySpan<byte> publicKey)
    {
        var hash = SHA256.HashData(publicKey);
        try
        {
            return Convert.ToHexString(hash);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hash);
        }
    }

    private IdentitySummary? FindLocalIdentityByFingerprint(string fingerprint)
    {
        foreach (var path in Directory.EnumerateFiles(EnsureIdentityDirectory(), "*.nrid")
                     .Take(MaximumLocalIdentities + 1))
        {
            byte[]? bytes = null;
            try
            {
                bytes = BoundedFileReader.ReadAllBytes(path, MaximumPrivateFileSize, "私密身份文件");
                using var metadata = ReadPrivateMetadata(bytes);
                if (string.Equals(metadata.Fingerprint, fingerprint, StringComparison.OrdinalIgnoreCase))
                {
                    return new IdentitySummary(
                        GetOrMigrateStoredIdentityId(path, metadata.Fingerprint),
                        metadata.Name);
                }
            }
            catch
            {
                // 损坏记录不会被当成相同身份。
            }
            finally
            {
                if (bytes is not null)
                {
                    CryptographicOperations.ZeroMemory(bytes);
                }
            }
        }

        return null;
    }

    private static string GetOrMigrateStoredIdentityId(string path, string fingerprint)
    {
        var fileId = Path.GetFileNameWithoutExtension(path);
        if (IsRandomRecordId(fileId))
        {
            return fileId.ToLowerInvariant();
        }

        if (!IsLegacyFingerprint(fileId) ||
            !string.Equals(fileId, fingerprint, StringComparison.OrdinalIgnoreCase))
        {
            throw new NingRanException("本机身份记录名称不正确，已停止使用该记录。");
        }

        var identityId = CreateRandomRecordId();
        var migratedPath = Path.Combine(Path.GetDirectoryName(path)!, identityId + ".nrid");
        File.Move(path, migratedPath);
        return identityId;
    }

    private static string CreateRandomRecordId() => Guid.NewGuid().ToString("N");

    private static bool IsRandomRecordId(string value) =>
        value.Length == 32 && value.All(Uri.IsHexDigit);

    private static bool IsLegacyFingerprint(string value) =>
        value.Length == 64 && value.All(Uri.IsHexDigit);

    private static string EnsureIdentityDirectory()
    {
        WindowsFileSystemSafety.ThrowIfProcessIsElevated();

        var parent = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "NingRan");
        Directory.CreateDirectory(parent);
        var directory = Path.Combine(parent, "Identities");
        if (!Directory.Exists(directory))
        {
            WindowsFileSystemSafety.CreatePrivateDirectory(directory);
        }
        else
        {
            WindowsFileSystemSafety.SecureExistingPrivateDirectory(directory);
        }

        return directory;
    }

    private static async Task<byte[]> ReadPrivateFileAsync(string path, CancellationToken cancellationToken)
    {
        try
        {
            var fullPath = Path.GetFullPath(path);
            if (!File.Exists(fullPath))
            {
                throw new NingRanException("请选择有效的凝然身份备份文件。");
            }

            using var handle = WindowsFileSystemSafety.OpenInputFile(fullPath);
            await using var stream = new FileStream(handle, FileAccess.Read, 16 * 1024, isAsync: true);
            if (stream.Length is <= 0 or > MaximumPrivateFileSize)
            {
                throw new NingRanException("请选择有效的凝然身份备份文件。");
            }

            var bytes = new byte[checked((int)stream.Length)];
            await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
            return bytes;
        }
        catch (NingRanException)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new NingRanException("无法读取凝然身份备份文件。", exception);
        }
    }

    private static Task<byte[]> ReadStoredPrivateFileAsync(string identityId, CancellationToken cancellationToken)
    {
        return ReadPrivateFileAsync(GetStoredIdentityPath(identityId), cancellationToken);
    }

    private static string GetStoredIdentityPath(string identityId)
    {
        if (!IsRandomRecordId(identityId))
        {
            throw new NingRanException("所选发送者身份不正确，请重新选择。");
        }

        return Path.Combine(EnsureIdentityDirectory(), identityId.ToLowerInvariant() + ".nrid");
    }

    private static async Task WriteNewFileSafelyAsync(
        string path,
        ReadOnlyMemory<byte> bytes,
        CancellationToken cancellationToken)
    {
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath)
            ?? throw new NingRanException("身份文件保存位置不正确。");
        Directory.CreateDirectory(directory);
        if (File.Exists(fullPath) || Directory.Exists(fullPath))
        {
            throw new NingRanException("身份文件保存位置已经存在同名内容。");
        }

        var temporaryPath = Path.Combine(directory, $".ningran-identity-{Guid.NewGuid():N}.part");
        Guid? temporaryRegistration = null;
        FileStream? temporaryFile = null;
        try
        {
            temporaryFile = WindowsFileSystemSafety.CreateNewTemporaryFile(temporaryPath, 64 * 1024);
            temporaryRegistration = TemporaryFileRegistry.Register(temporaryFile, temporaryPath);
            await temporaryFile.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
            await temporaryFile.FlushAsync(cancellationToken).ConfigureAwait(false);
            temporaryFile.Flush(flushToDisk: true);
            WindowsFileSystemSafety.RenameOpenFile(temporaryFile.SafeFileHandle, temporaryPath, fullPath);
            TemporaryFileRegistry.Unregister(temporaryRegistration);
            temporaryFile.Dispose();
            temporaryFile = null;
        }
        catch (Exception exception)
        {
            var cleaned = false;
            if (temporaryFile is not null)
            {
                try
                {
                    WindowsFileSystemSafety.DeleteOpenFile(temporaryFile.SafeFileHandle, temporaryPath);
                }
                catch
                {
                    // 关闭句柄后继续使用安全恢复登记。
                }

                temporaryFile.Dispose();
                temporaryFile = null;
                cleaned = !File.Exists(temporaryPath);
            }

            if (cleaned || TryDeleteFile(temporaryPath))
            {
                TemporaryFileRegistry.Unregister(temporaryRegistration);
            }
            else
            {
                throw new NingRanException(
                    "身份文件保存失败，并且临时文件未能自动删除。请关闭程序后重试清理。",
                    exception);
            }

            throw;
        }
        finally
        {
            temporaryFile?.Dispose();
        }
    }

    private static bool TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }

            return !File.Exists(path);
        }
        catch
        {
            return false;
        }
    }

    private sealed class PrivateIdentityMetadata(
        string name,
        string fingerprint,
        byte[] publicKey,
        byte[] publicSignature) : IDisposable
    {
        public string Name { get; } = name;

        public string Fingerprint { get; } = fingerprint;

        public byte[] PublicKey { get; } = publicKey;

        public byte[] PublicSignature { get; } = publicSignature;

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(PublicKey);
            CryptographicOperations.ZeroMemory(PublicSignature);
        }
    }
}

internal sealed class SigningIdentity(string name, string fingerprint, ECDsa key) : IDisposable
{
    public string Name { get; } = name;

    public string Fingerprint { get; } = fingerprint;

    public ECDsa Key { get; } = key;

    public PublicSigningIdentity CreatePublicIdentity()
    {
        var publicKey = Key.ExportSubjectPublicKeyInfo();
        try
        {
            var publicIdentityKey = ECDsa.Create();
            try
            {
                publicIdentityKey.ImportSubjectPublicKeyInfo(publicKey, out var read);
                if (read != publicKey.Length)
                {
                    throw new CryptographicException("无法导出发送者公开身份。");
                }

                return new PublicSigningIdentity(Name, Fingerprint, publicIdentityKey);
            }
            catch
            {
                publicIdentityKey.Dispose();
                throw;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKey);
        }
    }

    public void Dispose() => Key.Dispose();
}

internal sealed class PublicSigningIdentity(string name, string fingerprint, ECDsa key) : IDisposable
{
    public string Name { get; } = name;

    public string Fingerprint { get; } = fingerprint;

    public ECDsa Key { get; } = key;

    public void Dispose() => Key.Dispose();
}
