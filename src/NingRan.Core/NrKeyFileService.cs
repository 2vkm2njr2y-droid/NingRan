using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using NingRan.Core.Internal;

namespace NingRan.Core;

public sealed class NrKeyFileService
{
    private static ReadOnlySpan<byte> Magic => "NRKEY004"u8;
    private static ReadOnlySpan<byte> RetiredMagic => "NRKEY003"u8;

    private const int FixedSize = 152;
    private const int IntegrityInputHeaderSize = 120;
    private const int IntegrityTagOffset = 120;
    private const int IntegrityTagSize = 32;
    private const int MaximumFileSize = 16 * 1024;
    private const int MaximumProtectedBlobSize = 8 * 1024;
    private const int ExternalKeyBufferSize = 1024 * 1024;

    private readonly KdfParameters _kdfParameters;

    public NrKeyFileService(KdfParameters? kdfParameters = null)
    {
        _kdfParameters = kdfParameters ?? KdfParameters.Production;
        _kdfParameters.ValidateForReading();
    }

    public async Task CreateAsync(
        string path,
        string password,
        CancellationToken cancellationToken = default)
    {
        using var sensitivePassword = SensitivePassword.FromString(password);
        await CreateAsync(path, sensitivePassword, cancellationToken).ConfigureAwait(false);
    }

    public async Task CreateAsync(
        string path,
        SensitivePassword password,
        CancellationToken cancellationToken = default)
    {
        PasswordRules.ValidateForCreation(password);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        var fullPath = Path.GetFullPath(path);
        if (!string.Equals(Path.GetExtension(fullPath), ".nrkey", StringComparison.OrdinalIgnoreCase))
        {
            fullPath += ".nrkey";
        }

        var directory = Path.GetDirectoryName(fullPath)
            ?? throw new NingRanException("密钥文件保存位置不正确。");
        Directory.CreateDirectory(directory);
        if (File.Exists(fullPath) || Directory.Exists(fullPath))
        {
            throw new NingRanException("保存位置已经有同名文件，请更换名称。");
        }

        var fixedBytes = new byte[FixedSize];
        Magic.CopyTo(fixedBytes);
        BinaryPrimitives.WriteUInt16LittleEndian(fixedBytes.AsSpan(8, 2), FixedSize);
        BinaryPrimitives.WriteInt32LittleEndian(fixedBytes.AsSpan(12, 4), _kdfParameters.MemoryKib);
        BinaryPrimitives.WriteInt32LittleEndian(fixedBytes.AsSpan(16, 4), _kdfParameters.Iterations);
        BinaryPrimitives.WriteInt32LittleEndian(fixedBytes.AsSpan(20, 4), _kdfParameters.Parallelism);
        RandomNumberGenerator.Fill(fixedBytes.AsSpan(24, 16));
        RandomNumberGenerator.Fill(fixedBytes.AsSpan(40, 16));
        RandomNumberGenerator.Fill(fixedBytes.AsSpan(56, 12));

        var secret = RandomNumberGenerator.GetBytes(KeyDerivation.KeySize);
        byte[]? passwordKey = null;
        byte[]? wrapKey = null;
        byte[]? protectedBlob = null;
        byte[]? localIntegrityTag = null;
        var temporaryPath = Path.Combine(directory, $".ningran-key-{Guid.NewGuid():N}.part");
        Guid? temporaryRegistration = null;
        FileStream? temporaryFile = null;
        try
        {
            passwordKey = await KeyDerivation.DerivePasswordKeyAsync(
                password,
                fixedBytes.AsMemory(40, 16),
                _kdfParameters,
                cancellationToken).ConfigureAwait(false);
            wrapKey = KeyDerivation.DeriveKeyFileWrapKey(passwordKey, fixedBytes.AsSpan(24, 16));

            using (var cipher = new ChaCha20Poly1305(wrapKey))
            {
                cipher.Encrypt(
                    fixedBytes.AsSpan(56, 12),
                    secret,
                    fixedBytes.AsSpan(68, KeyDerivation.KeySize),
                    fixedBytes.AsSpan(100, CryptoSizes.Tag),
                    fixedBytes.AsSpan(0, 68));
            }

            var entropy = CreateDpapiEntropy(fixedBytes.AsSpan(24, 16));
            try
            {
                protectedBlob = ProtectedData.Protect(secret, entropy, DataProtectionScope.CurrentUser);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(entropy);
            }

            if (protectedBlob.Length is 0 or > MaximumProtectedBlobSize)
            {
                throw new NingRanException("Windows 账户保护密钥时返回了异常数据。");
            }

            BinaryPrimitives.WriteInt32LittleEndian(fixedBytes.AsSpan(116, 4), protectedBlob.Length);
            localIntegrityTag = ComputeLocalIntegrityTag(
                secret,
                fixedBytes.AsSpan(0, IntegrityInputHeaderSize),
                protectedBlob);
            localIntegrityTag.CopyTo(fixedBytes.AsSpan(IntegrityTagOffset, IntegrityTagSize));
            temporaryFile = WindowsFileSystemSafety.CreateNewTemporaryFile(temporaryPath, 64 * 1024);
            temporaryRegistration = TemporaryFileRegistry.Register(temporaryFile, temporaryPath);
            await temporaryFile.WriteAsync(fixedBytes, cancellationToken).ConfigureAwait(false);
            await temporaryFile.WriteAsync(protectedBlob, cancellationToken).ConfigureAwait(false);
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
                throw;
            }

            throw new NingRanException(
                "密钥文件创建失败，并且临时文件未能自动删除。程序下次启动时会继续尝试清理。",
                exception);
        }
        finally
        {
            temporaryFile?.Dispose();
            CryptographicOperations.ZeroMemory(secret);
            CryptographicOperations.ZeroMemory(fixedBytes);
            if (passwordKey is not null)
            {
                CryptographicOperations.ZeroMemory(passwordKey);
            }

            if (wrapKey is not null)
            {
                CryptographicOperations.ZeroMemory(wrapKey);
            }

            if (protectedBlob is not null)
            {
                CryptographicOperations.ZeroMemory(protectedBlob);
            }

            if (localIntegrityTag is not null)
            {
                CryptographicOperations.ZeroMemory(localIntegrityTag);
            }
        }
    }

    public async Task<KeyFileSecret> UnlockAsync(
        string path,
        string password,
        CancellationToken cancellationToken = default)
    {
        using var sensitivePassword = SensitivePassword.FromString(password);
        return await UnlockAsync(path, sensitivePassword, cancellationToken).ConfigureAwait(false);
    }

    public async Task<KeyFileSecret> UnlockAsync(
        string path,
        SensitivePassword password,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var fullPath = Path.GetFullPath(path);
        byte[] bytes;
        var prefix = new byte[Magic.Length];
        try
        {
            using var handle = WindowsFileSystemSafety.OpenInputFile(fullPath);
            await using var stream = new FileStream(
                handle,
                FileAccess.Read,
                ExternalKeyBufferSize,
                isAsync: true);
            var prefixLength = await stream.ReadAtLeastAsync(
                prefix,
                prefix.Length,
                throwOnEndOfStream: false,
                cancellationToken).ConfigureAwait(false);
            stream.Position = 0;

            var isCurrentNrKey = prefixLength == Magic.Length && prefix.AsSpan().SequenceEqual(Magic);
            var isRetiredNrKey = prefixLength == RetiredMagic.Length && prefix.AsSpan().SequenceEqual(RetiredMagic);
            if (!isCurrentNrKey && !isRetiredNrKey)
            {
                return await DeriveExternalFileSecretAsync(stream, cancellationToken).ConfigureAwait(false);
            }

            if (stream.Length is < FixedSize + 1 or > MaximumFileSize)
            {
                throw new NingRanException("凝然专用密匙文件大小异常或超过安全上限。");
            }

            bytes = new byte[checked((int)stream.Length)];
            await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
        }
        catch (NingRanException)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new NingRanException("无法读取密钥文件。", exception);
        }

        try
        {
            if (bytes.AsSpan(0, RetiredMagic.Length).SequenceEqual(RetiredMagic))
            {
                throw new NingRanException("这是已经停止支持的旧版密钥文件。请使用凝然加密 5.2 重新生成密钥文件和加密文件。");
            }

            if (!bytes.AsSpan(0, Magic.Length).SequenceEqual(Magic) ||
                BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(8, 2)) != FixedSize)
            {
                throw new NingRanException("这不是凝然加密 5.2 密钥文件。");
            }

            var protectedLength = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(116, 4));
            if (protectedLength is <= 0 or > MaximumProtectedBlobSize ||
                bytes.Length != FixedSize + protectedLength)
            {
                throw new NingRanException("密钥文件格式不正确或已经损坏。");
            }

            byte[]? localSecret = null;
            var entropy = CreateDpapiEntropy(bytes.AsSpan(24, 16));
            try
            {
                try
                {
                    localSecret = ProtectedData.Unprotect(
                        bytes.AsSpan(FixedSize, protectedLength).ToArray(),
                        entropy,
                        DataProtectionScope.CurrentUser);
                    if (localSecret.Length != KeyDerivation.KeySize)
                    {
                        CryptographicOperations.ZeroMemory(localSecret);
                        localSecret = null;
                    }
                }
                catch (CryptographicException)
                {
                    // 密钥文件可能来自另一台电脑，继续使用密码恢复副本。
                }

                if (localSecret is not null)
                {
                    var localIntegrityTag = ComputeLocalIntegrityTag(
                        localSecret,
                        bytes.AsSpan(0, IntegrityInputHeaderSize),
                        bytes.AsSpan(FixedSize, protectedLength));
                    try
                    {
                        if (!CryptographicOperations.FixedTimeEquals(
                                localIntegrityTag,
                                bytes.AsSpan(IntegrityTagOffset, IntegrityTagSize)))
                        {
                            CryptographicOperations.ZeroMemory(localSecret);
                            localSecret = null;
                        }
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(localIntegrityTag);
                    }
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(entropy);
            }

            if (password.IsEmpty && localSecret is not null)
            {
                var result = localSecret;
                localSecret = null;
                return new KeyFileSecret(result);
            }

            if (password.IsEmpty)
            {
                throw new NingRanException("此密钥文件不属于当前 Windows 账户，请输入创建密钥时使用的密码。");
            }

            var kdfParameters = new KdfParameters(
                BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(12, 4)),
                BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(16, 4)),
                BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(20, 4)));
            try
            {
                kdfParameters.ValidateForReading();
            }
            catch (InvalidDataException exception)
            {
                throw new NingRanException(exception.Message, exception);
            }

            byte[]? passwordKey = null;
            byte[]? wrapKey = null;
            var portableSecret = new byte[KeyDerivation.KeySize];
            try
            {
                passwordKey = await KeyDerivation.DerivePasswordKeyAsync(
                    password,
                    bytes.AsMemory(40, 16),
                    kdfParameters,
                    cancellationToken).ConfigureAwait(false);
                wrapKey = KeyDerivation.DeriveKeyFileWrapKey(passwordKey, bytes.AsSpan(24, 16));
                using var cipher = new ChaCha20Poly1305(wrapKey);
                cipher.Decrypt(
                    bytes.AsSpan(56, 12),
                    bytes.AsSpan(68, KeyDerivation.KeySize),
                    bytes.AsSpan(100, CryptoSizes.Tag),
                    portableSecret,
                    bytes.AsSpan(0, 68));
                if (localSecret is not null &&
                    !CryptographicOperations.FixedTimeEquals(localSecret, portableSecret))
                {
                    throw new NingRanException("密钥文件中的两份恢复数据不一致，文件可能已经损坏。");
                }

                if (localSecret is not null)
                {
                    CryptographicOperations.ZeroMemory(portableSecret);
                    var result = localSecret;
                    localSecret = null;
                    return new KeyFileSecret(result);
                }

                return new KeyFileSecret(portableSecret);
            }
            catch (CryptographicException exception)
            {
                CryptographicOperations.ZeroMemory(portableSecret);
                throw new NingRanException("密钥文件密码不正确，或者密钥文件已经损坏。", exception);
            }
            catch
            {
                CryptographicOperations.ZeroMemory(portableSecret);
                throw;
            }
            finally
            {
                if (passwordKey is not null)
                {
                    CryptographicOperations.ZeroMemory(passwordKey);
                }

                if (wrapKey is not null)
                {
                    CryptographicOperations.ZeroMemory(wrapKey);
                }

                if (localSecret is not null)
                {
                    CryptographicOperations.ZeroMemory(localSecret);
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static async Task<KeyFileSecret> DeriveExternalFileSecretAsync(
        FileStream stream,
        CancellationToken cancellationToken)
    {
        var buffer = GC.AllocateUninitializedArray<byte>(ExternalKeyBufferSize);
        var lengthBytes = new byte[sizeof(long)];
        BinaryPrimitives.WriteInt64LittleEndian(lengthBytes, stream.Length);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("NINGRAN-EXTERNAL-FILE-KEY-V1\0"u8);
        hash.AppendData(lengthBytes);
        try
        {
            while (true)
            {
                var read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                hash.AppendData(buffer.AsSpan(0, read));
            }

            cancellationToken.ThrowIfCancellationRequested();
            return new KeyFileSecret(hash.GetHashAndReset());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
            CryptographicOperations.ZeroMemory(lengthBytes);
        }
    }

    private static byte[] CreateDpapiEntropy(ReadOnlySpan<byte> fileId)
    {
        var prefix = Encoding.ASCII.GetBytes("NINGRAN-KEYFILE-V3-DPAPI");
        var input = new byte[prefix.Length + fileId.Length];
        prefix.CopyTo(input, 0);
        fileId.CopyTo(input.AsSpan(prefix.Length));
        try
        {
            return SHA256.HashData(input);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
        }
    }

    private static byte[] ComputeLocalIntegrityTag(
        ReadOnlySpan<byte> secret,
        ReadOnlySpan<byte> fixedHeader,
        ReadOnlySpan<byte> protectedBlob)
    {
        var input = new byte[checked(fixedHeader.Length + protectedBlob.Length)];
        fixedHeader.CopyTo(input);
        protectedBlob.CopyTo(input.AsSpan(fixedHeader.Length));
        try
        {
            return HMACSHA256.HashData(secret, input);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
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
}
