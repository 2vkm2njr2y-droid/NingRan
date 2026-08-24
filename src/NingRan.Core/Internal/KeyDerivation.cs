using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace NingRan.Core.Internal;

internal static class KeyDerivation
{
    public const int KeySize = 32;

    public static async Task<byte[]> DerivePasswordKeyAsync(
        SensitivePassword password,
        ReadOnlyMemory<byte> salt,
        KdfParameters parameters,
        CancellationToken cancellationToken)
    {
        parameters.ValidateForReading();
        cancellationToken.ThrowIfCancellationRequested();

        var passwordBytes = password.GetBytes().ToArray();
        using var passwordMemory = SensitiveMemoryLock.Create(passwordBytes);
        try
        {
            using var argon2 = new Argon2id(passwordBytes)
            {
                Salt = salt.ToArray(),
                MemorySize = parameters.MemoryKib,
                Iterations = parameters.Iterations,
                DegreeOfParallelism = parameters.Parallelism,
            };

            var result = await argon2.GetBytesAsync(KeySize).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    public static byte[] DeriveArchiveWrapKey(
        ReadOnlySpan<byte> passwordKey,
        ReadOnlySpan<byte> keyFileSecret,
        EncryptionMode mode,
        ReadOnlySpan<byte> salt)
    {
        byte[] input;
        string context;

        if (mode == EncryptionMode.Advanced)
        {
            if (keyFileSecret.Length != KeySize)
            {
                throw new NingRanException("高级模式需要有效的普通文件或凝然专用密匙文件。");
            }

            input = new byte[KeySize * 2];
            passwordKey.CopyTo(input);
            keyFileSecret.CopyTo(input.AsSpan(KeySize));
            context = "NINGRAN-ARCHIVE-V3-ADVANCED-WRAP";
        }
        else
        {
            input = passwordKey.ToArray();
            context = "NINGRAN-ARCHIVE-V3-STANDARD-WRAP";
        }

        try
        {
            var output = new byte[KeySize];
            HKDF.DeriveKey(
                HashAlgorithmName.SHA256,
                input,
                output,
                salt,
                Encoding.ASCII.GetBytes(context));
            return output;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
        }
    }

    public static byte[] DeriveKeyFileWrapKey(
        ReadOnlySpan<byte> passwordKey,
        ReadOnlySpan<byte> fileId)
    {
        var output = new byte[KeySize];
        HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            passwordKey,
            output,
            fileId,
            "NINGRAN-KEYFILE-V3-PORTABLE-WRAP"u8);
        return output;
    }

    public static byte[] DerivePhysicalDeviceWrapKey(
        ReadOnlySpan<byte> passwordKey,
        ReadOnlySpan<byte> deviceSecret,
        ReadOnlySpan<byte> archiveSalt,
        ReadOnlySpan<byte> deviceId)
    {
        if (passwordKey.Length != KeySize || deviceSecret.Length != KeySize)
        {
            throw new NingRanException("密码或物理设备凭证长度不正确。");
        }

        var input = new byte[KeySize * 2];
        var info = new byte["NINGRAN-ARCHIVE-V4-PHYSICAL-WRAP"u8.Length + deviceId.Length];
        try
        {
            passwordKey.CopyTo(input);
            deviceSecret.CopyTo(input.AsSpan(KeySize));
            "NINGRAN-ARCHIVE-V4-PHYSICAL-WRAP"u8.CopyTo(info);
            deviceId.CopyTo(info.AsSpan("NINGRAN-ARCHIVE-V4-PHYSICAL-WRAP"u8.Length));
            var output = new byte[KeySize];
            HKDF.DeriveKey(HashAlgorithmName.SHA256, input, output, archiveSalt, info);
            return output;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
            CryptographicOperations.ZeroMemory(info);
        }
    }
}
