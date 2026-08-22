using System.Security.Cryptography;

namespace NingRan.Core;

public sealed class KeyFileSecret : IDisposable
{
    private byte[]? _bytes;

    internal KeyFileSecret(byte[] bytes)
    {
        if (bytes.Length != 32)
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw new ArgumentException("密钥长度不正确。", nameof(bytes));
        }

        _bytes = bytes;
    }

    internal ReadOnlyMemory<byte> Memory => _bytes ?? throw new ObjectDisposedException(nameof(KeyFileSecret));

    public void Dispose()
    {
        var bytes = Interlocked.Exchange(ref _bytes, null);
        if (bytes is not null)
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }
}
