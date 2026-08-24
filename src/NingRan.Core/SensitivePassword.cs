using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using NingRan.Core.Internal;

namespace NingRan.Core;

public sealed class SensitivePassword : IDisposable
{
    private const int MaximumUtf8Bytes = 4096;

    private byte[]? _utf8Bytes;
    private SensitiveMemoryLock? _memoryLock;

    private SensitivePassword(byte[] utf8Bytes)
    {
        if (utf8Bytes.Length > MaximumUtf8Bytes)
        {
            CryptographicOperations.ZeroMemory(utf8Bytes);
            throw new ArgumentException("密码过长，请控制在 4096 个英文字符以内。", nameof(utf8Bytes));
        }

        _utf8Bytes = utf8Bytes;
        _memoryLock = SensitiveMemoryLock.Create(utf8Bytes);
    }

    public bool IsEmpty => GetBytes().Length == 0;

    public static SensitivePassword FromString(string password)
    {
        ArgumentNullException.ThrowIfNull(password);
        return new SensitivePassword(Encoding.UTF8.GetBytes(password));
    }

    public static SensitivePassword FromSecureString(SecureString password)
    {
        ArgumentNullException.ThrowIfNull(password);
        var characters = new char[password.Length];
        var pointer = IntPtr.Zero;
        try
        {
            pointer = Marshal.SecureStringToGlobalAllocUnicode(password);
            if (characters.Length > 0)
            {
                Marshal.Copy(pointer, characters, 0, characters.Length);
            }

            return new SensitivePassword(Encoding.UTF8.GetBytes(characters));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(characters.AsSpan()));
            if (pointer != IntPtr.Zero)
            {
                Marshal.ZeroFreeGlobalAllocUnicode(pointer);
            }
        }
    }

    public bool FixedTimeEquals(SensitivePassword other)
    {
        ArgumentNullException.ThrowIfNull(other);
        return CryptographicOperations.FixedTimeEquals(GetBytes().Span, other.GetBytes().Span);
    }

    public void Dispose()
    {
        Interlocked.Exchange(ref _memoryLock, null)?.Dispose();
        var bytes = Interlocked.Exchange(ref _utf8Bytes, null);
        if (bytes is not null)
        {
            CryptographicOperations.ZeroMemory(bytes);
        }

        GC.SuppressFinalize(this);
    }

    internal ReadOnlyMemory<byte> GetBytes()
    {
        var bytes = _utf8Bytes;
        ObjectDisposedException.ThrowIf(bytes is null, this);
        return bytes;
    }

    internal char[] CopyCharacters()
    {
        var bytes = GetBytes();
        var characters = new char[Encoding.UTF8.GetCharCount(bytes.Span)];
        Encoding.UTF8.GetChars(bytes.Span, characters);
        return characters;
    }

    ~SensitivePassword()
    {
        Interlocked.Exchange(ref _memoryLock, null)?.Dispose();
        var bytes = _utf8Bytes;
        if (bytes is not null)
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }
}
