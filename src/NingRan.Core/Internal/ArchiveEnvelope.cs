using System.Security.Cryptography;

namespace NingRan.Core.Internal;

internal static class ArchiveEnvelope
{
    public static async Task<ArchiveInfo> InspectAsync(
        Stream stream,
        CancellationToken cancellationToken,
        long archiveOffset = 0)
    {
        if (!stream.CanSeek)
        {
            throw new ArgumentException("加密文件流必须支持定位。", nameof(stream));
        }

        if (archiveOffset < 0 || archiveOffset > stream.Length - 8)
        {
            throw new NingRanException("凝然加密内容的位置不正确，文件可能已损坏。");
        }

        stream.Position = archiveOffset;
        var magic = new byte[8];
        try
        {
            await BinaryFormat.ReadExactlyAsync(stream, magic, cancellationToken).ConfigureAwait(false);
            if (ArchiveHeader.IsMagic(magic))
            {
                stream.Position = archiveOffset;
                await ArchiveHeader.InspectAsync(stream, cancellationToken).ConfigureAwait(false);
                return new ArchiveInfo(
                    EncryptionMode.Standard,
                    HidesExactSize: false,
                    HasSenderSignature: true,
                    PhysicalDevices: [],
                    FormatVersion: archiveOffset == 0 ? "6.1" : "7.0");
            }

            throw new NingRanException("此文件不是新版隐私格式，当前版本已停止支持旧格式。");
        }
        catch (EndOfStreamException exception)
        {
            throw new NingRanException("这不是完整的凝然加密文件。", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(magic);
        }
    }
}
