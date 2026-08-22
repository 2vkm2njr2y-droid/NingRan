using System.Buffers.Binary;
using System.Security.Cryptography;

namespace NingRan.Core.Internal;

internal sealed class ChunkedAeadReadStream : Stream
{
    private readonly Stream _input;
    private readonly ChaCha20Poly1305 _cipher;
    private readonly byte[] _noncePrefix;
    private readonly byte[] _headerHash;
    private readonly byte[] _plainBuffer = new byte[ChunkedAeadWriteStream.ChunkSize];
    private readonly byte[] _cipherBuffer = new byte[ChunkedAeadWriteStream.ChunkSize];
    private readonly bool _leaveOpen;
    private int _bufferLength;
    private int _bufferOffset;
    private ulong _chunkIndex;
    private bool _finalChunkSeen;
    private bool _disposed;

    public ChunkedAeadReadStream(
        Stream input,
        ReadOnlySpan<byte> dataKey,
        ReadOnlySpan<byte> noncePrefix,
        ReadOnlySpan<byte> headerHash,
        bool leaveOpen = false)
    {
        if (dataKey.Length != CryptoSizes.Key || noncePrefix.Length != 4 || headerHash.Length != 32)
        {
            throw new ArgumentException("解密流参数不正确。");
        }

        _input = input;
        _cipher = new ChaCha20Poly1305(dataKey);
        _noncePrefix = noncePrefix.ToArray();
        _headerHash = headerHash.ToArray();
        _leaveOpen = leaveOpen;
    }

    public override bool CanRead => !_disposed;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count) =>
        ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override async ValueTask<int> ReadAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (buffer.IsEmpty)
        {
            return 0;
        }

        if (_bufferOffset == _bufferLength)
        {
            if (_finalChunkSeen)
            {
                return 0;
            }

            await ReadNextChunkAsync(cancellationToken).ConfigureAwait(false);
            if (_bufferLength == 0 && _finalChunkSeen)
            {
                return 0;
            }
        }

        var count = Math.Min(buffer.Length, _bufferLength - _bufferOffset);
        _plainBuffer.AsMemory(_bufferOffset, count).CopyTo(buffer);
        _bufferOffset += count;
        return count;
    }

    private async Task ReadNextChunkAsync(CancellationToken cancellationToken)
    {
        if (_chunkIndex == ulong.MaxValue)
        {
            throw new NingRanException("加密文件的分块数量异常。");
        }

        var recordHeader = new byte[5];
        try
        {
            await BinaryFormat.ReadExactlyAsync(_input, recordHeader, cancellationToken).ConfigureAwait(false);
        }
        catch (EndOfStreamException exception)
        {
            throw new NingRanException("加密文件被截断，缺少结束标记。", exception);
        }

        var length = BinaryPrimitives.ReadUInt32LittleEndian(recordHeader.AsSpan(0, 4));
        var flags = recordHeader[4];
        if (length > ChunkedAeadWriteStream.ChunkSize || (flags & ~1) != 0 ||
            ((flags & 1) == 0 && length != ChunkedAeadWriteStream.ChunkSize))
        {
            throw new NingRanException("加密文件的分块格式不正确或已损坏。");
        }

        try
        {
            await BinaryFormat.ReadExactlyAsync(
                _input,
                _cipherBuffer.AsMemory(0, checked((int)length)),
                cancellationToken).ConfigureAwait(false);
            var tag = new byte[CryptoSizes.Tag];
            await BinaryFormat.ReadExactlyAsync(_input, tag, cancellationToken).ConfigureAwait(false);

            Span<byte> nonce = stackalloc byte[CryptoSizes.Nonce];
            _noncePrefix.CopyTo(nonce);
            BinaryPrimitives.WriteUInt64LittleEndian(nonce[4..], _chunkIndex);

            Span<byte> associatedData = stackalloc byte[45];
            _headerHash.CopyTo(associatedData);
            BinaryPrimitives.WriteUInt64LittleEndian(associatedData[32..40], _chunkIndex);
            BinaryPrimitives.WriteUInt32LittleEndian(associatedData[40..44], length);
            associatedData[44] = flags;

            _cipher.Decrypt(
                nonce,
                _cipherBuffer.AsSpan(0, checked((int)length)),
                tag,
                _plainBuffer.AsSpan(0, checked((int)length)),
                associatedData);

            _bufferLength = checked((int)length);
            _bufferOffset = 0;
            _finalChunkSeen = (flags & 1) != 0;
            _chunkIndex++;

            if (_finalChunkSeen)
            {
                var trailing = new byte[1];
                if (await _input.ReadAsync(trailing, cancellationToken).ConfigureAwait(false) != 0)
                {
                    throw new NingRanException("加密文件结束位置之后还有异常数据。");
                }
            }
        }
        catch (CryptographicException exception)
        {
            throw new NingRanException("加密内容未通过完整性检查，文件可能已被修改或损坏。", exception);
        }
        catch (EndOfStreamException exception)
        {
            throw new NingRanException("加密文件不完整。", exception);
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (_disposed)
        {
            return;
        }

        if (disposing)
        {
            _cipher.Dispose();
            CryptographicOperations.ZeroMemory(_plainBuffer);
            CryptographicOperations.ZeroMemory(_cipherBuffer);
            CryptographicOperations.ZeroMemory(_headerHash);
            CryptographicOperations.ZeroMemory(_noncePrefix);
            if (!_leaveOpen)
            {
                _input.Dispose();
            }
        }

        _disposed = true;
        base.Dispose(disposing);
    }

    public override void Flush() => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
