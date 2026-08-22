using System.Buffers.Binary;
using System.Security.Cryptography;

namespace NingRan.Core.Internal;

internal sealed class ChunkedAeadWriteStream : Stream
{
    public const int ChunkSize = 1024 * 1024;

    private readonly Stream _output;
    private readonly ChaCha20Poly1305 _cipher;
    private readonly byte[] _noncePrefix;
    private readonly byte[] _headerHash;
    private readonly byte[] _plainBuffer = new byte[ChunkSize];
    private readonly byte[] _cipherBuffer = new byte[ChunkSize];
    private readonly bool _leaveOpen;
    private int _buffered;
    private ulong _chunkIndex;
    private bool _completed;
    private bool _disposed;

    public ChunkedAeadWriteStream(
        Stream output,
        ReadOnlySpan<byte> dataKey,
        ReadOnlySpan<byte> noncePrefix,
        ReadOnlySpan<byte> headerHash,
        bool leaveOpen = false)
    {
        if (dataKey.Length != CryptoSizes.Key || noncePrefix.Length != 4 || headerHash.Length != 32)
        {
            throw new ArgumentException("加密流参数不正确。");
        }

        _output = output;
        _cipher = new ChaCha20Poly1305(dataKey);
        _noncePrefix = noncePrefix.ToArray();
        _headerHash = headerHash.ToArray();
        _leaveOpen = leaveOpen;
    }

    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => !_disposed && !_completed;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Flush() => _output.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken) =>
        _output.FlushAsync(cancellationToken);

    public override void Write(byte[] buffer, int offset, int count) =>
        WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override async ValueTask WriteAsync(
        ReadOnlyMemory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_completed)
        {
            throw new InvalidOperationException("加密流已经结束。");
        }

        while (!buffer.IsEmpty)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var count = Math.Min(ChunkSize - _buffered, buffer.Length);
            buffer[..count].CopyTo(_plainBuffer.AsMemory(_buffered));
            _buffered += count;
            buffer = buffer[count..];

            if (_buffered == ChunkSize)
            {
                await WriteChunkAsync(isFinal: false, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    public async Task CompleteAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_completed)
        {
            return;
        }

        await WriteChunkAsync(isFinal: true, cancellationToken).ConfigureAwait(false);
        await _output.FlushAsync(cancellationToken).ConfigureAwait(false);
        _completed = true;
    }

    private async Task WriteChunkAsync(bool isFinal, CancellationToken cancellationToken)
    {
        if (_chunkIndex == ulong.MaxValue)
        {
            throw new NingRanException("文件过大，无法继续安全加密。");
        }

        var flags = isFinal ? (byte)1 : (byte)0;
        var recordHeader = new byte[5];
        BinaryPrimitives.WriteUInt32LittleEndian(recordHeader.AsSpan(0, 4), (uint)_buffered);
        recordHeader[4] = flags;

        Span<byte> nonce = stackalloc byte[CryptoSizes.Nonce];
        _noncePrefix.CopyTo(nonce);
        BinaryPrimitives.WriteUInt64LittleEndian(nonce[4..], _chunkIndex);

        Span<byte> associatedData = stackalloc byte[45];
        _headerHash.CopyTo(associatedData);
        BinaryPrimitives.WriteUInt64LittleEndian(associatedData[32..40], _chunkIndex);
        BinaryPrimitives.WriteUInt32LittleEndian(associatedData[40..44], (uint)_buffered);
        associatedData[44] = flags;

        var tag = new byte[CryptoSizes.Tag];
        _cipher.Encrypt(
            nonce,
            _plainBuffer.AsSpan(0, _buffered),
            _cipherBuffer.AsSpan(0, _buffered),
            tag,
            associatedData);

        await _output.WriteAsync(recordHeader, cancellationToken).ConfigureAwait(false);
        await _output.WriteAsync(_cipherBuffer.AsMemory(0, _buffered), cancellationToken).ConfigureAwait(false);
        await _output.WriteAsync(tag, cancellationToken).ConfigureAwait(false);

        CryptographicOperations.ZeroMemory(_plainBuffer.AsSpan(0, _buffered));
        _buffered = 0;
        _chunkIndex++;
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
                _output.Dispose();
            }
        }

        _disposed = true;
        base.Dispose(disposing);
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
