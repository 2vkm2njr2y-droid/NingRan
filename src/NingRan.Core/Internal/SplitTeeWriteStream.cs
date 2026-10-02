namespace NingRan.Core.Internal;

/// <summary>把已加密字节写入分片，并可选地同时写入校验用临时文件。</summary>
internal sealed class SplitTeeWriteStream : Stream
{
    private readonly Stream? _primary;
    private readonly SplitArchivePartWriter _split;

    public SplitTeeWriteStream(Stream primary, SplitArchivePartWriter split)
    {
        _primary = primary;
        _split = split;
    }

    public SplitTeeWriteStream(SplitArchivePartWriter split)
    {
        _split = split;
    }

    public override bool CanRead => false;
    public override bool CanSeek => _primary?.CanSeek == true;
    public override bool CanWrite => true;
    public override long Length => _primary?.Length ?? throw new NotSupportedException();
    public override long Position
    {
        get => _primary?.Position ?? throw new NotSupportedException();
        set
        {
            if (_primary is null) throw new NotSupportedException();
            _primary.Position = value;
        }
    }
    public override void Flush()
    {
        _primary?.Flush();
        _split.FlushAsync(CancellationToken.None).GetAwaiter().GetResult();
    }
    public override async Task FlushAsync(CancellationToken cancellationToken)
    {
        if (_primary is not null) await _primary.FlushAsync(cancellationToken).ConfigureAwait(false);
        await _split.FlushAsync(cancellationToken).ConfigureAwait(false);
    }
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => _primary?.Seek(offset, origin)
        ?? throw new NotSupportedException();
    public override void SetLength(long value)
    {
        if (_primary is null) throw new NotSupportedException();
        _primary.SetLength(value);
    }
    public override void Write(byte[] buffer, int offset, int count)
    {
        _primary?.Write(buffer, offset, count);
        _split.WriteAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (_primary is not null) await _primary.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
        await _split.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
}
