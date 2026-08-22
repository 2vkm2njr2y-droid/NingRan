namespace NingRan.Core.Internal;

internal sealed class LengthLimitedReadStream : Stream
{
    private readonly Stream _inner;
    private readonly bool _leaveOpen;
    private long _remaining;

    public LengthLimitedReadStream(Stream inner, long length, bool leaveOpen)
    {
        _inner = inner;
        _remaining = length >= 0 ? length : throw new ArgumentOutOfRangeException(nameof(length));
        _leaveOpen = leaveOpen;
    }

    public override bool CanRead => _inner.CanRead;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        var wanted = (int)Math.Min(count, _remaining);
        if (wanted == 0)
        {
            return 0;
        }

        var read = _inner.Read(buffer, offset, wanted);
        _remaining -= read;
        return read;
    }

    public override int Read(Span<byte> buffer)
    {
        var wanted = (int)Math.Min(buffer.Length, _remaining);
        if (wanted == 0)
        {
            return 0;
        }

        var read = _inner.Read(buffer[..wanted]);
        _remaining -= read;
        return read;
    }

    public override async ValueTask<int> ReadAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        var wanted = (int)Math.Min(buffer.Length, _remaining);
        if (wanted == 0)
        {
            return 0;
        }

        var read = await _inner.ReadAsync(buffer[..wanted], cancellationToken).ConfigureAwait(false);
        _remaining -= read;
        return read;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_leaveOpen)
        {
            _inner.Dispose();
        }

        base.Dispose(disposing);
    }

    public override void Flush() => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
