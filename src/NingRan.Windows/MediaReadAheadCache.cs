using System.Security.Cryptography;
using System.IO;
using NingRan.Core;

namespace NingRan.Windows;

/// <summary>
/// 为连续播放保留一个仅在内存中的明文环形缓冲区。
/// 浏览器读取到一个分段时，后续约 48 MiB 会由后台提前解密；内存最多保留 256 MiB，
/// 拖动进度条则只读取新位置附近的分段。
/// </summary>
internal sealed class MediaReadAheadCache : IDisposable
{
    internal const int BlockSize = 4 * 1024 * 1024;
    private const int MaximumCachedBytes = 256 * 1024 * 1024;
    private const int ReadAheadBlockCount = 12;
    private readonly SecureArchiveSession _session;
    private readonly string _relativePath;
    private readonly long _length;
    private readonly CancellationTokenSource _shutdown = new();
    private readonly SemaphoreSlim _readSlots = new(2, 2);
    private readonly object _sync = new();
    private readonly Dictionary<long, Task<CacheBlock>> _pending = [];
    private readonly Dictionary<long, CacheBlock> _cached = [];
    private long _cachedBytes;
    private bool _disposed;

    public MediaReadAheadCache(SecureArchiveSession session, SecureArchiveEntry entry)
    {
        _session = session;
        _relativePath = entry.RelativePath;
        _length = entry.Length;
    }

    public Stream OpenRange(long start, long length)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (start < 0 || length < 0 || start > _length || length > _length - start)
        {
            throw new ArgumentOutOfRangeException(nameof(start), "媒体读取范围不正确。");
        }

        return new MediaReadAheadStream(this, start, length);
    }

    public async Task PrepareStartupAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_length <= 0) throw new InvalidDataException("媒体文件为空，无法播放。");
        var finalBlock = (_length - 1) / BlockSize;
        var required = new HashSet<long> { 0, Math.Min(1, finalBlock), finalBlock, Math.Max(0, finalBlock - 1) };
        await Task.WhenAll(required.Select(block => GetBlockAsync(block).WaitAsync(cancellationToken))).ConfigureAwait(false);
        WarmFrom(0);
    }

    public void WarmFrom(long position)
    {
        if (_disposed || position < 0 || position >= _length) return;
        var initialBlock = position / BlockSize;
        var finalBlock = Math.Min((_length - 1) / BlockSize, initialBlock + ReadAheadBlockCount - 1);
        for (var block = initialBlock; block <= finalBlock; block++) _ = GetBlockAsync(block);
    }

    internal async ValueTask<int> CopyToAsync(long position, Memory<byte> destination, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (destination.IsEmpty || position >= _length) return 0;
        var blockIndex = position / BlockSize;
        var blockOffset = checked((int)(position % BlockSize));
        var block = await GetBlockAsync(blockIndex).WaitAsync(cancellationToken).ConfigureAwait(false);
        var count = Math.Min(destination.Length, block.Length - blockOffset);
        lock (_sync)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(MediaReadAheadCache));
            block.Bytes.AsSpan(blockOffset, count).CopyTo(destination.Span);
            block.LastUsed = Environment.TickCount64;
        }
        WarmFrom(position + count);
        return count;
    }

    private Task<CacheBlock> GetBlockAsync(long blockIndex)
    {
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_cached.TryGetValue(blockIndex, out var cached))
            {
                cached.LastUsed = Environment.TickCount64;
                return Task.FromResult(cached);
            }
            if (_pending.TryGetValue(blockIndex, out var pending)) return pending;
            var task = Task.Run(() => LoadBlockAsync(blockIndex, _shutdown.Token));
            _pending[blockIndex] = task;
            _ = task.ContinueWith(completed => CompleteLoad(blockIndex, completed), CancellationToken.None,
                TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            return task;
        }
    }

    private async Task<CacheBlock> LoadBlockAsync(long blockIndex, CancellationToken cancellationToken)
    {
        var offset = checked(blockIndex * (long)BlockSize);
        if (offset < 0 || offset >= _length) throw new ArgumentOutOfRangeException(nameof(blockIndex));
        var bytes = new byte[checked((int)Math.Min(BlockSize, _length - offset))];
        try
        {
            await _readSlots.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                await using var source = _session.OpenEntryReadStream(_relativePath);
                source.Position = offset;
                await source.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _readSlots.Release();
            }
            return new CacheBlock(blockIndex, bytes);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw;
        }
    }

    private void CompleteLoad(long blockIndex, Task<CacheBlock> completed)
    {
        lock (_sync)
        {
            _pending.Remove(blockIndex);
            if (_disposed || !completed.IsCompletedSuccessfully)
            {
                if (completed.Status == TaskStatus.RanToCompletion) CryptographicOperations.ZeroMemory(completed.Result.Bytes);
                return;
            }

            var block = completed.Result;
            _cached[blockIndex] = block;
            _cachedBytes += block.Length;
            while (_cachedBytes > MaximumCachedBytes && _cached.Count > 1)
            {
                var evicted = _cached.Values.OrderBy(candidate => candidate.LastUsed).First();
                _cached.Remove(evicted.Index);
                _cachedBytes -= evicted.Length;
                CryptographicOperations.ZeroMemory(evicted.Bytes);
            }
        }
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (_disposed) return;
            _disposed = true;
            _shutdown.Cancel();
            foreach (var block in _cached.Values) CryptographicOperations.ZeroMemory(block.Bytes);
            _cached.Clear();
            _cachedBytes = 0;
        }
        // 后台读取可能正处于收尾阶段。保留这两个很小的协调对象，
        // 让取消的读取自行退出，避免切换文件时释放对象与后台线程相撞。
    }

    private sealed class CacheBlock(long index, byte[] bytes)
    {
        public long Index { get; } = index;
        public byte[] Bytes { get; } = bytes;
        public int Length => Bytes.Length;
        public long LastUsed { get; set; } = Environment.TickCount64;
    }
}

internal sealed class MediaReadAheadStream : Stream
{
    private readonly MediaReadAheadCache _cache;
    private readonly long _length;
    private readonly SemaphoreSlim _readGate = new(1, 1);
    private readonly object _positionSync = new();
    private long _position;
    private readonly long _start;

    public MediaReadAheadStream(MediaReadAheadCache cache, long start, long length)
    {
        _cache = cache;
        _start = start;
        _length = length;
    }

    public override bool CanRead => true;
    public override bool CanSeek => true;
    public override bool CanWrite => false;
    public override long Length => _length;
    public override long Position { get { lock (_positionSync) return _position; } set => Seek(value, SeekOrigin.Begin); }
    public override int Read(byte[] buffer, int offset, int count)
    {
        try { return ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult(); }
        catch (Exception exception) when (IsPlaybackReadFailure(exception)) { return 0; }
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        try
        {
            await _readGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                lock (_positionSync)
                {
                    if (_position >= _length) return 0;
                }

                var copied = 0;
                while (true)
                {
                    long position;
                    lock (_positionSync)
                    {
                        if (_position >= _length || copied >= buffer.Length) return copied;
                        position = _position;
                    }

                    var wanted = (int)Math.Min(buffer.Length - copied, _length - position);
                    var count = await _cache.CopyToAsync(_start + position, buffer.Slice(copied, wanted), cancellationToken).ConfigureAwait(false);
                    if (count == 0) return copied;
                    copied += count;
                    lock (_positionSync) _position += count;
                }
            }
            finally { _readGate.Release(); }
        }
        catch (Exception exception) when (IsPlaybackReadFailure(exception)) { return 0; }
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        var position = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => checked(_position + offset),
            SeekOrigin.End => checked(_length + offset),
            _ => throw new ArgumentOutOfRangeException(nameof(origin)),
        };
        if (position < 0 || position > _length) throw new IOException("媒体读取位置超出范围。");
        lock (_positionSync) _position = position;
        try { _cache.WarmFrom(_start + position); }
        catch (Exception exception) when (IsPlaybackReadFailure(exception)) { }
        return position;
    }

    public override void Flush() => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    private static bool IsPlaybackReadFailure(Exception exception) => exception is
        ObjectDisposedException or OperationCanceledException or IOException or NingRanException or InvalidDataException or
        AggregateException;
}
