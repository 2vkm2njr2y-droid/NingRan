using System.Buffers.Binary;
using System.Security.Cryptography;
using NingRan.Core.Internal;

namespace NingRan.Core;

/// <summary>
/// A writable view of one vault file. Changed blocks are kept encrypted until CommitAsync
/// atomically publishes a new catalog revision. Closing without CommitAsync abandons changes.
/// </summary>
public sealed class VaultWriteSession : Stream
{
    private static ReadOnlySpan<byte> TransactionMagic => "NRTXN001"u8;
    private const int HeaderSize = 8 + 16 + sizeof(int) + CryptoSizes.Nonce;
    private readonly VaultSession _session;
    private readonly Guid _transactionId = Guid.NewGuid();
    private readonly string _transactionPath;
    private readonly List<(long Start, long End)> _zeroRanges = [];
    private VaultCatalogEntry? _baseEntry;
    private long _position;
    private long _length;
    private bool _dirty;
    private bool _disposed;

    internal VaultWriteSession(VaultSession session, string relativePath, VaultCatalogEntry? baseEntry, bool truncate)
    {
        _session = session;
        RelativePath = relativePath;
        _baseEntry = baseEntry;
        _length = truncate ? 0 : baseEntry?.Length ?? 0;
        _dirty = baseEntry is null || truncate;
        _transactionPath = Path.Combine(session.JournalPath, _transactionId.ToString("N"));
        Directory.CreateDirectory(_transactionPath);
        if (truncate && baseEntry is { Length: > 0 })
        {
            _zeroRanges.Add((0, baseEntry.Length));
        }
    }

    public string RelativePath { get; private set; }
    public bool HasChanges => _dirty;
    public override bool CanRead => !_disposed;
    public override bool CanSeek => !_disposed;
    public override bool CanWrite => !_disposed;
    public override long Length { get { ThrowIfDisposed(); return _length; } }
    public override long Position
    {
        get { ThrowIfDisposed(); return _position; }
        set
        {
            ThrowIfDisposed();
            if (value < 0) throw new ArgumentOutOfRangeException(nameof(value));
            _position = value;
        }
    }

    public async Task CommitAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (!_dirty) return;
        await _session.CommitWriteAsync(this, cancellationToken).ConfigureAwait(false);
    }

    internal VaultCatalogEntry? BaseEntry => _baseEntry;

    public void ChangePath(string relativePath) => RelativePath = relativePath;

    internal void MarkCommitted(VaultCatalogEntry entry)
    {
        _baseEntry = entry;
        _dirty = false;
        _zeroRanges.Clear();
        ClearTransactionBlocks();
    }

    public override int Read(byte[] buffer, int offset, int count) =>
        ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (_position >= _length || buffer.IsEmpty) return 0;
        var count = checked((int)Math.Min(buffer.Length, _length - _position));
        await ReadAtAsync(_position, buffer[..count], cancellationToken).ConfigureAwait(false);
        _position += count;
        return count;
    }

    public override void Write(byte[] buffer, int offset, int count) =>
        WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (buffer.IsEmpty) return;
        var end = checked(_position + buffer.Length);
        var consumed = 0;
        while (consumed < buffer.Length)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var absolute = _position + consumed;
            var chunkIndex = checked((int)(absolute / VaultFormat.ChunkSize));
            var chunkOffset = checked((int)(absolute % VaultFormat.ChunkSize));
            var amount = Math.Min(buffer.Length - consumed, VaultFormat.ChunkSize - chunkOffset);
            var chunk = new byte[VaultFormat.ChunkSize];
            try
            {
                await ReadEffectiveChunkAsync(chunkIndex, chunk, cancellationToken).ConfigureAwait(false);
                buffer.Slice(consumed, amount).CopyTo(chunk.AsMemory(chunkOffset, amount));
                await WriteTransactionChunkAsync(chunkIndex, chunk, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(chunk);
            }
            consumed += amount;
        }
        RemoveZeroRange(_position, end);
        _position = end;
        _length = Math.Max(_length, end);
        _dirty = true;
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        ThrowIfDisposed();
        var next = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => checked(_position + offset),
            SeekOrigin.End => checked(_length + offset),
            _ => throw new ArgumentOutOfRangeException(nameof(origin)),
        };
        if (next < 0) throw new IOException("文件位置不能小于零。");
        _position = next;
        return next;
    }

    public override void SetLength(long value)
    {
        ThrowIfDisposed();
        if (value < 0) throw new ArgumentOutOfRangeException(nameof(value));
        if (value < _length)
        {
            _zeroRanges.Add((value, _length));
            var firstRemovedChunk = checked((int)((value + VaultFormat.ChunkSize - 1) / VaultFormat.ChunkSize));
            foreach (var path in Directory.EnumerateFiles(_transactionPath, "*.nrtxn"))
            {
                if (int.TryParse(Path.GetFileNameWithoutExtension(path), out var index) && index >= firstRemovedChunk)
                {
                    File.Delete(path);
                }
            }
        }
        else if (value > _length)
        {
            _zeroRanges.Add((_length, value));
        }
        _length = value;
        if (_position > value) _position = value;
        _dirty = true;
    }

    public override void Flush() => CommitAsync().GetAwaiter().GetResult();

    public override Task FlushAsync(CancellationToken cancellationToken) => CommitAsync(cancellationToken);

    internal async Task ReadAtAsync(long offset, Memory<byte> destination, CancellationToken cancellationToken)
    {
        var completed = 0;
        while (completed < destination.Length)
        {
            var absolute = checked(offset + completed);
            var chunkIndex = checked((int)(absolute / VaultFormat.ChunkSize));
            var chunkOffset = checked((int)(absolute % VaultFormat.ChunkSize));
            var amount = Math.Min(destination.Length - completed, VaultFormat.ChunkSize - chunkOffset);
            var chunk = new byte[VaultFormat.ChunkSize];
            try
            {
                await ReadEffectiveChunkAsync(chunkIndex, chunk, cancellationToken).ConfigureAwait(false);
                chunk.AsMemory(chunkOffset, amount).CopyTo(destination[completed..]);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(chunk);
            }
            completed += amount;
        }
    }

    private async Task ReadEffectiveChunkAsync(int chunkIndex, Memory<byte> destination, CancellationToken cancellationToken)
    {
        destination.Span.Clear();
        var chunkStart = (long)chunkIndex * VaultFormat.ChunkSize;
        if (_baseEntry is { } baseEntry && chunkStart < baseEntry.Length)
        {
            var amount = checked((int)Math.Min(VaultFormat.ChunkSize, baseEntry.Length - chunkStart));
            await VaultFormat.ReadFileAtAsync(
                _session.VaultPath, _session.Info, baseEntry, chunkStart,
                destination[..amount], _session.DataKey, cancellationToken).ConfigureAwait(false);
        }

        var transactionFile = TransactionFile(chunkIndex);
        if (File.Exists(transactionFile))
        {
            await ReadTransactionChunkAsync(transactionFile, chunkIndex, destination, cancellationToken).ConfigureAwait(false);
        }

        foreach (var range in _zeroRanges)
        {
            var start = Math.Max(range.Start, chunkStart);
            var end = Math.Min(range.End, chunkStart + VaultFormat.ChunkSize);
            if (end > start)
            {
                destination.Span.Slice(checked((int)(start - chunkStart)), checked((int)(end - start))).Clear();
            }
        }
    }

    private async Task WriteTransactionChunkAsync(int chunkIndex, ReadOnlyMemory<byte> plaintext, CancellationToken cancellationToken)
    {
        var nonce = RandomNumberGenerator.GetBytes(CryptoSizes.Nonce);
        var header = new byte[HeaderSize];
        var ciphertext = new byte[VaultFormat.ChunkSize];
        var tag = new byte[CryptoSizes.Tag];
        var temporary = Path.Combine(_transactionPath, $".{chunkIndex:D8}.{Guid.NewGuid():N}.part");
        try
        {
            TransactionMagic.CopyTo(header);
            _transactionId.TryWriteBytes(header.AsSpan(8, 16));
            BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(24, 4), chunkIndex);
            nonce.CopyTo(header.AsSpan(28));
            using (var cipher = new ChaCha20Poly1305(_session.DataKey.Span))
            {
                cipher.Encrypt(nonce, plaintext.Span, ciphertext, tag, header);
            }
            await using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                             VaultFormat.ChunkSize, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await output.WriteAsync(header, cancellationToken).ConfigureAwait(false);
                await output.WriteAsync(ciphertext, cancellationToken).ConfigureAwait(false);
                await output.WriteAsync(tag, cancellationToken).ConfigureAwait(false);
                await output.FlushAsync(cancellationToken).ConfigureAwait(false);
                output.Flush(flushToDisk: true);
            }
            File.Move(temporary, TransactionFile(chunkIndex), overwrite: true);
        }
        catch (IOException exception) when (IsDiskFull(exception))
        {
            throw new NingRanException("保险箱所在磁盘空间不足，原文件没有改变。", exception);
        }
        finally
        {
            TryDelete(temporary);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(header);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
        }
    }

    private async Task ReadTransactionChunkAsync(
        string path, int chunkIndex, Memory<byte> destination, CancellationToken cancellationToken)
    {
        var header = new byte[HeaderSize];
        var ciphertext = new byte[VaultFormat.ChunkSize];
        var tag = new byte[CryptoSizes.Tag];
        try
        {
            await using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
                VaultFormat.ChunkSize, FileOptions.Asynchronous | FileOptions.RandomAccess);
            await input.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);
            await input.ReadExactlyAsync(ciphertext, cancellationToken).ConfigureAwait(false);
            await input.ReadExactlyAsync(tag, cancellationToken).ConfigureAwait(false);
            if (input.Position != input.Length ||
                !header.AsSpan(0, 8).SequenceEqual(TransactionMagic) ||
                new Guid(header.AsSpan(8, 16)) != _transactionId ||
                BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(24, 4)) != chunkIndex)
            {
                throw new NingRanException("保险箱的未完成保存记录已经损坏，原文件没有改变。");
            }
            try
            {
                using var cipher = new ChaCha20Poly1305(_session.DataKey.Span);
                cipher.Decrypt(header.AsSpan(28, CryptoSizes.Nonce), ciphertext, tag, destination.Span, header);
            }
            catch (CryptographicException exception)
            {
                throw new NingRanException("保险箱的未完成保存记录未通过检查，原文件没有改变。", exception);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(header);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (_disposed) return;
        _dirty = false;
        _zeroRanges.Clear();
        _disposed = true;
        TryDeleteDirectory(_transactionPath);
        base.Dispose(disposing);
    }

    public void Abandon()
    {
        _dirty = false;
        _disposed = true;
        TryDeleteDirectory(_transactionPath);
    }

    private string TransactionFile(int chunkIndex) => Path.Combine(_transactionPath, $"{chunkIndex:D8}.nrtxn");
    private void RemoveZeroRange(long start, long end)
    {
        if (end <= start) return;
        for (var index = _zeroRanges.Count - 1; index >= 0; index--)
        {
            var range = _zeroRanges[index];
            if (end <= range.Start || start >= range.End) continue;
            _zeroRanges.RemoveAt(index);
            if (range.Start < start) _zeroRanges.Add((range.Start, start));
            if (end < range.End) _zeroRanges.Add((end, range.End));
        }
    }
    private void ClearTransactionBlocks()
    {
        foreach (var path in Directory.EnumerateFiles(_transactionPath)) TryDelete(path);
    }
    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);
    private static bool IsDiskFull(IOException exception) => (exception.HResult & 0xFFFF) is 0x27 or 0x70;
    private static void TryDelete(string path) { try { if (File.Exists(path)) File.Delete(path); } catch { } }
    private static void TryDeleteDirectory(string path) { try { if (Directory.Exists(path)) Directory.Delete(path, true); } catch { } }
}
