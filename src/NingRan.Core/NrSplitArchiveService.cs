using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using NingRan.Core.Internal;

namespace NingRan.Core;

/// <summary>
/// 处理由多个 .nrsplit 文件组成的加密包。分片只保存已经加密的字节，
/// 读取时按需从各分片定位，不会合并成一个完整的临时加密包。
/// </summary>
public static class NrSplitArchiveService
{
    public const string Extension = ".nrsplit";
    public const long MinimumPartSize = 100L * 1024 * 1024;
    public const long MaximumPartSize = 64L * 1024 * 1024 * 1024;
    public const long DefaultPartSize = 4L * 1024 * 1024 * 1024;

    internal const int HeaderSize = 116;
    internal const int Version = 1;
    internal static ReadOnlySpan<byte> Magic => "NRSPLIT1"u8;

    public static bool IsSupportedPartFile(string path)
    {
        try
        {
            return string.Equals(Path.GetExtension(path), Extension, StringComparison.OrdinalIgnoreCase) &&
                   SplitPartName.TryParse(Path.GetFullPath(path), out _, out _);
        }
        catch (Exception exception) when (exception is ArgumentException or IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    public static Stream OpenReadStream(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return SplitArchiveReadStream.Open(path);
    }

    internal static SplitArchivePartWriter CreateWriter(string outputPath, long maximumPartSize) =>
        new(outputPath, maximumPartSize);

    internal static bool TryGetPartBasePath(string path, out string basePath, out int index)
    {
        if (SplitPartName.TryParse(Path.GetFullPath(path), out basePath, out index)) return true;
        basePath = string.Empty;
        index = 0;
        return false;
    }
}

internal sealed class SplitArchivePartWriter : IAsyncDisposable
{
    private sealed class PendingPart
    {
        public required string StagingPath { get; init; }
        public required FileStream Stream { get; init; }
        public required IncrementalHash Hash { get; init; }
        public long PayloadLength { get; set; }
    }

    private readonly string _directory;
    private readonly string _baseName;
    private readonly long _payloadLimit;
    private readonly Guid _groupId = Guid.NewGuid();
    private readonly IncrementalHash _archiveHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    private readonly List<PendingPart> _parts = [];
    private bool _completed;
    private long _totalLength;

    public SplitArchivePartWriter(string outputPath, long maximumPartSize)
    {
        if (maximumPartSize is < NrSplitArchiveService.MinimumPartSize or > NrSplitArchiveService.MaximumPartSize)
        {
            throw new NingRanException("分片大小必须在 100 MB 到 64 GB 之间。");
        }

        var fullPath = Path.GetFullPath(outputPath);
        _directory = Path.GetDirectoryName(fullPath)
            ?? throw new NingRanException("分片保存位置不正确。");
        var fileName = Path.GetFileName(fullPath);
        if (!string.Equals(Path.GetExtension(fileName), NrSplitArchiveService.Extension, StringComparison.OrdinalIgnoreCase))
        {
            fileName += NrSplitArchiveService.Extension;
        }

        if (SplitPartName.TryParse(Path.Combine(_directory, fileName), out var parsedBase, out _))
        {
            _baseName = Path.GetFileName(parsedBase);
        }
        else
        {
            _baseName = Path.GetFileNameWithoutExtension(fileName);
        }

        if (string.IsNullOrWhiteSpace(_baseName) ||
            _baseName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
        {
            throw new NingRanException("分片文件名不正确。");
        }

        _payloadLimit = maximumPartSize - NrSplitArchiveService.HeaderSize;
        if (_payloadLimit <= 0) throw new NingRanException("分片大小太小。");
    }

    public async ValueTask WriteAsync(ReadOnlyMemory<byte> bytes, CancellationToken cancellationToken)
    {
        if (_completed) throw new ObjectDisposedException(nameof(SplitArchivePartWriter));
        while (!bytes.IsEmpty)
        {
            var part = await EnsurePartAsync(cancellationToken).ConfigureAwait(false);
            var available = checked(_payloadLimit - part.PayloadLength);
            var count = (int)Math.Min(available, bytes.Length);
            var chunk = bytes[..count];
            await part.Stream.WriteAsync(chunk, cancellationToken).ConfigureAwait(false);
            part.Hash.AppendData(chunk.Span);
            _archiveHash.AppendData(chunk.Span);
            part.PayloadLength = checked(part.PayloadLength + count);
            _totalLength = checked(_totalLength + count);
            bytes = bytes[count..];
        }
    }

    public async Task FlushAsync(CancellationToken cancellationToken)
    {
        foreach (var part in _parts)
        {
            await part.Stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    public async Task<IReadOnlyList<string>> CompleteAsync(CancellationToken cancellationToken)
    {
        if (_completed) throw new InvalidOperationException("分片写入已经完成。");
        _completed = true;
        var finalPaths = new List<string>(_parts.Count);
        try
        {
            if (_parts.Count == 0)
            {
                await EnsurePartAsync(cancellationToken).ConfigureAwait(false);
            }

            var archiveHash = _archiveHash.GetHashAndReset();
            try
            {
                for (var index = 0; index < _parts.Count; index++)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var part = _parts[index];
                    await part.Stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                    part.Stream.Flush(flushToDisk: true);
                    part.Stream.Dispose();
                    var partHash = part.Hash.GetHashAndReset();
                    try
                    {
                        var header = BuildHeader(index + 1, _parts.Count, part.PayloadLength, _totalLength,
                            archiveHash, partHash);
                        try
                        {
                            await using var patch = new FileStream(part.StagingPath, FileMode.Open, FileAccess.Write,
                                FileShare.Read, 4096, FileOptions.WriteThrough);
                            await patch.WriteAsync(header, cancellationToken).ConfigureAwait(false);
                            await patch.FlushAsync(cancellationToken).ConfigureAwait(false);
                            patch.Flush(flushToDisk: true);
                        }
                        finally { CryptographicOperations.ZeroMemory(header); }

                        var finalPath = Path.Combine(_directory, $"{_baseName}-{index + 1}{NrSplitArchiveService.Extension}");
                        if (File.Exists(finalPath) || Directory.Exists(finalPath))
                            throw new NingRanException($"分片保存位置已经存在：{Path.GetFileName(finalPath)}。");
                        File.Move(part.StagingPath, finalPath);
                        finalPaths.Add(finalPath);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(partHash);
                    }
                }

                return finalPaths;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(archiveHash);
            }
        }
        catch
        {
            foreach (var part in _parts)
            {
                try { await part.Stream.DisposeAsync().ConfigureAwait(false); } catch { }
            }
            TryDeleteStaging();
            foreach (var finalPath in finalPaths)
            {
                TryDeleteFile(finalPath);
            }
            throw;
        }
        finally
        {
            _archiveHash.Dispose();
            foreach (var part in _parts) part.Hash.Dispose();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (!_completed)
        {
            foreach (var part in _parts) await part.Stream.DisposeAsync().ConfigureAwait(false);
            TryDeleteStaging();
        }
        _archiveHash.Dispose();
        foreach (var part in _parts) part.Hash.Dispose();
    }

    private async Task<PendingPart> EnsurePartAsync(CancellationToken cancellationToken)
    {
        if (_parts.Count > 0 && _parts[^1].PayloadLength < _payloadLimit)
            return _parts[^1];

        cancellationToken.ThrowIfCancellationRequested();
        var index = _parts.Count + 1;
        var stagingPath = Path.Combine(_directory, $".{_baseName}-{index}.{Guid.NewGuid():N}.nrsplit.part");
        Directory.CreateDirectory(_directory);
        var stream = new FileStream(stagingPath, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read,
            1024 * 1024, FileOptions.Asynchronous | FileOptions.WriteThrough);
        try
        {
            await stream.WriteAsync(new byte[NrSplitArchiveService.HeaderSize], cancellationToken).ConfigureAwait(false);
            var part = new PendingPart
            {
                StagingPath = stagingPath,
                Stream = stream,
                Hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256),
            };
            _parts.Add(part);
            return part;
        }
        catch
        {
            await stream.DisposeAsync().ConfigureAwait(false);
            TryDeleteFile(stagingPath);
            throw;
        }
    }

    private byte[] BuildHeader(int index, int count, long payloadLength, long totalLength,
        byte[] archiveHash, byte[] partHash)
    {
        var header = new byte[NrSplitArchiveService.HeaderSize];
        NrSplitArchiveService.Magic.CopyTo(header);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(8), NrSplitArchiveService.Version);
        _groupId.TryWriteBytes(header.AsSpan(12, 16));
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(28), index);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(32), count);
        BinaryPrimitives.WriteInt64LittleEndian(header.AsSpan(36), payloadLength);
        BinaryPrimitives.WriteInt64LittleEndian(header.AsSpan(44), totalLength);
        archiveHash.CopyTo(header, 52);
        partHash.CopyTo(header, 84);
        return header;
    }

    private void TryDeleteStaging()
    {
        foreach (var part in _parts) TryDeleteFile(part.StagingPath);
    }

    private static void TryDeleteFile(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }
}

internal sealed class SplitArchiveReadStream : Stream, IArchiveRandomAccessStream
{
    private sealed record Part(string Path, FileStream Stream, long PayloadOffset, long PayloadLength, byte[] Hash);
    private readonly IReadOnlyList<Part> _parts;
    private readonly long _length;
    private long _position;
    private bool _disposed;

    private SplitArchiveReadStream(IReadOnlyList<Part> parts)
    {
        _parts = parts;
        _length = parts.Sum(part => part.PayloadLength);
    }

    public static SplitArchiveReadStream Open(string path)
    {
        if (!SplitPartName.TryParse(Path.GetFullPath(path), out var basePath, out _))
            throw new NingRanException("分片文件名不正确，无法确定分片组。");

        var directory = Path.GetDirectoryName(basePath) ?? throw new NingRanException("分片目录不正确。");
        var baseName = Path.GetFileName(basePath);
        var candidates = Directory.EnumerateFiles(directory, baseName + "-*" + NrSplitArchiveService.Extension)
            .Select(candidate => (Path: candidate, Parsed: SplitPartName.TryParse(candidate, out var parsedBase, out var index)
                && string.Equals(parsedBase, basePath, StringComparison.OrdinalIgnoreCase)
                ? index : 0))
            .Where(item => item.Parsed > 0)
            .OrderBy(item => item.Parsed)
            .ToArray();
        if (candidates.Length == 0) throw new NingRanException("没有找到同组分片。");

        var headers = new Dictionary<int, SplitPartHeader>();
        foreach (var candidate in candidates)
        {
            using var headerStream = new FileStream(candidate.Path, FileMode.Open, FileAccess.Read, FileShare.Read,
                NrSplitArchiveService.HeaderSize, FileOptions.SequentialScan);
            var header = SplitPartHeader.Read(headerStream, candidate.Path);
            if (header.Index != candidate.Parsed) throw new NingRanException($"分片编号不匹配：{Path.GetFileName(candidate.Path)}。");
            if (!headers.TryAdd(header.Index, header)) throw new NingRanException($"分片编号重复：part{header.Index}。");
        }

        var first = headers.Values.First();
        if (first.Count < 1 || first.Count > 1_000_000)
            throw new NingRanException("分片总数不在安全范围内。");
        var missing = Enumerable.Range(1, first.Count).Where(index => !headers.ContainsKey(index)).ToArray();
        if (missing.Length > 0)
            throw new NingRanException($"分片不完整，缺少：{string.Join("、", missing.Select(index => $"part{index}"))}。");
        if (headers.Count != first.Count)
            throw new NingRanException("分片目录中存在多余或重复分片。");

        var parts = new List<Part>(first.Count);
        try
        {
            long offset = 0;
            for (var index = 1; index <= first.Count; index++)
            {
                var header = headers[index];
                if (header.GroupId != first.GroupId || header.Count != first.Count ||
                    header.TotalLength != first.TotalLength || !header.ArchiveHash.AsSpan().SequenceEqual(first.ArchiveHash))
                    throw new NingRanException($"分片 part{index} 的分组信息不一致。");
                var stream = new FileStream(header.Path, FileMode.Open, FileAccess.Read, FileShare.Read,
                    1024 * 1024, FileOptions.SequentialScan);
                if (stream.Length != checked(NrSplitArchiveService.HeaderSize + header.PayloadLength))
                {
                    stream.Dispose();
                    throw new NingRanException($"分片 part{index} 的大小不正确。");
                }

                var actualHash = ComputePayloadHash(stream, header.PayloadLength);
                if (!CryptographicOperations.FixedTimeEquals(actualHash, header.PartHash))
                {
                    CryptographicOperations.ZeroMemory(actualHash);
                    stream.Dispose();
                    throw new NingRanException($"分片 part{index} 的完整性校验失败。");
                }

                parts.Add(new Part(header.Path, stream, offset, header.PayloadLength, actualHash));
                offset = checked(offset + header.PayloadLength);
            }

            if (offset != first.TotalLength)
                throw new NingRanException("分片总长度不一致。");
            return new SplitArchiveReadStream(parts);
        }
        catch
        {
            foreach (var part in parts) part.Stream.Dispose();
            throw;
        }
    }

    public ValueTask<int> ReadAtAsync(Memory<byte> buffer, long offset, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (offset < 0 || offset >= _length || buffer.IsEmpty) return ValueTask.FromResult(0);
        return ReadAtCoreAsync(buffer, offset, cancellationToken);
    }

    private async ValueTask<int> ReadAtCoreAsync(Memory<byte> buffer, long offset, CancellationToken cancellationToken)
    {
        var remaining = (int)Math.Min(buffer.Length, _length - offset);
        var copied = 0;
        while (copied < remaining)
        {
            var part = FindPart(offset + copied);
            var within = offset + copied - part.PayloadOffset;
            var count = (int)Math.Min(remaining - copied, part.PayloadLength - within);
            var read = 0;
            while (read < count)
            {
                var amount = await RandomAccess.ReadAsync(part.Stream.SafeFileHandle,
                    buffer.Slice(copied + read, count - read),
                    checked(NrSplitArchiveService.HeaderSize + within + read), cancellationToken).ConfigureAwait(false);
                if (amount == 0) throw new NingRanException("分片内容不完整。");
                read += amount;
            }
            copied += count;
        }
        return copied;
    }

    private Part FindPart(long offset) => _parts.FirstOrDefault(part => offset >= part.PayloadOffset &&
        offset < part.PayloadOffset + part.PayloadLength)
        ?? throw new EndOfStreamException("分片位置超出范围。");

    private static byte[] ComputePayloadHash(FileStream stream, long payloadLength)
    {
        stream.Position = NrSplitArchiveService.HeaderSize;
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[1024 * 1024];
        try
        {
            var remaining = payloadLength;
            while (remaining > 0)
            {
                var read = stream.Read(buffer, 0, (int)Math.Min(buffer.Length, remaining));
                if (read == 0) throw new NingRanException("分片内容不完整。");
                hash.AppendData(buffer, 0, read);
                remaining -= read;
            }
            return hash.GetHashAndReset();
        }
        finally { CryptographicOperations.ZeroMemory(buffer); }
    }

    protected override void Dispose(bool disposing)
    {
        if (!_disposed && disposing)
        {
            foreach (var part in _parts)
            {
                part.Stream.Dispose();
                CryptographicOperations.ZeroMemory(part.Hash);
            }
        }
        _disposed = true;
        base.Dispose(disposing);
    }

    public override bool CanRead => !_disposed;
    public override bool CanSeek => !_disposed;
    public override bool CanWrite => false;
    public override long Length => _length;
    public override long Position { get => _position; set => Seek(value, SeekOrigin.Begin); }
    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
    public override int Read(Span<byte> buffer)
    {
        if (buffer.Length == 0) return 0;
        var temporary = new byte[buffer.Length];
        var read = ReadAtAsync(temporary, _position, CancellationToken.None).AsTask().GetAwaiter().GetResult();
        temporary.AsSpan(0, read).CopyTo(buffer);
        CryptographicOperations.ZeroMemory(temporary);
        if (read > 0) _position += read;
        return read;
    }
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var read = await ReadAtAsync(buffer, _position, cancellationToken).ConfigureAwait(false);
        _position = checked(_position + read);
        return read;
    }
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    public override long Seek(long offset, SeekOrigin origin)
    {
        var target = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => checked(_position + offset),
            SeekOrigin.End => checked(_length + offset),
            _ => throw new ArgumentOutOfRangeException(nameof(origin)),
        };
        if (target < 0 || target > _length) throw new IOException("分片定位超出范围。");
        _position = target;
        return target;
    }
    public override void Flush() { }
    public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

internal interface IArchiveRandomAccessStream
{
    ValueTask<int> ReadAtAsync(Memory<byte> buffer, long offset, CancellationToken cancellationToken);
}

internal readonly record struct SplitPartHeader(
    string Path,
    Guid GroupId,
    int Index,
    int Count,
    long PayloadLength,
    long TotalLength,
    byte[] ArchiveHash,
    byte[] PartHash)
{
    public static SplitPartHeader Read(FileStream stream, string path)
    {
        var bytes = new byte[NrSplitArchiveService.HeaderSize];
        try
        {
            stream.ReadExactly(bytes);
            if (!bytes.AsSpan(0, 8).SequenceEqual(NrSplitArchiveService.Magic) ||
                BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(8)) != NrSplitArchiveService.Version)
                throw new NingRanException($"文件不是有效的凝然分片：{System.IO.Path.GetFileName(path)}。");
            var group = new Guid(bytes.AsSpan(12, 16));
            var index = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(28));
            var count = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(32));
            var payloadLength = BinaryPrimitives.ReadInt64LittleEndian(bytes.AsSpan(36));
            var totalLength = BinaryPrimitives.ReadInt64LittleEndian(bytes.AsSpan(44));
            if (index < 1 || count < 1 || payloadLength < 0 || totalLength < 0)
                throw new NingRanException($"分片头信息不正确：{System.IO.Path.GetFileName(path)}。");
            return new SplitPartHeader(path, group, index, count, payloadLength, totalLength,
                bytes[52..84].ToArray(), bytes[84..116].ToArray());
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
}

internal static class SplitPartName
{
    public static bool TryParse(string path, out string basePath, out int index)
    {
        basePath = string.Empty;
        index = 0;
        if (!string.Equals(Path.GetExtension(path), NrSplitArchiveService.Extension, StringComparison.OrdinalIgnoreCase))
            return false;
        var withoutExtension = path[..^NrSplitArchiveService.Extension.Length];
        var separator = withoutExtension.LastIndexOf('-');
        if (separator <= 0 || separator == withoutExtension.Length - 1 ||
            !int.TryParse(withoutExtension[(separator + 1)..], out index) || index < 1)
            return false;
        basePath = withoutExtension[..separator];
        return true;
    }
}


