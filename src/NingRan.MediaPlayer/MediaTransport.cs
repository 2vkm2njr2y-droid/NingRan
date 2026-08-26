using System.IO;
using System.IO.Pipes;
using System.Text.Json;
using NingRan.Core;

namespace NingRan.MediaPlayer;

public sealed record PlayerLaunchOptions(string Pipe, string SelectedPath)
{
    public static bool TryParse(string[] args, out PlayerLaunchOptions options)
    {
        options = null!;
        if (args.Length != 4) return false;

        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var index = 0; index < args.Length; index += 2)
        {
            if (args[index] is not ("--ningran-secure-pipe" or "--ningran-selected") ||
                !values.TryAdd(args[index], args[index + 1])) return false;
        }

        if (!values.TryGetValue("--ningran-secure-pipe", out var pipe) ||
            !pipe.StartsWith("NingRan.Media.", StringComparison.Ordinal) ||
            pipe.Length > 240 || pipe.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not ('.' or '-' or '_')) ||
            !values.TryGetValue("--ningran-selected", out var selectedPath) ||
            string.IsNullOrWhiteSpace(selectedPath) || selectedPath.Length > 32_000)
        {
            return false;
        }

        options = new PlayerLaunchOptions(pipe, selectedPath);
        return true;
    }
}

public sealed record LocalMediaLaunchOptions(IReadOnlyList<string> Files)
{
    public static bool TryParse(string[] args, out LocalMediaLaunchOptions options)
    {
        options = null!;
        if (args.Length == 0) return false;

        var files = new List<string>(args.Length);
        foreach (var argument in args)
        {
            if (string.IsNullOrWhiteSpace(argument) || argument.StartsWith("--", StringComparison.Ordinal)) return false;
            string fullPath;
            try { fullPath = Path.GetFullPath(argument); }
            catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
            {
                return false;
            }

            if (!IsSupportedMediaFile(fullPath)) return false;
            files.Add(fullPath);
        }

        options = new LocalMediaLaunchOptions(files
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray());
        return options.Files.Count > 0;
    }

    public static bool IsSupportedMediaFile(string path) =>
        File.Exists(path) && NrMediaFiles.TryGetKind(path) is SecureMediaKind.Audio or SecureMediaKind.Video;
}

public sealed record PlayerOptions(string Pipe, string SelectedPath, IReadOnlyList<MediaPipeCatalogEntry> Entries);
public sealed record MediaPipeCatalogEntry(string Id, string Name, long Length, string Mime, string Kind);
internal sealed record MediaPipeRequest(string Kind, long Start = 0, long Length = 0, string? Message = null, string? Path = null);
internal sealed record MediaPipeResponse(bool Success, string? Error = null, long Start = 0, long Length = 0,
    long TotalLength = 0, string? ContentType = null, IReadOnlyList<MediaPipeCatalogEntry>? Entries = null);

internal static class MediaPipeClient
{
    private const int MaximumFrameBytes = 4 * 1024 * 1024;

    public static async Task<PlayerOptions> OpenSessionAsync(PlayerLaunchOptions launch)
    {
        MediaPipeResponse? hello = null;
        Exception? lastProblem = null;
        for (var attempt = 0; attempt < 20; attempt++)
        {
            try
            {
                using var pipe = Connect(launch.Pipe);
                WriteFrame(pipe, new MediaPipeRequest("hello", Path: launch.SelectedPath));
                hello = ReadFrame<MediaPipeResponse>(pipe);
                if (hello?.Success == true) break;
                lastProblem = new IOException(hello?.Error ?? "凝然加密拒绝建立安全查看会话。");
            }
            catch (Exception exception) when (attempt < 19)
            {
                lastProblem = exception;
            }

            if (attempt < 19) await Task.Delay(50).ConfigureAwait(false);
        }

        if (hello?.Success != true)
        {
            throw new IOException(hello?.Error ?? "凝然加密没有确认安全查看会话。", lastProblem);
        }

        MediaPipeResponse catalog;
        using (var pipe = Connect(launch.Pipe))
        {
            WriteFrame(pipe, new MediaPipeRequest("catalog", Path: launch.SelectedPath));
            catalog = ReadFrame<MediaPipeResponse>(pipe) ?? throw new InvalidDataException("凝然加密没有回应媒体目录请求。");
        }

        if (!catalog.Success) throw new IOException(catalog.Error ?? "凝然加密拒绝提供媒体目录。");
        var entries = ValidateCatalog(catalog.Entries, launch.SelectedPath);
        return new PlayerOptions(launch.Pipe, launch.SelectedPath, entries);
    }

    public static void Notify(PlayerOptions options, MediaPipeCatalogEntry entry, string kind, string? message)
    {
        if (kind is not ("closed" or "problem")) throw new ArgumentOutOfRangeException(nameof(kind));
        using var pipe = Connect(options.Pipe);
        WriteFrame(pipe, new MediaPipeRequest(kind, Message: message, Path: entry.Id));
        var response = ReadFrame<MediaPipeResponse>(pipe) ?? throw new InvalidDataException("凝然加密没有回应播放器状态通知。");
        if (!response.Success) throw new IOException(response.Error ?? "凝然加密拒绝播放器状态通知。");
    }

    public static NamedPipeClientStream OpenRead(PlayerOptions options, MediaPipeCatalogEntry entry, long start, long requestedLength)
    {
        if (start < 0 || start >= entry.Length || requestedLength is <= 0 or > MaximumReadChunkBytes ||
            requestedLength > entry.Length - start)
        {
            throw new ArgumentOutOfRangeException(nameof(requestedLength));
        }
        var pipe = Connect(options.Pipe);
        try
        {
            WriteFrame(pipe, new MediaPipeRequest("read", start, requestedLength, Path: entry.Id));
            var response = ReadFrame<MediaPipeResponse>(pipe) ?? throw new InvalidDataException("凝然加密没有回应媒体读取请求。");
            if (!response.Success) throw new IOException(response.Error ?? "凝然加密拒绝提供媒体内容。");
            if (response.Start != start || response.Length != requestedLength || response.TotalLength != entry.Length ||
                !string.Equals(response.ContentType, entry.Mime, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("凝然加密返回的媒体片段与目录记录不一致。");
            }
            return pipe;
        }
        catch
        {
            pipe.Dispose();
            throw;
        }
    }

    private static IReadOnlyList<MediaPipeCatalogEntry> ValidateCatalog(
        IReadOnlyList<MediaPipeCatalogEntry>? supplied, string selectedPath)
    {
        if (supplied is null or { Count: 0 } || supplied.Count > 20_000)
        {
            throw new InvalidDataException("凝然加密返回的媒体目录为空或过大。");
        }

        var ids = new HashSet<string>(StringComparer.Ordinal);
        var entries = new List<MediaPipeCatalogEntry>(supplied.Count);
        foreach (var entry in supplied)
        {
            if (string.IsNullOrWhiteSpace(entry.Id) || entry.Id.Length > 32_000 ||
                string.IsNullOrWhiteSpace(entry.Name) || entry.Name.Length > 1_024 ||
                entry.Length < 0 || string.IsNullOrWhiteSpace(entry.Mime) || entry.Mime.Length > 256 ||
                entry.Mime.IndexOfAny(['\r', '\n']) >= 0 || entry.Kind is not ("video" or "audio") ||
                !ids.Add(entry.Id))
            {
                throw new InvalidDataException("凝然加密返回的媒体目录记录不正确。");
            }
            entries.Add(entry);
        }

        if (!ids.Contains(selectedPath)) throw new InvalidDataException("凝然加密返回的媒体目录不包含所选文件。");
        return entries.AsReadOnly();
    }

    internal const int MaximumReadChunkBytes = 1024 * 1024;

    private static NamedPipeClientStream Connect(string pipeName)
    {
        var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        try { pipe.Connect(5_000); return pipe; }
        catch { pipe.Dispose(); throw; }
    }

    internal static void WriteFrame(Stream stream, object message)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(message);
        if (bytes.Length > MaximumFrameBytes) throw new InvalidDataException("播放器消息过长。");
        stream.Write(BitConverter.GetBytes(bytes.Length));
        stream.Write(bytes);
        stream.Flush();
    }

    internal static T? ReadFrame<T>(Stream stream)
    {
        Span<byte> prefix = stackalloc byte[sizeof(int)];
        stream.ReadExactly(prefix);
        var length = BitConverter.ToInt32(prefix);
        if (length is <= 0 or > MaximumFrameBytes) throw new InvalidDataException("凝然加密的响应长度不正确。");
        var bytes = new byte[length];
        stream.ReadExactly(bytes);
        return JsonSerializer.Deserialize<T>(bytes);
    }
}

/// <summary>按需向凝然加密请求安全媒体字节；定位时会重新请求对应位置，不保存明文文件。</summary>
internal sealed class PipeMediaStream : Stream
{
    private readonly PlayerOptions _options;
    private readonly MediaPipeCatalogEntry _entry;
    private readonly object _sync = new();
    private NamedPipeClientStream? _pipe;
    private long _pipeRemaining;
    private long _position;
    private bool _disposed;

    public PipeMediaStream(PlayerOptions options, MediaPipeCatalogEntry entry)
    {
        _options = options;
        _entry = entry;
    }

    public override bool CanRead => !_disposed;
    public override bool CanSeek => !_disposed;
    public override bool CanWrite => false;
    public override long Length => _entry.Length;
    public override long Position
    {
        get { lock (_sync) return _position; }
        set { Seek(value, SeekOrigin.Begin); }
    }

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            if (_position >= Length || buffer.Length == 0) return 0;
            EnsureOpenPipe();
            var read = _pipe!.Read(buffer[..(int)Math.Min(buffer.Length, Math.Min(Length - _position, _pipeRemaining))]);
            if (read == 0 && _pipeRemaining > 0)
            {
                throw new EndOfStreamException("凝然加密提供的媒体片段提前结束。");
            }
            _position += read;
            _pipeRemaining -= read;
            if (_pipeRemaining == 0) ClosePipe();
            return read;
        }
    }

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(Read(buffer.Span));
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            var target = origin switch
            {
                SeekOrigin.Begin => offset,
                SeekOrigin.Current => checked(_position + offset),
                SeekOrigin.End => checked(Length + offset),
                _ => throw new ArgumentOutOfRangeException(nameof(origin)),
            };
            if (target < 0) throw new IOException("媒体读取位置不能小于零。");
            _position = Math.Min(target, Length);
            ClosePipe();
            return _position;
        }
    }

    public override void Flush() { }
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            lock (_sync) ClosePipe();
        }
        _disposed = true;
        base.Dispose(disposing);
    }

    private void EnsureOpenPipe()
    {
        if (_pipe is not null) return;
        _pipeRemaining = Math.Min(MediaPipeClient.MaximumReadChunkBytes, Length - _position);
        _pipe = MediaPipeClient.OpenRead(_options, _entry, _position, _pipeRemaining);
    }

    private void ClosePipe()
    {
        _pipe?.Dispose();
        _pipe = null;
        _pipeRemaining = 0;
    }

    private void ThrowIfDisposed()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(PipeMediaStream));
    }
}
