using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text.Json;
using System.Runtime.InteropServices;
using NingRan.Core;

namespace NingRan.Windows;

/// <summary>
/// 主程序只保留解锁会话；外部查看器只能通过受当前 Windows 用户限制、并逐次核对
/// 已启动播放器进程编号的本地管道按片段读取媒体。
/// 查看器不会得到密码、密匙、数据密钥或明文文件路径，管道中也不传递密钥或会话口令。
/// </summary>
internal sealed class MediaPlaybackHost : IAsyncDisposable
{
    private const int MaximumRequestBytes = 4 * 1024 * 1024;
    private const int MaximumMediaChunkBytes = 1024 * 1024;
    private readonly SecureArchiveSession _session;
    private readonly IReadOnlyDictionary<string, SecureArchiveEntry> _entries;
    private readonly string _initialEntryId;
    private readonly string _pipeName = $"NingRan.Media.{Environment.ProcessId}.{Guid.NewGuid():N}";
    private readonly CancellationTokenSource _shutdown = new();
    private readonly TaskCompletionSource _secureSessionConfirmed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly object _sync = new();
    private Task? _acceptLoop;
    private Process? _player;
    private bool _stopping;
    private int _disposeStarted;
    private bool _playerClosedNormally;
    private string? _playerProblem;

    public MediaPlaybackHost(SecureArchiveSession session, IReadOnlyList<SecureArchiveEntry> entries, SecureArchiveEntry initialEntry)
    {
        _session = session;
        // Media-Helper 自身已经支持音频、视频、图片和 PDF；这些条目都由
        // 独立窗口安全查看。无法启动或未安装时，调用方会回退内置查看器。
        _entries = entries.Where(CanOpenWithExternalViewer)
            .ToDictionary(entry => entry.RelativePath, StringComparer.Ordinal);
        if (_entries.Count == 0 || !_entries.ContainsKey(initialEntry.RelativePath))
        {
            throw new ArgumentException("安全查看器没有可打开的媒体文件。", nameof(entries));
        }
        _initialEntryId = initialEntry.RelativePath;
    }

    public event EventHandler<MediaPlayerStoppedEventArgs>? PlayerStoppedUnexpectedly;

    public static bool CanOpenWithExternalViewer(SecureArchiveEntry entry) =>
        !entry.IsDirectory &&
        entry.MediaKind is SecureMediaKind.Audio or SecureMediaKind.Video or
            SecureMediaKind.Image or SecureMediaKind.Pdf;

    public static string? FindExternalViewer()
    {
        // 播放器独立安装在受保护的 Program Files 目录。不要接受环境变量、当前
        // 文件夹或用户目录中的同名程序，否则解锁会话可能被交给伪装的查看器。
        var playerDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "media-helper");
        var candidate = Path.GetFullPath(Path.Combine(playerDirectory, "凝然媒体播放器.exe"));
        return string.Equals(
                   Path.GetDirectoryName(candidate),
                   Path.TrimEndingDirectorySeparator(Path.GetFullPath(playerDirectory)),
                   StringComparison.OrdinalIgnoreCase) &&
               File.Exists(candidate)
            ? candidate
            : null;
    }

    public async Task StartAsync(string playerPath)
    {
        if (NingRanRuntime.IsProcessElevated())
        {
            throw new InvalidOperationException("管理员高安全窗口禁止启动外部媒体查看器。");
        }

        var trustedViewerPath = FindExternalViewer();
        if (string.IsNullOrWhiteSpace(playerPath) ||
            trustedViewerPath is null ||
            !string.Equals(
                Path.GetFullPath(playerPath),
                Path.GetFullPath(trustedViewerPath),
                StringComparison.OrdinalIgnoreCase) ||
            !File.Exists(playerPath))
        {
            throw new FileNotFoundException("没有找到已独立安装的凝然媒体查看器。", playerPath);
        }

        _acceptLoop = Task.Run(AcceptLoopAsync);
        try
        {
            var info = new ProcessStartInfo
            {
                FileName = playerPath,
                WorkingDirectory = Path.GetDirectoryName(playerPath) ?? AppContext.BaseDirectory,
                UseShellExecute = false,
                RedirectStandardInput = false,
            };
            info.ArgumentList.Add("--ningran-secure-pipe");
            info.ArgumentList.Add(_pipeName);
            info.ArgumentList.Add("--ningran-selected");
            info.ArgumentList.Add(_initialEntryId);

            var player = Process.Start(info) ?? throw new InvalidOperationException("Windows 没有启动独立播放器。");
            player.EnableRaisingEvents = true;
            player.Exited += Player_Exited;
            lock (_sync) _player = player;
            await _secureSessionConfirmed.Task.WaitAsync(TimeSpan.FromSeconds(5), _shutdown.Token).ConfigureAwait(false);
        }
        catch
        {
            await DisposeAsync();
            throw;
        }
    }

    private async Task AcceptLoopAsync()
    {
        try
        {
            while (!_shutdown.IsCancellationRequested)
            {
                var server = new NamedPipeServerStream(_pipeName, PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
                try
                {
                    await server.WaitForConnectionAsync(_shutdown.Token).ConfigureAwait(false);
                    _ = Task.Run(() => ServeClientAsync(server));
                }
                catch
                {
                    server.Dispose();
                    throw;
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (IOException) when (_shutdown.IsCancellationRequested)
        {
        }
    }

    private async Task ServeClientAsync(NamedPipeServerStream server)
    {
        await using var ownedServer = server;
        try
        {
            if (!IsLaunchedPlayerConnection(server))
            {
                await WriteFrameAsync(server, new MediaPipeResponse(false, "连接来源不是本次启动的凝然媒体查看器。"), _shutdown.Token).ConfigureAwait(false);
                return;
            }

            var request = await ReadFrameAsync<MediaPipeRequest>(server, _shutdown.Token).ConfigureAwait(false);
            if (request is null)
            {
                await WriteFrameAsync(server, new MediaPipeResponse(false, "未通过播放器连接验证。"), _shutdown.Token).ConfigureAwait(false);
                return;
            }

            if (string.Equals(request.Kind, "hello", StringComparison.Ordinal))
            {
                if (!string.Equals(request.Path, _initialEntryId, StringComparison.Ordinal))
                {
                    await WriteFrameAsync(server, new MediaPipeResponse(false, "播放器请求的初始媒体不正确。"), _shutdown.Token).ConfigureAwait(false);
                    return;
                }
                await WriteFrameAsync(server, new MediaPipeResponse(true), _shutdown.Token).ConfigureAwait(false);
                return;
            }

            if (string.Equals(request.Kind, "closed", StringComparison.Ordinal))
            {
                _playerClosedNormally = true;
                await WriteFrameAsync(server, new MediaPipeResponse(true), _shutdown.Token).ConfigureAwait(false);
                return;
            }

            if (string.Equals(request.Kind, "problem", StringComparison.Ordinal))
            {
                _playerProblem = string.IsNullOrWhiteSpace(request.Message) ? "独立播放器发生了未说明的错误。" : request.Message;
                await WriteFrameAsync(server, new MediaPipeResponse(true), _shutdown.Token).ConfigureAwait(false);
                return;
            }

            if (string.Equals(request.Kind, "catalog", StringComparison.Ordinal))
            {
                var files = _entries.Values.Select(entry => new MediaPipeCatalogEntry(
                    entry.RelativePath,
                    entry.Name,
                    entry.Length,
                    NrMediaFiles.GetContentType(entry.Name),
                    entry.MediaKind switch
                    {
                        SecureMediaKind.Video => "video",
                        SecureMediaKind.Audio => "audio",
                        SecureMediaKind.Image => "image",
                        SecureMediaKind.Pdf => "pdf",
                        _ => "text",
                    })).ToArray();
                await WriteFrameAsync(server, new MediaPipeResponse(true, Entries: files), _shutdown.Token).ConfigureAwait(false);
                _secureSessionConfirmed.TrySetResult();
                return;
            }

            if (!string.Equals(request.Kind, "read", StringComparison.Ordinal))
            {
                await WriteFrameAsync(server, new MediaPipeResponse(false, "播放器请求类型不正确。"), _shutdown.Token).ConfigureAwait(false);
                return;
            }

            if (string.IsNullOrWhiteSpace(request.Path) || !_entries.TryGetValue(request.Path, out var entry) ||
                request.Start < 0 || request.Start >= entry.Length || request.Length is <= 0 or > MaximumMediaChunkBytes)
            {
                await WriteFrameAsync(server, new MediaPipeResponse(false, "读取位置或本次读取大小不符合安全查看要求。"), _shutdown.Token).ConfigureAwait(false);
                return;
            }

            var length = Math.Min(request.Length, entry.Length - request.Start);
            await WriteFrameAsync(server, new MediaPipeResponse(true, null, request.Start, length, entry.Length,
                NrMediaFiles.GetContentType(entry.Name)), _shutdown.Token).ConfigureAwait(false);

            await using var source = _session.OpenEntryReadStream(entry.RelativePath);
            source.Position = request.Start;
            await CopyExactlyAsync(source, server, length, _shutdown.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception exception)
        {
            _playerProblem ??= $"媒体读取失败：{exception.GetType().Name}：{exception.Message}";
            try { await WriteFrameAsync(server, new MediaPipeResponse(false, "主程序无法继续提供媒体片段。"), CancellationToken.None).ConfigureAwait(false); }
            catch { }
        }
    }

    private void Player_Exited(object? sender, EventArgs e)
    {
        var player = sender as Process;
        var exitCode = -1;
        try { exitCode = player?.ExitCode ?? -1; } catch { }
        if (_stopping || _playerClosedNormally || exitCode == 0)
        {
            return;
        }

        PlayerStoppedUnexpectedly?.Invoke(this, new MediaPlayerStoppedEventArgs(
            _entries[_initialEntryId].Name, _playerProblem ?? $"凝然媒体查看器意外退出（退出代码 {exitCode}）。"));
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposeStarted, 1) != 0)
        {
            return;
        }
        _stopping = true;
        try { _shutdown.Cancel(); }
        catch (ObjectDisposedException) { return; }
        Process? player;
        lock (_sync)
        {
            player = _player;
            _player = null;
        }

        if (player is not null)
        {
            try
            {
                if (!player.HasExited) player.CloseMainWindow();
                await player.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            }
            catch
            {
                try { if (!player.HasExited) player.Kill(entireProcessTree: true); } catch { }
            }
            finally { player.Dispose(); }
        }

        if (_acceptLoop is not null)
        {
            try { await _acceptLoop.ConfigureAwait(false); } catch { }
        }
        _shutdown.Dispose();
    }

    public async Task<int> WaitForExitAsync()
    {
        Process? player;
        lock (_sync) player = _player;
        if (player is null) throw new InvalidOperationException("查看器尚未启动。");
        await player.WaitForExitAsync().ConfigureAwait(false);
        return player.ExitCode;
    }

    private bool IsLaunchedPlayerConnection(NamedPipeServerStream server)
    {
        Process? player;
        lock (_sync) player = _player;
        if (player is null || player.HasExited || !GetNamedPipeClientProcessId(server.SafePipeHandle, out var clientProcessId)) return false;
        return clientProcessId == player.Id;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(Microsoft.Win32.SafeHandles.SafePipeHandle pipe, out uint clientProcessId);

    internal static async Task<T?> ReadFrameAsync<T>(Stream stream, CancellationToken cancellationToken)
    {
        var prefix = new byte[sizeof(int)];
        await stream.ReadExactlyAsync(prefix, cancellationToken).ConfigureAwait(false);
        var length = BitConverter.ToInt32(prefix, 0);
        if (length is <= 0 or > MaximumRequestBytes) throw new InvalidDataException("播放器请求长度不正确。");
        var bytes = new byte[length];
        await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
        return JsonSerializer.Deserialize<T>(bytes);
    }

    internal static async Task WriteFrameAsync(Stream stream, object value, CancellationToken cancellationToken)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(value);
        if (bytes.Length > MaximumRequestBytes) throw new InvalidDataException("播放器响应过长。");
        await stream.WriteAsync(BitConverter.GetBytes(bytes.Length), cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task CopyExactlyAsync(Stream source, Stream destination, long count, CancellationToken cancellationToken)
    {
        var buffer = new byte[128 * 1024];
        try
        {
            while (count > 0)
            {
                var read = await source.ReadAsync(buffer.AsMemory(0, (int)Math.Min(buffer.Length, count)), cancellationToken).ConfigureAwait(false);
                if (read == 0) throw new EndOfStreamException("媒体内容提前结束。");
                await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                count -= read;
            }
            await destination.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(buffer); }
    }
}

internal sealed class MediaPlayerStoppedEventArgs : EventArgs
{
    public MediaPlayerStoppedEventArgs(string fileName, string reason)
    {
        FileName = fileName;
        Reason = reason;
    }

    public string FileName { get; }
    public string Reason { get; }
}
internal sealed record MediaPipeRequest(string Kind, long Start = 0, long Length = 0, string? Message = null, string? Path = null);
internal sealed record MediaPipeResponse(bool Success, string? Error = null, long Start = 0, long Length = 0,
    long TotalLength = 0, string? ContentType = null, IReadOnlyList<MediaPipeCatalogEntry>? Entries = null);
internal sealed record MediaPipeCatalogEntry(string Id, string Name, long Length, string Mime, string Kind);
