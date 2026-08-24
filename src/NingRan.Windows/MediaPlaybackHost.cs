using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NingRan.Core;

namespace NingRan.Windows;

/// <summary>
/// 主程序只保留解锁会话；播放器进程只能通过一次性、带随机口令的本地管道按片段读取媒体。
/// 这样播放器故障不会带走主界面，也不会得到密码、密钥或明文文件。
/// </summary>
internal sealed class MediaPlaybackHost : IAsyncDisposable
{
    private const int MaximumRequestBytes = 16 * 1024;
    private readonly SecureArchiveSession _session;
    private readonly SecureArchiveEntry _entry;
    private readonly string _pipeName = $"NingRan.Media.{Environment.ProcessId}.{Guid.NewGuid():N}";
    private readonly string _token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    private readonly CancellationTokenSource _shutdown = new();
    private readonly object _sync = new();
    private Task? _acceptLoop;
    private Process? _player;
    private bool _stopping;
    private bool _playerClosedNormally;
    private string? _playerProblem;

    public MediaPlaybackHost(SecureArchiveSession session, SecureArchiveEntry entry)
    {
        _session = session;
        _entry = entry;
    }

    public event EventHandler<MediaPlayerStoppedEventArgs>? PlayerStoppedUnexpectedly;

    public async Task StartAsync()
    {
        var playerPath = Path.Combine(AppContext.BaseDirectory, "NingRan.MediaPlayer.exe");
        if (!File.Exists(playerPath))
        {
            throw new FileNotFoundException("独立播放器没有随主程序一起安装。请重新安装最新版凝然加密。", playerPath);
        }

        _acceptLoop = Task.Run(AcceptLoopAsync);
        try
        {
            var info = new ProcessStartInfo
            {
                FileName = playerPath,
                WorkingDirectory = AppContext.BaseDirectory,
                UseShellExecute = false,
                RedirectStandardInput = true,
            };
            info.ArgumentList.Add("--pipe");
            info.ArgumentList.Add(_pipeName);
            info.ArgumentList.Add("--name");
            info.ArgumentList.Add(_entry.Name);
            info.ArgumentList.Add("--length");
            info.ArgumentList.Add(_entry.Length.ToString(System.Globalization.CultureInfo.InvariantCulture));
            info.ArgumentList.Add("--mime");
            info.ArgumentList.Add(NrMediaFiles.GetContentType(_entry.Name));
            info.ArgumentList.Add("--kind");
            info.ArgumentList.Add(_entry.MediaKind == SecureMediaKind.Audio ? "audio" : "video");

            var player = Process.Start(info) ?? throw new InvalidOperationException("Windows 没有启动独立播放器。");
            await player.StandardInput.WriteLineAsync(_token).ConfigureAwait(false);
            await player.StandardInput.FlushAsync().ConfigureAwait(false);
            player.StandardInput.Close();
            player.EnableRaisingEvents = true;
            player.Exited += Player_Exited;
            lock (_sync) _player = player;
            await Task.Delay(350, _shutdown.Token).ConfigureAwait(false);
            if (player.HasExited)
            {
                throw new InvalidOperationException("独立播放器刚启动就退出了。请查看崩溃报告或重新安装最新版程序。");
            }
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
            var request = await ReadFrameAsync<MediaPipeRequest>(server, _shutdown.Token).ConfigureAwait(false);
            if (request is null || !TokenMatches(request.Token))
            {
                await WriteFrameAsync(server, new MediaPipeResponse(false, "未通过播放器连接验证。"), _shutdown.Token).ConfigureAwait(false);
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

            if (!string.Equals(request.Kind, "read", StringComparison.Ordinal))
            {
                await WriteFrameAsync(server, new MediaPipeResponse(false, "播放器请求类型不正确。"), _shutdown.Token).ConfigureAwait(false);
                return;
            }

            if (request.Start < 0 || request.Start >= _entry.Length || request.Length <= 0)
            {
                await WriteFrameAsync(server, new MediaPipeResponse(false, "读取位置超出媒体范围。"), _shutdown.Token).ConfigureAwait(false);
                return;
            }

            var length = Math.Min(request.Length, _entry.Length - request.Start);
            await WriteFrameAsync(server, new MediaPipeResponse(true, null, request.Start, length, _entry.Length,
                NrMediaFiles.GetContentType(_entry.Name)), _shutdown.Token).ConfigureAwait(false);

            await using var source = _session.OpenEntryReadStream(_entry.RelativePath);
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
            _entry.Name, _playerProblem ?? $"独立播放器意外退出（退出代码 {exitCode}）。"));
    }

    public async ValueTask DisposeAsync()
    {
        _stopping = true;
        _shutdown.Cancel();
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

    private bool TokenMatches(string? supplied)
    {
        if (string.IsNullOrWhiteSpace(supplied)) return false;
        var expectedBytes = Encoding.UTF8.GetBytes(_token);
        var suppliedBytes = Encoding.UTF8.GetBytes(supplied);
        try { return CryptographicOperations.FixedTimeEquals(expectedBytes, suppliedBytes); }
        finally
        {
            CryptographicOperations.ZeroMemory(expectedBytes);
            CryptographicOperations.ZeroMemory(suppliedBytes);
        }
    }

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
internal sealed record MediaPipeRequest(string Kind, string? Token, long Start = 0, long Length = 0, string? Message = null);
internal sealed record MediaPipeResponse(bool Success, string? Error = null, long Start = 0, long Length = 0,
    long TotalLength = 0, string? ContentType = null);
