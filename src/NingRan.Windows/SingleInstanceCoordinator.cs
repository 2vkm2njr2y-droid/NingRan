using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Windows.Threading;
using Microsoft.Win32.SafeHandles;

namespace NingRan.Windows;

internal sealed class SingleInstanceCoordinator : IDisposable
{
    private const string ProtocolActivationOnly = "-";
    private const int MaximumMessageCharacters = 256 * 1024;
    private readonly Mutex _mutex;
    private readonly CancellationTokenSource _cancellation = new();
    private readonly Dispatcher _dispatcher;
    private readonly Queue<string?> _pendingRequests = [];
    private readonly string _pipeName;
    private Action<string?>? _requestHandler;
    private Task? _listenerTask;
    private bool _ownsMutex;
    private bool _disposed;

    public SingleInstanceCoordinator(Dispatcher dispatcher)
    {
        _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
        var identitySuffix = CreateIdentitySuffix();
        _pipeName = $"NingRan.Encryption.6.{identitySuffix}";
        _mutex = new Mutex(initiallyOwned: false, $"Local\\{_pipeName}.Mutex");
        try
        {
            _ownsMutex = _mutex.WaitOne(0);
        }
        catch (AbandonedMutexException)
        {
            _ownsMutex = true;
        }
    }

    public bool IsPrimaryInstance => _ownsMutex;

    public void StartListening()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!IsPrimaryInstance || _listenerTask is not null)
        {
            return;
        }

        _listenerTask = ListenAsync(_cancellation.Token);
    }

    public void SetRequestHandler(Action<string?> handler)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(handler);
        _requestHandler = handler;
        while (_pendingRequests.TryDequeue(out var request))
        {
            handler(request);
        }
    }

    public async Task<bool> NotifyPrimaryAsync(
        string? associatedFile,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (IsPrimaryInstance)
        {
            return false;
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        try
        {
            await using var client = new NamedPipeClientStream(
                ".",
                _pipeName,
                PipeDirection.InOut,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
            await client.ConnectAsync(timeout.Token).ConfigureAwait(false);
            AllowServerToTakeForeground(client.SafePipeHandle);

            var message = associatedFile is null
                ? ProtocolActivationOnly
                : Convert.ToBase64String(Encoding.UTF8.GetBytes(Path.GetFullPath(associatedFile)));
            await using var writer = new StreamWriter(client, new UTF8Encoding(false), leaveOpen: true)
            {
                AutoFlush = true,
            };
            using var reader = new StreamReader(client, Encoding.UTF8, leaveOpen: true);
            await writer.WriteLineAsync(message.AsMemory(), timeout.Token).ConfigureAwait(false);
            var response = await reader.ReadLineAsync(timeout.Token).ConfigureAwait(false);
            return string.Equals(response, "OK", StringComparison.Ordinal);
        }
        catch (Exception exception) when (exception is IOException or TimeoutException or OperationCanceledException)
        {
            return false;
        }
    }

    private async Task ListenAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await using var server = new NamedPipeServerStream(
                    _pipeName,
                    PipeDirection.InOut,
                    maxNumberOfServerInstances: 1,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
                await server.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
                using var reader = new StreamReader(server, Encoding.UTF8, leaveOpen: true);
                await using var writer = new StreamWriter(server, new UTF8Encoding(false), leaveOpen: true)
                {
                    AutoFlush = true,
                };
                var message = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
                if (message is null || message.Length > MaximumMessageCharacters)
                {
                    await writer.WriteLineAsync("ERROR").ConfigureAwait(false);
                    continue;
                }

                string? path;
                try
                {
                    path = string.Equals(message, ProtocolActivationOnly, StringComparison.Ordinal)
                        ? null
                        : Encoding.UTF8.GetString(Convert.FromBase64String(message));
                }
                catch (FormatException)
                {
                    await writer.WriteLineAsync("ERROR").ConfigureAwait(false);
                    continue;
                }

                QueueRequest(path);
                await writer.WriteLineAsync("OK").ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (IOException) when (!cancellationToken.IsCancellationRequested)
            {
                // 连接可能在发送完成前关闭；继续等待下一次启动通知。
            }
        }
    }

    private void QueueRequest(string? path)
    {
        _dispatcher.BeginInvoke(() =>
        {
            if (_requestHandler is null)
            {
                _pendingRequests.Enqueue(path);
            }
            else
            {
                _requestHandler(path);
            }
        });
    }

    private static string CreateIdentitySuffix()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var sid = identity.User?.Value
            ?? throw new InvalidOperationException("无法确定当前 Windows 用户。");
        var sidBytes = Encoding.UTF8.GetBytes(sid);
        try
        {
            var hash = SHA256.HashData(sidBytes);
            try
            {
                return Convert.ToHexString(hash.AsSpan(0, 16));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(hash);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sidBytes);
        }
    }

    private static void AllowServerToTakeForeground(SafePipeHandle pipeHandle)
    {
        if (GetNamedPipeServerProcessId(pipeHandle, out var processId))
        {
            _ = AllowSetForegroundWindow(processId);
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _cancellation.Cancel();
        if (_ownsMutex)
        {
            try
            {
                _mutex.ReleaseMutex();
            }
            catch (ApplicationException)
            {
                // 进程关闭时互斥锁可能已经由运行时释放。
            }

            _ownsMutex = false;
        }

        _mutex.Dispose();
        _cancellation.Dispose();
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(
        SafePipeHandle pipe,
        out uint serverProcessId);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AllowSetForegroundWindow(uint processId);
}
