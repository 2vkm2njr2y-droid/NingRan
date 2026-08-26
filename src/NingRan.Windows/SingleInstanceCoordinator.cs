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
    private readonly Mutex _mutex;
    private readonly CancellationTokenSource _cancellation = new();
    private readonly Dispatcher _dispatcher;
    private readonly Queue<string?> _pendingRequests = [];
    private readonly string _pipeName;
    private readonly string? _trustedExecutablePath;
    private Action<string?>? _requestHandler;
    private Task? _listenerTask;
    private bool _ownsMutex;
    private bool _disposed;

    public SingleInstanceCoordinator(Dispatcher dispatcher)
    {
        _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
        var identitySuffix = CreateIdentitySuffix();
        _pipeName = $"NingRan.Encryption.6.{identitySuffix}";
        _trustedExecutablePath = SingleInstanceProcessIdentity.GetCurrentTrustedExecutablePath();
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
        if (!IsPrimaryInstance || _listenerTask is not null || _trustedExecutablePath is null)
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

    public async Task<bool> NotifyPrimaryAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (IsPrimaryInstance)
        {
            return false;
        }

        // 开发目录或其他可写位置无法防止同一用户替换程序文件，因此不通过管道传送文件路径。
        if (_trustedExecutablePath is null)
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
            if (!GetNamedPipeServerProcessId(client.SafePipeHandle, out var serverProcessId) ||
                !SingleInstanceProcessIdentity.IsMatchingTrustedProcess(serverProcessId, _trustedExecutablePath))
            {
                return false;
            }

            await using var writer = new StreamWriter(client, new UTF8Encoding(false), leaveOpen: true)
            {
                AutoFlush = true,
            };
            using var reader = new StreamReader(client, Encoding.UTF8, leaveOpen: true);
            // 单实例通道只发送无敏感内容的“激活”通知。文件路径始终由新进程自己处理。
            await writer.WriteLineAsync(ProtocolActivationOnly.AsMemory(), timeout.Token).ConfigureAwait(false);
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
                if (!GetNamedPipeClientProcessId(server.SafePipeHandle, out var clientProcessId) ||
                    _trustedExecutablePath is null ||
                    !SingleInstanceProcessIdentity.IsMatchingTrustedProcess(clientProcessId, _trustedExecutablePath))
                {
                    continue;
                }

                using var reader = new StreamReader(server, Encoding.UTF8, leaveOpen: true);
                await using var writer = new StreamWriter(server, new UTF8Encoding(false), leaveOpen: true)
                {
                    AutoFlush = true,
                };
                var message = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
                if (!string.Equals(message, ProtocolActivationOnly, StringComparison.Ordinal))
                {
                    await writer.WriteLineAsync("ERROR").ConfigureAwait(false);
                    continue;
                }

                QueueRequest(null);
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

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(
        SafePipeHandle pipe,
        out uint clientProcessId);

}

internal static class SingleInstanceProcessIdentity
{
    private const uint ProcessQueryLimitedInformation = 0x1000;

    public static string? GetCurrentTrustedExecutablePath()
    {
        var path = Normalize(Environment.ProcessPath);
        return path is not null && HighSecurityLaunch.IsTrustedInstalledComponent(path, "NingRan.exe")
            ? path
            : null;
    }

    public static bool IsMatchingTrustedProcess(uint processId, string expectedExecutablePath)
    {
        if (processId == 0 || processId > int.MaxValue || processId == (uint)Environment.ProcessId)
        {
            return false;
        }

        var actualPath = GetProcessImagePath(processId);
        return actualPath is not null &&
               string.Equals(actualPath, expectedExecutablePath, StringComparison.OrdinalIgnoreCase) &&
               HighSecurityLaunch.IsTrustedInstalledComponent(actualPath, "NingRan.exe");
    }

    private static string? GetProcessImagePath(uint processId)
    {
        using var process = OpenProcess(ProcessQueryLimitedInformation, inheritHandle: false, processId);
        if (process.IsInvalid)
        {
            return null;
        }

        var capacity = 32_768;
        var path = new StringBuilder(capacity);
        return QueryFullProcessImageName(process, flags: 0, path, ref capacity)
            ? Normalize(path.ToString())
            : null;
    }

    private static string? Normalize(string? path)
    {
        try
        {
            return string.IsNullOrWhiteSpace(path) ? null : Path.GetFullPath(path);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return null;
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        uint processId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(
        SafeProcessHandle process,
        uint flags,
        StringBuilder executableName,
        ref int size);
}
