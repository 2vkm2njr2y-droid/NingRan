namespace NingRan.Core.Internal;

internal sealed class PhysicalDeviceMonitor : IAsyncDisposable
{
    private readonly IReadOnlyList<PhysicalDeviceUnlock> _unlocks;
    private readonly Func<bool>? _forbiddenPresent;
    private readonly CancellationTokenSource _stop = new();
    private readonly CancellationTokenSource _linked;
    private readonly Task _monitorTask;

    public PhysicalDeviceMonitor(
        IReadOnlyList<PhysicalDeviceUnlock> unlocks,
        CancellationToken operationCancellation,
        Func<bool>? forbiddenPresent = null)
    {
        _unlocks = unlocks;
        _forbiddenPresent = forbiddenPresent;
        _linked = CancellationTokenSource.CreateLinkedTokenSource(operationCancellation, _stop.Token);
        _monitorTask = MonitorAsync(operationCancellation);
    }

    public CancellationToken Token => _linked.Token;

    public bool DeviceLost { get; private set; }

    public void ThrowIfDeviceLost()
    {
        if (DeviceLost)
        {
            throw new NingRanException("物理密匙不再满足解锁规则，操作已经取消，未完成内容将被清理。 ");
        }
    }

    public async ValueTask DisposeAsync()
    {
        _stop.Cancel();
        try
        {
            await _monitorTask.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }

        _linked.Dispose();
        _stop.Dispose();
    }

    private async Task MonitorAsync(CancellationToken operationCancellation)
    {
        while (!_stop.IsCancellationRequested && !operationCancellation.IsCancellationRequested)
        {
            if (_forbiddenPresent?.Invoke() == true)
            {
                DeviceLost = true;
                _linked.Cancel();
                return;
            }
            foreach (var unlock in _unlocks)
            {
                if (!unlock.IsPresent)
                {
                    DeviceLost = true;
                    _linked.Cancel();
                    return;
                }
            }

            await Task.Delay(250, _stop.Token).ConfigureAwait(false);
        }
    }
}
