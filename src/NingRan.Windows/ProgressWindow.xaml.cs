using System.ComponentModel;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using NingRan.Core;

namespace NingRan.Windows;

public partial class ProgressWindow : Window
{
    private bool _allowClose;
    private readonly DispatcherTimer _derivingTimer;
    private DateTime _derivingStartedAt;
    private bool _isDeriving;

    public ProgressWindow(bool isEncrypting, string? operationTitle = null)
    {
        InitializeComponent();
        TitleText.Text = UiLanguage.Translate(operationTitle ?? (isEncrypting ? "正在加密并验证" : "正在验证并解密"));
        _derivingTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _derivingTimer.Tick += (_, _) => UpdateDerivingWaitDisplay();
    }

    public event EventHandler? CancelRequested;

    public void UpdateProgress(CryptoProgress progress)
    {
        if (progress.Stage == CryptoStage.DerivingKey)
        {
            BeginDerivingWait();
            CurrentItemText.Text = UiLanguage.Translate("正在加强密码保护") + "…";
            UpdateDerivingWaitDisplay();
            return;
        }

        EndDerivingWait();
        var percent = progress.TotalBytes <= 0 ? 0 : progress.Fraction * 100;
        ProgressBar.Value = percent;
        PercentText.Text = $"{percent:0.0}%";
        CurrentItemText.Text = UiLanguage.Translate(progress.Message);
        RemainingText.Text = progress.EstimatedRemaining is { } remaining
            ? UiLanguage.Translate("预计剩余") + " " + FormatDuration(remaining)
            : UiLanguage.Translate(StageText(progress.Stage));
    }

    public void SetCancelling()
    {
        EndDerivingWait();
        CurrentItemText.Text = UiLanguage.Translate("正在取消并清理未完成内容…");
        RemainingText.Text = UiLanguage.Translate("原文件不会被改动");
        CancelButton.IsEnabled = false;
    }

    public void CloseAfterOperation()
    {
        _allowClose = true;
        Close();
    }

    private void CancelButton_Click(object sender, RoutedEventArgs e)
    {
        SetCancelling();
        CancelRequested?.Invoke(this, EventArgs.Empty);
    }

    private void TitleArea_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.LeftButton == MouseButtonState.Pressed)
        {
            DragMove();
        }
    }

    private void Window_Closing(object? sender, CancelEventArgs e)
    {
        if (!_allowClose)
        {
            e.Cancel = true;
        }
    }

    private void BeginDerivingWait()
    {
        if (_isDeriving) return;
        _isDeriving = true;
        _derivingStartedAt = DateTime.UtcNow;
        ProgressBar.Visibility = Visibility.Collapsed;
        PercentText.Visibility = Visibility.Collapsed;
        _derivingTimer.Start();
    }

    private void EndDerivingWait()
    {
        if (!_isDeriving) return;
        _isDeriving = false;
        _derivingTimer.Stop();
        ProgressBar.Visibility = Visibility.Visible;
        PercentText.Visibility = Visibility.Visible;
        ProgressBar.Value = 0;
        PercentText.Text = "0%";
    }

    private void UpdateDerivingWaitDisplay()
    {
        if (!_isDeriving) return;
        var elapsed = DateTime.UtcNow - _derivingStartedAt;
        var dots = new string('.', (int)(elapsed.TotalSeconds % 4));
        CurrentItemText.Text = UiLanguage.Translate("正在加强密码保护") + dots;
        RemainingText.Text = UiLanguage.Translate("已等待") + " " + FormatDuration(elapsed);
    }

    private static string StageText(CryptoStage stage) => stage switch
    {
        CryptoStage.Preparing => "正在检查所选内容",
        CryptoStage.DerivingKey => "正在加强密码保护",
        CryptoStage.Encrypting => "正在写入加密内容",
        CryptoStage.Verifying => "正在检查加密结果",
        CryptoStage.Decrypting => "正在还原内容",
        CryptoStage.Finalizing => "正在完成保存",
        _ => string.Empty,
    };

    private static string FormatDuration(TimeSpan duration)
    {
        if (duration.TotalHours >= 1)
        {
            return $"{(int)duration.TotalHours} 小时 {duration.Minutes} 分";
        }

        return duration.TotalMinutes >= 1
            ? $"{(int)duration.TotalMinutes} 分 {duration.Seconds} 秒"
            : $"{Math.Max(1, duration.Seconds)} 秒";
    }
}
