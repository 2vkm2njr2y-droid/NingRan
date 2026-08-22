using System.ComponentModel;
using System.Windows;
using System.Windows.Input;
using NingRan.Core;

namespace NingRan.Windows;

public partial class ProgressWindow : Window
{
    private bool _allowClose;

    public ProgressWindow(bool isEncrypting)
    {
        InitializeComponent();
        TitleText.Text = isEncrypting ? "正在加密并验证" : "正在验证并解密";
    }

    public event EventHandler? CancelRequested;

    public void UpdateProgress(CryptoProgress progress)
    {
        var percent = progress.TotalBytes <= 0 ? 0 : progress.Fraction * 100;
        ProgressBar.Value = percent;
        PercentText.Text = $"{percent:0.0}%";
        CurrentItemText.Text = progress.Message;
        RemainingText.Text = progress.EstimatedRemaining is { } remaining
            ? $"预计剩余 {FormatDuration(remaining)}"
            : StageText(progress.Stage);
    }

    public void SetCancelling()
    {
        CurrentItemText.Text = "正在取消并清理未完成内容…";
        RemainingText.Text = "原文件不会被改动";
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
