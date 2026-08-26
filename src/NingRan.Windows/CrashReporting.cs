using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using NingRan.Core;

namespace NingRan.Windows;

/// <summary>
/// 错误报告只在当前提示窗口存在期间保留。它会记录诊断所需的组件和错误信息，
/// 但会隐藏本机路径以及可能形似密码或密钥的字段。
/// </summary>
internal static class CrashReportService
{
    private static string DirectoryPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "NingRan", "CrashReports");

    public static void CleanupPreviousReports()
    {
        if (NingRanRuntime.IsProcessElevated())
        {
            return;
        }

        try
        {
            if (!Directory.Exists(DirectoryPath)) return;
            foreach (var file in Directory.EnumerateFiles(DirectoryPath, "*.json")) File.Delete(file);
        }
        catch { /* 下次启动仍会再尝试，不能因为删除报告失败而阻止程序打开。 */ }
    }

    public static string Create(string feature, string message, Exception? exception = null)
    {
        if (NingRanRuntime.IsProcessElevated())
        {
            throw new InvalidOperationException("管理员模式不创建普通用户目录中的错误报告。");
        }

        Directory.CreateDirectory(DirectoryPath);
        var path = Path.Combine(DirectoryPath, $"report-{DateTime.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}.json");
        var report = new CrashReport(DateTimeOffset.UtcNow, feature, Redact(message),
            exception?.GetType().FullName, exception is null ? null : Redact(exception.ToString()),
            Environment.OSVersion.VersionString, Environment.ProcessId, "<已隐藏>");
        File.WriteAllText(path, JsonSerializer.Serialize(report, CrashReportJsonContext.Default.CrashReport));
        return path;
    }

    public static void Delete(string? path)
    {
        if (NingRanRuntime.IsProcessElevated() || string.IsNullOrWhiteSpace(path)) return;
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }

    private static string Redact(string text)
    {
        var withoutPaths = Regex.Replace(text, @"(?i)([A-Z]:\\|\\\\)[^\r\n]+", "<本机路径已隐藏>");
        return Regex.Replace(withoutPaths, @"(?i)(password|密码|密匙|密钥|key)\s*[:=]\s*\S+", "$1=<已隐藏>");
    }
}

internal sealed record CrashReport(DateTimeOffset OccurredAtUtc, string Feature, string Message,
    string? ExceptionType, string? ExceptionDetails, string WindowsVersion, int ProcessId, string AppDirectory);

internal sealed class CrashReportDialog : Window
{
    private readonly string _path;

    private CrashReportDialog(Window? owner, string title, string summary, string path)
    {
        _path = path;
        Owner = owner;
        Title = UiLanguage.Translate(title);
        Width = 620;
        Height = 380;
        MinWidth = 520;
        MinHeight = 300;
        WindowStartupLocation = owner is null ? WindowStartupLocation.CenterScreen : WindowStartupLocation.CenterOwner;
        var reportText = File.ReadAllText(path);
        var export = new Button { Content = UiLanguage.Translate("导出报告"), Padding = new Thickness(16, 6, 16, 6), Margin = new Thickness(0, 14, 8, 0) };
        export.Click += Export_Click;
        var close = new Button { Content = UiLanguage.Translate("关闭"), IsDefault = true, IsCancel = true, Padding = new Thickness(18, 6, 18, 6), Margin = new Thickness(0, 14, 0, 0) };
        var description = new TextBlock
        {
            Text = UiLanguage.IsEnglish
                ? summary + "\n\nA temporary detailed report was generated. It contains no passwords, keys, file contents, or full local paths; you can export it now. The report is deleted when this window closes."
                : summary + "\n\n已生成临时详细报告。报告不包含密码、密钥、文件内容或本机完整路径；您可以现在导出。关闭此窗口后报告会自动删除。",
            TextWrapping = TextWrapping.Wrap,
        };
        var details = new TextBox
        {
            Margin = new Thickness(0, 14, 0, 0), Text = reportText, IsReadOnly = true, TextWrapping = TextWrapping.Wrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto, FontFamily = new System.Windows.Media.FontFamily("Consolas"), FontSize = 11,
        };
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Children = { export, close } };
        Grid.SetRow(details, 1);
        Grid.SetRow(buttons, 2);
        Content = new Border
        {
            Padding = new Thickness(20),
            Child = new Grid
            {
                RowDefinitions = { new RowDefinition { Height = GridLength.Auto }, new RowDefinition(), new RowDefinition { Height = GridLength.Auto } },
                Children =
                {
                    description,
                    details,
                    buttons,
                }
            }
        };
        Closed += (_, _) => CrashReportService.Delete(_path);
    }

    public static void ShowTemporary(Window? owner, string title, string summary, string feature, Exception? exception = null)
    {
        string? path = null;
        try
        {
            path = CrashReportService.Create(feature, summary, exception);
            new CrashReportDialog(owner, title, summary, path).ShowDialog();
        }
        catch
        {
            if (owner is not null) MessageBox.Show(owner, summary, title, MessageBoxButton.OK, MessageBoxImage.Error);
            else MessageBox.Show(summary, title, MessageBoxButton.OK, MessageBoxImage.Error);
            CrashReportService.Delete(path);
        }
    }

    private void Export_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog
        {
            Title = UiLanguage.Translate("导出错误报告"),
            FileName = UiLanguage.IsEnglish ? $"NingRan-error-report-{DateTime.Now:yyyyMMdd-HHmmss}.json" : $"凝然错误报告-{DateTime.Now:yyyyMMdd-HHmmss}.json",
            Filter = UiLanguage.Translate("报告文件|*.json"),
        };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            File.Copy(_path, dialog.FileName, overwrite: false);
            MessageBox.Show(this, "错误报告已导出。", "凝然加密", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception exception)
        {
            MessageBox.Show(this, exception.Message, "无法导出错误报告", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }
}

[System.Text.Json.Serialization.JsonSerializable(typeof(CrashReport))]
[System.Text.Json.Serialization.JsonSourceGenerationOptions(WriteIndented = true)]
internal partial class CrashReportJsonContext : JsonSerializerContext;
