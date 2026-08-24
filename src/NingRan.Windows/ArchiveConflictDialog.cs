using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace NingRan.Windows;

internal enum ArchiveConflictChoice
{
    Cancel,
    KeepBoth,
    Replace,
}

internal sealed class ArchiveConflictDialog : Window
{
    private ArchiveConflictDialog(string name, long existingSize, long incomingSize)
    {
        Title = "发现同名内容";
        Width = 430;
        SizeToContent = SizeToContent.Height;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ResizeMode = ResizeMode.NoResize;
        ShowInTaskbar = false;
        Background = Brushes.White;

        var panel = new StackPanel { Margin = new Thickness(22) };
        panel.Children.Add(new TextBlock
        {
            Text = "目标文件夹中已有同名内容",
            FontSize = 16,
            FontWeight = FontWeights.SemiBold,
        });
        panel.Children.Add(new TextBlock
        {
            Text = $"名称：{name}\n现有大小：{FormatSize(existingSize)}\n追加内容大小：{FormatSize(incomingSize)}",
            Margin = new Thickness(0, 12, 0, 18),
            TextWrapping = TextWrapping.Wrap,
            Foreground = new SolidColorBrush(Color.FromRgb(75, 89, 84)),
        });
        var buttons = new WrapPanel { HorizontalAlignment = HorizontalAlignment.Right };
        buttons.Children.Add(CreateButton("保留二者", ArchiveConflictChoice.KeepBoth, true));
        buttons.Children.Add(CreateButton("替换", ArchiveConflictChoice.Replace, false));
        buttons.Children.Add(CreateButton("取消", ArchiveConflictChoice.Cancel, false));
        panel.Children.Add(buttons);
        Content = panel;
    }

    public ArchiveConflictChoice Choice { get; private set; } = ArchiveConflictChoice.Cancel;

    public static ArchiveConflictChoice Show(Window owner, string name, long existingSize, long incomingSize)
    {
        var dialog = new ArchiveConflictDialog(name, existingSize, incomingSize) { Owner = owner };
        dialog.ShowDialog();
        return dialog.Choice;
    }

    private Button CreateButton(string text, ArchiveConflictChoice choice, bool primary)
    {
        var button = new Button
        {
            Content = text,
            Padding = new Thickness(12, 6, 12, 6),
            Margin = new Thickness(7, 0, 0, 0),
            Background = primary ? new SolidColorBrush(Color.FromRgb(38, 126, 91)) : Brushes.White,
            Foreground = primary ? Brushes.White : new SolidColorBrush(Color.FromRgb(38, 88, 68)),
            BorderBrush = new SolidColorBrush(Color.FromRgb(176, 211, 194)),
        };
        button.Click += (_, _) =>
        {
            Choice = choice;
            DialogResult = true;
        };
        return button;
    }

    private static string FormatSize(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} B",
        < 1024 * 1024 => $"{bytes / 1024d:F1} KB",
        < 1024L * 1024 * 1024 => $"{bytes / 1024d / 1024:F1} MB",
        _ => $"{bytes / 1024d / 1024 / 1024:F1} GB",
    };
}
