using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace NingRan.Windows;

internal enum ArchiveConflictChoice
{
    Cancel,
    Skip,
    KeepBoth,
    Replace,
    SkipAll,
    KeepBothAll,
    ReplaceAll,
}

internal sealed class ArchiveConflictDialog : Window
{
    private ArchiveConflictDialog(string name, long existingSize, long incomingSize)
    {
        Title = "发现同名内容";
        Width = 640;
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
            Text = $"名称：{name}\n现有大小：{FormatSize(existingSize)}\n准备追加：{FormatSize(incomingSize)}\n" +
                   (existingSize == incomingSize ? "两个项目大小相同，请仍按实际内容判断。" : "两个项目大小不同。"),
            Margin = new Thickness(0, 12, 0, 18),
            TextWrapping = TextWrapping.Wrap,
            Foreground = new SolidColorBrush(Color.FromRgb(75, 89, 84)),
        });
        panel.Children.Add(new TextBlock
        {
            Text = "只处理这一个冲突",
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 0, 0, 7),
        });
        var singleButtons = new WrapPanel { HorizontalAlignment = HorizontalAlignment.Right };
        singleButtons.Children.Add(CreateButton("自动改名", ArchiveConflictChoice.KeepBoth, true));
        singleButtons.Children.Add(CreateButton("替换", ArchiveConflictChoice.Replace, false));
        singleButtons.Children.Add(CreateButton("跳过", ArchiveConflictChoice.Skip, false));
        panel.Children.Add(singleButtons);

        panel.Children.Add(new TextBlock
        {
            Text = "这次剩余的同名内容都这样处理",
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 16, 0, 7),
        });
        var allButtons = new WrapPanel { HorizontalAlignment = HorizontalAlignment.Right };
        allButtons.Children.Add(CreateButton("全部自动改名", ArchiveConflictChoice.KeepBothAll, false));
        allButtons.Children.Add(CreateButton("全部替换", ArchiveConflictChoice.ReplaceAll, false));
        allButtons.Children.Add(CreateButton("全部跳过", ArchiveConflictChoice.SkipAll, false));
        panel.Children.Add(allButtons);

        var cancelButtons = new WrapPanel { HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 16, 0, 0) };
        cancelButtons.Children.Add(CreateButton("取消整个追加操作", ArchiveConflictChoice.Cancel, false));
        panel.Children.Add(cancelButtons);
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
