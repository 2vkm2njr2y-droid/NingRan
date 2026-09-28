using System.Windows;
using System.Windows.Controls;

namespace NingRan.Windows;

internal sealed class VaultPathPromptWindow : Window
{
    private readonly TextBox _input;

    public VaultPathPromptWindow(string title, string hint, string initialValue)
    {
        Title = title;
        Width = 520;
        Height = 230;
        ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;
        var root = new Grid { Margin = new Thickness(20) };
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition());
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.Children.Add(new TextBlock { Text = title, FontSize = 17, FontWeight = FontWeights.SemiBold });
        var hintText = new TextBlock { Text = hint, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 7, 0, 10), Foreground = System.Windows.Media.Brushes.DimGray };
        Grid.SetRow(hintText, 1);
        root.Children.Add(hintText);
        _input = new TextBox { Text = initialValue, MinHeight = 34, MaxLength = 1024 };
        Grid.SetRow(_input, 2);
        root.Children.Add(_input);
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        var cancel = new Button { Content = UiLanguage.IsEnglish ? "Cancel" : "取消", IsCancel = true, MinWidth = 82, Margin = new Thickness(0, 0, 8, 0) };
        var confirm = new Button { Content = UiLanguage.IsEnglish ? "OK" : "确定", IsDefault = true, MinWidth = 82 };
        confirm.Click += (_, _) =>
        {
            if (!string.IsNullOrWhiteSpace(_input.Text)) DialogResult = true;
        };
        buttons.Children.Add(cancel);
        buttons.Children.Add(confirm);
        Grid.SetRow(buttons, 4);
        root.Children.Add(buttons);
        Content = root;
        Loaded += (_, _) => { _input.Focus(); _input.SelectAll(); };
    }

    public string Value => _input.Text.Trim().Replace('\\', '/');
}
