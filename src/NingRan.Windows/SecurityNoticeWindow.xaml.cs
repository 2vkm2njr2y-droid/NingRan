using System.Windows;
using System.Windows.Input;

namespace NingRan.Windows;

public partial class SecurityNoticeWindow : Window
{
    public SecurityNoticeWindow()
    {
        InitializeComponent();
    }

    private void ExitButton_Click(object sender, RoutedEventArgs e) => Close();

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ChangedButton == MouseButton.Left)
        {
            DragMove();
        }
    }
}
