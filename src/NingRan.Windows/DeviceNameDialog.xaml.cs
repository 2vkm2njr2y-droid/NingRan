using System.Windows;

namespace NingRan.Windows;

public partial class DeviceNameDialog : Window
{
    public DeviceNameDialog(string? initialName = null)
    {
        InitializeComponent();
        NameInput.Text = initialName ?? string.Empty;
        Loaded += (_, _) =>
        {
            NameInput.Focus();
            NameInput.SelectAll();
        };
    }

    public string DeviceName => NameInput.Text.Trim();

    private void Confirm_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(NameInput.Text))
        {
            ErrorText.Text = "请填写设备名称。";
            return;
        }

        DialogResult = true;
    }
}
