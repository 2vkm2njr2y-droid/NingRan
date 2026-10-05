using System.Windows;
using System.Windows.Input;

namespace NingRan.Windows;

public partial class ExportArchiveWindow : Window
{
    public ExportArchiveWindow(string? selectedEntryName = null)
    {
        InitializeComponent();
        if (!string.IsNullOrWhiteSpace(selectedEntryName))
        {
            SubtitleText.Text = $"明文选项导出当前选中的“{selectedEntryName}”；加密包选项导出整个已打开的加密包。";
        }
        ApplyLanguage();
    }

    public bool ExportAsEncryptedPackage => EncryptedPackageOption.IsChecked == true;

    private void ApplyLanguage()
    {
        if (!UiLanguage.IsEnglish) return;

        TitleText.Text = "Export content";
        SubtitleText.Text = "Choose what to export this time";
        EncryptedPackageTitle.Text = "Export encrypted package (.nrenc)";
        EncryptedPackageDescription.Text = "Copy it to any disk or share it. The content remains encrypted and no plaintext is created.";
        PlaintextTitle.Text = "Export plaintext";
        PlaintextDescription.Text = "Restore ordinary files or folders. Protect the exported plaintext location yourself.";
        CancelButton.Content = "Cancel";
        ContinueButton.Content = "Continue";
    }

    private void ContinueButton_Click(object sender, RoutedEventArgs e) => DialogResult = true;

    private void CancelButton_Click(object sender, RoutedEventArgs e) => DialogResult = false;

    private void TitleArea_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.LeftButton == MouseButtonState.Pressed)
        {
            DragMove();
        }
    }
}
