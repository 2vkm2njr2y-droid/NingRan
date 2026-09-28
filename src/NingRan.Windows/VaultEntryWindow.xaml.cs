using System.Windows;

namespace NingRan.Windows;

public enum VaultWindowMode
{
    Create,
    Open,
}

public partial class VaultEntryWindow : Window
{
    public VaultEntryWindow()
    {
        InitializeComponent();
        if (!UiLanguage.IsEnglish) return;
        Title = "NingRan Vault";
        TitleText.Text = "NingRan Vault";
        SubtitleText.Text = "Choose what you want to do. Creating and opening use separate interfaces.";
        CreateTitleText.Text = "Create a vault";
        CreateDescriptionText.Text = "Choose a location, capacity, and password, with an optional independent space opened by a second password.";
        CreateVaultButton.Content = "Start creating";
        OpenTitleText.Text = "Open a vault";
        OpenDescriptionText.Text = "Choose an existing vault, enter its password, then mount it as a temporary drive and open it automatically.";
        OpenVaultButton.Content = "Start opening";
        HintText.Text = "In-app browsing is offered only as a fallback if mounting fails.";
    }

    public VaultWindowMode SelectedMode { get; private set; }

    private void CreateVault_Click(object sender, RoutedEventArgs e)
    {
        SelectedMode = VaultWindowMode.Create;
        DialogResult = true;
    }

    private void OpenVault_Click(object sender, RoutedEventArgs e)
    {
        SelectedMode = VaultWindowMode.Open;
        DialogResult = true;
    }
}
