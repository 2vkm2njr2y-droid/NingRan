using System.Windows;
using System.Windows.Controls;

namespace NingRan.Windows;

public partial class HelpWindow : Window
{
    public HelpWindow()
    {
        InitializeComponent();
        HelpNavigation.SelectedIndex = 0;
    }

    private void HelpNavigation_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        var target = HelpNavigation.SelectedIndex switch
        {
            0 => OverviewSection,
            1 => ArchiveSection,
            2 => PasswordsSection,
            3 => PrivacySection,
            4 => SecureViewingSection,
            5 => SafetySection,
            _ => null,
        };
        target?.BringIntoView();
    }
}
