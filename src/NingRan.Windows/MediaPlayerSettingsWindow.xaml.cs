using System.Windows;

namespace NingRan.Windows;

public partial class MediaPlayerSettingsWindow : Window
{
    internal MediaPlayerSettingsWindow(MediaPlayerPreferences preferences, bool externalPlayerAvailable)
    {
        InitializeComponent();
        NingRanPlayerRadio.IsChecked =
            preferences.AudioVideoPlayer == AudioVideoPlayerChoice.NingRanPlayer;
        BuiltInPlayerRadio.IsChecked =
            preferences.AudioVideoPlayer == AudioVideoPlayerChoice.BuiltInPlayer;
        ExternalPlayerStatusText.Text = UiLanguage.IsEnglish
            ? externalPlayerAvailable
                ? "NingRan Player was detected on this computer."
                : "NingRan Player is not currently installed."
            : externalPlayerAvailable
                ? "已在这台电脑上检测到凝然播放器。"
                : "这台电脑目前没有安装凝然播放器。";
    }

    internal AudioVideoPlayerChoice SelectedChoice => BuiltInPlayerRadio.IsChecked == true
        ? AudioVideoPlayerChoice.BuiltInPlayer
        : AudioVideoPlayerChoice.NingRanPlayer;

    private void SaveChoice_Click(object sender, RoutedEventArgs e) => DialogResult = true;
}
