using System.ComponentModel;
using System.IO;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using LibVLCSharp.Shared;
using NingRan.Core;
using NativeMediaPlayer = LibVLCSharp.Shared.MediaPlayer;

namespace NingRan.Windows;

public partial class VaultMediaViewerWindow : Window
{
    private readonly VaultSession _session;
    private readonly VaultEntry _entry;
    private LibVLC? _vlc;
    private NativeMediaPlayer? _player;
    private Media? _media;
    private Stream? _stream;
    private DispatcherTimer? _timer;
    private bool _viewReady;
    private bool _windowReady;
    private bool _started;
    private bool _closing;

    public VaultMediaViewerWindow(VaultSession session, VaultEntry entry)
    {
        _session = session;
        _entry = entry;
        InitializeComponent();
        FileNameText.Text = entry.Name;
        if (UiLanguage.IsEnglish)
        {
            Title = "Secure vault media viewer";
            TitleText.Text = "Secure in-app playback";
            LoadingText.Text = "Reading media securely from the vault...";
            VolumeText.Text = "Volume";
            CloseButton.Content = "Close";
        }
    }

    private void MediaView_Loaded(object sender, RoutedEventArgs e)
    {
        _viewReady = true;
        TryStartPlayback();
    }

    private void Window_Loaded(object sender, RoutedEventArgs e)
    {
        _windowReady = true;
        TryStartPlayback();
    }

    private void TryStartPlayback()
    {
        if (_started || !_windowReady || !_viewReady || _closing) return;
        _started = true;
        try
        {
            if (NingRanRuntime.IsProcessElevated())
                throw new NingRanException(UiLanguage.IsEnglish ? "Secure media playback is unavailable while running as administrator." : "以管理员身份运行时不能使用安全媒体播放。");
            Environment.SetEnvironmentVariable("VLC_PLUGIN_PATH", null, EnvironmentVariableTarget.Process);
            var nativeDirectory = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "libvlc", "win-x64"));
            if (!File.Exists(Path.Combine(nativeDirectory, "libvlc.dll")) || !Directory.Exists(Path.Combine(nativeDirectory, "plugins")))
                throw new NingRanException(UiLanguage.IsEnglish ? "The built-in playback components are incomplete. Reinstall the latest version." : "内置播放组件不完整，请重新安装最新版凝然加密。");

            LibVLCSharp.Shared.Core.Initialize(nativeDirectory);
            _vlc = new LibVLC("--no-video-title-show", "--file-caching=3500", "--quiet");
            _player = new NativeMediaPlayer(_vlc) { Volume = (int)VolumeSlider.Value };
            _player.Playing += Player_StateChanged;
            _player.Paused += Player_StateChanged;
            _player.Stopped += Player_StateChanged;
            _player.EncounteredError += Player_EncounteredError;
            MediaView.MediaPlayer = _player;
            _stream = _session.OpenReadStream(_entry.RelativePath);
            _media = new Media(_vlc, new StreamMediaInput(_stream), ":file-caching=3500", ":network-caching=0");
            if (!_player.Play(_media)) throw new NingRanException(UiLanguage.IsEnglish ? "The playback core could not start reading this file." : "播放核心未能开始读取这个文件。");
            _timer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromMilliseconds(250) };
            _timer.Tick += Timer_Tick;
            _timer.Start();
        }
        catch (Exception exception)
        {
            LoadingText.Text = UiLanguage.IsEnglish ? $"Could not play this file inside the app: {exception.Message}" : $"无法在程序内播放这个文件：{exception.Message}";
            PlayButton.IsEnabled = ProgressSlider.IsEnabled = VolumeSlider.IsEnabled = false;
        }
    }

    private void Player_StateChanged(object? sender, EventArgs e) => Dispatcher.BeginInvoke(() =>
    {
        if (_closing || _player is null) return;
        LoadingText.Visibility = _player.IsPlaying ? Visibility.Collapsed : LoadingText.Visibility;
        PlayButton.Content = _player.IsPlaying ? (UiLanguage.IsEnglish ? "Pause" : "暂停") : (UiLanguage.IsEnglish ? "Play" : "播放");
    });

    private void Player_EncounteredError(object? sender, EventArgs e) => Dispatcher.BeginInvoke(() =>
    {
        if (_closing) return;
        LoadingText.Visibility = Visibility.Visible;
        LoadingText.Text = UiLanguage.IsEnglish ? "Playback stopped because this media could not be read." : "媒体无法继续读取，播放已停止。";
    });

    private void Timer_Tick(object? sender, EventArgs e)
    {
        var player = _player;
        if (player is null) return;
        if (!ProgressSlider.IsMouseCaptureWithin && player.Length > 0)
            ProgressSlider.Value = Math.Clamp(player.Time / (double)player.Length * 1000d, 0d, 1000d);
        TimeText.Text = $"{FormatTime(player.Time)} / {FormatTime(player.Length)}";
    }

    private void Play_Click(object sender, RoutedEventArgs e)
    {
        if (_player is null) return;
        if (_player.IsPlaying) _player.Pause(); else _player.Play();
    }

    private void ProgressSlider_PreviewMouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    {
        if (_player?.Length is > 0) _player.Time = checked((long)(_player.Length * ProgressSlider.Value / 1000d));
    }

    private void VolumeSlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
    {
        if (_player is not null) _player.Volume = (int)Math.Round(e.NewValue);
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();

    private void Window_Closing(object? sender, CancelEventArgs e)
    {
        if (_closing) return;
        _closing = true;
        _timer?.Stop();
        try { _player?.Stop(); } catch { }
        MediaView.MediaPlayer = null;
        _media?.Dispose();
        _media = null;
        _stream?.Dispose();
        _stream = null;
        _player?.Dispose();
        _player = null;
        _vlc?.Dispose();
        _vlc = null;
        MediaView.Dispose();
    }

    private static string FormatTime(long milliseconds)
    {
        if (milliseconds < 0) milliseconds = 0;
        var span = TimeSpan.FromMilliseconds(milliseconds);
        return span.TotalHours >= 1 ? $"{(int)span.TotalHours}:{span.Minutes:00}:{span.Seconds:00}" : $"{span.Minutes}:{span.Seconds:00}";
    }
}
