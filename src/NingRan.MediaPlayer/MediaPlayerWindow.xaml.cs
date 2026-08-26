using System.ComponentModel;
using System.IO;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using LibVLCSharp.Shared;
using Microsoft.Win32;
using NingRan.Core;
using VlcCore = LibVLCSharp.Shared.Core;
using NativeMediaPlayer = LibVLCSharp.Shared.MediaPlayer;

namespace NingRan.MediaPlayer;

public partial class MediaPlayerWindow : Window
{
    private readonly PlayerOptions? _secureOptions;
    private readonly List<PlaylistEntry> _entries;
    private LibVLC? _vlc;
    private NativeMediaPlayer? _player;
    private Media? _media;
    private PipeMediaStream? _secureStream;
    private DispatcherTimer? _uiTimer;
    private int _currentIndex;
    private bool _seeking;
    private bool _closing;
    private bool _reportedProblem;
    private bool _fullScreen;

    public MediaPlayerWindow(PlayerOptions options)
        : this(options, options.Entries
            .Where(entry => entry.Kind is "audio" or "video")
            .Select(entry => PlaylistEntry.FromSecure(entry)))
    {
    }

    public MediaPlayerWindow(IReadOnlyList<string> files)
        : this(null, files.Select(PlaylistEntry.FromLocal))
    {
    }

    private MediaPlayerWindow(PlayerOptions? secureOptions, IEnumerable<PlaylistEntry> entries)
    {
        _secureOptions = secureOptions;
        _entries = entries.ToList();
        if (_entries.Count == 0)
        {
            throw new InvalidDataException("没有可播放的音频或视频文件。");
        }

        InitializeComponent();
        OpenButton.Visibility = _secureOptions is null ? Visibility.Visible : Visibility.Collapsed;
        Title = _secureOptions is null ? "凝然媒体播放器" : "凝然媒体播放器 - 安全查看";
        UpdateHeader();
    }

    private void Window_Loaded(object sender, RoutedEventArgs e)
    {
        try
        {
            EnsurePlayer();
            PlayCurrent();
        }
        catch (Exception exception)
        {
            ShowProblem($"播放器无法启动：{exception.Message}");
        }
    }

    private void EnsurePlayer()
    {
        if (_player is not null) return;

        Environment.SetEnvironmentVariable("VLC_PLUGIN_PATH", null, EnvironmentVariableTarget.Process);
        var nativeDirectory = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "libvlc", "win-x64"));
        if (!File.Exists(Path.Combine(nativeDirectory, "libvlc.dll")) ||
            !Directory.Exists(Path.Combine(nativeDirectory, "plugins")))
        {
            throw new InvalidDataException("播放器文件不完整，请重新安装凝然媒体播放器。");
        }

        VlcCore.Initialize(nativeDirectory);
        _vlc = new LibVLC(
            "--no-video-title-show",
            "--file-caching=1800",
            "--network-caching=1800",
            "--quiet");
        _player = new NativeMediaPlayer(_vlc)
        {
            Volume = (int)Math.Round(VolumeSlider.Value),
            Mute = false,
        };
        _player.Playing += Player_PlaybackStateChanged;
        _player.Paused += Player_PlaybackStateChanged;
        _player.Stopped += Player_PlaybackStateChanged;
        _player.EndReached += Player_EndReached;
        _player.EncounteredError += Player_EncounteredError;
        MediaView.MediaPlayer = _player;
        _uiTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(250) };
        _uiTimer.Tick += UiTimer_Tick;
        _uiTimer.Start();
    }

    private void PlayCurrent()
    {
        if (_player is null || _vlc is null) return;
        var entry = _entries[_currentIndex];
        StopCurrentMedia();
        HideProblem();

        if (entry.LocalPath is not null)
        {
            _media = new Media(_vlc, entry.LocalPath, FromType.FromPath);
        }
        else
        {
            if (_secureOptions is null || entry.SecureEntry is null)
            {
                throw new InvalidOperationException("安全媒体播放会话不完整。");
            }

            _secureStream = new PipeMediaStream(_secureOptions, entry.SecureEntry);
            _media = new Media(_vlc, new StreamMediaInput(_secureStream),
                ":file-caching=1800", ":network-caching=1800", ":clock-jitter=0", ":clock-synchro=0");
        }

        UpdateHeader();
        if (!_player.Play(_media))
        {
            throw new InvalidOperationException("播放核心没有接受这个媒体文件。");
        }
    }

    private void StopCurrentMedia()
    {
        try { _player?.Stop(); } catch { }
        _media?.Dispose();
        _media = null;
        _secureStream?.Dispose();
        _secureStream = null;
        ProgressSlider.Value = 0;
        CurrentTimeText.Text = "0:00";
        DurationText.Text = "0:00";
    }

    private void Player_PlaybackStateChanged(object? sender, EventArgs e)
    {
        _ = Dispatcher.BeginInvoke(() =>
        {
            if (_player is null || _closing) return;
            PlayButton.Content = _player.IsPlaying ? "❚❚" : "▶";
        });
    }

    private void UiTimer_Tick(object? sender, EventArgs e)
    {
        if (_player?.Length is not > 0) return;
        CurrentTimeText.Text = FormatTime(_player.Time);
        DurationText.Text = FormatTime(_player.Length);
        if (!_seeking)
        {
            ProgressSlider.Value = Math.Clamp(
                _player.Time * ProgressSlider.Maximum / _player.Length,
                ProgressSlider.Minimum,
                ProgressSlider.Maximum);
        }
    }
    private void Player_EndReached(object? sender, EventArgs e) =>
        _ = Dispatcher.BeginInvoke(() => SwitchEntry(1, loop: false));

    private void Player_EncounteredError(object? sender, EventArgs e) =>
        _ = Dispatcher.BeginInvoke(() => ShowProblem("无法读取或解码这个媒体文件。"));

    private void UpdateHeader()
    {
        var entry = _entries[_currentIndex];
        TitleText.Text = _secureOptions is null
            ? entry.Name
            : $"安全查看  {entry.Name}";
        CurrentFileText.Text = _entries.Count == 1
            ? entry.Name
            : $"{_currentIndex + 1} / {_entries.Count}  {entry.Name}";
        PreviousButton.IsEnabled = _currentIndex > 0;
        NextButton.IsEnabled = _currentIndex + 1 < _entries.Count;
    }

    private void Previous_Click(object sender, RoutedEventArgs e) => SwitchEntry(-1, loop: false);
    private void Next_Click(object sender, RoutedEventArgs e) => SwitchEntry(1, loop: false);

    private void SwitchEntry(int offset, bool loop)
    {
        var target = _currentIndex + offset;
        if (target < 0 || target >= _entries.Count)
        {
            if (!loop) return;
            target = target < 0 ? _entries.Count - 1 : 0;
        }

        _currentIndex = target;
        try { PlayCurrent(); }
        catch (Exception exception) { ShowProblem($"无法播放下一项：{exception.Message}"); }
    }

    private void PlayPause_Click(object sender, RoutedEventArgs e)
    {
        if (_player is null) return;
        if (_player.IsPlaying) _player.Pause();
        else _player.Play();
    }

    private void MediaArea_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ClickCount == 2)
        {
            SetFullScreen(!_fullScreen);
            return;
        }
        if (e.ClickCount == 1 && e.OriginalSource is not System.Windows.Controls.Slider)
        {
            PlayPause_Click(sender, e);
        }
    }

    private void BackTen_Click(object sender, RoutedEventArgs e) => SeekBy(-10_000);
    private void ForwardThirty_Click(object sender, RoutedEventArgs e) => SeekBy(30_000);

    private void SeekBy(long offset)
    {
        if (_player?.Length is not > 0) return;
        _player.Time = Math.Clamp(_player.Time + offset, 0, _player.Length);
    }

    private void ProgressSlider_PreviewMouseLeftButtonDown(object sender, MouseButtonEventArgs e) => _seeking = true;

    private void ProgressSlider_PreviewMouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    {
        if (_player?.Length is > 0)
        {
            _player.Time = (long)Math.Round(_player.Length * ProgressSlider.Value / ProgressSlider.Maximum);
        }
        _seeking = false;
    }

    private void VolumeSlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
    {
        if (_player is not null) _player.Volume = (int)Math.Round(e.NewValue);
    }

    private void Open_Click(object sender, RoutedEventArgs e)
    {
        if (_secureOptions is not null) return;
        var dialog = new OpenFileDialog
        {
            Filter = "音频和视频|*.mp3;*.wav;*.m4a;*.aac;*.flac;*.ogg;*.wma;*.mp4;*.m4v;*.mov;*.avi;*.wmv;*.webm;*.mkv;*.mpeg;*.mpg;*.3gp;*.ts;*.mpv|所有文件|*.*",
            Multiselect = true,
            CheckFileExists = true,
        };
        if (dialog.ShowDialog(this) != true) return;

        var files = dialog.FileNames
            .Where(LocalMediaLaunchOptions.IsSupportedMediaFile)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (files.Length == 0)
        {
            MessageBox.Show(this, "请选择受支持的音频或视频文件。", "凝然媒体播放器",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        _entries.Clear();
        _entries.AddRange(files.Select(PlaylistEntry.FromLocal));
        _currentIndex = 0;
        try { PlayCurrent(); }
        catch (Exception exception) { ShowProblem($"无法打开媒体：{exception.Message}"); }
    }

    private void Fullscreen_Click(object sender, RoutedEventArgs e) => SetFullScreen(!_fullScreen);

    private void SetFullScreen(bool enabled)
    {
        if (_fullScreen == enabled) return;
        _fullScreen = enabled;
        TitleRow.Height = enabled ? new GridLength(0) : new GridLength(44);
        WindowState = enabled ? WindowState.Maximized : WindowState.Normal;
    }

    private void Window_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        switch (e.Key)
        {
            case Key.Space:
                PlayPause_Click(sender, e);
                e.Handled = true;
                break;
            case Key.Left:
                SeekBy(-5_000);
                e.Handled = true;
                break;
            case Key.Right:
                SeekBy(5_000);
                e.Handled = true;
                break;
            case Key.Escape when _fullScreen:
                SetFullScreen(false);
                e.Handled = true;
                break;
        }
    }

    private void ShowProblem(string message)
    {
        if (_closing) return;
        StatusText.Text = message;
        StatusPanel.Visibility = Visibility.Visible;
        ReportSecureProblem(message);
    }

    private void HideProblem()
    {
        StatusPanel.Visibility = Visibility.Collapsed;
        StatusText.Text = string.Empty;
    }

    internal void MarkProblem(string message) => ShowProblem(message);

    private void ReportSecureProblem(string message)
    {
        if (_reportedProblem || _secureOptions is null) return;
        _reportedProblem = true;
        try { MediaPipeClient.Notify(_secureOptions, _entries[_currentIndex].SecureEntry!, "problem", message); }
        catch { }
    }

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ClickCount == 2) { ToggleMaximize(); return; }
        if (e.LeftButton == MouseButtonState.Pressed) DragMove();
    }

    private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
    private void Maximize_Click(object sender, RoutedEventArgs e) => ToggleMaximize();
    private void Close_Click(object sender, RoutedEventArgs e) => Close();

    private void ToggleMaximize()
    {
        if (_fullScreen) SetFullScreen(false);
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
        MaximizeButton.Content = WindowState == WindowState.Maximized ? "❐" : "□";
    }

    private void Window_Closing(object sender, CancelEventArgs e)
    {
        if (_closing) return;
        _closing = true;
        if (!_reportedProblem && _secureOptions is not null)
        {
            try { MediaPipeClient.Notify(_secureOptions, _entries[_currentIndex].SecureEntry!, "closed", null); }
            catch { }
        }

        StopCurrentMedia();
        if (_uiTimer is not null)
        {
            _uiTimer.Stop();
            _uiTimer.Tick -= UiTimer_Tick;
            _uiTimer = null;
        }
        if (_player is not null)
        {
            _player.Playing -= Player_PlaybackStateChanged;
            _player.Paused -= Player_PlaybackStateChanged;
            _player.Stopped -= Player_PlaybackStateChanged;
            _player.EndReached -= Player_EndReached;
            _player.EncounteredError -= Player_EncounteredError;
        }
        MediaView.MediaPlayer = null;
        _player?.Dispose();
        _player = null;
        _vlc?.Dispose();
        _vlc = null;
        MediaView.Dispose();
    }

    private sealed record PlaylistEntry(string Name, string? LocalPath, MediaPipeCatalogEntry? SecureEntry)
    {
        public static PlaylistEntry FromLocal(string path) => new(Path.GetFileName(path), path, null);
        public static PlaylistEntry FromSecure(MediaPipeCatalogEntry entry) => new(entry.Name, null, entry);
    }

    private static string FormatTime(long milliseconds)
    {
        var seconds = Math.Max(0, milliseconds / 1000);
        return $"{seconds / 60}:{seconds % 60:D2}";
    }
}
