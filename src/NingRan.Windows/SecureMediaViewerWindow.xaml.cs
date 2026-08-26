using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Media.Animation;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Interop;
using System.Windows.Threading;
using LibVLCSharp.Shared;
using NingRan.Core;
using NativeMediaPlayer = LibVLCSharp.Shared.MediaPlayer;

namespace NingRan.Windows;

public partial class SecureMediaViewerWindow : Window
{
    private readonly SecureArchiveSession _session;
    private readonly IReadOnlyList<SecureArchiveEntry> _folderEntries;
    private readonly SecureArchiveEntry _initialEntry;
    private IReadOnlyList<SecureArchiveEntry> _filteredEntries = [];
    private SecureArchiveEntry? _currentEntry;
    private MediaReadAheadCache? _mediaCache;
    private CancellationTokenRegistration _sessionCancellation;
    private bool _closing;
    private bool _mediaFullscreen;
    private WindowState _windowStateBeforeFullscreen;
    private int _loadVersion;
    private LibVLC? _nativeVlc;
    private NativeMediaPlayer? _nativePlayer;
    private Media? _nativeMedia;
    private Stream? _nativeStream;
    private NativeMediaPlayer? _nativePreviewPlayer;
    private Media? _nativePreviewMedia;
    private Stream? _nativePreviewStream;
    private DispatcherTimer? _nativeUiTimer;
    private DispatcherTimer? _nativeHideTimer;
    private DispatcherTimer? _nativePointerTimer;
    private bool _nativeViewReady;
    private bool _nativeFailureInProgress;
    private bool _nativeSeeking;
    private DispatcherTimer? _nativePreviewTimer;
    private DispatcherTimer? _nativePreviewTimeoutTimer;
    private DispatcherTimer? _nativeVideoClickTimer;
    private long _nativePreviewRequestedTime = -1;
    private double _nativeVideoAspect = 16d / 9d;
    private bool _nativeHasPlayedFrame;
    private bool _nativePreviewHasFrame;
    private bool _nativePreviewFramePending;
    private bool _nativePreviewViewReady;
    private CursorPosition _lastNativeCursorPosition;
    private bool _hasLastNativeCursorPosition;
    private bool _isDraggingImage;
    private Point _imageDragStart;
    private Point _imageTranslateStart;

    private const int WmKeyDown = 0x0100;
    private const int WmSysKeyDown = 0x0104;
    private const int WmMouseMove = 0x0200;
    private const int VirtualKeyLeft = 0x25;
    private const int VirtualKeyRight = 0x27;
    private const int VirtualKeyEscape = 0x1B;

    [StructLayout(LayoutKind.Sequential)]
    private struct CursorPosition
    {
        public int X;
        public int Y;
    }

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetCursorPos(out CursorPosition position);

    [DllImport("user32.dll")]
    private static extern uint GetDoubleClickTime();

    public SecureMediaViewerWindow(SecureArchiveSession session, IReadOnlyList<SecureArchiveEntry> folderEntries, SecureArchiveEntry initialEntry)
    {
        _session = session;
        _folderEntries = folderEntries;
        _initialEntry = initialEntry;
        InitializeComponent();
        ComponentDispatcher.ThreadPreprocessMessage += ViewerThreadPreprocessMessage;
        TitleText.Text = UiLanguage.Translate("凝然加密 · 安全媒体播放器");
        SubtitleText.Text = UiLanguage.IsEnglish
            ? $"No plaintext is saved · {folderEntries.Count} media files can be viewed securely in this folder."
            : $"不保存明文 · 当前文件夹内有 {folderEntries.Count} 个可安全查看的媒体文件。";
        _sessionCancellation = _session.CancellationToken.Register(() => Dispatcher.BeginInvoke(() =>
        {
            if (_closing) return;
            MessageBox.Show(this, "授权物理设备已被拔出或发生变化，安全查看将关闭。", "凝然加密", MessageBoxButton.OK, MessageBoxImage.Warning);
            Close();
        }));
    }

    private async void Window_Loaded(object sender, RoutedEventArgs e)
    {
        DockNativeControlBar();
        ApplyFilter();
        try { EnsureNativePlayer(); }
        catch (Exception exception)
        {
            EmptyText.Text = UiLanguage.IsEnglish
                ? $"Built-in player could not start: {exception.Message}"
                : $"内置播放器无法启动：{exception.Message}";
            return;
        }
        var initial = _filteredEntries.FirstOrDefault(entry => string.Equals(entry.RelativePath, _initialEntry.RelativePath, StringComparison.OrdinalIgnoreCase));
        if (initial is null && _filteredEntries.Count > 0) initial = _filteredEntries[0];
        if (initial is null) return;
        Playlist.SelectedItem = initial;
        await LoadEntryAsync(initial);
    }

    private void TypeFilterCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!IsLoaded) return;
        var previouslySelected = _currentEntry?.RelativePath;
        ApplyFilter();
        Playlist.SelectedItem = _filteredEntries.FirstOrDefault(entry => string.Equals(entry.RelativePath, previouslySelected, StringComparison.OrdinalIgnoreCase));
        if (Playlist.SelectedItem is null && _filteredEntries.Count > 0) Playlist.SelectedIndex = 0;
    }

    private async void Playlist_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (Playlist.SelectedItem is not SecureArchiveEntry entry || string.Equals(entry.RelativePath, _currentEntry?.RelativePath, StringComparison.OrdinalIgnoreCase)) return;
        await LoadEntryAsync(entry);
    }

    private void ApplyFilter()
    {
        var filter = (TypeFilterCombo.SelectedItem as ComboBoxItem)?.Tag as string ?? "all";
        _filteredEntries = _folderEntries.Where(entry => filter switch
        {
            "image" => entry.MediaKind == SecureMediaKind.Image,
            "video" => entry.MediaKind == SecureMediaKind.Video,
            "audio" => entry.MediaKind == SecureMediaKind.Audio,
            "text" => entry.MediaKind == SecureMediaKind.Text,
            _ => true,
        }).ToArray();
        Playlist.ItemsSource = _filteredEntries;
    }

    private async Task LoadEntryAsync(SecureArchiveEntry entry)
    {
        var loadVersion = unchecked(++_loadVersion);
        try
        {
            LeaveMediaFullscreen();
            StopNativePlayback();
            DisposeMediaCache();
            _currentEntry = entry;
            CurrentFileText.Text = entry.Name;
            HideContentViews();
            switch (entry.MediaKind)
            {
                case SecureMediaKind.Text: await LoadTextAsync(entry); break;
                case SecureMediaKind.Image: await LoadImageAsync(entry); break;
                case SecureMediaKind.Audio:
                case SecureMediaKind.Video: await LoadPlayableMediaAsync(entry, loadVersion); break;
                default: throw new InvalidOperationException(UiLanguage.Translate("该文件不是可直接查看的媒体类型。"));
            }
        }
        catch (OperationCanceledException) when (loadVersion == _loadVersion) { Close(); }
        catch (Exception exception)
        {
            if (loadVersion != _loadVersion) return;
            StopNativePlayback();
            DisposeMediaCache();
            HideContentViews();
            EmptyView.Visibility = Visibility.Visible;
            EmptyText.Text = UiLanguage.IsEnglish
                ? $"Could not open this file in the app: {exception.Message}"
                : $"无法在程序内打开此文件：{exception.Message}";
            CrashReportDialog.ShowTemporary(this, UiLanguage.Translate("无法打开媒体"), exception.Message,
                UiLanguage.Translate("安全媒体查看"), exception);
        }
    }

    private async Task LoadTextAsync(SecureArchiveEntry entry)
    {
        await using var stream = _session.OpenEntryReadStream(entry.RelativePath);
        using var reader = new StreamReader(stream, detectEncodingFromByteOrderMarks: true, leaveOpen: false);
        TextView.Text = await reader.ReadToEndAsync(_session.CancellationToken);
        TextView.Visibility = Visibility.Visible;
    }

    private async Task LoadImageAsync(SecureArchiveEntry entry)
    {
        await using var stream = _session.OpenEntryReadStream(entry.RelativePath);
        var image = new BitmapImage();
        image.BeginInit();
        image.CacheOption = BitmapCacheOption.OnLoad;
        image.StreamSource = stream;
        image.EndInit();
        image.Freeze();
        ImageView.Source = image;
        ResetImageView();
        ImageScroll.Visibility = Visibility.Visible;
        ImageZoomPanel.Visibility = Visibility.Visible;
    }

    private async Task LoadPlayableMediaAsync(SecureArchiveEntry entry, int loadVersion)
    {
        _nativeHasPlayedFrame = false;
        _nativeVideoAspect = 16d / 9d;
        NativeMediaHost.Visibility = Visibility.Visible;
        UpdateNativePresentationBounds();
        SetNativeLoading(true, UiLanguage.Translate("正在安全加载视频…"));
        await Dispatcher.Yield();
        EnsureNativePlayer();
        if (_nativePlayer is null || _nativeVlc is null) throw new NingRanException(UiLanguage.Translate("播放核心尚未准备好，请稍后重试。"));
        var cache = new MediaReadAheadCache(_session, entry);
        _mediaCache = cache;

        try
        {
            await cache.PrepareStartupAsync(_session.CancellationToken)
                .WaitAsync(TimeSpan.FromSeconds(60), _session.CancellationToken);
        }
        catch (TimeoutException exception)
        {
            throw new NingRanException(UiLanguage.Translate("媒体信息在 60 秒内未能准备完成，已停止播放以避免窗口卡死。"), exception);
        }

        if (loadVersion != _loadVersion || !ReferenceEquals(_mediaCache, cache)) return;
        _nativeFailureInProgress = false;
        _nativeStream = cache.OpenRange(0, entry.Length);
        _nativeMedia = new Media(_nativeVlc!, new StreamMediaInput(_nativeStream),
            ":file-caching=3500", ":network-caching=3500", ":clock-jitter=0", ":clock-synchro=0");
        _ = ConfigureNativePreviewAsync(cache, entry, loadVersion);
        PlaybackRulePanel.Visibility = Visibility.Visible;
        if (!_nativePlayer!.Play(_nativeMedia))
        {
            throw new NingRanException(UiLanguage.Translate("播放核心未能开始读取媒体。"));
        }
        RevealNativeControls();
    }

    private void NativeMediaView_Loaded(object sender, RoutedEventArgs e)
    {
        _nativeViewReady = true;
        try { EnsureNativePlayer(); }
        catch (Exception exception)
        {
            EmptyText.Text = UiLanguage.IsEnglish
                ? $"Built-in player could not start: {exception.Message}"
                : $"内置播放器无法启动：{exception.Message}";
        }
    }

    private void DockNativeControlBar()
    {
        // XAML 中控制栏需要先作为 VideoView 的覆盖层创建；窗口就绪后把它移到
        // 播放区的独立底部行，避免在普通窗口模式遮住视频画面。
        if (VisualTreeHelper.GetParent(NativeMediaControlBar) is not Panel overlay) return;
        overlay.Children.Remove(NativeMediaControlBar);
        NativeMediaHost.RowDefinitions.Clear();
        NativeMediaHost.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        NativeMediaHost.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        Grid.SetRow(NativeMediaPresentation, 0);
        NativeMediaHost.Children.Add(NativeMediaControlBar);
        Grid.SetRow(NativeMediaControlBar, 1);
        NativeMediaControlBar.SizeChanged += (_, _) => UpdateNativePresentationBounds();
        Dispatcher.BeginInvoke(UpdateNativePresentationBounds, DispatcherPriority.Loaded);
    }

    private void EnsureNativePlayer()
    {
        if (_nativePlayer is not null) return;
        if (!_nativeViewReady) return;
        if (NingRanRuntime.IsProcessElevated()) return;
        Environment.SetEnvironmentVariable("VLC_PLUGIN_PATH", null, EnvironmentVariableTarget.Process);
        var nativeDirectory = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "libvlc", "win-x64"));
        if (!File.Exists(Path.Combine(nativeDirectory, "libvlc.dll")) ||
            !Directory.Exists(Path.Combine(nativeDirectory, "plugins")))
        {
            throw new NingRanException(UiLanguage.Translate("内置播放组件不完整，请重新安装最新版凝然加密。"));
        }
        LibVLCSharp.Shared.Core.Initialize(nativeDirectory);
        _nativeVlc = new LibVLC("--no-video-title-show", "--file-caching=3500", "--network-caching=3500", "--quiet");
        _nativePlayer = new NativeMediaPlayer(_nativeVlc);
        _nativePlayer.EndReached += NativePlayer_EndReached;
        _nativePlayer.EncounteredError += NativePlayer_EncounteredError;
        _nativePlayer.Playing += NativePlayer_PlaybackStateChanged;
        _nativePlayer.Paused += NativePlayer_PlaybackStateChanged;
        _nativePlayer.Stopped += NativePlayer_PlaybackStateChanged;
        _nativePlayer.Buffering += NativePlayer_Buffering;
        _nativePlayer.TimeChanged += NativePlayer_TimeChanged;
        _nativePlayer.Mute = false;
        _nativePlayer.Volume = (int)Math.Round(NativeVolumeSlider.Value);
        NativeMediaView.MediaPlayer = _nativePlayer;
        _nativeUiTimer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromMilliseconds(250) };
        _nativeUiTimer.Tick += NativeUiTimer_Tick;
        _nativeUiTimer.Start();
        _nativeHideTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
        _nativeHideTimer.Tick += NativeHideTimer_Tick;
        _nativePointerTimer = new DispatcherTimer(DispatcherPriority.Input) { Interval = TimeSpan.FromMilliseconds(75) };
        _nativePointerTimer.Tick += NativePointerTimer_Tick;
        _nativePointerTimer.Start();
        _nativePreviewTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(180) };
        _nativePreviewTimer.Tick += NativePreviewTimer_Tick;
        _nativePreviewTimeoutTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        _nativePreviewTimeoutTimer.Tick += NativePreviewTimeoutTimer_Tick;
    }

    private void StopNativePlayback()
    {
        _nativeVideoClickTimer?.Stop();
        _nativeHideTimer?.Stop();
        _nativePreviewTimer?.Stop();
        _nativeSeeking = false;
        StopNativePreview();
        try { _nativePlayer?.Stop(); } catch { }
        _nativeMedia?.Dispose();
        _nativeMedia = null;
        _nativeStream = null;
        _nativeHasPlayedFrame = false;
        NativeMediaHost.Visibility = Visibility.Collapsed;
        NativePreviewPopup.Visibility = Visibility.Collapsed;
        SetNativeLoading(false);
        NativePlayButton.Content = "▶";
        NativeTimeText.Text = "0:00";
        NativeDurationText.Text = "0:00";
        NativeProgressSlider.Value = 0;
    }

    private void NativePlayer_PlaybackStateChanged(object? sender, EventArgs e) =>
        Dispatcher.BeginInvoke(() =>
        {
            var player = _nativePlayer;
            if (player is null) return;
            if (player.IsPlaying)
            {
                // 播放核心会在媒体刚开始时重新建立声音通道；此时明确恢复主视频的声音。
                player.Mute = false;
                player.Volume = (int)Math.Round(NativeVolumeSlider.Value);
            }
            NativePlayButton.Content = player.IsPlaying ? "❚❚" : "▶";
        });

    private void NativePlayer_Buffering(object? sender, MediaPlayerBufferingEventArgs e)
    {
        if (_closing || !_nativeHasPlayedFrame) return;
        _ = Dispatcher.BeginInvoke(() => SetNativeLoading(e.Cache < 99.5f, UiLanguage.Translate("正在缓冲视频…")));
    }

    private void NativePlayer_TimeChanged(object? sender, MediaPlayerTimeChangedEventArgs e)
    {
        if (_closing || e.Time <= 0) return;
        _ = Dispatcher.BeginInvoke(() =>
        {
            _nativeHasPlayedFrame = true;
            SetNativeLoading(false);
        });
    }

    private void NativePlayer_EncounteredError(object? sender, EventArgs e) =>
        Dispatcher.BeginInvoke(() => HandleNativePlaybackFailure("播放核心无法继续读取或解码此媒体。"));

    private async void NativePlayer_EndReached(object? sender, EventArgs e)
    {
        await Dispatcher.InvokeAsync(async () =>
        {
            if (_closing || _currentEntry is null) return;
            var rule = (PlaybackRuleCombo.SelectedItem as ComboBoxItem)?.Tag as string ?? "stop";
            if (rule == "one") { await LoadEntryAsync(_currentEntry); return; }
            if (rule is "next" or "all") MoveSelection(1, rule == "all");
        });
    }

    private void HandleNativePlaybackFailure(string reason)
    {
        if (_closing || _nativeFailureInProgress) return;
        _nativeFailureInProgress = true;
        StopNativePlayback();
        DisposeMediaCache();
        HideContentViews();
        EmptyView.Visibility = Visibility.Visible;
        EmptyText.Text = UiLanguage.Translate("播放器已停止，您已回到文件列表。");
        CrashReportDialog.ShowTemporary(this, UiLanguage.Translate("播放器出现错误"),
            UiLanguage.Translate(reason), UiLanguage.Translate("内嵌安全播放器"));
    }

    private async Task ConfigureNativePreviewAsync(MediaReadAheadCache cache, SecureArchiveEntry entry, int loadVersion)
    {
        try
        {
            if (_nativeVlc is null) return;
            using var analysisStream = cache.OpenRange(0, entry.Length);
            using var analysisMedia = new Media(_nativeVlc, new StreamMediaInput(analysisStream), ":no-audio", ":file-caching=750");
            await analysisMedia.Parse(MediaParseOptions.ParseLocal, 12_000, _session.CancellationToken);
            if (_closing || loadVersion != _loadVersion || !ReferenceEquals(_mediaCache, cache)) return;
            var video = analysisMedia.Tracks.FirstOrDefault(track => track.TrackType == TrackType.Video).Data.Video;
            if (video.Width == 0 || video.Height == 0) return;
            var aspect = video.Width / (double)video.Height;
            var width = 220;
            var height = 124;
            if (aspect >= width / (double)height) height = Math.Max(56, (int)Math.Round(width / aspect));
            else width = Math.Max(56, (int)Math.Round(height * aspect));
            await Dispatcher.InvokeAsync(() =>
            {
                _nativeVideoAspect = video.Width / (double)video.Height;
                UpdateNativePresentationBounds();
                StartNativePreview(cache, entry, width, height, loadVersion);
            });
        }
        catch (OperationCanceledException) { }
        catch { /* 主播放不依赖预览；预览失败时保持隐藏。 */ }
    }

    private void StartNativePreview(MediaReadAheadCache cache, SecureArchiveEntry entry, int width, int height, int loadVersion)
    {
        if (_closing || loadVersion != _loadVersion || !ReferenceEquals(_mediaCache, cache)) return;
        StopNativePreview();
        _nativePreviewHasFrame = false;
        _nativePreviewFramePending = false;
        NativePreviewVideoView.Width = width;
        NativePreviewVideoView.Height = height;
    }

    private void NativePreviewVideoView_Loaded(object sender, RoutedEventArgs e)
    {
        _nativePreviewViewReady = true;
    }

    private bool StartNativePreviewPlayback()
    {
        if (_nativePreviewPlayer is not null) return true;
        if (!_nativePreviewViewReady || _nativeVlc is null || _mediaCache is null || _currentEntry is null) return false;
        try
        {
            _nativePreviewStream = _mediaCache.OpenRange(0, _currentEntry.Length);
            // 预览只关闭自己的声音轨道，绝不使用会影响主视频的全局静音设置。
            _nativePreviewMedia = new Media(_nativeVlc!, new StreamMediaInput(_nativePreviewStream),
                ":file-caching=350", ":network-caching=350", ":clock-jitter=0", ":clock-synchro=0");
            _nativePreviewPlayer = new NativeMediaPlayer(_nativeVlc!);
            _nativePreviewPlayer.Playing += NativePreviewPlayer_Playing;
            _nativePreviewPlayer.TimeChanged += NativePreviewPlayer_TimeChanged;
            _nativePreviewPlayer.EncounteredError += NativePreviewPlayer_EncounteredError;
            NativePreviewVideoView.Visibility = Visibility.Visible;
            NativePreviewVideoView.MediaPlayer = _nativePreviewPlayer;
            return _nativePreviewPlayer.Play(_nativePreviewMedia);
        }
        catch
        {
            StopNativePreview();
            return false;
        }
    }

    private void StopNativePreview()
    {
        _nativePreviewRequestedTime = -1;
        _nativePreviewTimeoutTimer?.Stop();
        _nativePreviewHasFrame = false;
        _nativePreviewFramePending = false;
        if (_nativePreviewPlayer is not null)
        {
            _nativePreviewPlayer.Playing -= NativePreviewPlayer_Playing;
            _nativePreviewPlayer.TimeChanged -= NativePreviewPlayer_TimeChanged;
            _nativePreviewPlayer.EncounteredError -= NativePreviewPlayer_EncounteredError;
            try { _nativePreviewPlayer.Stop(); } catch { }
        }
        NativePreviewVideoView.MediaPlayer = null;
        _nativePreviewPlayer?.Dispose();
        _nativePreviewPlayer = null;
        _nativePreviewMedia?.Dispose();
        _nativePreviewMedia = null;
        _nativePreviewStream?.Dispose();
        _nativePreviewStream = null;
        NativePreviewLoadingPanel.Visibility = Visibility.Collapsed;
        NativePreviewVideoView.Visibility = Visibility.Collapsed;
    }

    private void NativePreviewPlayer_TimeChanged(object? sender, MediaPlayerTimeChangedEventArgs e)
    {
        if (_closing || e.Time < 0) return;
        _ = Dispatcher.BeginInvoke(() =>
        {
            _nativePreviewHasFrame = true;
            _nativePreviewFramePending = false;
            _nativePreviewTimeoutTimer?.Stop();
            SetNativePreviewLoading(false);
        });
    }

    private void NativePreviewPlayer_Playing(object? sender, EventArgs e)
    {
        // LibVLC 文档建议关闭声音轨道而不是使用静音；此设置只属于预览播放器。
        try { _nativePreviewPlayer?.SetAudioTrack(-1); } catch { }
    }

    private void NativePreviewPlayer_EncounteredError(object? sender, EventArgs e) =>
        _ = Dispatcher.BeginInvoke(() => SetNativePreviewUnavailable());

    private void NativePlayButton_Click(object sender, RoutedEventArgs e)
    {
        if (_nativePlayer is null || _nativeMedia is null) return;
        if (_nativePlayer.IsPlaying) _nativePlayer.Pause();
        else _nativePlayer.Play();
        RevealNativeControls();
    }

    private void NativePrevious_Click(object sender, RoutedEventArgs e) => MoveSelection(-1, false);

    private void NativeNext_Click(object sender, RoutedEventArgs e) => MoveSelection(1, false);

    private void NativeBackTenSeconds_Click(object sender, RoutedEventArgs e) => SeekNativeMedia(-10_000);

    private void NativeForwardThirtySeconds_Click(object sender, RoutedEventArgs e) => SeekNativeMedia(30_000);

    private void NativeLoop_Click(object sender, RoutedEventArgs e)
    {
        PlaybackRuleCombo.SelectedIndex = (PlaybackRuleCombo.SelectedIndex + 1) % PlaybackRuleCombo.Items.Count;
        var item = PlaybackRuleCombo.SelectedItem as ComboBoxItem;
        var rule = item?.Tag as string ?? "stop";
        NativeLoopButton.Foreground = new SolidColorBrush(rule is "one" or "all"
            ? Color.FromRgb(100, 224, 189)
            : Color.FromRgb(216, 238, 228));
        var ruleLabel = item?.Content is string content ? UiLanguage.Translate(content) : UiLanguage.Translate("停止");
        NativeLoopButton.ToolTip = $"{UiLanguage.Translate("播放结束后：")}{ruleLabel}";
        RevealNativeControls();
    }

    private void SeekNativeMedia(long delta)
    {
        if (_nativePlayer?.Length is not > 0) return;
        _nativePlayer.Time = Math.Clamp(_nativePlayer.Time + delta, 0, _nativePlayer.Length);
        RevealNativeControls();
    }

    private void NativeProgressSlider_PreviewMouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    {
        if (_nativePlayer?.Length is not > 0) return;
        _nativeSeeking = true;
        _nativePlayer.Time = (long)(_nativePlayer.Length * (NativeProgressSlider.Value / NativeProgressSlider.Maximum));
        _nativeSeeking = false;
        RevealNativeControls();
    }

    private void NativeProgressSlider_PreviewMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ChangedButton != MouseButton.Left || _nativePlayer?.Length is not > 0) return;
        var point = e.GetPosition(NativeProgressSlider);
        var fraction = Math.Clamp(point.X / Math.Max(1, NativeProgressSlider.ActualWidth), 0, 1);
        _nativeSeeking = true;
        NativeProgressSlider.Value = fraction * NativeProgressSlider.Maximum;
        _nativePlayer.Time = (long)(_nativePlayer.Length * fraction);
        _nativeSeeking = false;
        RevealNativeControls();
    }

    private void NativeVolumeSlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
    {
        if (_nativePlayer is not null) _nativePlayer.Volume = (int)Math.Round(e.NewValue);
    }

    private void NativeFullscreen_Click(object sender, RoutedEventArgs e)
    {
        if (_mediaFullscreen) LeaveMediaFullscreen();
        else SetMediaFullscreen(true);
        e.Handled = true;
    }

    private void Viewer_PreviewMouseMove(object sender, MouseEventArgs e) => RevealNativeControlsFromPointer();

    private void NativeMediaHost_MouseMove(object sender, MouseEventArgs e) => RevealNativeControlsFromPointer();

    private void NativeMediaView_MouseMove(object sender, MouseEventArgs e) => RevealNativeControlsFromPointer();

    private void NativeMediaOverlay_MouseMove(object sender, MouseEventArgs e) => RevealNativeControlsFromPointer();

    private void NativeMediaOverlay_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        NativeMediaHost.Focus();
        if (e.ClickCount == 2)
        {
            _nativeVideoClickTimer?.Stop();
            if (_mediaFullscreen) LeaveMediaFullscreen();
            else SetMediaFullscreen(true);
            e.Handled = true;
            return;
        }

        if (_currentEntry?.MediaKind == SecureMediaKind.Video && _nativePlayer is not null)
        {
            QueueNativeVideoClick();
            e.Handled = true;
        }
    }

    private void QueueNativeVideoClick()
    {
        _nativeVideoClickTimer ??= new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(GetDoubleClickTime()) };
        _nativeVideoClickTimer.Tick -= NativeVideoClickTimer_Tick;
        _nativeVideoClickTimer.Tick += NativeVideoClickTimer_Tick;
        _nativeVideoClickTimer.Stop();
        _nativeVideoClickTimer.Start();
    }

    private void NativeVideoClickTimer_Tick(object? sender, EventArgs e)
    {
        _nativeVideoClickTimer?.Stop();
        if (_currentEntry?.MediaKind != SecureMediaKind.Video || _nativePlayer is null) return;
        if (_nativePlayer.IsPlaying) _nativePlayer.Pause();
        else _nativePlayer.Play();
        RevealNativeControls();
    }

    private void NativeMediaHost_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Escape && _mediaFullscreen)
        {
            LeaveMediaFullscreen();
            e.Handled = true;
            return;
        }
        if (TrySeekWithKeyboard(e.Key)) e.Handled = true;
    }

    private void NativeMediaHost_SizeChanged(object sender, SizeChangedEventArgs e) => UpdateNativePresentationBounds();

    private void RevealNativeControlsFromPointer()
    {
        if (_mediaFullscreen && NativeMediaHost.IsVisible) RevealNativeControls();
    }

    private void NativeUiTimer_Tick(object? sender, EventArgs e)
    {
        if (_nativePlayer is null || _nativeMedia is null) return;
        var length = _nativePlayer.Length;
        var time = _nativePlayer.Time;
        NativeTimeText.Text = FormatMediaTime(time);
        NativeDurationText.Text = FormatMediaTime(length);
        if (!_nativeSeeking && length > 0) NativeProgressSlider.Value = Math.Clamp(time * 1000d / length, 0, 1000);
    }

    private void NativePointerTimer_Tick(object? sender, EventArgs e)
    {
        if (!_mediaFullscreen || !NativeMediaHost.IsVisible || _nativePlayer?.IsPlaying != true || !GetCursorPos(out var current))
        {
            _hasLastNativeCursorPosition = false;
            return;
        }

        var position = NativeMediaHost.PointFromScreen(new Point(current.X, current.Y));
        var insideVideo = position.X >= 0 && position.Y >= 0 &&
                          position.X <= NativeMediaHost.ActualWidth && position.Y <= NativeMediaHost.ActualHeight;
        if (!insideVideo)
        {
            _hasLastNativeCursorPosition = false;
            return;
        }

        var changed = !_hasLastNativeCursorPosition || current.X != _lastNativeCursorPosition.X || current.Y != _lastNativeCursorPosition.Y;
        _lastNativeCursorPosition = current;
        _hasLastNativeCursorPosition = true;
        if (changed) RevealNativeControls();
    }

    private void UpdateNativePresentationBounds()
    {
        var hostWidth = NativeMediaHost.ActualWidth;
        var hostHeight = NativeMediaHost.RowDefinitions.Count > 0
            ? NativeMediaHost.RowDefinitions[0].ActualHeight
            : NativeMediaHost.ActualHeight;
        if (hostWidth <= 0 || hostHeight <= 0 || _nativeVideoAspect <= 0) return;

        var width = hostWidth;
        var height = width / _nativeVideoAspect;
        if (height > hostHeight)
        {
            height = hostHeight;
            width = height * _nativeVideoAspect;
        }

        NativeMediaPresentation.Width = Math.Max(1, Math.Round(width));
        NativeMediaPresentation.Height = Math.Max(1, Math.Round(height));
    }

    private void SetNativeLoading(bool visible, string? caption = null)
    {
        if (caption is not null) NativeLoadingCaption.Text = caption;
        NativeMediaLoadingOverlay.Visibility = visible ? Visibility.Visible : Visibility.Collapsed;
        NativeLoadingSpinner.BeginAnimation(RotateTransform.AngleProperty, visible
            ? new DoubleAnimation(0, 360, TimeSpan.FromMilliseconds(850)) { RepeatBehavior = RepeatBehavior.Forever }
            : null);
    }

    private void NativeHideTimer_Tick(object? sender, EventArgs e)
    {
        _nativeHideTimer?.Stop();
        if (_mediaFullscreen && _nativePlayer?.IsPlaying == true) SetNativeControlsVisible(false);
    }

    private void RevealNativeControls()
    {
        if (!_mediaFullscreen || NativeMediaControlBar.Opacity < 0.99)
        {
            SetNativeControlsVisible(true);
        }
        _nativeHideTimer?.Stop();
        if (_mediaFullscreen && _nativePlayer?.IsPlaying == true) _nativeHideTimer?.Start();
    }

    private void SetNativeControlsVisible(bool visible)
    {
        if (!_mediaFullscreen)
        {
            NativeMediaControlBar.BeginAnimation(OpacityProperty, null);
            NativeMediaHint.BeginAnimation(OpacityProperty, null);
            NativeMediaControlBar.Opacity = 1;
            NativeMediaControlBar.IsHitTestVisible = true;
            NativeMediaHint.Opacity = 0.76;
            return;
        }

        if (visible)
        {
            NativeMediaControlBar.IsHitTestVisible = true;
            NativeMediaControlBar.BeginAnimation(OpacityProperty,
                new DoubleAnimation(1, TimeSpan.FromMilliseconds(160)));
        }
        else
        {
            var hideAnimation = new DoubleAnimation(0, TimeSpan.FromMilliseconds(240));
            hideAnimation.Completed += (_, _) =>
            {
                if (NativeMediaControlBar.Opacity < 0.01) NativeMediaControlBar.IsHitTestVisible = false;
            };
            NativeMediaControlBar.BeginAnimation(OpacityProperty, hideAnimation);
        }
        NativeMediaHint.BeginAnimation(OpacityProperty, new DoubleAnimation(visible ? 0.76 : 0,
            TimeSpan.FromMilliseconds(visible ? 160 : 240)));
    }

    private void NativeProgressSlider_PreviewMouseMove(object sender, MouseEventArgs e)
    {
        if (_nativePlayer?.Length is not > 0) return;
        // 首次悬停时也先取得控制栏的最终位置，避免预览框完成布局后再次向下跳动。
        NativeMediaHost.UpdateLayout();
        NativePreviewPopup.Visibility = Visibility.Visible;
        var point = e.GetPosition(NativeProgressSlider);
        var fraction = Math.Clamp(point.X / Math.Max(1, NativeProgressSlider.ActualWidth), 0, 1);
        // 控制栏位于播放区下方，已经不是预览层的子元素；通过屏幕坐标转换，
        // 避免直接向旧的父元素换算位置而引发窗口异常。
        var overlayPoint = NativeMediaOverlay.PointFromScreen(NativeProgressSlider.PointToScreen(point));
        var popupLeft = Math.Clamp(overlayPoint.X - NativePreviewPopup.Width / 2, 8,
            Math.Max(8, NativeMediaOverlay.ActualWidth - NativePreviewPopup.Width - 8));
        // 预览始终贴在独立控制栏上方；不再以视频画面底部为基准，避免出现大块空白。
        var controlBarTop = NativeMediaOverlay.PointFromScreen(
            NativeMediaControlBar.PointToScreen(new Point(0, 0))).Y;
        var popupHeight = NativePreviewPopup.Height;
        var popupTop = Math.Max(8, controlBarTop - popupHeight - 10);
        NativePreviewPopup.VerticalAlignment = VerticalAlignment.Top;
        NativePreviewPopup.Margin = new Thickness(popupLeft, popupTop, 0, 0);
        NativePreviewTime.Text = FormatMediaTime((long)(_nativePlayer.Length * fraction));
        RequestNativePreview((long)(_nativePlayer.Length * fraction));
        RevealNativeControls();
    }

    private void NativeProgressSlider_MouseLeave(object sender, MouseEventArgs e) => NativePreviewPopup.Visibility = Visibility.Collapsed;

    private void RequestNativePreview(long time)
    {
        _nativePreviewRequestedTime = time;
        SetNativePreviewLoading(true, UiLanguage.Translate("正在生成预览…"));
        _nativePreviewTimer?.Stop();
        _nativePreviewTimer?.Start();
    }

    private void NativePreviewTimer_Tick(object? sender, EventArgs e)
    {
        _nativePreviewTimer?.Stop();
        if (_nativePreviewRequestedTime < 0) return;
        if (!StartNativePreviewPlayback())
        {
            SetNativePreviewUnavailable();
            return;
        }
        _nativePreviewFramePending = true;
        _nativePreviewTimeoutTimer?.Stop();
        _nativePreviewTimeoutTimer?.Start();
        _nativePreviewPlayer!.Time = _nativePreviewRequestedTime;
    }

    private void NativePreviewTimeoutTimer_Tick(object? sender, EventArgs e)
    {
        _nativePreviewTimeoutTimer?.Stop();
        if (!_nativePreviewFramePending || _nativePreviewHasFrame) return;
        SetNativePreviewUnavailable();
    }

    private void SetNativePreviewUnavailable()
    {
        _nativePreviewFramePending = false;
        _nativePreviewTimeoutTimer?.Stop();
        SetNativePreviewLoading(true, UiLanguage.Translate("预览暂不可用"));
    }

    private void SetNativePreviewLoading(bool visible, string? caption = null)
    {
        if (caption is not null) NativePreviewLoadingText.Text = caption;
        NativePreviewLoadingPanel.Visibility = visible ? Visibility.Visible : Visibility.Collapsed;
        NativePreviewLoadingSpinner.BeginAnimation(RotateTransform.AngleProperty, visible && caption != UiLanguage.Translate("预览暂不可用")
            ? new DoubleAnimation(0, 360, TimeSpan.FromMilliseconds(720)) { RepeatBehavior = RepeatBehavior.Forever }
            : null);
    }

    private static string FormatMediaTime(long milliseconds)
    {
        var seconds = Math.Max(0, milliseconds / 1000);
        return $"{seconds / 60}:{seconds % 60:D2}";
    }

    protected override void OnPreviewKeyDown(KeyEventArgs e)
    {
        if (e.Key == Key.Escape && _mediaFullscreen)
        {
            LeaveMediaFullscreen();
            e.Handled = true;
            return;
        }
        if (TrySeekWithKeyboard(e.Key)) e.Handled = true;
        base.OnPreviewKeyDown(e);
    }

    private void ViewerThreadPreprocessMessage(ref MSG msg, ref bool handled)
    {
        if (_closing) return;
        if ((msg.message is WmKeyDown or WmSysKeyDown) &&
            msg.wParam.ToInt64() == VirtualKeyEscape && _mediaFullscreen)
        {
            LeaveMediaFullscreen();
            handled = true;
            return;
        }
        if (!IsActive || !NativeMediaHost.IsVisible) return;
        if (msg.message == WmMouseMove)
        {
            RevealNativeControlsFromPointer();
            return;
        }
        if (handled) return;
        if (msg.message is not WmKeyDown and not WmSysKeyDown) return;
        var key = msg.wParam.ToInt64() switch
        {
            VirtualKeyLeft => Key.Left,
            VirtualKeyRight => Key.Right,
            VirtualKeyEscape => Key.Escape,
            _ => Key.None,
        };
        if (key == Key.Escape && _mediaFullscreen)
        {
            LeaveMediaFullscreen();
            handled = true;
            return;
        }
        if (key != Key.None && TrySeekWithKeyboard(key)) handled = true;
    }

    private bool TrySeekWithKeyboard(Key key)
    {
        if (_nativePlayer?.Length is not > 0 || (key != Key.Left && key != Key.Right)) return false;
        _nativePlayer.Time = Math.Clamp(_nativePlayer.Time + (key == Key.Left ? -5000 : 5000), 0, _nativePlayer.Length);
        RevealNativeControls();
        return true;
    }

    private void ImageScroll_MouseWheel(object sender, MouseWheelEventArgs e)
    {
        if (Keyboard.Modifiers.HasFlag(ModifierKeys.Control))
        {
            ImageZoomSlider.Value = Math.Clamp(ImageZoomSlider.Value + (e.Delta > 0 ? 0.1 : -0.1),
                ImageZoomSlider.Minimum, ImageZoomSlider.Maximum);
            e.Handled = true;
            return;
        }
        // 未按 Ctrl 时不改变图片位置，也不再显示滚动条。
    }

    private void ImageScroll_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (ImageZoomSlider.Value <= 1 || e.ChangedButton != MouseButton.Left) return;
        _isDraggingImage = true;
        _imageDragStart = e.GetPosition(ImageScroll);
        _imageTranslateStart = new Point(ImageTranslate.X, ImageTranslate.Y);
        ImageScroll.CaptureMouse();
        Cursor = Cursors.SizeAll;
        e.Handled = true;
    }

    private void ImageScroll_MouseMove(object sender, MouseEventArgs e)
    {
        if (!_isDraggingImage || e.LeftButton != MouseButtonState.Pressed) return;
        var point = e.GetPosition(ImageScroll);
        ImageTranslate.X = _imageTranslateStart.X + point.X - _imageDragStart.X;
        ImageTranslate.Y = _imageTranslateStart.Y + point.Y - _imageDragStart.Y;
    }

    private void ImageScroll_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    {
        if (!_isDraggingImage) return;
        _isDraggingImage = false;
        ImageScroll.ReleaseMouseCapture();
        Cursor = Cursors.Arrow;
        e.Handled = true;
    }

    private void MoveSelection(int offset, bool loop)
    {
        if (_currentEntry is null || _filteredEntries.Count == 0) return;
        var current = _filteredEntries.ToList().FindIndex(entry => string.Equals(entry.RelativePath, _currentEntry.RelativePath, StringComparison.OrdinalIgnoreCase));
        var target = current + offset;
        if (target < 0 || target >= _filteredEntries.Count)
        {
            if (!loop) return;
            target = target < 0 ? _filteredEntries.Count - 1 : 0;
        }
        Playlist.SelectedItem = _filteredEntries[target];
        Playlist.ScrollIntoView(_filteredEntries[target]);
    }

    private void ZoomOut_Click(object sender, RoutedEventArgs e) => ImageZoomSlider.Value = Math.Max(ImageZoomSlider.Minimum, ImageZoomSlider.Value - 0.2);
    private void ZoomIn_Click(object sender, RoutedEventArgs e) => ImageZoomSlider.Value = Math.Min(ImageZoomSlider.Maximum, ImageZoomSlider.Value + 0.2);
    private void ImageZoomReset_Click(object sender, RoutedEventArgs e) => ResetImageView();
    private void ImageZoomSlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
    {
        ImageScale.ScaleX = e.NewValue;
        ImageScale.ScaleY = e.NewValue;
        if (e.NewValue <= 1)
        {
            ImageTranslate.X = 0;
            ImageTranslate.Y = 0;
        }
    }

    private void ResetImageView()
    {
        ImageZoomSlider.Value = 1;
        ImageTranslate.X = 0;
        ImageTranslate.Y = 0;
    }

    private void HideContentViews()
    {
        EmptyView.Visibility = Visibility.Collapsed;
        ImageScroll.Visibility = Visibility.Collapsed;
        TextView.Visibility = Visibility.Collapsed;
        NativeMediaHost.Visibility = Visibility.Collapsed;
        ImageZoomPanel.Visibility = Visibility.Collapsed;
        PlaybackRulePanel.Visibility = Visibility.Collapsed;
        NativePreviewPopup.Visibility = Visibility.Collapsed;
        ImageView.Source = null;
        TextView.Clear();
    }

    private void DisposeMediaCache()
    {
        _mediaCache?.Dispose();
        _mediaCache = null;
    }

    private void SetMediaFullscreen(bool enabled)
    {
        if (_mediaFullscreen == enabled) return;
        _mediaFullscreen = enabled;
        if (enabled)
        {
            _hasLastNativeCursorPosition = false;
            _windowStateBeforeFullscreen = WindowState;
            ViewerRoot.Margin = new Thickness(0);
            ViewerHeader.Visibility = Visibility.Collapsed;
            PlaylistPanel.Visibility = Visibility.Collapsed;
            ViewerBody.Margin = new Thickness(0);
            ViewerBody.ColumnDefinitions[0].Width = new GridLength(0);
            ViewerBody.ColumnDefinitions[1].Width = new GridLength(0);
            Grid.SetColumn(MediaPanel, 0);
            Grid.SetColumnSpan(MediaPanel, 3);
            MediaPanel.CornerRadius = new CornerRadius(0);
            MediaPanel.Padding = new Thickness(0);
            SetNativeControlBarAppearance();
            WindowState = WindowState.Maximized;
            RevealNativeControls();
        }
        else LeaveMediaFullscreen();
    }

    private void LeaveMediaFullscreen()
    {
        if (!_mediaFullscreen) return;
        _mediaFullscreen = false;
        _hasLastNativeCursorPosition = false;
        ViewerRoot.Margin = new Thickness(22);
        ViewerHeader.Visibility = Visibility.Visible;
        PlaylistPanel.Visibility = Visibility.Visible;
        ViewerBody.Margin = new Thickness(0, 18, 0, 0);
        ViewerBody.ColumnDefinitions[0].Width = new GridLength(280);
        ViewerBody.ColumnDefinitions[1].Width = new GridLength(16);
        Grid.SetColumn(MediaPanel, 2);
        Grid.SetColumnSpan(MediaPanel, 1);
        MediaPanel.CornerRadius = new CornerRadius(15);
        MediaPanel.Padding = new Thickness(18);
        SetNativeControlBarAppearance();
        WindowState = _windowStateBeforeFullscreen;
        _nativeHideTimer?.Stop();
        SetNativeControlsVisible(true);
    }

    private void SetNativeControlBarAppearance()
    {
        NativeMediaControlBar.Background = new SolidColorBrush(_mediaFullscreen
            ? Color.FromArgb(154, 23, 53, 44)
            : Color.FromArgb(240, 23, 53, 44));
        NativeMediaControlBar.Margin = new Thickness(0);
    }

    // 浏览器预览已经移除：它在部分本机视频上无法提供画面，导致预览无限加载。
#if false
    private static (long Start, long Length, bool Partial) ParseRange(CoreWebView2HttpRequestHeaders headers, long totalLength)
    {
        string? range;
        try { range = headers.GetHeader("Range"); } catch { range = null; }
        if (string.IsNullOrWhiteSpace(range)) return (0, totalLength, false);
        if (!range.StartsWith("bytes=", StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException(UiLanguage.Translate("不支持的媒体读取范围。"));
        var parts = range[6..].Split(',', 2)[0].Trim().Split('-', 2);
        if (parts.Length != 2) throw new InvalidDataException(UiLanguage.Translate("媒体读取范围不正确。"));
        if (string.IsNullOrWhiteSpace(parts[0]))
        {
            if (!long.TryParse(parts[1], out var suffix) || suffix <= 0) throw new InvalidDataException(UiLanguage.Translate("媒体读取范围不正确。"));
            var start = Math.Max(0, totalLength - suffix);
            return (start, totalLength - start, true);
        }
        if (!long.TryParse(parts[0], out var startValue) || startValue < 0 || startValue >= totalLength) throw new InvalidDataException(UiLanguage.Translate("媒体读取位置超出范围。"));
        var end = string.IsNullOrWhiteSpace(parts[1]) ? totalLength - 1 :
            long.TryParse(parts[1], out var requestedEnd) ? Math.Min(requestedEnd, totalLength - 1) : throw new InvalidDataException(UiLanguage.Translate("媒体读取范围不正确。"));
        if (end < startValue) throw new InvalidDataException(UiLanguage.Translate("媒体读取范围不正确。"));
        return (startValue, end - startValue + 1, true);
    }

    private static string BuildPreviewCaptureHtml(string previewId)
    {
        var source = JsonSerializer.Serialize($"{MediaUrlPrefix}?preview={Guid.NewGuid():N}");
        var id = JsonSerializer.Serialize(previewId);
        return $$$"""
<!doctype html><html><body style="margin:0;background:transparent"><video id="preview" muted preload="auto" playsinline crossorigin="anonymous" style="width:1px;height:1px;opacity:0"><source src={{{source}}}></video><script>
const video=document.getElementById('preview'),playerId={{{id}}};let queued=null,busy=false;const send=x=>chrome.webview.postMessage(JSON.stringify({...x,playerId}));
const wait=(event,timeout)=>new Promise((ok,no)=>{let timer=setTimeout(()=>{video.removeEventListener(event,done);no(new Error('timeout'))},timeout);function done(){clearTimeout(timer);ok()}video.addEventListener(event,done,{once:true})});
const nextFrame=()=>new Promise(ok=>{if(video.requestVideoFrameCallback)video.requestVideoFrameCallback(()=>ok());else requestAnimationFrame(()=>requestAnimationFrame(ok));});
async function capture(request){queued=request;if(busy)return;busy=true;while(queued){const current=queued;queued=null;try{if(video.readyState<2)await wait('loadeddata',3500);if(Math.abs(video.currentTime-current.time)>.04){const seeked=wait('seeked',1800);video.currentTime=current.time;await seeked}await nextFrame();if(queued)continue;const canvas=document.createElement('canvas');canvas.width=220;canvas.height=124;const context=canvas.getContext('2d');context.fillStyle='#000';context.fillRect(0,0,220,124);const ratio=Math.min(220/(video.videoWidth||220),124/(video.videoHeight||124)),width=(video.videoWidth||220)*ratio,height=(video.videoHeight||124)*ratio;context.drawImage(video,(220-width)/2,(124-height)/2,width,height);send({kind:'preview-frame',requestId:current.requestId,image:canvas.toDataURL('image/jpeg',.72)})}catch{if(!queued)send({kind:'preview-error',requestId:current.requestId})}}busy=false}
window.captureSecurePreview=capture;video.addEventListener('loadedmetadata',()=>send({kind:'preview-ready'}));video.addEventListener('error',()=>send({kind:'preview-error',requestId:-1}));
</script></body></html>
""";
    }

    private string BuildPlayerHtml(SecureArchiveEntry entry, string playerId)
    {
        var element = entry.MediaKind == SecureMediaKind.Audio ? "audio" : "video";
        var name = SecurityElement.Escape(entry.Name) ?? UiLanguage.Translate("媒体");
        var hint = UiLanguage.IsEnglish ? "← / → Seek    Double-click for full screen" : "← / → 调整播放进度　双击画面全屏";
        var playTitle = UiLanguage.Translate("播放或暂停");
        var progressLabel = UiLanguage.Translate("播放进度");
        var volumeLabel = UiLanguage.Translate("音量");
        var fullscreenTitle = UiLanguage.Translate("全屏");
        var decodeError = UiLanguage.Translate("媒体无法解码或读取。");
        var source = $"{MediaUrlPrefix}?v={Guid.NewGuid():N}";
        var template = """
<!doctype html><html><head><meta charset="utf-8"><style>
:root{color-scheme:dark}html,body,#stage{height:100%;width:100%;margin:0;overflow:hidden;background:#090b0a;font-family:"Segoe UI",sans-serif}#stage{position:relative;display:flex;align-items:center;justify-content:center}video,audio{width:100%;height:100%;max-width:100%;max-height:100%;object-fit:contain;background:#090b0a;outline:none}audio{height:92px;max-width:760px}#bar{position:absolute;left:18px;right:18px;bottom:16px;z-index:4;display:flex;align-items:center;gap:12px;padding:10px 13px;border-radius:12px;background:rgba(8,12,10,.68);backdrop-filter:blur(9px);transition:opacity .24s ease,transform .24s ease}#stage.hide-bar #bar{opacity:0;transform:translateY(10px);pointer-events:none}button{border:0;color:#fff;background:transparent;font-size:18px;min-width:30px;cursor:pointer}input[type=range]{accent-color:#41b883}#progress{flex:1;cursor:pointer}#time{min-width:96px;color:#eef7f1;font-size:13px;white-space:nowrap;font-variant-numeric:tabular-nums}#preview{position:absolute;display:none;z-index:5;bottom:59px;width:220px;padding:5px;border-radius:8px;background:rgba(8,12,10,.9);box-shadow:0 8px 20px #0008;pointer-events:none}#preview img{display:block;width:220px;height:124px;object-fit:contain;background:#000;border-radius:5px}#preview label{display:block;text-align:center;color:#fff;font-size:12px;margin-top:3px}#hint{position:absolute;top:15px;left:18px;color:#b6c9bf;font-size:13px;opacity:.76;transition:opacity .3s}#stage.playing #hint{opacity:0}
</style></head><body><div id="stage"><{{element}} id="media" preload="auto" playsinline crossorigin="anonymous" aria-label="{{name}}"><source src="{{source}}" type="{{mime}}"></{{element}}><div id="hint">{{hint}}</div><div id="preview"><img><label></label></div><div id="bar"><button id="play" title="{{playTitle}}">▶</button><span id="time">0:00 / 0:00</span><input id="progress" type="range" min="0" max="1000" value="0" aria-label="{{progressLabel}}"><input id="volume" type="range" min="0" max="1" step=".05" value="1" aria-label="{{volumeLabel}}"><button id="fullscreen" title="{{fullscreenTitle}}">⛶</button></div></div><script>
const m=document.getElementById('media'),stage=document.getElementById('stage'),play=document.getElementById('play'),progress=document.getElementById('progress'),time=document.getElementById('time'),preview=document.getElementById('preview'),previewImg=preview.querySelector('img'),previewLabel=preview.querySelector('label'),volume=document.getElementById('volume');let hideTimer=0,wantedPreview=-1,previewBusy=false,previewTimer=0,previewStarted=false;const previewVideo=document.createElement('video');previewVideo.muted=true;previewVideo.preload='none';previewVideo.crossOrigin='anonymous';const post=x=>chrome.webview.postMessage(JSON.stringify({...x,playerId:'{{playerId}}'}));const fmt=s=>{s=Number.isFinite(s)?Math.max(0,Math.floor(s)):0;return Math.floor(s/60)+':'+String(s%60).padStart(2,'0')};function paint(){progress.value=m.duration?Math.round(m.currentTime/m.duration*1000):0;time.textContent=fmt(m.currentTime)+' / '+fmt(m.duration)}function reveal(){stage.classList.remove('hide-bar');clearTimeout(hideTimer);if(document.fullscreenElement)hideTimer=setTimeout(()=>stage.classList.add('hide-bar'),3000)}
play.onclick=()=>m.paused?m.play():m.pause();m.onplay=()=>{play.textContent='❚❚';stage.classList.add('playing')};m.onpause=()=>play.textContent='▶';m.ontimeupdate=paint;m.onloadedmetadata=paint;m.onended=()=>{play.textContent='▶';post({kind:'ended'});reveal()};m.onerror=()=>post({kind:'problem',message:'{{decodeError}}'});progress.oninput=()=>{if(m.duration)m.currentTime=m.duration*(progress.value/1000)};volume.oninput=()=>m.volume=volume.value;document.addEventListener('keydown',e=>{if(e.key==='ArrowLeft'||e.key==='ArrowRight'){m.currentTime=Math.max(0,Math.min(m.duration||0,m.currentTime+(e.key==='ArrowLeft'?-5:5)));e.preventDefault();reveal()}});const toggle=()=>document.fullscreenElement?document.exitFullscreen():stage.requestFullscreen();stage.ondblclick=toggle;document.getElementById('fullscreen').onclick=toggle;document.addEventListener('fullscreenchange',()=>{post({kind:'fullscreen',value:!!document.fullscreenElement});reveal()});stage.addEventListener('mousemove',reveal);reveal();
async function drawPreview(){if(previewBusy||wantedPreview<0)return;previewBusy=true;let at=wantedPreview;wantedPreview=-1;try{if(!previewStarted){previewStarted=true;previewVideo.src='{{previewSource}}';previewVideo.load();await new Promise((ok,no)=>{let t=setTimeout(no,1800);previewVideo.onloadedmetadata=()=>{clearTimeout(t);ok()};previewVideo.onerror=()=>{clearTimeout(t);no()}})}if(Math.abs(previewVideo.currentTime-at)>.15){previewVideo.currentTime=at;await new Promise((ok,no)=>{let t=setTimeout(no,1800);previewVideo.onseeked=()=>{clearTimeout(t);ok()};previewVideo.onerror=()=>{clearTimeout(t);no()}})}let c=document.createElement('canvas'),w=220,h=124;c.width=w;c.height=h;let x=c.getContext('2d');x.fillStyle='#000';x.fillRect(0,0,w,h);let r=Math.min(w/(previewVideo.videoWidth||w),h/(previewVideo.videoHeight||h)),dw=(previewVideo.videoWidth||w)*r,dh=(previewVideo.videoHeight||h)*r;x.drawImage(previewVideo,(w-dw)/2,(h-dh)/2,dw,dh);previewImg.src=c.toDataURL('image/jpeg',.72);previewLabel.textContent=fmt(at)}catch{}finally{previewBusy=false;if(wantedPreview>=0)drawPreview()}}
progress.addEventListener('pointermove',e=>{if(!m.duration)return;let r=progress.getBoundingClientRect(),f=Math.max(0,Math.min(1,(e.clientX-r.left)/r.width)),at=m.duration*f;preview.style.display='block';preview.style.left=Math.max(10,Math.min(window.innerWidth-240,e.clientX-110))+'px';clearTimeout(previewTimer);previewTimer=setTimeout(()=>{wantedPreview=at;drawPreview()},180)});progress.addEventListener('pointerleave',()=>preview.style.display='none');
</script></div></body></html>
""";
        return template.Replace("{{element}}", element, StringComparison.Ordinal)
            .Replace("{{name}}", name, StringComparison.Ordinal)
            .Replace("{{source}}", source, StringComparison.Ordinal)
            .Replace("{{previewSource}}", $"{source}&preview=1", StringComparison.Ordinal)
            .Replace("{{playerId}}", playerId, StringComparison.Ordinal)
            .Replace("{{hint}}", hint, StringComparison.Ordinal)
            .Replace("{{playTitle}}", playTitle, StringComparison.Ordinal)
            .Replace("{{progressLabel}}", progressLabel, StringComparison.Ordinal)
            .Replace("{{volumeLabel}}", volumeLabel, StringComparison.Ordinal)
            .Replace("{{fullscreenTitle}}", fullscreenTitle, StringComparison.Ordinal)
            .Replace("{{decodeError}}", decodeError, StringComparison.Ordinal)
            .Replace("{{mime}}", NrMediaFiles.GetContentType(entry.Name), StringComparison.Ordinal);
    }
#endif

    private async void Window_Closing(object? sender, CancelEventArgs e)
    {
        if (_closing) return;
        _closing = true;
        e.Cancel = true;
        _sessionCancellation.Dispose();
        LeaveMediaFullscreen();
        StopNativePlayback();
        DisposeMediaCache();
        _nativeUiTimer?.Stop();
        _nativeHideTimer?.Stop();
        _nativePointerTimer?.Stop();
        if (_nativePlayer is not null)
        {
        _nativePlayer.EndReached -= NativePlayer_EndReached;
            _nativePlayer.EncounteredError -= NativePlayer_EncounteredError;
            _nativePlayer.Playing -= NativePlayer_PlaybackStateChanged;
            _nativePlayer.Paused -= NativePlayer_PlaybackStateChanged;
            _nativePlayer.Stopped -= NativePlayer_PlaybackStateChanged;
            _nativePlayer.Buffering -= NativePlayer_Buffering;
            _nativePlayer.TimeChanged -= NativePlayer_TimeChanged;
        }
        ComponentDispatcher.ThreadPreprocessMessage -= ViewerThreadPreprocessMessage;
        NativeMediaView.MediaPlayer = null;
        _nativePlayer?.Dispose();
        _nativePlayer = null;
        NativePreviewVideoView.MediaPlayer = null;
        NativePreviewVideoView.Dispose();
        _nativeVlc?.Dispose();
        _nativeVlc = null;
        NativeMediaView.Dispose();
        await Task.Yield();
        Close();
    }

}
