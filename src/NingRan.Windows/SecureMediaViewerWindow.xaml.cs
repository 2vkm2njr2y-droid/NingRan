using System.ComponentModel;
using System.IO;
using System.Security;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media.Imaging;
using Microsoft.Web.WebView2.Core;
using NingRan.Core;

namespace NingRan.Windows;

public partial class SecureMediaViewerWindow : Window
{
    private const string MediaUrlPrefix = "https://ningran-media.local/media";
    private readonly SecureArchiveSession _session;
    private readonly IReadOnlyList<SecureArchiveEntry> _folderEntries;
    private readonly SecureArchiveEntry _initialEntry;
    private IReadOnlyList<SecureArchiveEntry> _filteredEntries = [];
    private SecureArchiveEntry? _currentEntry;
    private string? _browserUserDataDirectory;
    private CancellationTokenRegistration _sessionCancellation;
    private bool _browserReady;
    private bool _closing;

    public SecureMediaViewerWindow(
        SecureArchiveSession session,
        IReadOnlyList<SecureArchiveEntry> folderEntries,
        SecureArchiveEntry initialEntry)
    {
        _session = session;
        _folderEntries = folderEntries;
        _initialEntry = initialEntry;
        InitializeComponent();
        TitleText.Text = initialEntry.Name;
        SubtitleText.Text = $"当前文件夹内有 {folderEntries.Count} 个可在程序内查看的媒体文件。";
        _sessionCancellation = _session.CancellationToken.Register(() =>
        {
            Dispatcher.BeginInvoke(() =>
            {
                if (!_closing)
                {
                    MessageBox.Show(this, "授权物理设备已被拔出或发生变化，安全查看将关闭。", "凝然加密",
                        MessageBoxButton.OK, MessageBoxImage.Warning);
                    Close();
                }
            });
        });
    }

    private async void Window_Loaded(object sender, RoutedEventArgs e)
    {
        ApplyFilter();
        Playlist.SelectedItem = _filteredEntries.FirstOrDefault(entry =>
            string.Equals(entry.RelativePath, _initialEntry.RelativePath, StringComparison.OrdinalIgnoreCase));
        if (Playlist.SelectedItem is null && _filteredEntries.Count > 0)
        {
            Playlist.SelectedIndex = 0;
        }

        try
        {
            await EnsureBrowserAsync();
        }
        catch (Exception exception)
        {
            // 文本和图片仍可正常使用；播放音视频时会显示明确的运行环境问题。
            EmptyText.Text = $"内置音视频组件无法启动：{exception.Message}";
        }
    }

    private void TypeFilterCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!IsLoaded) return;
        var previouslySelected = _currentEntry?.RelativePath;
        ApplyFilter();
        Playlist.SelectedItem = _filteredEntries.FirstOrDefault(entry =>
            string.Equals(entry.RelativePath, previouslySelected, StringComparison.OrdinalIgnoreCase));
        if (Playlist.SelectedItem is null && _filteredEntries.Count > 0)
        {
            Playlist.SelectedIndex = 0;
        }
    }

    private async void Playlist_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (Playlist.SelectedItem is not SecureArchiveEntry entry ||
            string.Equals(entry.RelativePath, _currentEntry?.RelativePath, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

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
        try
        {
            _currentEntry = entry;
            CurrentFileText.Text = entry.Name;
            HideContentViews();
            switch (entry.MediaKind)
            {
                case SecureMediaKind.Text:
                    await LoadTextAsync(entry);
                    break;
                case SecureMediaKind.Image:
                    await LoadImageAsync(entry);
                    break;
                case SecureMediaKind.Audio:
                case SecureMediaKind.Video:
                    await LoadPlayableMediaAsync(entry);
                    break;
                default:
                    throw new InvalidOperationException("该文件不是可直接查看的媒体类型。");
            }
        }
        catch (OperationCanceledException)
        {
            Close();
        }
        catch (Exception exception)
        {
            HideContentViews();
            EmptyView.Visibility = Visibility.Visible;
            EmptyText.Text = $"无法在程序内打开此文件：{exception.Message}";
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
        ImageZoomSlider.Value = 1;
        ImageScroll.Visibility = Visibility.Visible;
        ImageZoomPanel.Visibility = Visibility.Visible;
    }

    private async Task LoadPlayableMediaAsync(SecureArchiveEntry entry)
    {
        await EnsureBrowserAsync();
        if (!_browserReady)
        {
            throw new NingRanException("内置音视频组件尚未准备好。");
        }

        MediaBrowser.Visibility = Visibility.Visible;
        PlaybackRulePanel.Visibility = Visibility.Visible;
        var elementName = entry.MediaKind == SecureMediaKind.Video ? "video" : "audio";
        var escapedName = SecurityElement.Escape(entry.Name) ?? "媒体";
        var mimeType = NrMediaFiles.GetContentType(entry.Name);
        var html = "<!doctype html><html><head><meta charset=\"utf-8\"><style>" +
                   "html,body{height:100%;margin:0;background:#17221E;color:#F3F7F5;font-family:Segoe UI,sans-serif}" +
                   elementName + "{width:100%;height:100%;outline:none}audio{height:82px;margin-top:35%;}" +
                   "</style></head><body><" + elementName + " id=\"media\" title=\"" + escapedName +
                   "\" controls autoplay controlslist=\"nodownload noremoteplayback\"><source src=\"" +
                   MediaUrlPrefix + "?v=" + Guid.NewGuid().ToString("N") + "\" type=\"" + mimeType +
                   "\"></" + elementName + "><script>const m=document.getElementById('media');" +
                   "m.addEventListener('ended',()=>chrome.webview.postMessage('ended'));</script></body></html>";
        MediaBrowser.CoreWebView2.NavigateToString(html);
    }

    private async Task EnsureBrowserAsync()
    {
        if (_browserReady) return;
        _browserUserDataDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "NingRan",
            "MediaViewer",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_browserUserDataDirectory);
        var options = new CoreWebView2EnvironmentOptions("--disk-cache-size=0 --media-cache-size=0 --disable-application-cache");
        var environment = await CoreWebView2Environment.CreateAsync(null, _browserUserDataDirectory, options);
        await MediaBrowser.EnsureCoreWebView2Async(environment);
        MediaBrowser.CoreWebView2.Settings.AreDevToolsEnabled = false;
        MediaBrowser.CoreWebView2.Settings.AreDefaultContextMenusEnabled = false;
        MediaBrowser.CoreWebView2.Settings.AreBrowserAcceleratorKeysEnabled = false;
        MediaBrowser.CoreWebView2.AddWebResourceRequestedFilter($"{MediaUrlPrefix}*", CoreWebView2WebResourceContext.All);
        MediaBrowser.CoreWebView2.WebResourceRequested += MediaBrowser_WebResourceRequested;
        MediaBrowser.CoreWebView2.WebMessageReceived += MediaBrowser_WebMessageReceived;
        _browserReady = true;
    }

    private void MediaBrowser_WebResourceRequested(object? sender, CoreWebView2WebResourceRequestedEventArgs e)
    {
        if (_currentEntry is null || _currentEntry.MediaKind is not (SecureMediaKind.Audio or SecureMediaKind.Video))
        {
            e.Response = MediaBrowser.CoreWebView2.Environment.CreateWebResourceResponse(
                new MemoryStream(), 404, "Not Found", "Cache-Control: no-store\r\n");
            return;
        }

        try
        {
            var (start, length, partial) = ParseRange(e.Request.Headers, _currentEntry.Length);
            var source = _session.OpenEntryReadStream(_currentEntry.RelativePath);
            var stream = new RangeLimitedStream(source, start, length);
            var headers = $"Content-Type: {NrMediaFiles.GetContentType(_currentEntry.Name)}\r\n" +
                          $"Content-Length: {length}\r\nAccept-Ranges: bytes\r\n" +
                          "Cache-Control: no-store, no-cache, must-revalidate\r\nPragma: no-cache\r\n";
            if (partial)
            {
                headers += $"Content-Range: bytes {start}-{start + length - 1}/{_currentEntry.Length}\r\n";
            }

            e.Response = MediaBrowser.CoreWebView2.Environment.CreateWebResourceResponse(
                stream,
                partial ? 206 : 200,
                partial ? "Partial Content" : "OK",
                headers);
        }
        catch (Exception exception)
        {
            e.Response = MediaBrowser.CoreWebView2.Environment.CreateWebResourceResponse(
                new MemoryStream(), 416, "Range Not Satisfiable",
                $"Cache-Control: no-store\r\nX-NingRan-Error: {Uri.EscapeDataString(exception.Message)}\r\n");
        }
    }

    private async void MediaBrowser_WebMessageReceived(object? sender, CoreWebView2WebMessageReceivedEventArgs e)
    {
        if (e.TryGetWebMessageAsString() != "ended") return;
        var rule = (PlaybackRuleCombo.SelectedItem as ComboBoxItem)?.Tag as string ?? "stop";
        if (rule == "stop") return;
        if (rule == "one")
        {
            await LoadEntryAsync(_currentEntry!);
            return;
        }

        MoveSelection(1, loop: rule == "all");
    }

    private void ImageScroll_MouseWheel(object sender, MouseWheelEventArgs e)
    {
        if (_filteredEntries.Count < 2) return;
        var atTop = ImageScroll.VerticalOffset <= 0;
        var atBottom = ImageScroll.VerticalOffset >= ImageScroll.ScrollableHeight;
        if (e.Delta > 0 && atTop)
        {
            MoveSelection(-1, loop: false);
            e.Handled = true;
        }
        else if (e.Delta < 0 && atBottom)
        {
            MoveSelection(1, loop: false);
            e.Handled = true;
        }
    }

    private void MoveSelection(int offset, bool loop)
    {
        if (_currentEntry is null || _filteredEntries.Count == 0) return;
        var current = _filteredEntries.ToList().FindIndex(entry =>
            string.Equals(entry.RelativePath, _currentEntry.RelativePath, StringComparison.OrdinalIgnoreCase));
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
    private void ImageZoomSlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
    {
        ImageScale.ScaleX = e.NewValue;
        ImageScale.ScaleY = e.NewValue;
    }

    private void HideContentViews()
    {
        EmptyView.Visibility = Visibility.Collapsed;
        ImageScroll.Visibility = Visibility.Collapsed;
        TextView.Visibility = Visibility.Collapsed;
        MediaBrowser.Visibility = Visibility.Collapsed;
        ImageZoomPanel.Visibility = Visibility.Collapsed;
        PlaybackRulePanel.Visibility = Visibility.Collapsed;
        ImageView.Source = null;
        TextView.Clear();
    }

    private static (long Start, long Length, bool Partial) ParseRange(CoreWebView2HttpRequestHeaders headers, long totalLength)
    {
        if (totalLength < 0) throw new InvalidOperationException("媒体长度不正确。");
        string? range;
        try { range = headers.GetHeader("Range"); }
        catch { range = null; }
        if (string.IsNullOrWhiteSpace(range)) return (0, totalLength, false);
        if (!range.StartsWith("bytes=", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("不支持的读取范围。");
        var parts = range[6..].Split(',', 2)[0].Trim().Split('-', 2);
        if (parts.Length != 2) throw new InvalidOperationException("读取范围不正确。");
        long start;
        long end;
        if (string.IsNullOrWhiteSpace(parts[0]))
        {
            if (!long.TryParse(parts[1], out var suffix) || suffix <= 0) throw new InvalidOperationException("读取范围不正确。");
            start = Math.Max(0, totalLength - suffix);
            end = totalLength - 1;
        }
        else
        {
            if (!long.TryParse(parts[0], out start) || start < 0 || start >= totalLength) throw new InvalidOperationException("读取范围超出文件。");
            end = string.IsNullOrWhiteSpace(parts[1]) ? totalLength - 1 :
                long.TryParse(parts[1], out var requestedEnd) ? Math.Min(requestedEnd, totalLength - 1) : throw new InvalidOperationException("读取范围不正确。");
            if (end < start) throw new InvalidOperationException("读取范围不正确。");
        }

        return (start, checked(end - start + 1), true);
    }

    private void Window_Closing(object? sender, CancelEventArgs e)
    {
        _closing = true;
        _sessionCancellation.Dispose();
        if (_browserReady && MediaBrowser.CoreWebView2 is not null)
        {
            MediaBrowser.CoreWebView2.WebResourceRequested -= MediaBrowser_WebResourceRequested;
            MediaBrowser.CoreWebView2.WebMessageReceived -= MediaBrowser_WebMessageReceived;
        }

        MediaBrowser.Dispose();
        if (!string.IsNullOrWhiteSpace(_browserUserDataDirectory))
        {
            try { Directory.Delete(_browserUserDataDirectory, recursive: true); }
            catch { /* WebView2 正在结束时可能仍持有目录；其中不缓存媒体响应。 */ }
        }
    }
}

internal sealed class RangeLimitedStream : Stream
{
    private readonly Stream _inner;
    private readonly long _length;
    private long _position;

    public RangeLimitedStream(Stream inner, long start, long length)
    {
        _inner = inner;
        _length = length;
        _inner.Position = start;
    }

    public override bool CanRead => _inner.CanRead;
    public override bool CanSeek => _inner.CanSeek;
    public override bool CanWrite => false;
    public override long Length => _length;
    public override long Position { get => _position; set => Seek(value, SeekOrigin.Begin); }
    public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (_position >= _length) return 0;
        var read = await _inner.ReadAsync(buffer[..(int)Math.Min(buffer.Length, _length - _position)], cancellationToken).ConfigureAwait(false);
        _position += read;
        return read;
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        var target = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => _position + offset,
            SeekOrigin.End => _length + offset,
            _ => throw new ArgumentOutOfRangeException(nameof(origin)),
        };
        if (target < 0 || target > _length) throw new IOException("读取位置超出范围。");
        _inner.Position = target + (_inner.Position - _position);
        _position = target;
        return target;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) _inner.Dispose();
        base.Dispose(disposing);
    }

    public override void Flush() => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
