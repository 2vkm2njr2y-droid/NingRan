using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using LibVLCSharp.Shared;
using NingRan.Core;
using NativeMediaPlayer = LibVLCSharp.Shared.MediaPlayer;

namespace NingRan.Windows;

public partial class SecureArchiveExplorerWindow : Window
{
    private SecureArchiveSession _session;
    private readonly MainWindow _host;
    private readonly ObservableCollection<ExplorerEntryItem> _items = [];
    private readonly SemaphoreSlim _videoThumbnailGate = new(1, 1);
    private bool _thumbnailViewReady;
    private string _filter = "All";
    private LibVLC? _thumbnailVlc;
    private NativeMediaPlayer? _thumbnailPlayer;
    private Media? _thumbnailMedia;
    private Stream? _thumbnailStream;
    private bool _closing;

    public SecureArchiveExplorerWindow(SecureArchiveSession session, MainWindow host)
    {
        _session = session;
        _host = host;
        InitializeComponent();
        DataContext = this;
        ArchiveNameText.Text = Path.GetFileName(session.ArchivePath);
        RefreshItems();
    }

    public ObservableCollection<ExplorerEntryItem> Items => _items;

    internal void ReplaceSession(SecureArchiveSession session)
    {
        _session = session;
        ArchiveNameText.Text = Path.GetFileName(session.ArchivePath);
        RefreshItems();
    }

    private void RefreshItems()
    {
        _items.Clear();
        var query = SearchInput?.Text?.Trim() ?? string.Empty;
        foreach (var entry in _session.Entries
                     .Where(entry => string.IsNullOrWhiteSpace(query) ||
                         entry.RelativePath.Contains(query, StringComparison.CurrentCultureIgnoreCase))
                     .Where(EntryMatchesFilter)
                     .OrderBy(entry => !entry.IsDirectory)
                     .ThenBy(entry => entry.RelativePath, StringComparer.CurrentCultureIgnoreCase))
        {
            var item = new ExplorerEntryItem(entry);
            _items.Add(item);
            _ = LoadThumbnailAsync(item);
        }
        CountText.Text = $"{_items.Count:N0} 个项目";
        StatusText.Text = $"共 {_items.Count:N0} 个项目 · 双击文件即可安全查看";
    }

    private bool EntryMatchesFilter(SecureArchiveEntry entry)
    {
        return _filter switch
        {
            "Image" => entry.MediaKind == SecureMediaKind.Image,
            "Video" => entry.MediaKind == SecureMediaKind.Video,
            "Document" => !entry.IsDirectory && entry.MediaKind is not (SecureMediaKind.Image or SecureMediaKind.Video),
            _ => true,
        };
    }

    private async Task LoadThumbnailAsync(ExplorerEntryItem item)
    {
        if (item.Entry.IsDirectory) return;
        try
        {
            if (item.Entry.MediaKind == SecureMediaKind.Image)
            {
                await using var stream = _session.OpenEntryReadStream(item.Entry.RelativePath);
                var bitmap = new BitmapImage();
                bitmap.BeginInit();
                bitmap.CacheOption = BitmapCacheOption.OnLoad;
                bitmap.DecodePixelWidth = 180;
                bitmap.StreamSource = stream;
                bitmap.EndInit();
                bitmap.Freeze();
                await Dispatcher.InvokeAsync(() => item.Thumbnail = bitmap);
                return;
            }

            if (item.Entry.MediaKind == SecureMediaKind.Video)
            {
                await LoadVideoThumbnailAsync(item);
            }
        }
        catch { }
    }

    private void ThumbnailHost_Loaded(object sender, RoutedEventArgs e) => _thumbnailViewReady = true;

    private async Task LoadVideoThumbnailAsync(ExplorerEntryItem item)
    {
        await _videoThumbnailGate.WaitAsync();
        var snapshotPath = Path.Combine(Path.GetTempPath(), "NingRan", "thumbnails", $"{Guid.NewGuid():N}.png");
        try
        {
            if (!_thumbnailViewReady) return;
            var nativeDirectory = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "libvlc", "win-x64"));
            if (!File.Exists(Path.Combine(nativeDirectory, "libvlc.dll")) || !Directory.Exists(Path.Combine(nativeDirectory, "plugins"))) return;
            Directory.CreateDirectory(Path.GetDirectoryName(snapshotPath)!);
            await Dispatcher.InvokeAsync(() =>
            {
                LibVLCSharp.Shared.Core.Initialize(nativeDirectory);
                _thumbnailVlc ??= new LibVLC("--no-video-title-show", "--quiet", "--no-audio");
                _thumbnailPlayer ??= new NativeMediaPlayer(_thumbnailVlc);
                ThumbnailVideoView.MediaPlayer = _thumbnailPlayer;
                _thumbnailStream = _session.OpenEntryReadStream(item.Entry.RelativePath);
                _thumbnailMedia = new Media(_thumbnailVlc, new StreamMediaInput(_thumbnailStream), ":file-caching=350", ":network-caching=350");
                _thumbnailPlayer.Play(_thumbnailMedia);
            });
            for (var attempt = 0; attempt < 20 && !File.Exists(snapshotPath); attempt++)
            {
                await Task.Delay(100);
                await Dispatcher.InvokeAsync(() => _thumbnailPlayer?.TakeSnapshot(0, snapshotPath, 160, 90));
            }
            if (!File.Exists(snapshotPath)) return;
            await Dispatcher.InvokeAsync(() =>
            {
                using var input = File.OpenRead(snapshotPath);
                var bitmap = new BitmapImage();
                bitmap.BeginInit(); bitmap.CacheOption = BitmapCacheOption.OnLoad; bitmap.StreamSource = input; bitmap.EndInit(); bitmap.Freeze();
                item.Thumbnail = bitmap;
            });
        }
        catch { }
        finally
        {
            await Dispatcher.InvokeAsync(() =>
            {
                try { _thumbnailPlayer?.Stop(); } catch { }
                ThumbnailVideoView.MediaPlayer = null;
                _thumbnailMedia?.Dispose(); _thumbnailMedia = null;
                _thumbnailStream?.Dispose(); _thumbnailStream = null;
            });
            try { if (File.Exists(snapshotPath)) File.Delete(snapshotPath); } catch { }
            _videoThumbnailGate.Release();
        }
    }

    private static DrawingImage CreateIcon(string text, Color color)
    {
        var drawing = new GeometryDrawing(new SolidColorBrush(color), null,
            new RectangleGeometry(new Rect(0, 0, 96, 72), 7, 7));
        var group = new DrawingGroup();
        group.Children.Add(drawing);
        group.Children.Add(new GeometryDrawing(Brushes.DarkSlateGray, null,
            Geometry.Parse("M 39,24 L 65,36 L 39,48 Z")));
        return new DrawingImage(group);
    }

    private void Search_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        if (IsInitialized) RefreshItems();
    }

    private void Refresh_Click(object sender, RoutedEventArgs e) => RefreshItems();

    private void NavFilter_Click(object sender, RoutedEventArgs e)
    {
        if (sender is System.Windows.Controls.Button button && button.Tag is string filter)
        {
            _filter = filter;
            RefreshItems();
        }
    }

    private async void ItemsList_MouseDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (ItemsList.SelectedItem is ExplorerEntryItem item && !item.Entry.IsDirectory)
            await _host.OpenEntryFromExplorerAsync(item.Entry);
    }

    private async void Export_Click(object sender, RoutedEventArgs e)
    {
        if (ItemsList.SelectedItem is ExplorerEntryItem item) await _host.ExportEntryFromExplorerAsync(item.Entry);
    }

    private async void Append_Click(object sender, RoutedEventArgs e)
    {
        if (ItemsList.SelectedItem is ExplorerEntryItem item)
        {
            await _host.AppendFromExplorerAsync(item.Entry);
        }
        else
        {
            StatusText.Text = "请先选中要追加到的文件夹。";
        }
    }
    private async void Delete_Click(object sender, RoutedEventArgs e)
    {
        if (ItemsList.SelectedItem is ExplorerEntryItem item) await _host.DeleteFromExplorerAsync(item.Entry);
    }
    private async void Verify_Click(object sender, RoutedEventArgs e) => await _host.VerifyFromExplorerAsync();
    private void Size_Click(object sender, RoutedEventArgs e) => _host.ShowSizeFromExplorer();
    private void Close_Click(object sender, RoutedEventArgs e) => Close();

    private void Window_Closing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        if (_closing) return;
        _closing = true;
        _host.CloseAssociatedExplorer();
    }
}

public sealed class ExplorerEntryItem : INotifyPropertyChanged
{
    public ExplorerEntryItem(SecureArchiveEntry entry)
    {
        Entry = entry;
        Thumbnail = CreateDefaultThumbnail(entry);
    }

    public SecureArchiveEntry Entry { get; }
    public string Name => Entry.Name;
    public string RelativePath => Entry.RelativePath;
    public string TypeText => Entry.IsDirectory ? "文件夹" : Entry.MediaKind switch
    {
        SecureMediaKind.Image => "图片",
        SecureMediaKind.Video => "视频",
        SecureMediaKind.Audio => "音频",
        SecureMediaKind.Pdf => "PDF 文档",
        SecureMediaKind.Text => "文本文档",
        _ => "文件",
    };
    public string DetailText => Entry.IsDirectory ? "" : $"{FormatBytes(Entry.Length)} · {new DateTime(Entry.LastWriteUtcTicks, DateTimeKind.Utc).ToLocalTime():yyyy-MM-dd HH:mm}";
    private ImageSource _thumbnail = null!;
    public ImageSource Thumbnail
    {
        get => _thumbnail;
        set
        {
            _thumbnail = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Thumbnail)));
        }
    }
    public event PropertyChangedEventHandler? PropertyChanged;

    private static ImageSource CreateDefaultThumbnail(SecureArchiveEntry entry)
    {
        var text = entry.IsDirectory ? "▰" : entry.MediaKind switch
        {
            SecureMediaKind.Video => "▶",
            SecureMediaKind.Image => "▧",
            SecureMediaKind.Audio => "♫",
            SecureMediaKind.Pdf => "PDF",
            _ => "▤",
        };
        var group = new DrawingGroup();
        group.Children.Add(new GeometryDrawing(new SolidColorBrush(entry.IsDirectory ? Color.FromRgb(255, 244, 196) : Color.FromRgb(241, 245, 249)), null,
            new RectangleGeometry(new Rect(0, 0, 96, 72), 7, 7)));
        group.Children.Add(new GeometryDrawing(Brushes.DarkSlateGray, null,
            Geometry.Parse("M 30,28 L 66,28 L 66,48 L 30,48 Z")));
        return new DrawingImage(group);
    }

    private static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        var value = (double)Math.Max(bytes, 0);
        var index = 0;
        while (value >= 1024 && index < units.Length - 1) { value /= 1024; index++; }
        return $"{value:0.##} {units[index]}";
    }
}
