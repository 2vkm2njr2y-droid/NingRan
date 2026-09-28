using System.Collections.ObjectModel;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Media.Imaging;
using Microsoft.Win32;
using NingRan.Core;

namespace NingRan.Windows;

public partial class VaultWorkspaceWindow : Window
{
    private static readonly HashSet<string> TextExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".txt", ".md", ".csv", ".json", ".xml", ".yaml", ".yml", ".log", ".ini", ".cs", ".js", ".ts", ".html", ".css",
    };
    private static readonly HashSet<string> ImageExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".png", ".jpg", ".jpeg", ".bmp", ".gif", ".tif", ".tiff", ".webp",
    };
    private static readonly HashSet<string> MediaExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".mp3", ".wav", ".flac", ".m4a", ".aac", ".ogg", ".opus", ".wma",
        ".mp4", ".mkv", ".mov", ".avi", ".webm", ".m4v", ".wmv", ".mpeg", ".mpg",
    };
    private readonly NrVaultService _service;
    private readonly VaultSession _session;
    private CancellationTokenSource? _operationCancellation;
    private bool _busy;
    private bool _closingForLock;

    public VaultWorkspaceWindow(NrVaultService service, VaultSession session)
    {
        InitializeComponent();
        _service = service;
        _session = session;
        RefreshTree();
        if (UiLanguage.IsEnglish) ApplyEnglish();
    }

    private VaultWorkspaceTreeItem? SelectedItem => FileTree.SelectedItem as VaultWorkspaceTreeItem;

    private void ApplyEnglish()
    {
        Title = "Browse vault inside app";
        TitleText.Text = "Secure in-app browsing";
        HintText.Text = "No temporary drive is created. Supported text, images, audio, and video are read on demand inside the app; a regular file is created only when you explicitly export it.";
        AddFilesButton.Content = "Add files"; AddFolderButton.Content = "Add folder"; NewFolderButton.Content = "New folder";
        MoveButton.Content = "Move or rename"; ReplaceButton.Content = "Replace contents"; DeleteButton.Content = "Delete";
        PreviewButton.Content = "Secure view"; ExportButton.Content = "Export plaintext...";
        PreviewHint.Text = "Select a file, then choose Secure view.";
        StatusText.Text = "Select an item to work with.";
        CancelButton.Content = "Cancel operation"; CloseButton.Content = "Close";
    }

    private void RefreshTree(string? selectPath = null)
    {
        var items = _session.Entries.ToDictionary(
            entry => entry.Id,
            entry => new VaultWorkspaceTreeItem(entry));
        var roots = new ObservableCollection<VaultWorkspaceTreeItem>();
        foreach (var item in items.Values.OrderBy(item => !item.IsDirectory).ThenBy(item => item.Name, StringComparer.CurrentCultureIgnoreCase))
        {
            if (item.Entry.ParentId != Guid.Empty && items.TryGetValue(item.Entry.ParentId, out var parent)) parent.Children.Add(item);
            else roots.Add(item);
        }
        SortTree(roots);
        FileTree.ItemsSource = roots;
        StatusText.Text = UiLanguage.IsEnglish
            ? $"{_session.Entries.Count:N0} item(s), {FormatBytes(_session.ContentBytes)} used of {FormatBytes(_session.WorkspaceCapacityBytes)}."
            : $"当前空间共 {_session.Entries.Count:N0} 项，已用 {FormatBytes(_session.ContentBytes)}，空间容量 {FormatBytes(_session.WorkspaceCapacityBytes)}。";
        _ = selectPath;
    }

    private static void SortTree(IEnumerable<VaultWorkspaceTreeItem> items)
    {
        foreach (var item in items)
        {
            var sorted = item.Children.OrderBy(child => !child.IsDirectory).ThenBy(child => child.Name, StringComparer.CurrentCultureIgnoreCase).ToArray();
            item.Children.Clear();
            foreach (var child in sorted) item.Children.Add(child);
            SortTree(item.Children);
        }
    }

    private async void AddFiles_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        var dialog = new OpenFileDialog { Title = UiLanguage.IsEnglish ? "Choose files to add" : "选择要加入当前空间的文件", Filter = "All files|*.*", Multiselect = true, CheckFileExists = true };
        if (dialog.ShowDialog(this) == true) await AddSourcesAsync(dialog.FileNames);
    }

    private async void AddFolder_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        var dialog = new OpenFolderDialog { Title = UiLanguage.IsEnglish ? "Choose a folder to add" : "选择要加入当前空间的文件夹" };
        if (dialog.ShowDialog(this) == true) await AddSourcesAsync([dialog.FolderName]);
    }

    private async Task AddSourcesAsync(IReadOnlyList<string> paths)
    {
        await RunOperationAsync(async token =>
        {
            StatusText.Text = UiLanguage.IsEnglish ? "Adding and checking sources..." : "正在加入并检查资料…";
            await _service.AddSourcesAsync(_session, paths, cancellationToken: token);
            RefreshTree();
        });
    }

    private async void NewFolder_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        var parent = SelectedItem?.IsDirectory == true ? SelectedItem.RelativePath + "/" : string.Empty;
        var dialog = new VaultPathPromptWindow(
            UiLanguage.IsEnglish ? "New folder" : "新建文件夹",
            UiLanguage.IsEnglish ? "Enter the folder path inside the current space." : "填写当前空间内的新文件夹路径。",
            parent) { Owner = this };
        if (dialog.ShowDialog() != true) return;
        await RunOperationAsync(async token =>
        {
            await _session.CreateDirectoryAsync(dialog.Value, token);
            RefreshTree(dialog.Value);
        });
    }

    private async void Move_Click(object sender, RoutedEventArgs e)
    {
        if (_busy || SelectedItem is null) return;
        var selected = SelectedItem;
        var dialog = new VaultPathPromptWindow(
            UiLanguage.IsEnglish ? "Move or rename" : "移动或重命名",
            UiLanguage.IsEnglish ? "Enter the new full path inside the current space." : "填写当前空间内的新完整路径。可以只改名称，也可以移动到已有文件夹。",
            selected.RelativePath) { Owner = this };
        if (dialog.ShowDialog() != true || string.Equals(dialog.Value, selected.RelativePath, StringComparison.Ordinal)) return;
        await RunOperationAsync(async token =>
        {
            await _session.MoveAsync(selected.RelativePath, dialog.Value, replaceIfExists: false, token);
            RefreshTree(dialog.Value);
        });
    }

    private async void Delete_Click(object sender, RoutedEventArgs e)
    {
        if (_busy || SelectedItem is null) return;
        var selected = SelectedItem;
        var answer = MessageBox.Show(this,
            UiLanguage.IsEnglish ? $"Move “{selected.Name}” to the vault recycle bin?" : $"把“{selected.Name}”移到保险箱回收站？",
            UiLanguage.IsEnglish ? "Confirm delete" : "确认删除",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);
        if (answer != MessageBoxResult.Yes) return;
        await RunOperationAsync(async token =>
        {
            await _session.DeleteAsync(selected.RelativePath, token);
            ClearPreview();
            RefreshTree();
        });
    }

    private async void Replace_Click(object sender, RoutedEventArgs e)
    {
        if (_busy || SelectedItem is null || SelectedItem.IsDirectory) return;
        var selected = SelectedItem;
        var dialog = new OpenFileDialog
        {
            Title = UiLanguage.IsEnglish ? $"Choose replacement contents for {selected.Name}" : $"选择用于替换“{selected.Name}”内容的文件",
            Filter = "All files|*.*",
            Multiselect = false,
            CheckFileExists = true,
        };
        if (dialog.ShowDialog(this) != true) return;
        var answer = MessageBox.Show(this,
            UiLanguage.IsEnglish
                ? $"Replace the encrypted contents of “{selected.Name}”? Its name and location inside the vault will stay unchanged."
                : $"用所选文件替换“{selected.Name}”的加密内容吗？它在保险箱内的名称和位置不会改变。",
            UiLanguage.IsEnglish ? "Confirm replacement" : "确认替换",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);
        if (answer != MessageBoxResult.Yes) return;

        await RunOperationAsync(async token =>
        {
            StatusText.Text = UiLanguage.IsEnglish ? "Replacing and checking the encrypted contents..." : "正在替换并检查加密内容…";
            await using var input = new FileStream(dialog.FileName, FileMode.Open, FileAccess.Read, FileShare.Read,
                1024 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
            using var output = _session.OpenWriteStream(selected.RelativePath, truncate: true);
            try
            {
                await input.CopyToAsync(output, 1024 * 1024, token);
                await output.CommitAsync(token);
            }
            catch
            {
                output.Abandon();
                throw;
            }
            ClearPreview();
            RefreshTree(selected.RelativePath);
        });
    }

    private async void Preview_Click(object sender, RoutedEventArgs e)
    {
        if (_busy || SelectedItem is null || SelectedItem.IsDirectory) return;
        var selected = SelectedItem;
        ClearPreview();
        await RunOperationAsync(async token =>
        {
            var extension = Path.GetExtension(selected.Name);
            if (TextExtensions.Contains(extension))
            {
                if (selected.Entry.Length > 8L * 1024 * 1024)
                    throw new NingRanException(UiLanguage.IsEnglish ? "Text secure view is limited to 8 MB per file." : "文字安全查看单个文件最多 8 MB。请缩小文件或明确导出。 ");
                await using var stream = _session.OpenReadStream(selected.RelativePath);
                using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, leaveOpen: false);
                TextPreview.Text = await reader.ReadToEndAsync(token);
                TextPreview.Visibility = Visibility.Visible;
                PreviewHint.Visibility = Visibility.Collapsed;
                return;
            }
            if (ImageExtensions.Contains(extension))
            {
                if (selected.Entry.Length > 128L * 1024 * 1024)
                    throw new NingRanException(UiLanguage.IsEnglish ? "This image is too large for in-app secure view." : "这张图片过大，无法在程序内安全查看。");
                await using var stream = _session.OpenReadStream(selected.RelativePath);
                var bitmap = new BitmapImage();
                bitmap.BeginInit();
                bitmap.CacheOption = BitmapCacheOption.OnLoad;
                bitmap.StreamSource = stream;
                bitmap.EndInit();
                bitmap.Freeze();
                token.ThrowIfCancellationRequested();
                ImagePreview.Source = bitmap;
                ImagePreviewScroll.Visibility = Visibility.Visible;
                PreviewHint.Visibility = Visibility.Collapsed;
                return;
            }
            if (MediaExtensions.Contains(extension))
            {
                var viewer = new VaultMediaViewerWindow(_session, selected.Entry) { Owner = this };
                viewer.Show();
                return;
            }
            throw new NingRanException(UiLanguage.IsEnglish
                ? "This file type is not yet supported by the in-app viewer. Export it only if you accept that a plaintext file may leave external records."
                : "程序内部查看暂不支持这种文件。只有在接受明文可能留下外部记录时，才应明确导出。 ");
        });
    }

    private async void Export_Click(object sender, RoutedEventArgs e)
    {
        if (_busy || SelectedItem is null || SelectedItem.IsDirectory) return;
        var selected = SelectedItem;
        var warning = MessageBox.Show(this,
            UiLanguage.IsEnglish
                ? "Exporting creates a regular plaintext file. Windows, cloud-sync software, antivirus tools, or other apps may leave records. Continue?"
                : "导出会产生普通明文文件，Windows、云同步软件、杀毒软件或其他程序可能留下记录。是否继续？",
            UiLanguage.IsEnglish ? "Plaintext export warning" : "明文导出提醒",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);
        if (warning != MessageBoxResult.Yes) return;
        var save = new SaveFileDialog { FileName = selected.Name, Title = UiLanguage.IsEnglish ? "Choose plaintext export location" : "选择明文导出位置", OverwritePrompt = true };
        if (save.ShowDialog(this) != true) return;
        await RunOperationAsync(async token =>
        {
            StatusText.Text = UiLanguage.IsEnglish ? "Exporting the selected file..." : "正在导出所选文件…";
            var parent = Path.GetDirectoryName(save.FileName) ?? throw new NingRanException("导出位置不正确。");
            var temporary = Path.Combine(parent, $".{Path.GetFileName(save.FileName)}-{Guid.NewGuid():N}.part");
            try
            {
                await using var input = _session.OpenReadStream(selected.RelativePath);
                await using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                                 1024 * 1024, FileOptions.Asynchronous | FileOptions.WriteThrough))
                {
                    await input.CopyToAsync(output, 1024 * 1024, token);
                    await output.FlushAsync(token);
                    output.Flush(flushToDisk: true);
                }
                token.ThrowIfCancellationRequested();
                File.Move(temporary, save.FileName, overwrite: true);
                StatusText.Text = UiLanguage.IsEnglish ? "Plaintext export completed." : "明文导出完成。";
            }
            finally
            {
                try { if (File.Exists(temporary)) File.Delete(temporary); } catch { }
            }
        });
    }

    private async Task RunOperationAsync(Func<CancellationToken, Task> operation)
    {
        if (_busy) return;
        _busy = true;
        SetButtonsEnabled(false);
        _operationCancellation = new CancellationTokenSource();
        CancelButton.Visibility = Visibility.Visible;
        try { await operation(_operationCancellation.Token); }
        catch (OperationCanceledException) { StatusText.Text = UiLanguage.IsEnglish ? "Operation cancelled." : "操作已取消。"; }
        catch (Exception exception)
        {
            if (!_closingForLock)
                MessageBox.Show(this, exception.Message, Title, MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            _operationCancellation.Dispose();
            _operationCancellation = null;
            CancelButton.Visibility = Visibility.Collapsed;
            _busy = false;
            if (!_closingForLock) SetButtonsEnabled(true);
        }
    }

    private void SetButtonsEnabled(bool enabled)
    {
        AddFilesButton.IsEnabled = AddFolderButton.IsEnabled = NewFolderButton.IsEnabled = MoveButton.IsEnabled =
            ReplaceButton.IsEnabled = DeleteButton.IsEnabled = PreviewButton.IsEnabled = ExportButton.IsEnabled = CloseButton.IsEnabled = enabled;
    }

    private void FileTree_SelectedItemChanged(object sender, RoutedPropertyChangedEventArgs<object> e)
    {
        ClearPreview();
        if (SelectedItem is { } selected)
            StatusText.Text = selected.IsDirectory
                ? selected.RelativePath
                : $"{selected.RelativePath} · {FormatBytes(selected.Entry.Length)}";
    }

    private void ClearPreview()
    {
        TextPreview.Text = string.Empty;
        TextPreview.Visibility = Visibility.Collapsed;
        ImagePreview.Source = null;
        ImagePreviewScroll.Visibility = Visibility.Collapsed;
        PreviewHint.Visibility = Visibility.Visible;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => _operationCancellation?.Cancel();
    private void Close_Click(object sender, RoutedEventArgs e) => Close();

    private void Window_Closing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        if (_busy && !_closingForLock)
        {
            _operationCancellation?.Cancel();
            e.Cancel = true;
            return;
        }
        ClearPreview();
    }

    public void CloseForLock()
    {
        _closingForLock = true;
        _operationCancellation?.Cancel();
        ClearPreview();
        Close();
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

public sealed class VaultWorkspaceTreeItem(VaultEntry entry)
{
    public VaultEntry Entry { get; } = entry;
    public string Name => Entry.Name;
    public string RelativePath => Entry.RelativePath;
    public bool IsDirectory => Entry.IsDirectory;
    public string DisplayName => IsDirectory ? $"📁 {Name}" : $"📄 {Name}";
    public ObservableCollection<VaultWorkspaceTreeItem> Children { get; } = [];
}
