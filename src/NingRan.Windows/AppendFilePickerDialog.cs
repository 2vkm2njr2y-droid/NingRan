using System.ComponentModel;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace NingRan.Windows;

/// <summary>
/// Windows 文件管理器式的多文件选择窗口。普通单击重置选择，Shift+单击逐个追加选择。
/// </summary>
public partial class AppendFilePickerDialog : Window
{
    private readonly HashSet<string> _selectedFiles = new(StringComparer.OrdinalIgnoreCase);
    private readonly Stack<string> _backHistory = new();
    private readonly Stack<string> _forwardHistory = new();
    private readonly AppendFilePickerPreferences _preferences;
    private IReadOnlyList<PickerEntry> _allEntries = [];
    private string _currentDirectory;
    private PickerSortColumn _sortColumn;
    private bool _sortDescending;
    private bool _updatingSelection;

    public AppendFilePickerDialog(string? initialDirectory)
    {
        InitializeComponent();

        _preferences = AppendFilePickerPreferences.Load();
        _sortColumn = Enum.TryParse(_preferences.SortColumn, ignoreCase: true, out PickerSortColumn savedSort)
            ? savedSort
            : PickerSortColumn.Name;
        _sortDescending = _preferences.SortDescending;
        _currentDirectory = GetInitialDirectory(_preferences.LastDirectory, initialDirectory);

        Width = Clamp(_preferences.Width, MinWidth, 1800, 920);
        Height = Clamp(_preferences.Height, MinHeight, 1200, 620);

        PopulateDriveButtons();
        Navigate(_currentDirectory, recordHistory: false);
    }

    public IReadOnlyList<string> SelectedFiles => _selectedFiles
        .OrderBy(path => path, StringComparer.CurrentCultureIgnoreCase)
        .ToArray();

    private static string GetInitialDirectory(string? savedDirectory, string? requestedDirectory)
    {
        foreach (var candidate in new[]
                 {
                     savedDirectory,
                     requestedDirectory,
                     Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                     Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                     Environment.CurrentDirectory,
                 })
        {
            if (!string.IsNullOrWhiteSpace(candidate) && Directory.Exists(candidate))
                return Path.GetFullPath(candidate);
        }

        return Path.GetPathRoot(Environment.SystemDirectory) ?? Environment.CurrentDirectory;
    }

    private static double Clamp(double value, double minimum, double maximum, double fallback) =>
        double.IsFinite(value) ? Math.Clamp(value, minimum, maximum) : fallback;

    private void PopulateDriveButtons()
    {
        DriveButtons.Children.Clear();
        try
        {
            foreach (var drive in DriveInfo.GetDrives().Where(item => item.IsReady))
            {
                var label = string.IsNullOrWhiteSpace(drive.VolumeLabel)
                    ? drive.Name
                    : $"{drive.VolumeLabel} ({drive.Name.TrimEnd('\\')})";
                var button = new Button
                {
                    Content = $"▰  {label}",
                    Tag = drive.RootDirectory.FullName,
                    ToolTip = drive.RootDirectory.FullName,
                };
                button.SetResourceReference(StyleProperty, "NavigationButton");
                button.Click += QuickLocation_Click;
                DriveButtons.Children.Add(button);
            }
        }
        catch (IOException)
        {
            // 某些可移动设备会在列举期间离线；左侧清单缺少该设备不影响其余位置。
        }
        catch (UnauthorizedAccessException)
        {
            // 无权查询设备名称时仍可使用地址栏访问有权限的位置。
        }
    }

    private void RefreshDirectory()
    {
        AddressInput.Text = _currentDirectory;
        FolderTitle.Text = new DirectoryInfo(_currentDirectory).Name;
        if (string.IsNullOrWhiteSpace(FolderTitle.Text)) FolderTitle.Text = _currentDirectory;

        try
        {
            var directory = new DirectoryInfo(_currentDirectory);
            var entries = new List<PickerEntry>();
            foreach (var childDirectory in directory.EnumerateDirectories())
            {
                if (IsAllowedEntry(childDirectory)) entries.Add(PickerEntry.FromDirectory(childDirectory));
            }

            foreach (var file in directory.EnumerateFiles())
            {
                if (IsAllowedEntry(file)) entries.Add(PickerEntry.FromFile(file));
            }

            _allEntries = entries;
            RefreshVisibleEntries();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            MessageBox.Show(this, $"无法读取这个位置：\n\n{exception.Message}", Title,
                MessageBoxButton.OK, MessageBoxImage.Warning);
            _allEntries = [];
            RefreshVisibleEntries();
        }

        UpdateNavigationButtons();
    }

    private static bool IsAllowedEntry(FileSystemInfo entry)
    {
        try
        {
            return (entry.Attributes & (FileAttributes.Hidden | FileAttributes.System)) == 0;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private void RefreshVisibleEntries()
    {
        var search = SearchInput.Text.Trim();
        IEnumerable<PickerEntry> visible = _allEntries;
        if (search.Length > 0)
        {
            visible = visible.Where(entry => entry.Name.Contains(search, StringComparison.CurrentCultureIgnoreCase));
        }

        visible = visible
            .OrderBy(entry => entry.IsDirectory ? 0 : 1)
            .ThenBy(entry => entry, Comparer<PickerEntry>.Create(CompareEntries));

        _updatingSelection = true;
        try
        {
            FileList.ItemsSource = visible.ToArray();
            FileList.SelectedItems.Clear();
            foreach (var entry in FileList.Items.OfType<PickerEntry>())
            {
                if (!entry.IsDirectory && _selectedFiles.Contains(entry.Path))
                    FileList.SelectedItems.Add(entry);
            }
        }
        finally
        {
            _updatingSelection = false;
        }

        UpdateSelectionSummary();
    }

    private int CompareEntries(PickerEntry left, PickerEntry right)
    {
        var comparison = _sortColumn switch
        {
            PickerSortColumn.Modified => left.Modified.CompareTo(right.Modified),
            PickerSortColumn.Type => StringComparer.CurrentCultureIgnoreCase.Compare(left.TypeText, right.TypeText),
            PickerSortColumn.Size => left.Length.CompareTo(right.Length),
            _ => StringComparer.CurrentCultureIgnoreCase.Compare(left.Name, right.Name),
        };
        if (comparison == 0)
            comparison = StringComparer.CurrentCultureIgnoreCase.Compare(left.Name, right.Name);
        return _sortDescending ? -comparison : comparison;
    }

    private void Navigate(string path, bool recordHistory = true)
    {
        try
        {
            var fullPath = Path.GetFullPath(Environment.ExpandEnvironmentVariables(path.Trim().Trim('"')));
            if (!Directory.Exists(fullPath))
            {
                MessageBox.Show(this, "请输入一个存在的文件夹位置。", Title,
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            if (recordHistory && !string.Equals(fullPath, _currentDirectory, StringComparison.OrdinalIgnoreCase))
            {
                _backHistory.Push(_currentDirectory);
                _forwardHistory.Clear();
            }

            _currentDirectory = fullPath;
            SearchInput.Text = string.Empty;
            RefreshDirectory();
        }
        catch (Exception exception) when (exception is ArgumentException or IOException or UnauthorizedAccessException)
        {
            MessageBox.Show(this, $"无法打开这个位置：\n\n{exception.Message}", Title,
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void UpdateNavigationButtons()
    {
        BackButton.IsEnabled = _backHistory.Count > 0;
        ForwardButton.IsEnabled = _forwardHistory.Count > 0;
        UpButton.IsEnabled = Directory.GetParent(_currentDirectory) is not null;
    }

    private void Back_Click(object sender, RoutedEventArgs e)
    {
        if (_backHistory.Count == 0) return;
        var destination = _backHistory.Pop();
        _forwardHistory.Push(_currentDirectory);
        _currentDirectory = destination;
        SearchInput.Text = string.Empty;
        RefreshDirectory();
    }

    private void Forward_Click(object sender, RoutedEventArgs e)
    {
        if (_forwardHistory.Count == 0) return;
        var destination = _forwardHistory.Pop();
        _backHistory.Push(_currentDirectory);
        _currentDirectory = destination;
        SearchInput.Text = string.Empty;
        RefreshDirectory();
    }

    private void Up_Click(object sender, RoutedEventArgs e)
    {
        var parent = Directory.GetParent(_currentDirectory);
        if (parent is not null) Navigate(parent.FullName);
    }

    private void AddressInput_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.Enter) return;
        Navigate(AddressInput.Text);
        e.Handled = true;
    }

    private void SearchInput_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (SearchPlaceholder is null) return;
        SearchPlaceholder.Visibility = string.IsNullOrEmpty(SearchInput.Text)
            ? Visibility.Visible
            : Visibility.Collapsed;
        RefreshVisibleEntries();
    }

    private void QuickLocation_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string location }) return;
        var path = location switch
        {
            "Home" => Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            "Desktop" => Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            "Downloads" => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            "Documents" => Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            "Pictures" => Environment.GetFolderPath(Environment.SpecialFolder.MyPictures),
            _ => location,
        };
        Navigate(path);
    }

    private void FileList_PreviewMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        var item = FindVisualParent<ListViewItem>(e.OriginalSource as DependencyObject);
        if (item?.DataContext is not PickerEntry entry) return;

        if ((Keyboard.Modifiers & ModifierKeys.Shift) == ModifierKeys.Shift)
        {
            _updatingSelection = true;
            try
            {
                item.IsSelected = true;
                if (!entry.IsDirectory) _selectedFiles.Add(entry.Path);
            }
            finally
            {
                _updatingSelection = false;
            }

            item.Focus();
            UpdateSelectionSummary();
            e.Handled = true;
            return;
        }

        // Ctrl 保留 Windows 的切换选择习惯；没有组合键的普通单击只保留当前项目。
        if ((Keyboard.Modifiers & ModifierKeys.Control) == ModifierKeys.Control) return;
        _selectedFiles.Clear();
        if (!entry.IsDirectory) _selectedFiles.Add(entry.Path);
        UpdateSelectionSummary();
    }

    private static T? FindVisualParent<T>(DependencyObject? child) where T : DependencyObject
    {
        while (child is not null)
        {
            if (child is T match) return match;
            child = VisualTreeHelper.GetParent(child);
        }

        return null;
    }

    private void FileList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_updatingSelection) return;
        foreach (var entry in e.RemovedItems.OfType<PickerEntry>().Where(item => !item.IsDirectory))
            _selectedFiles.Remove(entry.Path);
        foreach (var entry in e.AddedItems.OfType<PickerEntry>().Where(item => !item.IsDirectory))
            _selectedFiles.Add(entry.Path);
        UpdateSelectionSummary();
    }

    private void FileList_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        var item = FindVisualParent<ListViewItem>(e.OriginalSource as DependencyObject);
        if (item?.DataContext is not PickerEntry entry) return;
        if (entry.IsDirectory)
        {
            Navigate(entry.Path);
            return;
        }

        if (_selectedFiles.Count > 0) DialogResult = true;
    }

    private void FileList_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.Enter || FileList.SelectedItem is not PickerEntry entry) return;
        if (entry.IsDirectory) Navigate(entry.Path);
        else if (_selectedFiles.Count > 0) DialogResult = true;
        e.Handled = true;
    }

    private void ColumnHeader_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not GridViewColumnHeader { Tag: string columnName } ||
            !Enum.TryParse(columnName, ignoreCase: true, out PickerSortColumn column)) return;

        if (_sortColumn == column) _sortDescending = !_sortDescending;
        else
        {
            _sortColumn = column;
            _sortDescending = false;
        }

        RefreshVisibleEntries();
    }

    private void UpdateSelectionSummary()
    {
        SelectionSummary.Text = _selectedFiles.Count == 0
            ? UiLanguage.Translate("尚未选择文件")
            : UiLanguage.IsEnglish
                ? $"{_selectedFiles.Count:N0} file(s) selected"
                : $"已选择 {_selectedFiles.Count:N0} 个文件";
        ConfirmButton.IsEnabled = _selectedFiles.Count > 0;
    }

    private void Confirm_Click(object sender, RoutedEventArgs e)
    {
        if (_selectedFiles.Count > 0) DialogResult = true;
    }

    private void Window_Closing(object? sender, CancelEventArgs e)
    {
        var bounds = WindowState == WindowState.Normal
            ? new Rect(Left, Top, ActualWidth, ActualHeight)
            : RestoreBounds;
        new AppendFilePickerPreferences
        {
            LastDirectory = Directory.Exists(_currentDirectory) ? _currentDirectory : null,
            Width = bounds.Width,
            Height = bounds.Height,
            SortColumn = _sortColumn.ToString(),
            SortDescending = _sortDescending,
        }.Save();
    }

    private static string FormatSize(long bytes) => bytes switch
    {
        < 1024 => $"{bytes:N0} B",
        < 1024 * 1024 => $"{bytes / 1024d:N1} KB",
        < 1024L * 1024 * 1024 => $"{bytes / 1024d / 1024:N1} MB",
        _ => $"{bytes / 1024d / 1024 / 1024:N1} GB",
    };

    private enum PickerSortColumn
    {
        Name,
        Modified,
        Type,
        Size,
    }

    private sealed class PickerEntry
    {
        private PickerEntry(string path, string name, bool isDirectory, DateTime modified, long length, string extension)
        {
            Path = path;
            Name = name;
            IsDirectory = isDirectory;
            Modified = modified;
            Length = length;
            Icon = isDirectory ? "📁" : "▧";
            ModifiedText = modified.ToString("g");
            TypeText = isDirectory
                ? UiLanguage.Translate("文件夹")
                : string.IsNullOrWhiteSpace(extension)
                    ? UiLanguage.Translate("文件")
                    : UiLanguage.IsEnglish
                        ? $"{extension.TrimStart('.').ToUpperInvariant()} file"
                        : $"{extension.TrimStart('.').ToUpperInvariant()} 文件";
            SizeText = isDirectory ? string.Empty : FormatSize(length);
        }

        public string Path { get; }
        public string Name { get; }
        public bool IsDirectory { get; }
        public DateTime Modified { get; }
        public long Length { get; }
        public string Icon { get; }
        public string ModifiedText { get; }
        public string TypeText { get; }
        public string SizeText { get; }

        public static PickerEntry FromDirectory(DirectoryInfo directory) =>
            new(directory.FullName, directory.Name, true, directory.LastWriteTime, 0, string.Empty);

        public static PickerEntry FromFile(FileInfo file) =>
            new(file.FullName, file.Name, false, file.LastWriteTime, file.Length, file.Extension);
    }
}

internal sealed class AppendFilePickerPreferences
{
    public string? LastDirectory { get; init; }
    public double Width { get; init; } = 920;
    public double Height { get; init; } = 620;
    public string SortColumn { get; init; } = "Name";
    public bool SortDescending { get; init; }

    public static AppendFilePickerPreferences Load()
    {
        try
        {
            if (!File.Exists(SettingsPath)) return new AppendFilePickerPreferences();
            return JsonSerializer.Deserialize<AppendFilePickerPreferences>(File.ReadAllText(SettingsPath)) ??
                   new AppendFilePickerPreferences();
        }
        catch (Exception exception) when (exception is IOException or JsonException or UnauthorizedAccessException)
        {
            return new AppendFilePickerPreferences();
        }
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(SettingsPath)!);
            File.WriteAllText(SettingsPath, JsonSerializer.Serialize(this));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // 设置无法写入时只影响下次打开窗口，不影响这次追加操作。
        }
    }

    private static string SettingsPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "NingRan",
        "append-file-picker.json");
}
