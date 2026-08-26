using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using NingRan.Core;

namespace NingRan.Windows;

internal sealed class MediaViewerFailurePreferences
{
    public IReadOnlyList<string> IgnoredProblems { get; init; } = [];

    public static MediaViewerFailurePreferences Load()
    {
        if (NingRanRuntime.IsProcessElevated()) return new MediaViewerFailurePreferences();

        try
        {
            if (!File.Exists(SettingsPath)) return new MediaViewerFailurePreferences();
            return JsonSerializer.Deserialize<MediaViewerFailurePreferences>(File.ReadAllText(SettingsPath)) ?? new MediaViewerFailurePreferences();
        }
        catch (Exception exception) when (exception is IOException or JsonException or UnauthorizedAccessException)
        {
            return new MediaViewerFailurePreferences();
        }
    }

    public bool IsIgnored(string problemId) => IgnoredProblems.Contains(problemId, StringComparer.Ordinal);

    public MediaViewerFailurePreferences Ignore(string problemId)
    {
        if (NingRanRuntime.IsProcessElevated()) return this;

        var problems = IgnoredProblems.Append(problemId).Distinct(StringComparer.Ordinal).ToArray();
        var updated = new MediaViewerFailurePreferences { IgnoredProblems = problems };
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(SettingsPath)!);
            File.WriteAllText(SettingsPath, JsonSerializer.Serialize(updated));
        }
        catch
        {
            // 无法保存时本次仍会继续使用内嵌查看；下次会再次提示，避免静默隐藏问题。
        }
        return updated;
    }

    private static string SettingsPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NingRan", "media-viewer-notices.json");
}

internal static class MediaViewerFailureNotice
{
    /// <summary>显示原因；返回 true 表示用户选择不再提示这一种相同问题。</summary>
    public static bool Show(Window owner, string reason)
    {
        var dialog = new Window
        {
            Owner = owner,
            Title = "凝然媒体查看器未启动",
            Width = 560,
            Height = 250,
            MinWidth = 480,
            MinHeight = 220,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            ResizeMode = ResizeMode.NoResize,
        };
        var ignore = false;
        var description = new TextBlock
        {
            Text = $"将改用内嵌查看，不会导出普通文件。\n\n原因：{reason}\n\n选择“忽略此问题”后，出现同样原因时将不再弹窗。",
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(20, 18, 20, 8),
        };
        var ignoreButton = new Button { Content = "忽略此问题", Padding = new Thickness(14, 6, 14, 6), Margin = new Thickness(0, 0, 8, 0) };
        ignoreButton.Click += (_, _) => { ignore = true; dialog.Close(); };
        var continueButton = new Button { Content = "使用内嵌查看", IsDefault = true, Padding = new Thickness(14, 6, 14, 6) };
        continueButton.Click += (_, _) => dialog.Close();
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(20, 8, 20, 18) };
        buttons.Children.Add(ignoreButton);
        buttons.Children.Add(continueButton);
        var panel = new DockPanel();
        DockPanel.SetDock(buttons, Dock.Bottom);
        panel.Children.Add(buttons);
        panel.Children.Add(description);
        dialog.Content = panel;
        dialog.ShowDialog();
        return ignore;
    }
}
