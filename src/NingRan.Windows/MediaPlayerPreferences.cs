using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using NingRan.Core;

namespace NingRan.Windows;

[JsonConverter(typeof(JsonStringEnumConverter))]
internal enum AudioVideoPlayerChoice
{
    NingRanPlayer,
    BuiltInPlayer,
    DefaultProgram,
}

internal sealed class MediaPlayerPreferences
{
    public AudioVideoPlayerChoice AudioVideoPlayer { get; init; } = AudioVideoPlayerChoice.NingRanPlayer;

    public static MediaPlayerPreferences Load() => Load(SettingsPath);

    internal static MediaPlayerPreferences Load(string settingsPath)
    {
        try
        {
            if (!File.Exists(settingsPath)) return new MediaPlayerPreferences();
            var preferences = JsonSerializer.Deserialize<MediaPlayerPreferences>(File.ReadAllText(settingsPath));
            return preferences is not null && Enum.IsDefined(preferences.AudioVideoPlayer)
                ? preferences
                : new MediaPlayerPreferences();
        }
        catch (Exception exception) when (exception is IOException or JsonException or UnauthorizedAccessException)
        {
            // 设置丢失或损坏时恢复到原有行为：优先使用凝然播放器。
            return new MediaPlayerPreferences();
        }
    }

    public void Save() => Save(SettingsPath);

    internal void Save(string settingsPath)
    {
        var directory = Path.GetDirectoryName(settingsPath)
            ?? throw new InvalidOperationException("播放器设置位置不正确。");
        Directory.CreateDirectory(directory);
        var temporaryPath = settingsPath + ".tmp";
        try
        {
            File.WriteAllText(temporaryPath, JsonSerializer.Serialize(this));
            File.Move(temporaryPath, settingsPath, overwrite: true);
        }
        finally
        {
            try { File.Delete(temporaryPath); } catch { }
        }
    }

    private static string SettingsPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "NingRan",
        "media-player-settings.json");
}

internal static class MediaPlayerSelection
{
    public static bool ShouldUseExternalViewer(
        SecureMediaKind? mediaKind,
        MediaPlayerPreferences preferences,
        bool externalViewersBlocked)
    {
        if (externalViewersBlocked || ShouldUseDefaultProgram(preferences)) return false;
        return mediaKind switch
        {
            SecureMediaKind.Image or SecureMediaKind.Pdf => true,
            SecureMediaKind.Audio or SecureMediaKind.Video =>
                preferences.AudioVideoPlayer == AudioVideoPlayerChoice.NingRanPlayer,
            _ => false,
        };
    }

    public static bool ShouldUseDefaultProgram(MediaPlayerPreferences preferences) =>
        preferences.AudioVideoPlayer == AudioVideoPlayerChoice.DefaultProgram;

    public static bool ShouldIncludeInExternalCatalog(
        SecureMediaKind? mediaKind,
        MediaPlayerPreferences preferences) =>
        !ShouldUseDefaultProgram(preferences) &&
        (mediaKind is SecureMediaKind.Image or SecureMediaKind.Pdf ||
        mediaKind is SecureMediaKind.Audio or SecureMediaKind.Video &&
        preferences.AudioVideoPlayer == AudioVideoPlayerChoice.NingRanPlayer);

    public static bool IsPreferredExternalAudioVideo(
        SecureMediaKind? mediaKind,
        MediaPlayerPreferences preferences) =>
        mediaKind is SecureMediaKind.Audio or SecureMediaKind.Video &&
        preferences.AudioVideoPlayer == AudioVideoPlayerChoice.NingRanPlayer;
}
