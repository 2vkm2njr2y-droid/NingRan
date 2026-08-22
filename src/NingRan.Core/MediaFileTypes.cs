namespace NingRan.Core;

public enum SecureMediaKind
{
    Text,
    Image,
    Audio,
    Video,
}

/// <summary>可由凝然内置阅读器或播放器直接处理的常见文件类型。</summary>
public static class NrMediaFiles
{
    private static readonly HashSet<string> TextExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".txt", ".md", ".markdown", ".log", ".csv", ".json", ".xml", ".yml", ".yaml",
    };

    private static readonly HashSet<string> ImageExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tif", ".tiff",
    };

    private static readonly HashSet<string> AudioExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".mp3", ".wav", ".m4a", ".aac", ".flac", ".ogg", ".wma",
    };

    private static readonly HashSet<string> VideoExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".mp4", ".m4v", ".mov", ".avi", ".wmv", ".webm", ".mkv", ".mpeg", ".mpg", ".3gp", ".ts", ".mpv",
    };

    public static bool IsSupportedPath(string path)
    {
        var extension = Path.GetExtension(path);
        return TextExtensions.Contains(extension) || ImageExtensions.Contains(extension) ||
               AudioExtensions.Contains(extension) || VideoExtensions.Contains(extension);
    }

    public static SecureMediaKind? TryGetKind(string path)
    {
        var extension = Path.GetExtension(path);
        if (TextExtensions.Contains(extension)) return SecureMediaKind.Text;
        if (ImageExtensions.Contains(extension)) return SecureMediaKind.Image;
        if (AudioExtensions.Contains(extension)) return SecureMediaKind.Audio;
        if (VideoExtensions.Contains(extension)) return SecureMediaKind.Video;
        return null;
    }

    public static string GetContentType(string path) => Path.GetExtension(path).ToLowerInvariant() switch
    {
        ".txt" or ".log" => "text/plain; charset=utf-8",
        ".md" or ".markdown" => "text/markdown; charset=utf-8",
        ".csv" => "text/csv; charset=utf-8",
        ".json" => "application/json",
        ".xml" => "application/xml",
        ".yml" or ".yaml" => "text/yaml; charset=utf-8",
        ".png" => "image/png",
        ".jpg" or ".jpeg" => "image/jpeg",
        ".gif" => "image/gif",
        ".bmp" => "image/bmp",
        ".webp" => "image/webp",
        ".tif" or ".tiff" => "image/tiff",
        ".mp3" => "audio/mpeg",
        ".wav" => "audio/wav",
        ".m4a" => "audio/mp4",
        ".aac" => "audio/aac",
        ".flac" => "audio/flac",
        ".ogg" => "audio/ogg",
        ".wma" => "audio/x-ms-wma",
        ".mp4" or ".m4v" => "video/mp4",
        ".mov" => "video/quicktime",
        ".avi" => "video/x-msvideo",
        ".wmv" => "video/x-ms-wmv",
        ".webm" => "video/webm",
        ".mkv" => "video/x-matroska",
        ".mpeg" or ".mpg" => "video/mpeg",
        ".3gp" => "video/3gpp",
        ".ts" => "video/mp2t",
        ".mpv" => "video/mp4",
        _ => "application/octet-stream",
    };
}
