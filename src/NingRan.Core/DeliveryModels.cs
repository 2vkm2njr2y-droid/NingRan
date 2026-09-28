namespace NingRan.Core;

/// <summary>安全交付包中与加密目录一起受到保护的使用规则。</summary>
public sealed record DeliveryPackageInfo(
    int Version,
    string Name,
    string Description,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset? ExpiresAtUtc,
    bool AllowExport,
    string? RecipientContactId,
    string? RecipientName,
    string? RecipientFingerprint)
{
    public const int CurrentVersion = 1;
    public const int MaximumNameLength = 120;
    public const int MaximumDescriptionLength = 4_000;

    public bool IsPermanent => ExpiresAtUtc is null;

    public bool IsExpiredAt(DateTimeOffset utcNow) =>
        ExpiresAtUtc is { } expiresAt && utcNow.ToUniversalTime() >= expiresAt;

    public static DeliveryPackageInfo Create(
        string name,
        string? description,
        DateTimeOffset createdAtUtc,
        DateTimeOffset? expiresAtUtc,
        bool allowExport,
        TrustedContactSummary? recipient = null)
    {
        var normalizedName = (name ?? string.Empty).Trim();
        var normalizedDescription = (description ?? string.Empty).Trim();
        if (normalizedName.Length is < 1 or > MaximumNameLength)
        {
            throw new NingRanException($"交付名称应为 1 到 {MaximumNameLength} 个字符。");
        }

        if (normalizedDescription.Length > MaximumDescriptionLength)
        {
            throw new NingRanException($"交付说明不能超过 {MaximumDescriptionLength} 个字符。");
        }

        var created = createdAtUtc.ToUniversalTime();
        var expires = expiresAtUtc?.ToUniversalTime();
        if (expires is { } end && end <= created)
        {
            throw new NingRanException("有效截止时间必须晚于创建时间。");
        }

        if (recipient?.RequiresReverification == true)
        {
            throw new NingRanException("所选联系人尚未重新核对，不能显示为已确认的接收方。");
        }

        return new DeliveryPackageInfo(
            CurrentVersion,
            normalizedName,
            normalizedDescription,
            created,
            expires,
            allowExport,
            recipient?.Id,
            recipient?.Name,
            recipient?.Fingerprint);
    }

    internal void ValidateForReading()
    {
        if (Version != CurrentVersion)
        {
            throw new NingRanException("此安全交付包由更高版本的凝然创建，请更新凝然后再打开。");
        }

        if (string.IsNullOrWhiteSpace(Name) || Name.Length > MaximumNameLength ||
            Description.Length > MaximumDescriptionLength)
        {
            throw new NingRanException("安全交付信息不正确或已经损坏。");
        }

        if (ExpiresAtUtc is { } expires && expires <= CreatedAtUtc)
        {
            throw new NingRanException("安全交付包的有效期信息不正确。");
        }

        var hasRecipient = !string.IsNullOrWhiteSpace(RecipientContactId) ||
                           !string.IsNullOrWhiteSpace(RecipientName) ||
                           !string.IsNullOrWhiteSpace(RecipientFingerprint);
        if (hasRecipient && (string.IsNullOrWhiteSpace(RecipientContactId) ||
                             string.IsNullOrWhiteSpace(RecipientName) ||
                             RecipientName.Length > 200 ||
                             RecipientFingerprint is null || RecipientFingerprint.Length != 64 ||
                             !RecipientFingerprint.All(Uri.IsHexDigit)))
        {
            throw new NingRanException("安全交付包的接收方信息不正确。");
        }
    }
}
