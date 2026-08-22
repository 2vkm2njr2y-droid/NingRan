namespace NingRan.Core;

public sealed record IdentitySummary(string Id, string Name)
{
    public string DisplayText => Name;
}

public sealed record IdentityCreationResult(IdentitySummary Identity);

public sealed record PublicIdentityInfo(string Name, string VerificationCode);

public sealed record TrustedContactSummary(
    string Id,
    string Name,
    DateTime TrustedAtUtc)
{
    public string DisplayText => Name;
}
