namespace NingRan.Core;

public sealed record TemporaryContentCleanupFailure(string Path, string Reason);

public sealed record TemporaryContentCleanupResult(
    int RemovedDirectoryCount,
    IReadOnlyList<TemporaryContentCleanupFailure> Failures);
