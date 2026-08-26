using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using NingRan.Core;

namespace NingRan.Windows;

internal sealed class TrustedContactBrokerClient
{
    public const string ArgumentName = "--trusted-contact-request";
    public const int CancelledExitCode = 2;

    private readonly NrTrustedContactService _service;

    public TrustedContactBrokerClient(NrTrustedContactService service)
    {
        _service = service ?? throw new ArgumentNullException(nameof(service));
    }

    public async Task<TrustedContactSummary?> TrustAsync(
        string publicIdentityPath,
        CancellationToken cancellationToken = default)
    {
        var requestPath = _service.CreateTrustRequest(publicIdentityPath);
        var binding = TakeBinding(requestPath, TrustedContactBrokerAction.Trust);
        var completedFingerprint = await RunAsync(binding, cancellationToken).ConfigureAwait(true);
        if (completedFingerprint is null)
        {
            return null;
        }

        return FindProtectedContact(completedFingerprint)
               ?? throw new NingRanException("管理员确认已经完成，但未能读取新建的受保护联系人记录。");
    }

    public async Task<TrustedContactSummary?> ReverifyAsync(
        TrustedContactSummary contact,
        CancellationToken cancellationToken = default)
    {
        var requestPath = _service.CreateReverificationRequest(contact);
        var binding = TakeBinding(requestPath, TrustedContactBrokerAction.Trust, expectedContact: contact);
        var completedFingerprint = await RunAsync(binding, cancellationToken).ConfigureAwait(true);
        if (completedFingerprint is null)
        {
            return null;
        }

        return FindProtectedContact(completedFingerprint)
               ?? throw new NingRanException("管理员确认已经完成，但未能读取重新核对后的联系人记录。");
    }

    public async Task<bool> RemoveAsync(
        TrustedContactSummary contact,
        CancellationToken cancellationToken = default)
    {
        var requestPath = _service.CreateRemoveRequest(contact);
        var binding = TakeBinding(requestPath, TrustedContactBrokerAction.Remove, contact);
        return await RunAsync(binding, cancellationToken).ConfigureAwait(true) is not null;
    }

    public static bool IsBrokerArgumentPresent(IReadOnlyList<string> arguments) =>
        arguments.Count > 0 &&
        string.Equals(arguments[0], ArgumentName, StringComparison.Ordinal);

    public static bool TryReadRequestBinding(
        IReadOnlyList<string> arguments,
        out TrustedContactBrokerLaunchBinding? binding)
    {
        binding = null;
        if (arguments.Count != 7 || !IsBrokerArgumentPresent(arguments))
        {
            return false;
        }

        try
        {
            if (!IsCanonicalHex(arguments[2]) ||
                !IsCanonicalHex(arguments[3]) ||
                !Enum.TryParse<TrustedContactBrokerAction>(arguments[4], out var action) ||
                !Enum.IsDefined(action) ||
                !IsCanonicalHex(arguments[6]))
            {
                return false;
            }

            var contactId = string.Equals(arguments[5], "-", StringComparison.Ordinal)
                ? null
                : arguments[5];
            if ((action == TrustedContactBrokerAction.Trust && contactId is not null) ||
                (action == TrustedContactBrokerAction.Remove && string.IsNullOrWhiteSpace(contactId)))
            {
                return false;
            }

            binding = new TrustedContactBrokerLaunchBinding(
                Path.GetFullPath(arguments[1]),
                arguments[2],
                arguments[3],
                action,
                contactId,
                arguments[6]);
            return true;
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }

    private TrustedContactSummary? FindProtectedContact(string fingerprint) =>
        _service.ListTrustedContacts().FirstOrDefault(candidate => string.Equals(
            candidate.Fingerprint,
            fingerprint,
            StringComparison.OrdinalIgnoreCase));

    private static TrustedContactBrokerLaunchBinding TakeBinding(
        string requestPath,
        TrustedContactBrokerAction expectedAction,
        TrustedContactSummary? expectedContact = null)
    {
        try
        {
            var binding = TrustedContactBroker.TakeLaunchBinding(requestPath);
            var fingerprintMatches = expectedContact is null || string.Equals(
                NormalizeFingerprint(expectedContact.Fingerprint),
                binding.ExpectedFingerprint,
                StringComparison.Ordinal);
            var contactMatches = expectedAction == TrustedContactBrokerAction.Trust ||
                                 string.Equals(
                                     expectedContact?.Id,
                                     binding.ContactId,
                                     StringComparison.Ordinal);
            if (binding.Action != expectedAction || !fingerprintMatches || !contactMatches)
            {
                throw new NingRanException(
                    "可信联系人在启动管理员确认前已经变化，请刷新联系人列表后重新开始。");
            }

            return binding;
        }
        catch
        {
            TrustedContactBroker.DeleteRequest(requestPath);
            throw;
        }
    }

    private static async Task<string?> RunAsync(
        TrustedContactBrokerLaunchBinding binding,
        CancellationToken cancellationToken)
    {
        try
        {
            var executablePath = Environment.ProcessPath;
            if (string.IsNullOrWhiteSpace(executablePath) ||
                !HighSecurityLaunch.IsTrustedInstalledComponent(executablePath, "NingRan.exe"))
            {
                throw new NingRanException(
                    "可信联系人管理员确认只能从受保护的正式安装位置启动。请先安装或升级凝然加密。");
            }

            NativeElevatedProcess process;
            try
            {
                process = await NativeElevationLauncher.StartAsync(
                    NingRan.Security.NativeElevationBinding.Modes.TrustedContact,
                    [
                        ArgumentName,
                        binding.RequestPath,
                        binding.RequestNonce,
                        binding.RequestSha256,
                        binding.Action.ToString(),
                        binding.ContactId ?? "-",
                        binding.ExpectedFingerprint,
                    ],
                    cancellationToken).ConfigureAwait(true);
            }
            catch (Win32Exception exception) when (HighSecurityLaunch.WasCancelled(exception))
            {
                return null;
            }

            using (process)
            {
                await process.WaitForExitAsync(cancellationToken).ConfigureAwait(true);
                return process.ExitCode switch
                {
                    0 => binding.ExpectedFingerprint,
                    CancelledExitCode => null,
                    _ => throw new NingRanException("可信联系人管理员确认没有完成，联系人记录未更改。"),
                };
            }
        }
        finally
        {
            TrustedContactBroker.DeleteRequest(binding.RequestPath);
        }
    }

    private static bool IsCanonicalHex(string? value) =>
        value is not null &&
        value.Length == 64 &&
        value.All(character => character is >= '0' and <= '9' or >= 'A' and <= 'F');

    private static string NormalizeFingerprint(string fingerprint) =>
        (fingerprint ?? string.Empty)
        .Replace("-", string.Empty, StringComparison.Ordinal)
        .ToUpperInvariant();
}
