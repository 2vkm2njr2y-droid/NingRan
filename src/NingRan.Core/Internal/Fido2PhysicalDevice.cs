using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace NingRan.Core.Internal;

internal sealed class Fido2PhysicalDevice
{
    private const string RelyingPartyId = "ningran.local";
    private const uint CrossPlatform = 2;
    private const uint UserVerificationRequired = 1;
    private const byte AuthenticatorDataUserPresent = 0x01;
    private const byte AuthenticatorDataUserVerified = 0x04;
    private const int AuthenticatorDataFlagsOffset = 32;
    private const int MinimumAuthenticatorDataLength = 37;
    private const uint AttestationNone = 1;
    private const uint TransportUsb = 0x00000001;
    private const uint TransportNfc = 0x00000002;
    private const uint TransportBle = 0x00000004;
    private const uint TransportInternal = 0x00000010;
    private const uint TransportHybrid = 0x00000020;
    private const uint TransportSmartCard = 0x00000040;
    private const uint AllowedPhysicalTransports = TransportUsb | TransportNfc | TransportBle | TransportSmartCard;

    public async Task<PhysicalDeviceDescriptor> RegisterAsync(
        string name,
        nint ownerWindowHandle,
        CancellationToken cancellationToken)
    {
        EnsureAvailable(ownerWindowHandle);
        using var memory = new NativeMemoryScope();
        var userId = RandomNumberGenerator.GetBytes(32);
        try
        {
            var rp = new WebAuthnRpEntity
            {
                Version = 1,
                Id = memory.String(RelyingPartyId),
                Name = memory.String("凝然加密"),
            };
            var user = new WebAuthnUserEntity
            {
                Version = 1,
                IdLength = checked((uint)userId.Length),
                Id = memory.Bytes(userId),
                Name = memory.String($"ningran-{Guid.NewGuid():N}"),
                DisplayName = memory.String(name),
            };
            var algorithm = new WebAuthnCoseCredentialParameter
            {
                Version = 1,
                CredentialType = memory.String("public-key"),
                Algorithm = -7,
            };
            var algorithms = new WebAuthnCoseCredentialParameters
            {
                Count = 1,
                Parameters = memory.Struct(algorithm),
            };
            var clientJson = CreateClientDataJson("webauthn.create");
            try
            {
                var clientData = new WebAuthnClientData
                {
                    Version = 1,
                    JsonLength = checked((uint)clientJson.Length),
                    Json = memory.Bytes(clientJson),
                    HashAlgorithm = memory.String("SHA-256"),
                };
                var hmacEnabled = memory.Int32(1);
                var extension = new WebAuthnExtension
                {
                    Identifier = memory.String("hmac-secret"),
                    DataLength = sizeof(int),
                    Data = hmacEnabled,
                };
                var cancellationId = GetCancellationId(memory);
                var options = new WebAuthnMakeCredentialOptions
                {
                    Version = 6,
                    TimeoutMilliseconds = 120_000,
                    Extensions = new WebAuthnExtensions
                    {
                        Count = 1,
                        Extensions = memory.Struct(extension),
                    },
                    AuthenticatorAttachment = CrossPlatform,
                    UserVerificationRequirement = UserVerificationRequired,
                    AttestationConveyancePreference = AttestationNone,
                    CancellationId = cancellationId,
                    EnablePrf = 1,
                };

                nint attestationPointer = 0;
                var registration = cancellationToken.Register(() => Cancel(cancellationId));
                try
                {
                    var result = await Task.Run(() => WebAuthNAuthenticatorMakeCredential(
                        ownerWindowHandle,
                        ref rp,
                        ref user,
                        ref algorithms,
                        ref clientData,
                        ref options,
                        out attestationPointer), CancellationToken.None).ConfigureAwait(false);
                    ThrowForResult(result, cancellationToken, "无法在 FIDO2 安全密钥上创建凝然加密凭证");
                    if (attestationPointer == 0)
                    {
                        throw new NingRanException("FIDO2 安全密钥没有返回登记结果。 ");
                    }

                    var attestation = Marshal.PtrToStructure<WebAuthnCredentialAttestation>(attestationPointer);
                    EnsureUserVerified(
                        attestation.AuthenticatorDataLength,
                        attestation.AuthenticatorData,
                        "登记安全密钥");
                    if (attestation.Version < 5 || attestation.PrfEnabled == 0 ||
                        attestation.CredentialIdLength is 0 or > 2048 || attestation.CredentialId == 0)
                    {
                        throw new NingRanException(
                            "这把 FIDO2 安全密钥不支持离线加密所需的 HMAC-secret/PRF 功能，不能登记；程序不会改用较弱方式。 ");
                    }

                    EnsurePhysicalTransport(attestation.UsedTransport);
                    var credentialId = new byte[attestation.CredentialIdLength];
                    Marshal.Copy(attestation.CredentialId, credentialId, 0, credentialId.Length);
                    var id = Convert.ToHexString(SHA256.HashData(credentialId));
                    var descriptor = new PhysicalDeviceDescriptor(
                        PhysicalDeviceKind.Fido2SecurityKey,
                        id,
                        name,
                        DescribeTransport(attestation.UsedTransport),
                        0,
                        credentialId);

                    var verificationSalt = RandomNumberGenerator.GetBytes(32);
                    try
                    {
                        var verified = await GetAssertionAsync(
                            [new PhysicalDeviceRequirement(descriptor, verificationSalt)],
                            ownerWindowHandle,
                            cancellationToken).ConfigureAwait(false);
                        CryptographicOperations.ZeroMemory(verified.Secret);
                    }
                    catch
                    {
                        CryptographicOperations.ZeroMemory(credentialId);
                        throw;
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(verificationSalt);
                    }

                    return descriptor;
                }
                finally
                {
                    registration.Dispose();
                    if (attestationPointer != 0)
                    {
                        WebAuthNFreeCredentialAttestation(attestationPointer);
                    }
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(clientJson);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(userId);
        }
    }

    public async Task<PhysicalDeviceUnlock> UnlockAnyAsync(
        IReadOnlyList<PhysicalDeviceRequirement> requirements,
        nint ownerWindowHandle,
        CancellationToken cancellationToken)
    {
        EnsureAvailable(ownerWindowHandle);
        if (requirements.Count == 0 || requirements.Any(requirement =>
                requirement.Device.Kind != PhysicalDeviceKind.Fido2SecurityKey ||
                requirement.Device.CredentialId is null or { Length: 0 } ||
                requirement.SecretSalt.Length != 32))
        {
            throw new NingRanException("FIDO2 安全密钥授权信息不正确或文件已损坏。 ");
        }

        var result = await GetAssertionAsync(requirements, ownerWindowHandle, cancellationToken)
            .ConfigureAwait(false);
        var requirement = requirements[result.Index];
        async Task Revalidate(CancellationToken token)
        {
            var checkedAgain = await GetAssertionAsync([requirement], ownerWindowHandle, token)
                .ConfigureAwait(false);
            CryptographicOperations.ZeroMemory(checkedAgain.Secret);
        }

        return new PhysicalDeviceUnlock(requirement.Device, result.Secret, revalidate: Revalidate);
    }

    private static async Task<(int Index, byte[] Secret)> GetAssertionAsync(
        IReadOnlyList<PhysicalDeviceRequirement> requirements,
        nint ownerWindowHandle,
        CancellationToken cancellationToken)
    {
        using var memory = new NativeMemoryScope();
        var nativeCredentials = new WebAuthnCredential[requirements.Count];
        var nativeSaltMappings = new WebAuthnCredentialWithHmacSecretSalt[requirements.Count];
        for (var index = 0; index < requirements.Count; index++)
        {
            var credential = requirements[index].Device.CredentialId!;
            var credentialPointer = memory.Bytes(credential);
            nativeCredentials[index] = new WebAuthnCredential
            {
                Version = 1,
                IdLength = checked((uint)credential.Length),
                Id = credentialPointer,
                CredentialType = memory.String("public-key"),
            };
            var salt = new WebAuthnHmacSecretSalt
            {
                FirstLength = 32,
                First = memory.Bytes(requirements[index].SecretSalt),
            };
            nativeSaltMappings[index] = new WebAuthnCredentialWithHmacSecretSalt
            {
                CredentialIdLength = checked((uint)credential.Length),
                CredentialId = credentialPointer,
                Salt = memory.Struct(salt),
            };
        }

        var clientJson = CreateClientDataJson("webauthn.get");
        try
        {
            var clientData = new WebAuthnClientData
            {
                Version = 1,
                JsonLength = checked((uint)clientJson.Length),
                Json = memory.Bytes(clientJson),
                HashAlgorithm = memory.String("SHA-256"),
            };
            var saltValues = new WebAuthnHmacSecretSaltValues
            {
                CredentialCount = checked((uint)nativeSaltMappings.Length),
                Credentials = memory.Array(nativeSaltMappings),
            };
            var cancellationId = GetCancellationId(memory);
            var options = new WebAuthnGetAssertionOptions
            {
                Version = 6,
                TimeoutMilliseconds = 120_000,
                CredentialList = new WebAuthnCredentials
                {
                    Count = checked((uint)nativeCredentials.Length),
                    Credentials = memory.Array(nativeCredentials),
                },
                AuthenticatorAttachment = CrossPlatform,
                UserVerificationRequirement = UserVerificationRequired,
                CancellationId = cancellationId,
                HmacSecretSaltValues = memory.Struct(saltValues),
            };

            nint assertionPointer = 0;
            var registration = cancellationToken.Register(() => Cancel(cancellationId));
            try
            {
                var result = await Task.Run(() => WebAuthNAuthenticatorGetAssertion(
                    ownerWindowHandle,
                    RelyingPartyId,
                    ref clientData,
                    ref options,
                    out assertionPointer), CancellationToken.None).ConfigureAwait(false);
                ThrowForResult(result, cancellationToken, "FIDO2 安全密钥未能完成开锁");
                if (assertionPointer == 0)
                {
                    throw new NingRanException("FIDO2 安全密钥没有返回开锁结果。 ");
                }

                var assertion = Marshal.PtrToStructure<WebAuthnAssertion>(assertionPointer);
                EnsureUserVerified(
                    assertion.AuthenticatorDataLength,
                    assertion.AuthenticatorData,
                    "使用安全密钥开锁");
                EnsurePhysicalTransport(assertion.UsedTransport);
                if (assertion.Credential.IdLength is 0 or > 2048 || assertion.Credential.Id == 0 ||
                    assertion.HmacSecret == 0)
                {
                    throw new NingRanException(
                        "这把 FIDO2 安全密钥没有返回离线加密所需的 HMAC-secret/PRF 结果。 ");
                }

                var usedCredential = new byte[assertion.Credential.IdLength];
                Marshal.Copy(assertion.Credential.Id, usedCredential, 0, usedCredential.Length);
                try
                {
                    var index = -1;
                    for (var current = 0; current < requirements.Count; current++)
                    {
                        if (CryptographicOperations.FixedTimeEquals(
                                usedCredential,
                                requirements[current].Device.CredentialId!))
                        {
                            index = current;
                            break;
                        }
                    }

                    if (index < 0)
                    {
                        throw new NingRanException("安全密钥返回了未经此文件授权的凭证。 ");
                    }

                    var hmac = Marshal.PtrToStructure<WebAuthnHmacSecretSalt>(assertion.HmacSecret);
                    if (hmac.FirstLength != 32 || hmac.First == 0)
                    {
                        throw new NingRanException(
                            "安全密钥返回的离线开锁凭证长度不正确。 ");
                    }

                    var secret = new byte[32];
                    Marshal.Copy(hmac.First, secret, 0, secret.Length);
                    return (index, secret);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(usedCredential);
                }
            }
            finally
            {
                registration.Dispose();
                if (assertionPointer != 0)
                {
                    WebAuthNFreeAssertion(assertionPointer);
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(clientJson);
        }
    }

    private static byte[] CreateClientDataJson(string operation)
    {
        var challenge = RandomNumberGenerator.GetBytes(32);
        try
        {
            var encoded = Convert.ToBase64String(challenge)
                .TrimEnd('=').Replace('+', '-').Replace('/', '_');
            return JsonSerializer.SerializeToUtf8Bytes(new
            {
                type = operation,
                challenge = encoded,
                origin = "https://ningran.local",
                crossOrigin = false,
            });
        }
        finally
        {
            CryptographicOperations.ZeroMemory(challenge);
        }
    }

    private static nint GetCancellationId(NativeMemoryScope memory)
    {
        var pointer = memory.Allocate(Marshal.SizeOf<Guid>());
        var result = WebAuthNGetCancellationId(pointer);
        if (result < 0)
        {
            Marshal.ThrowExceptionForHR(result);
        }

        return pointer;
    }

    private static void Cancel(nint cancellationId)
    {
        try
        {
            WebAuthNCancelCurrentOperation(cancellationId);
        }
        catch
        {
            // Cancellation is best effort; the Windows dialog may already have closed.
        }
    }

    private static void EnsureAvailable(nint ownerWindowHandle)
    {
        if (!OperatingSystem.IsWindows() || ownerWindowHandle == 0)
        {
            throw new NingRanException("FIDO2 安全密钥操作需要在 Windows 程序窗口中进行。 ");
        }

        uint version;
        try
        {
            version = WebAuthNGetApiVersionNumber();
        }
        catch (DllNotFoundException exception)
        {
            throw new NingRanException("当前 Windows 版本不支持 FIDO2 安全密钥。 ", exception);
        }

        if (version < 6)
        {
            throw new NingRanException(
                "当前 Windows 的 FIDO2 功能过旧，不支持离线加密所需的 HMAC-secret/PRF。 ");
        }
    }

    private static void ThrowForResult(int result, CancellationToken cancellationToken, string message)
    {
        if (result >= 0)
        {
            return;
        }

        if (cancellationToken.IsCancellationRequested)
        {
            throw new OperationCanceledException(cancellationToken);
        }

        var detail = Marshal.GetExceptionForHR(result)?.Message;
        throw new NingRanException($"{message}。请确认插入的是支持 HMAC-secret/PRF 且已设置 PIN 或生物识别的外接 FIDO2 安全密钥，并按 Windows 提示完成验证；程序不会退回到仅触摸确认。{(string.IsNullOrWhiteSpace(detail) ? string.Empty : $"\n\nWindows：{detail}")}");
    }

    private static void EnsureUserVerified(
        uint authenticatorDataLength,
        nint authenticatorData,
        string operation)
    {
        if (authenticatorData == 0 || authenticatorDataLength < MinimumAuthenticatorDataLength)
        {
            throw new NingRanException(
                $"{operation}时，Windows 返回的验证资料不完整，无法确认已使用 PIN 或生物识别，操作已拒绝。 ");
        }

        var flags = Marshal.ReadByte(authenticatorData, AuthenticatorDataFlagsOffset);
        if ((flags & (AuthenticatorDataUserPresent | AuthenticatorDataUserVerified)) !=
            (AuthenticatorDataUserPresent | AuthenticatorDataUserVerified))
        {
            throw new NingRanException(
                $"{operation}时未确认 PIN 或生物识别，操作已拒绝；程序不会退回到仅触摸确认。 ");
        }
    }

    private static void EnsurePhysicalTransport(uint transport)
    {
        if ((transport & AllowedPhysicalTransports) == 0 ||
            (transport & (TransportInternal | TransportHybrid)) != 0)
        {
            throw new NingRanException(
                "检测到的不是允许的外接 FIDO2 安全密钥。内置 Windows Hello 和手机中转不能作为本功能的物理密钥。 ");
        }
    }

    private static string DescribeTransport(uint transport)
    {
        var parts = new List<string>();
        if ((transport & TransportUsb) != 0) parts.Add("USB");
        if ((transport & TransportNfc) != 0) parts.Add("NFC");
        if ((transport & TransportBle) != 0) parts.Add("蓝牙");
        if ((transport & TransportSmartCard) != 0) parts.Add("智能卡");
        return $"FIDO2 安全密钥（{string.Join('/', parts)}）";
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WebAuthnRpEntity
    {
        public uint Version;
        public nint Id;
        public nint Name;
        public nint Icon;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WebAuthnUserEntity
    {
        public uint Version;
        public uint IdLength;
        public nint Id;
        public nint Name;
        public nint Icon;
        public nint DisplayName;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WebAuthnClientData
    {
        public uint Version;
        public uint JsonLength;
        public nint Json;
        public nint HashAlgorithm;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WebAuthnCoseCredentialParameter
    {
        public uint Version;
        public nint CredentialType;
        public int Algorithm;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WebAuthnCoseCredentialParameters
    {
        public uint Count;
        public nint Parameters;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WebAuthnCredential
    {
        public uint Version;
        public uint IdLength;
        public nint Id;
        public nint CredentialType;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WebAuthnCredentials
    {
        public uint Count;
        public nint Credentials;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WebAuthnExtension
    {
        public nint Identifier;
        public uint DataLength;
        public nint Data;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WebAuthnExtensions
    {
        public uint Count;
        public nint Extensions;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WebAuthnMakeCredentialOptions
    {
        public uint Version;
        public uint TimeoutMilliseconds;
        public WebAuthnCredentials CredentialList;
        public WebAuthnExtensions Extensions;
        public uint AuthenticatorAttachment;
        public int RequireResidentKey;
        public uint UserVerificationRequirement;
        public uint AttestationConveyancePreference;
        public uint Flags;
        public nint CancellationId;
        public nint ExcludeCredentialList;
        public uint EnterpriseAttestation;
        public uint LargeBlobSupport;
        public int PreferResidentKey;
        public int BrowserInPrivateMode;
        public int EnablePrf;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WebAuthnGetAssertionOptions
    {
        public uint Version;
        public uint TimeoutMilliseconds;
        public WebAuthnCredentials CredentialList;
        public WebAuthnExtensions Extensions;
        public uint AuthenticatorAttachment;
        public uint UserVerificationRequirement;
        public uint Flags;
        public nint U2fAppId;
        public nint U2fAppIdUsed;
        public nint CancellationId;
        public nint AllowCredentialList;
        public uint LargeBlobOperation;
        public uint LargeBlobLength;
        public nint LargeBlob;
        public nint HmacSecretSaltValues;
        public int BrowserInPrivateMode;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WebAuthnHmacSecretSalt
    {
        public uint FirstLength;
        public nint First;
        public uint SecondLength;
        public nint Second;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WebAuthnCredentialWithHmacSecretSalt
    {
        public uint CredentialIdLength;
        public nint CredentialId;
        public nint Salt;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WebAuthnHmacSecretSaltValues
    {
        public nint GlobalSalt;
        public uint CredentialCount;
        public nint Credentials;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WebAuthnCredentialAttestation
    {
        public uint Version;
        public nint FormatType;
        public uint AuthenticatorDataLength;
        public nint AuthenticatorData;
        public uint AttestationLength;
        public nint Attestation;
        public uint AttestationDecodeType;
        public nint AttestationDecode;
        public uint AttestationObjectLength;
        public nint AttestationObject;
        public uint CredentialIdLength;
        public nint CredentialId;
        public WebAuthnExtensions Extensions;
        public uint UsedTransport;
        public int EnterpriseAttestation;
        public int LargeBlobSupported;
        public int ResidentKey;
        public int PrfEnabled;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WebAuthnAssertion
    {
        public uint Version;
        public uint AuthenticatorDataLength;
        public nint AuthenticatorData;
        public uint SignatureLength;
        public nint Signature;
        public WebAuthnCredential Credential;
        public uint UserIdLength;
        public nint UserId;
        public WebAuthnExtensions Extensions;
        public uint LargeBlobLength;
        public nint LargeBlob;
        public uint LargeBlobStatus;
        public nint HmacSecret;
        public uint UsedTransport;
    }

    private sealed class NativeMemoryScope : IDisposable
    {
        private readonly List<nint> _allocations = [];

        public nint Allocate(int size)
        {
            var pointer = Marshal.AllocHGlobal(size);
            Marshal.Copy(new byte[size], 0, pointer, size);
            _allocations.Add(pointer);
            return pointer;
        }

        public nint String(string value)
        {
            var pointer = Marshal.StringToHGlobalUni(value);
            _allocations.Add(pointer);
            return pointer;
        }

        public nint Bytes(ReadOnlySpan<byte> bytes)
        {
            var pointer = Allocate(bytes.Length);
            Marshal.Copy(bytes.ToArray(), 0, pointer, bytes.Length);
            return pointer;
        }

        public nint Int32(int value)
        {
            var pointer = Allocate(sizeof(int));
            Marshal.WriteInt32(pointer, value);
            return pointer;
        }

        public nint Struct<T>(T value) where T : struct
        {
            var pointer = Allocate(Marshal.SizeOf<T>());
            Marshal.StructureToPtr(value, pointer, false);
            return pointer;
        }

        public nint Array<T>(T[] values) where T : struct
        {
            var itemSize = Marshal.SizeOf<T>();
            var pointer = Allocate(checked(itemSize * values.Length));
            for (var index = 0; index < values.Length; index++)
            {
                Marshal.StructureToPtr(values[index], pointer + index * itemSize, false);
            }

            return pointer;
        }

        public void Dispose()
        {
            foreach (var pointer in _allocations.AsEnumerable().Reverse())
            {
                Marshal.FreeHGlobal(pointer);
            }

            _allocations.Clear();
        }
    }

    [DllImport("webauthn.dll")]
    private static extern uint WebAuthNGetApiVersionNumber();

    [DllImport("webauthn.dll")]
    private static extern int WebAuthNGetCancellationId(nint cancellationId);

    [DllImport("webauthn.dll")]
    private static extern int WebAuthNCancelCurrentOperation(nint cancellationId);

    [DllImport("webauthn.dll", CharSet = CharSet.Unicode)]
    private static extern int WebAuthNAuthenticatorMakeCredential(
        nint window,
        ref WebAuthnRpEntity relyingParty,
        ref WebAuthnUserEntity user,
        ref WebAuthnCoseCredentialParameters algorithms,
        ref WebAuthnClientData clientData,
        ref WebAuthnMakeCredentialOptions options,
        out nint attestation);

    [DllImport("webauthn.dll", CharSet = CharSet.Unicode)]
    private static extern int WebAuthNAuthenticatorGetAssertion(
        nint window,
        string relyingPartyId,
        ref WebAuthnClientData clientData,
        ref WebAuthnGetAssertionOptions options,
        out nint assertion);

    [DllImport("webauthn.dll")]
    private static extern void WebAuthNFreeCredentialAttestation(nint attestation);

    [DllImport("webauthn.dll")]
    private static extern void WebAuthNFreeAssertion(nint assertion);
}
