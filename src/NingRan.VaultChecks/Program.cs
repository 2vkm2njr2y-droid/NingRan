using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Compression;
using System.Reflection;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text;
using NingRan.Core;
using NingRan.Core.Internal;

namespace NingRan.VaultChecks;

internal static class Program
{
    private const string Password = "Vault check 8.0.1!";
    private const string HardwareDailyPassword = "Hardware daily 8.0.1!";
    private const string HardwareHiddenPassword = "Hidden hardware 9.7.3#";
    private const string HardwareTestDirectoryName = "NingRan-DualVault-HardwareAcceptance";
    private const string HardwareVaultFileName = "hardware-acceptance.nrvault";
    private const string HardwareStateFileName = "完整状态.bin";
    private const int HardwareStateLength = 4 * 1024 * 1024 + 137;
    private const int ChunkSize = 1024 * 1024;
    private const long NewVaultCapacity = 128L * 1024 * 1024;

    private static async Task<int> Main(string[] args)
    {
        if (args.Length > 0 && args[0].StartsWith("--hardware-", StringComparison.OrdinalIgnoreCase))
        {
            return await RunHardwareCommandAsync(args);
        }

        if (args.Length > 0 && string.Equals(args[0], "--crash-worker", StringComparison.OrdinalIgnoreCase))
        {
            return await RunCrashWorkerAsync(args);
        }

        var root = Path.Combine(Path.GetTempPath(), "NingRan.VaultChecks", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            await RunAsync(root);
            var runLargeWithUpgrade = args.Contains("--large", StringComparer.OrdinalIgnoreCase);
            var runLargeNewOnly = args.Contains("--large-new-only", StringComparer.OrdinalIgnoreCase);
            if (runLargeWithUpgrade || runLargeNewOnly)
            {
                var requestedRoot = Environment.GetEnvironmentVariable("NINGRAN_LARGE_VAULT_TEST_ROOT");
                if (string.IsNullOrWhiteSpace(requestedRoot))
                    throw new InvalidOperationException("运行大容量检查前必须设置 NINGRAN_LARGE_VAULT_TEST_ROOT，并选择有足够空间的测试磁盘。");
                await RunLargeCapacityChecksAsync(requestedRoot, includeLegacyUpgrade: runLargeWithUpgrade);
            }
            var previousReleaseIndex = Array.FindIndex(args,
                argument => string.Equals(argument, "--previous-release", StringComparison.OrdinalIgnoreCase));
            if (previousReleaseIndex >= 0)
            {
                if (previousReleaseIndex + 1 >= args.Length)
                    throw new InvalidOperationException("--previous-release 后必须提供旧版程序目录。");
                await RunPreviousReleaseCompatibilityCheckAsync(root, args[previousReleaseIndex + 1]);
            }
            Console.WriteLine("保险箱自动检查通过。");
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"保险箱自动检查失败：{exception.Message}");
            return 1;
        }
        finally
        {
            TryDeleteTestFolder(root);
        }
    }

    private static async Task<int> RunHardwareCommandAsync(string[] args)
    {
        if (args.Length != 2)
        {
            Console.Error.WriteLine("硬件验收命令必须提供一个已经存在的测试盘目录。");
            return 2;
        }

        try
        {
            var requestedRoot = Path.GetFullPath(args[1]);
            if (!Directory.Exists(requestedRoot))
                throw new InvalidOperationException("指定的硬件验收测试盘目录不存在。");
            if (string.Equals(args[0], "--hardware-prepare", StringComparison.OrdinalIgnoreCase))
            {
                await PrepareHardwareAcceptanceAsync(requestedRoot);
            }
            else if (string.Equals(args[0], "--hardware-write-loop", StringComparison.OrdinalIgnoreCase))
            {
                await RunHardwareWriteLoopAsync(requestedRoot);
            }
            else if (string.Equals(args[0], "--hardware-write-once", StringComparison.OrdinalIgnoreCase))
            {
                await RunHardwareWriteOnceAsync(requestedRoot);
            }
            else if (string.Equals(args[0], "--hardware-verify", StringComparison.OrdinalIgnoreCase))
            {
                await VerifyHardwareAcceptanceAsync(GetExistingHardwareTestDirectory(requestedRoot));
            }
            else
            {
                throw new InvalidOperationException("未知的硬件验收命令。");
            }
            return 0;
        }
        catch (OperationCanceledException)
        {
            Console.WriteLine("硬件验收持续写入已由测试人员正常停止；现在可以执行核验命令。");
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"硬件验收命令失败：{exception.Message}");
            return 1;
        }
    }

    private static async Task PrepareHardwareAcceptanceAsync(string requestedRoot)
    {
        var testDirectory = Path.Combine(requestedRoot, HardwareTestDirectoryName);
        if (Directory.Exists(testDirectory) || File.Exists(testDirectory))
            throw new InvalidOperationException($"测试目录已经存在，为避免覆盖任何内容已停止：{testDirectory}");
        Directory.CreateDirectory(testDirectory);
        try
        {
            var service = new NrVaultService(KdfParameters.Testing);
            var vaultPath = Path.Combine(testDirectory, HardwareVaultFileName);
            using (var dailyPassword = SensitivePassword.FromString(HardwareDailyPassword))
            using (var hiddenPassword = SensitivePassword.FromString(HardwareHiddenPassword))
            using (var request = new CreateDualVaultRequest(
                       vaultPath,
                       dailyPassword,
                       hiddenPassword,
                       fixedCapacityBytes: NewVaultCapacity,
                       dailyCapacityBytes: 24L * ChunkSize,
                       hiddenCapacityBytes: 24L * ChunkSize))
            {
                await service.CreateDualAsync(request);
            }

            using (var daily = await UnlockWithPasswordAsync(service, vaultPath, HardwareDailyPassword))
                await WriteHardwareStateAsync(daily, version: 0, createNew: true, CancellationToken.None);
            using (var hidden = await UnlockWithPasswordAsync(service, vaultPath, HardwareHiddenPassword))
                await WriteHardwareStateAsync(hidden, version: 0, createNew: true, CancellationToken.None);

            await File.WriteAllTextAsync(
                Path.Combine(testDirectory, "TEST-ONLY.txt"),
                "这是凝然双层保险箱真实拔盘/断电验收目录，只包含可删除的测试资料。\r\n",
                Encoding.UTF8);
            await VerifyHardwareAcceptanceAsync(testDirectory);
            Console.WriteLine($"硬件验收测试保险箱已准备：{vaultPath}");
        }
        catch
        {
            TryDeleteTestFolder(testDirectory);
            throw;
        }
    }

    private static async Task RunHardwareWriteLoopAsync(string requestedRoot)
    {
        var testDirectory = GetExistingHardwareTestDirectory(requestedRoot);
        var (dailyVersion, hiddenVersion) = await VerifyHardwareAcceptanceAsync(testDirectory);
        var nextVersion = checked(Math.Max(dailyVersion, hiddenVersion) + 1);
        using var stop = new CancellationTokenSource();
        ConsoleCancelEventHandler handler = (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            stop.Cancel();
        };
        Console.CancelKeyPress += handler;
        try
        {
            Console.WriteLine("持续写入已开始。请按真实验收方案执行拔盘或可控断电；普通停止请按 Ctrl+C。");
            while (true)
            {
                stop.Token.ThrowIfCancellationRequested();
                await WriteHardwareCycleAsync(testDirectory, nextVersion, stop.Token);
                Console.WriteLine($"已完整提交测试版本 {nextVersion}。开始下一轮……");
                Console.Out.Flush();
                nextVersion = checked(nextVersion + 1);
            }
        }
        finally { Console.CancelKeyPress -= handler; }
    }

    private static async Task RunHardwareWriteOnceAsync(string requestedRoot)
    {
        var testDirectory = GetExistingHardwareTestDirectory(requestedRoot);
        var before = await VerifyHardwareAcceptanceAsync(testDirectory);
        var nextVersion = checked(Math.Max(before.DailyVersion, before.HiddenVersion) + 1);
        await WriteHardwareCycleAsync(testDirectory, nextVersion, CancellationToken.None);
        var after = await VerifyHardwareAcceptanceAsync(testDirectory);
        Assert(after == (nextVersion, nextVersion), "一次完整写入结束后的版本核验不一致。");
        Console.WriteLine($"一次完整写入已安全结束，两个空间均为版本 {nextVersion}。现在可以使用 Windows 安全弹出测试盘。");
    }

    private static async Task WriteHardwareCycleAsync(
        string testDirectory,
        long version,
        CancellationToken cancellationToken)
    {
        var service = new NrVaultService();
        var vaultPath = Path.Combine(testDirectory, HardwareVaultFileName);
        using (var daily = await UnlockWithPasswordAsync(service, vaultPath, HardwareDailyPassword))
            await WriteHardwareStateAsync(daily, version, createNew: false, cancellationToken);
        using (var hidden = await UnlockWithPasswordAsync(service, vaultPath, HardwareHiddenPassword))
            await WriteHardwareStateAsync(hidden, version, createNew: false, cancellationToken);
    }

    private static async Task WriteHardwareStateAsync(
        VaultSession session,
        long version,
        bool createNew,
        CancellationToken cancellationToken)
    {
        var state = new byte[HardwareStateLength];
        var marker = checked((byte)(version % 251 + 1));
        Array.Fill(state, marker);
        BinaryPrimitives.WriteInt64LittleEndian(state, version);
        try
        {
            await using var output = session.OpenWriteStream(
                HardwareStateFileName,
                createNew: createNew,
                truncate: !createNew);
            await output.WriteAsync(state, cancellationToken);
            await output.CommitAsync(cancellationToken);
        }
        finally { CryptographicOperations.ZeroMemory(state); }
    }

    private static async Task<(long DailyVersion, long HiddenVersion)> VerifyHardwareAcceptanceAsync(
        string testDirectory)
    {
        var vaultPath = Path.Combine(testDirectory, HardwareVaultFileName);
        if (!File.Exists(vaultPath))
            throw new InvalidOperationException("硬件验收测试保险箱不存在，不能核验。");
        if (new FileInfo(vaultPath).Length != NewVaultCapacity)
            throw new InvalidOperationException("硬件验收测试保险箱总大小已经改变。");

        var service = new NrVaultService();
        long dailyVersion;
        long hiddenVersion;
        using (var daily = await UnlockWithPasswordAsync(service, vaultPath, HardwareDailyPassword))
        {
            dailyVersion = await ReadAndVerifyHardwareStateAsync(daily);
            await daily.VerifyAsync();
        }
        using (var hidden = await UnlockWithPasswordAsync(service, vaultPath, HardwareHiddenPassword))
        {
            hiddenVersion = await ReadAndVerifyHardwareStateAsync(hidden);
            await hidden.VerifyAsync();
        }
        Console.WriteLine($"硬件验收核验通过：日常空间完整版本 {dailyVersion}，隐蔽空间完整版本 {hiddenVersion}。");
        return (dailyVersion, hiddenVersion);
    }

    private static async Task<long> ReadAndVerifyHardwareStateAsync(VaultSession session)
    {
        await using var input = session.OpenReadStream(HardwareStateFileName);
        if (input.Length != HardwareStateLength)
            throw new InvalidOperationException("硬件中断后测试文件长度不是一个完整版本。");
        var versionBytes = new byte[sizeof(long)];
        var buffer = new byte[ChunkSize];
        try
        {
            await input.ReadExactlyAsync(versionBytes);
            var version = BinaryPrimitives.ReadInt64LittleEndian(versionBytes);
            if (version < 0) throw new InvalidOperationException("硬件中断后测试版本编号不正确。");
            var marker = checked((byte)(version % 251 + 1));
            while (true)
            {
                var read = await input.ReadAsync(buffer);
                if (read == 0) break;
                if (buffer.AsSpan(0, read).IndexOfAnyExcept(marker) >= 0)
                    throw new InvalidOperationException("硬件中断后测试内容混入了半个版本。");
            }
            return version;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(versionBytes);
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    private static string GetExistingHardwareTestDirectory(string requestedRoot)
    {
        var testDirectory = Path.Combine(requestedRoot, HardwareTestDirectoryName);
        if (!Directory.Exists(testDirectory))
            throw new InvalidOperationException($"没有找到硬件验收测试目录：{testDirectory}");
        return testDirectory;
    }

    private static async Task<int> RunCrashWorkerAsync(string[] args)
    {
        if (args.Length != 4)
        {
            Console.Error.WriteLine("强制中断测试工作进程参数不完整。");
            return 2;
        }

        var vaultPath = Path.GetFullPath(args[1]);
        var mode = args[2];
        var readyMarker = Path.GetFullPath(args[3]);
        try
        {
            var service = new NrVaultService();
            using var session = await UnlockAsync(service, vaultPath);
            var replacement = new byte[3 * ChunkSize + 271];
            Array.Fill(replacement, (byte)0xA5);
            try
            {
                var output = session.OpenWriteStream("强制中断检查.bin", truncate: true);
                await output.WriteAsync(replacement);
                if (string.Equals(mode, "after-commit", StringComparison.Ordinal))
                    await output.CommitAsync();
                else if (!string.Equals(mode, "before-commit", StringComparison.Ordinal))
                    throw new InvalidOperationException("未知的强制中断测试模式。");

                await File.WriteAllTextAsync(readyMarker, mode, Encoding.UTF8);
                await Task.Delay(Timeout.InfiniteTimeSpan);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(replacement);
            }
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"强制中断测试工作进程失败：{exception.Message}");
            return 1;
        }
        return 0;
    }

    private static async Task RunPreviousReleaseCompatibilityCheckAsync(string root, string previousReleaseDirectory)
    {
        var previousRoot = Path.GetFullPath(previousReleaseDirectory);
        var previousCorePath = Path.Combine(previousRoot, "NingRan.Core.dll");
        if (!File.Exists(previousCorePath))
            throw new InvalidOperationException("旧版程序目录中没有找到 NingRan.Core.dll。");

        const string dailyPasswordText = "Compatibility daily 8.0.1!";
        const string hiddenPasswordText = "Compatibility hidden 9.7.3#";
        const string previousPasswordText = "Previous release vault 8.0.1!";
        const string previousArchivePasswordText = "Previous archive 8.0.1!";
        const string previousIdentityPasswordText = "Previous identity 8.0.1!";
        const string previousContent = "由上一版本凝然生成，供新版兼容检查。";
        var vaultPath = Path.Combine(root, "新版格式保持兼容的保险箱");
        var previousVaultPath = Path.Combine(root, "上一版本创建的保险箱");
        var previousSourcePath = Path.Combine(root, "上一版本加密资料.txt");
        var previousArchivePath = Path.Combine(root, "上一版本创建的加密包.nrenc");
        await File.WriteAllTextAsync(previousSourcePath, previousContent, Encoding.UTF8);
        var service = new NrVaultService(KdfParameters.Testing);
        using (var dailyPassword = SensitivePassword.FromString(dailyPasswordText))
        using (var hiddenPassword = SensitivePassword.FromString(hiddenPasswordText))
        using (var request = new CreateDualVaultRequest(
                   vaultPath,
                   dailyPassword,
                   hiddenPassword,
                   fixedCapacityBytes: NewVaultCapacity,
                   dailyCapacityBytes: 8L * ChunkSize,
                   hiddenCapacityBytes: 8L * ChunkSize))
        {
            await service.CreateDualAsync(request);
        }

        byte[] beforeHash;
        await using (var input = new FileStream(vaultPath, FileMode.Open, FileAccess.Read, FileShare.Read,
                         ChunkSize, FileOptions.Asynchronous | FileOptions.SequentialScan))
            beforeHash = await SHA256.HashDataAsync(input);

        var loadContext = new AssemblyLoadContext($"NingRanPreviousRelease-{Guid.NewGuid():N}", isCollectible: true);
        loadContext.Resolving += (_, name) =>
        {
            var candidate = Path.Combine(previousRoot, name.Name + ".dll");
            return File.Exists(candidate) ? loadContext.LoadFromAssemblyPath(candidate) : null;
        };
        string? failureMessage = null;
        try
        {
            var core = loadContext.LoadFromAssemblyPath(previousCorePath);
            var publicAndNonPublicStatic = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static;
            var previousKdfType = core.GetType("NingRan.Core.KdfParameters", throwOnError: true)!;
            var previousKdf = previousKdfType.GetProperty("Testing", publicAndNonPublicStatic)?.GetValue(null)
                ?? throw new InvalidOperationException("旧版没有提供自动检查所需的密码参数。");
            var serviceType = core.GetType("NingRan.Core.NrVaultService", throwOnError: true)!;
            var constructor = serviceType.GetConstructors(BindingFlags.Public | BindingFlags.Instance)
                .OrderBy(candidate => candidate.GetParameters().Length)
                .FirstOrDefault()
                ?? throw new InvalidOperationException("旧版没有公开的保险箱读取服务构造方法。");
            var serviceArguments = new object?[constructor.GetParameters().Length];
            serviceArguments[0] = previousKdf;
            var previousService = constructor.Invoke(serviceArguments)
                ?? throw new InvalidOperationException("无法建立旧版保险箱读取服务。");
            var inspect = serviceType.GetMethods(BindingFlags.Public | BindingFlags.Instance)
                .Single(method => method.Name == "InspectAsync" && method.GetParameters().Length is 1 or 2);
            var parameters = inspect.GetParameters().Length == 1
                ? new object?[] { vaultPath }
                : new object?[] { vaultPath, CancellationToken.None };
            try
            {
                var task = inspect.Invoke(previousService, parameters) as Task
                    ?? throw new InvalidOperationException("旧版 InspectAsync 没有返回可等待的任务。");
                await task;
            }
            catch (Exception exception)
            {
                failureMessage = UnwrapReflectionException(exception).Message;
            }

            var sensitivePasswordType = core.GetType("NingRan.Core.SensitivePassword", throwOnError: true)!;
            var fromString = sensitivePasswordType.GetMethod(
                "FromString",
                BindingFlags.Public | BindingFlags.Static,
                [typeof(string)])
                ?? throw new InvalidOperationException("旧版没有可用的密码读取方法。");
            var encryptionModeType = core.GetType("NingRan.Core.EncryptionMode", throwOnError: true)!;
            var vaultSizeProtectionType = core.GetType("NingRan.Core.VaultSizeProtection", throwOnError: true)!;
            var standardMode = Enum.Parse(encryptionModeType, "Standard");
            var hideExactSize = Enum.Parse(vaultSizeProtectionType, "HideExactSize");
            var previousPassword = fromString.Invoke(null, [previousPasswordText])
                ?? throw new InvalidOperationException("无法建立旧版保险箱密码。");
            var createRequestType = core.GetType("NingRan.Core.CreateVaultRequest", throwOnError: true)!;
            var createRequest = createRequestType.GetConstructors().Single().Invoke([
                previousVaultPath,
                previousPassword,
                standardMode,
                null,
                null,
                new[] { previousSourcePath },
                hideExactSize,
                IntPtr.Zero,
                NewVaultCapacity,
            ]);
            try
            {
                var create = serviceType.GetMethods(BindingFlags.Public | BindingFlags.Instance)
                    .Single(method => method.Name == "CreateAsync" && method.GetParameters().Length == 3);
                var createTask = create.Invoke(previousService, [createRequest, null, CancellationToken.None]) as Task
                    ?? throw new InvalidOperationException("旧版创建保险箱没有返回可等待的任务。");
                await createTask;
            }
            finally
            {
                (createRequest as IDisposable)?.Dispose();
            }

            var identityServiceType = core.GetType("NingRan.Core.NrIdentityService", throwOnError: true)!;
            var identityService = identityServiceType.GetConstructors().Single().Invoke([previousKdf]);
            string? identityId = null;
            try
            {
                var createIdentity = identityServiceType.GetMethods(BindingFlags.Public | BindingFlags.Instance)
                    .Single(method => method.Name == "CreateAsync" &&
                                      method.GetParameters().Length == 3 &&
                                      method.GetParameters()[1].ParameterType == typeof(string));
                var identityTask = createIdentity.Invoke(
                    identityService,
                    ["上一版本兼容检查", previousIdentityPasswordText, CancellationToken.None]) as Task
                    ?? throw new InvalidOperationException("旧版创建身份没有返回可等待的任务。");
                await identityTask;
                var identityResult = identityTask.GetType().GetProperty("Result")?.GetValue(identityTask)
                    ?? throw new InvalidOperationException("旧版没有返回创建后的身份。");
                var identity = identityResult.GetType().GetProperty("Identity")?.GetValue(identityResult)
                    ?? throw new InvalidOperationException("旧版身份结果不完整。");
                identityId = identity.GetType().GetProperty("Id")?.GetValue(identity) as string
                    ?? throw new InvalidOperationException("旧版身份没有内部编号。");

                var archiveServiceType = core.GetType("NingRan.Core.NrArchiveService", throwOnError: true)!;
                var archiveServiceArguments = new object?[archiveServiceType.GetConstructors().Single().GetParameters().Length];
                archiveServiceArguments[0] = previousKdf;
                archiveServiceArguments[2] = identityService;
                var previousArchiveService = archiveServiceType.GetConstructors().Single().Invoke(archiveServiceArguments);
                var compressionType = core.GetType("NingRan.Core.ArchiveCompressionLevel", throwOnError: true)!;
                var standardCompression = Enum.Parse(compressionType, "Standard");
                var encryptRequestType = core.GetType("NingRan.Core.EncryptRequest", throwOnError: true)!;
                var encryptRequestConstructor = encryptRequestType.GetConstructors()
                    .Single(candidate => candidate.GetParameters().Length == 12 &&
                                         candidate.GetParameters()[2].ParameterType == typeof(string));
                var encryptRequest = encryptRequestConstructor.Invoke([
                    previousSourcePath,
                    previousArchivePath,
                    previousArchivePasswordText,
                    standardMode,
                    null,
                    false,
                    standardCompression,
                    identityId,
                    previousIdentityPasswordText,
                    null,
                    IntPtr.Zero,
                    null,
                ]);
                try
                {
                    var encrypt = archiveServiceType.GetMethods(BindingFlags.Public | BindingFlags.Instance)
                        .Single(method => method.Name == "EncryptAsync" && method.GetParameters().Length == 3);
                    var encryptTask = encrypt.Invoke(
                        previousArchiveService,
                        [encryptRequest, null, CancellationToken.None]) as Task
                        ?? throw new InvalidOperationException("旧版创建加密包没有返回可等待的任务。");
                    await encryptTask;
                }
                finally
                {
                    (encryptRequest as IDisposable)?.Dispose();
                }
            }
            finally
            {
                if (!string.IsNullOrWhiteSpace(identityId))
                {
                    var deletePassword = fromString.Invoke(null, [previousIdentityPasswordText]);
                    try
                    {
                        var deleteIdentity = identityServiceType.GetMethods(BindingFlags.Public | BindingFlags.Instance)
                            .Single(method => method.Name == "DeleteLocalIdentityAsync" && method.GetParameters().Length == 3);
                        var deleteTask = deleteIdentity.Invoke(
                            identityService,
                            [identityId, deletePassword, CancellationToken.None]) as Task;
                        if (deleteTask is not null) await deleteTask;
                    }
                    finally
                    {
                        (deletePassword as IDisposable)?.Dispose();
                    }
                }
            }
        }
        finally
        {
            loadContext.Unload();
        }

        byte[] afterHash;
        await using (var input = new FileStream(vaultPath, FileMode.Open, FileAccess.Read, FileShare.Read,
                         ChunkSize, FileOptions.Asynchronous | FileOptions.SequentialScan))
            afterHash = await SHA256.HashDataAsync(input);
        try
        {
            Assert(string.IsNullOrWhiteSpace(failureMessage),
                $"上一版本无法读取保持兼容的保险箱格式。实际信息：{failureMessage}");
            Assert(beforeHash.AsSpan().SequenceEqual(afterHash),
                "旧版程序检查新版保险箱后修改了保险箱文件。");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(beforeHash);
            CryptographicOperations.ZeroMemory(afterHash);
        }

        using (var previousVault = await UnlockWithPasswordAsync(service, previousVaultPath, previousPasswordText))
        {
            await AssertTextAsync(previousVault, Path.GetFileName(previousSourcePath), previousContent);
            await previousVault.VerifyAsync();
        }
        await VerifyPreviousReleaseArchiveAsync(
            previousArchivePath,
            previousArchivePasswordText,
            Path.GetFileName(previousSourcePath),
            previousContent);
        Console.WriteLine("新版读取上一版本的 .nrenc 与保险箱检查通过，保险箱格式也保持向前兼容。");
    }

    private static async Task VerifyPreviousReleaseArchiveAsync(
        string archivePath,
        string passwordText,
        string expectedPath,
        string expectedText)
    {
        var archiveService = new NrArchiveService(KdfParameters.Testing);
        var info = await archiveService.InspectAsync(archivePath);
        Assert(info.FormatVersion == "6.1", "新版没有把上一版本的 .nrenc 识别为兼容格式。");
        await using var input = new FileStream(
            archivePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            IndexedPayloadContainer.BlockSize,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var password = SensitivePassword.FromString(passwordText);
        var unlocked = await ArchiveHeader.ReadAndUnlockAsync(
            input,
            password,
            ReadOnlyMemory<byte>.Empty,
            new NrPhysicalDeviceService(),
            0,
            CancellationToken.None,
            EncryptionMode.Standard);
        try
        {
            using var payload = await IndexedPayloadContainer.OpenAsync(
                input,
                unlocked.Header,
                unlocked.DataKey,
                CancellationToken.None,
                0,
                input.Length);
            await IndexedPayloadContainer.ValidateAllAsync(
                input,
                unlocked.Header,
                unlocked.DataKey,
                payload,
                null,
                CancellationToken.None);
            var entry = payload.Entries.SingleOrDefault(candidate =>
                candidate.Kind == PayloadEntryKind.File &&
                string.Equals(candidate.RelativePath, expectedPath, StringComparison.Ordinal));
            Assert(entry is not null, "新版没有读出上一版本 .nrenc 中的文件目录。");
            await using var content = new MemoryStream();
            await IndexedPayloadContainer.CopyEntryToStreamAsync(
                input,
                unlocked.Header,
                unlocked.DataKey,
                payload,
                entry!,
                content,
                CancellationToken.None);
            content.Position = 0;
            using var reader = new StreamReader(content, Encoding.UTF8, leaveOpen: true);
            Assert(await reader.ReadToEndAsync() == expectedText, "新版读取上一版本 .nrenc 的内容不正确。");
        }
        finally
        {
            unlocked.PhysicalUnlock?.Dispose();
            CryptographicOperations.ZeroMemory(unlocked.DataKey);
            CryptographicOperations.ZeroMemory(unlocked.Header.Bytes);
            CryptographicOperations.ZeroMemory(unlocked.Header.PayloadNoncePrefix);
            CryptographicOperations.ZeroMemory(unlocked.Header.HeaderHash);
        }
    }

    private static Exception UnwrapReflectionException(Exception exception)
    {
        while (exception is TargetInvocationException { InnerException: not null } or AggregateException { InnerException: not null })
            exception = exception.InnerException!;
        return exception;
    }

    private static async Task RunAsync(string root)
    {
        var sourceRoot = Path.Combine(root, "原始资料");
        var nested = Path.Combine(sourceRoot, "嵌套资料");
        var emptyDirectory = Path.Combine(sourceRoot, "空目录");
        Directory.CreateDirectory(nested);
        Directory.CreateDirectory(emptyDirectory);

        const string secretText = "这是一段只能在保险箱解锁后读取的中文内容。";
        var notePath = Path.Combine(nested, "说明.txt");
        await File.WriteAllTextAsync(notePath, secretText, Encoding.UTF8);
        await File.WriteAllBytesAsync(Path.Combine(sourceRoot, "空文件.bin"), []);

        var largeBytes = RandomNumberGenerator.GetBytes(ChunkSize * 2 + 131_329);
        var largePath = Path.Combine(sourceRoot, "超大文件.bin");
        await File.WriteAllBytesAsync(largePath, largeBytes);

        var initialDuplicate = Path.Combine(root, "首次资料", "重复.txt");
        Directory.CreateDirectory(Path.GetDirectoryName(initialDuplicate)!);
        await File.WriteAllTextAsync(initialDuplicate, "首次资料", Encoding.UTF8);

        var vaultPath = Path.Combine(root, "中文保险箱");
        var service = new NrVaultService(KdfParameters.Testing);
        using (var password = SensitivePassword.FromString(Password))
        using (var request = new CreateVaultRequest(
                   vaultPath,
                   password,
                   EncryptionMode.Standard,
                   sourcePaths: [sourceRoot, initialDuplicate],
                   sizeProtection: VaultSizeProtection.HideExactSize,
                   fixedCapacityBytes: NewVaultCapacity))
        {
            var created = await service.CreateAsync(request);
            Assert(created.EntryCount == 7, "创建后目录数量不正确。");
            Assert(NrVaultService.IsVaultFile(created.Info.VaultPath), "没有识别出新建的单文件保险箱。");
            Assert(new FileInfo(vaultPath).Length == NewVaultCapacity, "新版保险箱没有保持所选固定容量。");
            var inspected = await service.InspectAsync(vaultPath);
            Assert(inspected.FormatVersion == 3 && inspected.CapacityBytes == NewVaultCapacity,
                "没有直接读出新版保险箱的格式和固定容量。");
        }

        await ExpectFailureAsync(async () =>
        {
            using var wrongPassword = SensitivePassword.FromString("Wrong password 8.0.1!");
            using var request = new UnlockVaultRequest(vaultPath, wrongPassword);
            using var ignored = await service.UnlockAsync(request);
        }, "错误密码不应能够解锁保险箱。");

        using (var session = await UnlockAsync(service, vaultPath))
        {
            Assert(session.TryGetEntry("原始资料/嵌套资料/说明.txt", out var note) && note is not null,
                "没有找到中文嵌套路径中的文件。");
            Assert(session.TryGetEntry("原始资料/空目录", out var empty) && empty?.IsDirectory == true,
                "没有保留空文件夹。");
            Assert(session.TryGetEntry("原始资料/空文件.bin", out var emptyFile) && emptyFile?.Length == 0,
                "没有保留空文件。");

            await using (var noteStream = session.OpenReadStream("原始资料/嵌套资料/说明.txt"))
            using (var reader = new StreamReader(noteStream, Encoding.UTF8, leaveOpen: false))
            {
                Assert(await reader.ReadToEndAsync() == secretText, "读取的中文文件内容不正确。");
            }

            await using (var largeStream = session.OpenReadStream("原始资料/超大文件.bin"))
            {
                var offset = ChunkSize - 97;
                largeStream.Seek(offset, SeekOrigin.Begin);
                var actual = new byte[8_192];
                await largeStream.ReadExactlyAsync(actual);
                Assert(actual.AsSpan().SequenceEqual(largeBytes.AsSpan(offset, actual.Length)),
                    "分段边界附近的按需读取内容不正确。");
            }

            await session.VerifyAsync();

            var secondDuplicate = Path.Combine(root, "后续资料", "重复.txt");
            Directory.CreateDirectory(Path.GetDirectoryName(secondDuplicate)!);
            await File.WriteAllTextAsync(secondDuplicate, "后续资料", Encoding.UTF8);
            var added = await service.AddSourcesAsync(session, [secondDuplicate]);
            Assert(added.AddedEntries == 1, "追加同名文件时没有加入一个新文件。");
            Assert(session.TryGetEntry("重复 (1).txt", out var renamed) && renamed is not null,
                "追加同名文件没有自动改名。");
            await VerifyWritableOperationsAsync(session);
            await session.VerifyAsync();
            await VerifyDirectVaultExportAsync(session, root, secretText);
        }

        using (var reopened = await UnlockAsync(service, vaultPath))
        {
            Assert(reopened.TryGetEntry("重复 (1).txt", out _), "重新解锁后没有保存追加的资料。");
            Assert(reopened.TryGetEntry("工作区/恢复.txt", out var restored) && restored?.Length == 19,
                "重新解锁后没有保存第二阶段的修改结果。");
            await using (var restoredStream = reopened.OpenReadStream("工作区/恢复.txt"))
            {
                var restoredBytes = new byte[19];
                await restoredStream.ReadExactlyAsync(restoredBytes);
                Assert(Encoding.UTF8.GetString(restoredBytes) == "012XYZ6789ABCDEFGHI", "重新解锁后的修改内容不正确。");
            }
            await reopened.VerifyAsync();
        }

        Assert(!Directory.Exists(vaultPath + ".history"), "新版固定容量保险箱不应在旁边建立历史版本目录。");

        var secondVaultPath = Path.Combine(root, "第二个保险箱");
        using (var password = SensitivePassword.FromString(Password))
        using (var request = new CreateVaultRequest(
                   secondVaultPath,
                   password,
                   EncryptionMode.Standard,
                   sourcePaths: [initialDuplicate],
                   fixedCapacityBytes: NewVaultCapacity))
        {
            await service.CreateAsync(request);
        }
        using (var secondVault = await UnlockAsync(service, secondVaultPath))
        {
            Assert(secondVault.HistoryRetentionDays == 15, "第二个保险箱错误继承了其他保险箱的历史保留天数。");
            Assert(secondVault.HistoryMaximumBytes == 0, "第二个保险箱错误继承了其他保险箱的历史空间上限。");
        }

        Assert(File.Exists(vaultPath) && !Directory.Exists(vaultPath), "新建保险箱没有以单文件形式保存。");
        Assert(new FileInfo(vaultPath).Length == NewVaultCapacity, "多次修改后保险箱总大小发生了变化。");
        AssertEncryptedStorageDoesNotExposePlaintext(vaultPath, secretText);
        await VerifyFutureFormatIsNotModifiedAsync(service, vaultPath);
        await VerifyCancellationLeavesNoPartialVaultAsync(service, root, sourceRoot);
        await VerifyMidCreationCancellationLeavesNoPartialVaultAsync(service, root);
        await VerifyLegacyUpgradeAsync(service, root);
        await VerifyInterruptedCatalogFallsBackAsync(service, root, vaultPath);
        await VerifyDualWorkspaceAsync(service, root, vaultPath);
        await VerifyTamperingIsDetectedAsync(service, vaultPath);
        VerifyPreviousReleaseCompatibilityArchiveAtLargeCapacities();
        await VerifyHardTerminationRecoveryAsync(service, root);
        await VerifyHardwareAcceptanceHarnessAsync(root);
    }

    private static async Task VerifyDirectVaultExportAsync(
        VaultSession session,
        string root,
        string expectedText)
    {
        var archivePath = Path.Combine(root, "保险箱直接导出.nrenc");
        var archiveService = new NrArchiveService(
            KdfParameters.Testing,
            keyFileService: null,
            identityService: null,
            trustedContactService: null,
            allowUnsignedArchivesForTesting: true);
        var reportedProgress = new List<CryptoProgress>();
        EncryptionResult exportResult;
        const string exportPasswordText = "Vault direct export 8.0.2!";
        using (var exportPassword = SensitivePassword.FromString(exportPasswordText))
        using (var request = new EncryptRequest(
                   session,
                   archivePath,
                   exportPassword,
                   EncryptionMode.Standard,
                   SizePadding: SizePaddingMode.None,
                   Compression: ArchiveCompressionLevel.Standard))
        {
            Assert(request.IsVaultExport && request.SourceVault == session,
                "保险箱导出请求没有保留直接读取会话。");
            exportResult = await archiveService.EncryptAsync(
                request,
                new InlineProgress(reportedProgress.Add));
        }

        Assert(File.Exists(archivePath), "保险箱没有直接导出为 .nrenc。");
        Assert(exportResult.ArchiveHash.Length == 0,
            "保险箱导出仍执行了只用于原文件删除保护的整包校验值读取。");
        Assert(reportedProgress.Any(value => value.Stage == CryptoStage.Encrypting &&
                                             value.Message.Contains("分析压缩方式", StringComparison.Ordinal)),
            "保险箱导出没有报告压缩分析阶段的进度。");
        Assert(reportedProgress.Any(value => value.Stage == CryptoStage.Verifying &&
                                             value.Fraction > 2d / 3d),
            "保险箱导出没有报告完整验证阶段的实际百分比。");
        var metrics = NrArchiveService.EstimateProgressMetrics(
            completed: 75,
            total: 100,
            stageStartCompleted: 50,
            stageElapsed: TimeSpan.FromSeconds(5));
        Assert(metrics.BytesPerSecond == 5 && metrics.EstimatedRemaining == TimeSpan.FromSeconds(5),
            "大文件导出的阶段速度或预计剩余时间计算不正确。");
        using var openPassword = SensitivePassword.FromString(exportPasswordText);
        await using var input = new FileStream(
            archivePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            IndexedPayloadContainer.BlockSize,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        var unlocked = await ArchiveHeader.ReadAndUnlockAsync(
            input,
            openPassword,
            ReadOnlyMemory<byte>.Empty,
            new NrPhysicalDeviceService(),
            0,
            CancellationToken.None,
            EncryptionMode.Standard);
        try
        {
            using var archive = await IndexedPayloadContainer.OpenAsync(
                input,
                unlocked.Header,
                unlocked.DataKey,
                CancellationToken.None,
                archiveOffset: 0,
                archiveLength: input.Length);
            await IndexedPayloadContainer.ValidateAllAsync(
                input,
                unlocked.Header,
                unlocked.DataKey,
                archive,
                null,
                CancellationToken.None);
            var expectedRoot = session.Info.Name;
            var notePath = $"{expectedRoot}/原始资料/嵌套资料/说明.txt";
            var note = archive.Entries.SingleOrDefault(entry =>
                string.Equals(entry.RelativePath, notePath, StringComparison.Ordinal));
            Assert(note is not null, "直接导出的加密包没有使用保险箱名称作为最外层文件夹。");
            Assert(!archive.Entries.Any(entry => entry.RelativePath.Contains(":\\", StringComparison.Ordinal)),
                "直接导出的加密包仍然把临时盘符当作文件夹名称。");
            await using var content = new MemoryStream();
            await IndexedPayloadContainer.CopyEntryToStreamAsync(
                input,
                unlocked.Header,
                unlocked.DataKey,
                archive,
                note!,
                content,
                CancellationToken.None);
            content.Position = 0;
            using var reader = new StreamReader(content, Encoding.UTF8, leaveOpen: true);
            Assert(await reader.ReadToEndAsync() == expectedText, "直接导出的 .nrenc 内容不正确。");
        }
        finally
        {
            unlocked.PhysicalUnlock?.Dispose();
            CryptographicOperations.ZeroMemory(unlocked.DataKey);
            CryptographicOperations.ZeroMemory(unlocked.Header.Bytes);
            CryptographicOperations.ZeroMemory(unlocked.Header.PayloadNoncePrefix);
            CryptographicOperations.ZeroMemory(unlocked.Header.HeaderHash);
        }
        Console.WriteLine("保险箱无需临时磁盘直接导出 .nrenc 检查通过。");
    }

    private static async Task VerifyHardwareAcceptanceHarnessAsync(string root)
    {
        var testDirectory = Path.Combine(root, HardwareTestDirectoryName);
        try
        {
            await PrepareHardwareAcceptanceAsync(root);
            await WriteHardwareCycleAsync(testDirectory, version: 1, CancellationToken.None);
            var versions = await VerifyHardwareAcceptanceAsync(testDirectory);
            Assert(versions == (1L, 1L), "硬件验收工具没有保存并核验一个完整的新版本。");
        }
        finally { TryDeleteTestFolder(testDirectory); }
        Console.WriteLine("真实硬件两阶段验收工具自检通过。");
    }

    private static async Task RunLargeCapacityChecksAsync(string requestedRoot, bool includeLegacyUpgrade)
    {
        var parent = Path.GetFullPath(requestedRoot);
        Directory.CreateDirectory(parent);
        var testRoot = Path.Combine(parent, $"NingRan-LargeVaultChecks-{Guid.NewGuid():N}");
        Directory.CreateDirectory(testRoot);
        try
        {
            var service = new NrVaultService(KdfParameters.Testing);
            foreach (var gib in new[] { 20L, 50L, 100L })
            {
                var capacity = checked(gib * 1024 * 1024 * 1024);
                var drive = new DriveInfo(Path.GetPathRoot(testRoot)!);
                if (drive.AvailableFreeSpace < capacity + 2L * 1024 * 1024 * 1024)
                    throw new InvalidOperationException($"测试磁盘空间不足，无法安全执行 {gib} GB 保险箱检查。");
                var path = Path.Combine(testRoot, $"{gib}GB-保险箱");
                var baselineMemory = Environment.WorkingSet;
                long peakMemory = baselineMemory;
                var creationClock = Stopwatch.StartNew();
                using (var password = SensitivePassword.FromString(Password))
                using (var request = new CreateVaultRequest(path, password, fixedCapacityBytes: capacity))
                {
                    await service.CreateAsync(request, new InlineProgress(_ =>
                    {
                        peakMemory = Math.Max(peakMemory, Environment.WorkingSet);
                    }));
                }
                creationClock.Stop();
                Assert(new FileInfo(path).Length == capacity, $"{gib} GB 保险箱总大小不正确。");
                Assert(peakMemory - baselineMemory < 512L * 1024 * 1024,
                    $"{gib} GB 保险箱创建期间内存增长超过 512 MB 固定上限。");

                var inspectClock = Stopwatch.StartNew();
                var info = await service.InspectAsync(path);
                inspectClock.Stop();
                Assert(info.CapacityBytes == capacity && inspectClock.Elapsed < TimeSpan.FromSeconds(10),
                    $"{gib} GB 保险箱没有在 10 秒内直接读出基本信息。");
                using (var session = await UnlockAsync(service, path))
                {
                    var data = RandomNumberGenerator.GetBytes(1024 * 1024);
                    try
                    {
                        await using var output = session.OpenWriteStream("局部修改检查.bin", createNew: true);
                        await output.WriteAsync(data);
                        await output.CommitAsync();
                    }
                    finally { CryptographicOperations.ZeroMemory(data); }
                    Assert(new FileInfo(path).Length == capacity, $"{gib} GB 保险箱局部修改后总大小变化。");
                    await session.VerifyAsync();
                }
                Console.WriteLine($"{gib} GB 实盘检查通过：创建 {creationClock.Elapsed:g}，信息读取 {inspectClock.Elapsed:g}，峰值增量 {FormatBytesForConsole(peakMemory - baselineMemory)}。");
                File.Delete(path);
            }
            if (includeLegacyUpgrade)
                await RunLargeLegacyUpgradeCheckAsync(service, testRoot);
        }
        finally
        {
            try { if (Directory.Exists(testRoot)) Directory.Delete(testRoot, recursive: true); } catch { }
        }
    }

    private static void VerifyPreviousReleaseCompatibilityArchiveAtLargeCapacities()
    {
        foreach (var gib in new[] { 20L, 50L, 100L })
        {
            var capacity = checked(gib * 1024 * 1024 * 1024);
            var info = new VaultInfo(
                $"virtual-{gib}GB", Guid.NewGuid(), EncryptionMode.Standard,
                VaultSizeProtection.HideExactSize, DateTimeOffset.UtcNow,
                WorkspaceVaultContainer.FormatVersion, capacity);
            var compatibilityArchive = WorkspaceVaultContainer
                .BuildPreviousReleaseCompatibilityArchiveForTesting(info, capacity);
            try
            {
                using var virtualVault = new SparseTailReadStream(capacity, compatibilityArchive);
                using var archive = new ZipArchive(virtualVault, ZipArchiveMode.Read, leaveOpen: false);
                var entry = archive.GetEntry("vault.info")
                    ?? throw new InvalidOperationException($"{gib} GB 保险箱尾部缺少旧版只读识别信息。");
                var publicInfo = new byte[64];
                using var entryStream = entry.Open();
                entryStream.ReadExactly(publicInfo);
                try
                {
                    Assert(publicInfo.AsSpan(0, 8).SequenceEqual("NRVAULT1"u8) &&
                           BinaryPrimitives.ReadInt32LittleEndian(publicInfo.AsSpan(8, 4)) ==
                           WorkspaceVaultContainer.FormatVersion,
                        $"{gib} GB 保险箱尾部的旧版只读识别信息不正确。");
                }
                finally { CryptographicOperations.ZeroMemory(publicInfo); }
            }
            finally { CryptographicOperations.ZeroMemory(compatibilityArchive); }
        }
        Console.WriteLine("20/50/100 GB 旧版只读识别尾部检查通过。");
    }

    private static async Task VerifyHardTerminationRecoveryAsync(NrVaultService service, string root)
    {
        var vaultPath = Path.Combine(root, "强制中断恢复保险箱");
        var original = new byte[ChunkSize + 137];
        Array.Fill(original, (byte)0x3C);
        string journalPath;
        try
        {
            using (var password = SensitivePassword.FromString(Password))
            using (var request = new CreateVaultRequest(vaultPath, password, fixedCapacityBytes: NewVaultCapacity))
                await service.CreateAsync(request);

            using (var session = await UnlockAsync(service, vaultPath))
            {
                journalPath = session.JournalPath;
                await using var output = session.OpenWriteStream("强制中断检查.bin", createNew: true);
                await output.WriteAsync(original);
                await output.CommitAsync();
            }

            var beforeMarker = Path.Combine(root, $"before-{Guid.NewGuid():N}.ready");
            using (var worker = StartCrashWorker(vaultPath, "before-commit", beforeMarker))
            {
                await WaitForWorkerMarkerAsync(worker, beforeMarker);
                Assert(Directory.Exists(journalPath) &&
                       Directory.EnumerateFiles(journalPath, "*.nrtxn", SearchOption.AllDirectories).Any(),
                    "强制结束前没有形成可验证的未完成加密写入。");
                await KillWorkerAsync(worker);
            }
            File.Delete(beforeMarker);

            using (var recovered = await UnlockAsync(service, vaultPath))
            {
                await AssertFileFilledAsync(recovered, "强制中断检查.bin", original.Length, 0x3C,
                    "写入完成前强制结束后，原内容没有保持不变。");
                await recovered.VerifyAsync();
                Assert(!Directory.EnumerateFiles(journalPath, "*.nrtxn", SearchOption.AllDirectories).Any(),
                    "重新解锁后没有清理被强制中断的临时写入。");
            }

            var afterMarker = Path.Combine(root, $"after-{Guid.NewGuid():N}.ready");
            using (var worker = StartCrashWorker(vaultPath, "after-commit", afterMarker))
            {
                await WaitForWorkerMarkerAsync(worker, afterMarker);
                await KillWorkerAsync(worker);
            }
            File.Delete(afterMarker);

            using (var recovered = await UnlockAsync(service, vaultPath))
            {
                await AssertFileFilledAsync(recovered, "强制中断检查.bin", 3L * ChunkSize + 271, 0xA5,
                    "写入完成后强制结束，已经保存的新内容发生丢失。");
                await recovered.VerifyAsync();
            }
        }
        finally { CryptographicOperations.ZeroMemory(original); }
        Console.WriteLine("独立进程在保存前后被强制结束的恢复检查通过。");
    }

    private static Process StartCrashWorker(string vaultPath, string mode, string markerPath)
    {
        var processPath = Environment.ProcessPath
            ?? throw new InvalidOperationException("无法确定强制中断测试程序路径。");
        var startInfo = new ProcessStartInfo
        {
            FileName = processPath,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        if (string.Equals(Path.GetFileNameWithoutExtension(processPath), "dotnet", StringComparison.OrdinalIgnoreCase))
            startInfo.ArgumentList.Add(Assembly.GetExecutingAssembly().Location);
        startInfo.ArgumentList.Add("--crash-worker");
        startInfo.ArgumentList.Add(vaultPath);
        startInfo.ArgumentList.Add(mode);
        startInfo.ArgumentList.Add(markerPath);
        return Process.Start(startInfo)
            ?? throw new InvalidOperationException("无法启动强制中断测试工作进程。");
    }

    private static async Task WaitForWorkerMarkerAsync(Process worker, string markerPath)
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(45);
        while (!File.Exists(markerPath))
        {
            if (worker.HasExited)
            {
                var error = await worker.StandardError.ReadToEndAsync();
                throw new InvalidOperationException($"强制中断测试工作进程提前退出（{worker.ExitCode}）：{error}");
            }
            if (DateTime.UtcNow >= deadline)
                throw new TimeoutException("等待强制中断测试工作进程准备完成超时。");
            await Task.Delay(50);
        }
    }

    private static async Task KillWorkerAsync(Process worker)
    {
        if (!worker.HasExited)
            worker.Kill(entireProcessTree: true);
        await worker.WaitForExitAsync();
        Assert(worker.ExitCode != 0, "强制中断测试工作进程没有被实际终止。");
    }

    private static async Task AssertFileFilledAsync(
        VaultSession session,
        string relativePath,
        long expectedLength,
        byte expectedByte,
        string message)
    {
        await using var input = session.OpenReadStream(relativePath);
        Assert(input.Length == expectedLength, message);
        var buffer = new byte[ChunkSize];
        try
        {
            while (true)
            {
                var read = await input.ReadAsync(buffer);
                if (read == 0) break;
                Assert(buffer.AsSpan(0, read).IndexOfAnyExcept(expectedByte) < 0, message);
            }
        }
        finally { CryptographicOperations.ZeroMemory(buffer); }
    }

    private static string FormatBytesForConsole(long bytes)
    {
        var mib = bytes / (1024d * 1024);
        return $"{mib:0.##} MB";
    }

    private static async Task RunLargeLegacyUpgradeCheckAsync(NrVaultService service, string testRoot)
    {
        const long contentLength = 20L * 1024 * 1024 * 1024;
        const long targetCapacity = 25L * 1024 * 1024 * 1024;
        var drive = new DriveInfo(Path.GetPathRoot(testRoot)!);
        if (drive.AvailableFreeSpace < 80L * 1024 * 1024 * 1024)
            throw new InvalidOperationException("20 GB 旧保险箱升级实盘检查至少需要 80 GB 可用空间。");
        var legacyPath = Path.Combine(testRoot, "20GB-旧版保险箱");
        var targetPath = Path.Combine(testRoot, "20GB-升级结果");
        await CreateLargeLegacyPackedVaultAsync(legacyPath, contentLength);
        byte[] originalHash;
        await using (var input = new FileStream(legacyPath, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024, FileOptions.SequentialScan))
            originalHash = await SHA256.HashDataAsync(input);
        var inspectClock = Stopwatch.StartNew();
        var oldInfo = await service.InspectAsync(legacyPath);
        inspectClock.Stop();
        Assert(oldInfo.FormatVersion == 1 && inspectClock.Elapsed < TimeSpan.FromSeconds(10),
            "20 GB 旧保险箱没有在 10 秒内直接显示基本信息。");

        var baselineMemory = Environment.WorkingSet;
        long peakMemory = baselineMemory;
        var upgradeClock = Stopwatch.StartNew();
        using (var password = SensitivePassword.FromString(Password))
        using (var request = new UpgradeVaultRequest(
                   legacyPath, targetPath, password, fixedCapacityBytes: targetCapacity))
        {
            await service.UpgradeLegacyAsync(request, new InlineProgress(_ =>
            {
                peakMemory = Math.Max(peakMemory, Environment.WorkingSet);
            }));
        }
        upgradeClock.Stop();
        Assert(new FileInfo(targetPath).Length == targetCapacity, "20 GB 旧保险箱升级后的固定容量不正确。");
        Assert(peakMemory - baselineMemory < 512L * 1024 * 1024,
            "20 GB 旧保险箱升级期间内存增长超过 512 MB 固定上限。");
        await using (var input = new FileStream(legacyPath, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024, FileOptions.SequentialScan))
        {
            var afterHash = await SHA256.HashDataAsync(input);
            try { Assert(afterHash.AsSpan().SequenceEqual(originalHash), "20 GB 旧保险箱升级后原文件发生变化。"); }
            finally { CryptographicOperations.ZeroMemory(afterHash); }
        }
        using (var upgraded = await UnlockAsync(service, targetPath))
        {
            Assert(upgraded.TryGetEntry("20GB测试资料.bin", out var entry) && entry?.Length == contentLength,
                "20 GB 旧保险箱升级后目录或大小不正确。");
            await using var stream = upgraded.OpenReadStream("20GB测试资料.bin");
            var sample = new byte[4096];
            await stream.ReadExactlyAsync(sample);
            Assert(sample.AsSpan().IndexOfAnyExcept((byte)0) < 0, "20 GB 升级结果开头内容不正确。");
            stream.Position = contentLength - sample.Length;
            await stream.ReadExactlyAsync(sample);
            Assert(sample.AsSpan().IndexOfAnyExcept((byte)0) < 0, "20 GB 升级结果结尾内容不正确。");
            CryptographicOperations.ZeroMemory(sample);
        }
        Console.WriteLine($"20 GB 旧保险箱升级实盘检查通过：升级 {upgradeClock.Elapsed:g}，信息读取 {inspectClock.Elapsed:g}，峰值增量 {FormatBytesForConsole(peakMemory - baselineMemory)}。");
        CryptographicOperations.ZeroMemory(originalHash);
        File.Delete(targetPath);
        File.Delete(legacyPath);
    }

    private static async Task CreateLargeLegacyPackedVaultAsync(string containerPath, long contentLength)
    {
        var directory = Path.Combine(Path.GetDirectoryName(containerPath)!, $"large-legacy-{Guid.NewGuid():N}");
        Directory.CreateDirectory(Path.Combine(directory, "catalog"));
        Directory.CreateDirectory(Path.Combine(directory, "data"));
        var info = new VaultInfo(
            directory, Guid.NewGuid(), EncryptionMode.Standard, VaultSizeProtection.HideExactSize,
            DateTimeOffset.UtcNow, VaultFormat.CurrentVersion);
        ArchiveHeader? header = null;
        byte[]? dataKey = null;
        try
        {
            await VaultFormat.WriteInfoAsync(Path.Combine(directory, "vault.info"), info, CancellationToken.None);
            using var password = SensitivePassword.FromString(Password);
            var created = await ArchiveHeader.CreateAsync(
                password, ReadOnlyMemory<byte>.Empty, EncryptionMode.Standard, false,
                KdfParameters.Testing, CancellationToken.None);
            header = created.Header;
            dataKey = created.DataKey;
            await File.WriteAllBytesAsync(Path.Combine(directory, "vault.keys"), header.Bytes);
            var entry = new VaultCatalogEntry(
                Guid.NewGuid(), Guid.Empty, "20GB测试资料.bin", false, contentLength,
                DateTime.UtcNow.Ticks, checked((int)((contentLength + ChunkSize - 1) / ChunkSize)));
            await using var source = new ZeroReadStream(contentLength);
            await VaultFormat.WriteFileAsync(
                directory, info, entry, source, dataKey, [entry], null, CancellationToken.None);
            await VaultFormat.WriteCatalogAsync(directory, info, [entry], 1, dataKey, CancellationToken.None);
            VaultContainer.Pack(directory, containerPath);
        }
        finally
        {
            try { if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true); } catch { }
            if (dataKey is not null) CryptographicOperations.ZeroMemory(dataKey);
            if (header is not null)
            {
                CryptographicOperations.ZeroMemory(header.Bytes);
                CryptographicOperations.ZeroMemory(header.PayloadNoncePrefix);
                CryptographicOperations.ZeroMemory(header.HeaderHash);
            }
        }
    }

    private static async Task VerifyWritableOperationsAsync(VaultSession session)
    {
        await session.CreateDirectoryAsync("工作区");
        await using (var created = session.OpenWriteStream("工作区/编辑.txt", createNew: true))
        {
            var initial = Encoding.UTF8.GetBytes("0123456789");
            await created.WriteAsync(initial);
            await created.CommitAsync();
        }

        await using (var edited = session.OpenWriteStream("工作区/编辑.txt"))
        {
            edited.Position = 3;
            await edited.WriteAsync(Encoding.UTF8.GetBytes("XYZ"));
            edited.Position = edited.Length;
            await edited.WriteAsync(Encoding.UTF8.GetBytes("-ADD"));
            edited.SetLength(12);
            edited.SetLength(19);
            edited.Position = 10;
            await edited.WriteAsync(Encoding.UTF8.GetBytes("ABCDEFGHI"));
            await edited.CommitAsync();
        }

        await session.MoveAsync("工作区/编辑.txt", "工作区/改名.txt", replaceIfExists: false);
        await session.DeleteAsync("工作区/改名.txt");
        Assert(session.TryGetEntry("保险箱回收站/改名.txt", out _), "删除的文件没有进入保险箱回收站。");
        await session.MoveAsync("保险箱回收站/改名.txt", "工作区/恢复.txt", replaceIfExists: false);

        await using (var copySource = session.OpenReadStream("工作区/恢复.txt"))
        await using (var copyTarget = session.OpenWriteStream("工作区/副本.txt", createNew: true))
        {
            await copySource.CopyToAsync(copyTarget);
            await copyTarget.CommitAsync();
        }
        await session.DeleteAsync("工作区/副本.txt");
        await session.DeleteAsync("保险箱回收站/副本.txt");
        Assert(!session.TryGetEntry("保险箱回收站/副本.txt", out _), "从回收站再次删除后仍能找到文件。");

        await using (var abandoned = session.OpenWriteStream("工作区/未完成.txt", createNew: true))
        {
            await abandoned.WriteAsync(Encoding.UTF8.GetBytes("不应保存"));
        }
        Assert(!session.TryGetEntry("工作区/未完成.txt", out _), "未提交写入在关闭后错误出现在保险箱中。");

        await using (var replacementTarget = session.OpenWriteStream("工作区/替换检查.txt", createNew: true))
        {
            await replacementTarget.WriteAsync(Encoding.UTF8.GetBytes("这是替换前应被完整移除的较长内容"));
            await replacementTarget.CommitAsync();
        }
        await using (var replaced = session.OpenWriteStream("工作区/替换检查.txt", truncate: true))
        {
            await replaced.WriteAsync(Encoding.UTF8.GetBytes("替换后的短内容"));
            await replaced.CommitAsync();
        }
        await AssertTextAsync(session, "工作区/替换检查.txt", "替换后的短内容");

        await using (var abandonedReplacement = session.OpenWriteStream("工作区/替换检查.txt", truncate: true))
        {
            await abandonedReplacement.WriteAsync(Encoding.UTF8.GetBytes("不应覆盖原内容"));
        }
        await AssertTextAsync(session, "工作区/替换检查.txt", "替换后的短内容");

        var originalCancellationBytes = new byte[2 * ChunkSize + 17];
        var partialReplacementBytes = new byte[ChunkSize];
        Array.Fill(originalCancellationBytes, (byte)0x31);
        Array.Fill(partialReplacementBytes, (byte)0x72);
        try
        {
            await using (var original = session.OpenWriteStream("工作区/取消替换.bin", createNew: true))
            {
                await original.WriteAsync(originalCancellationBytes);
                await original.CommitAsync();
            }
            var cancellationObserved = false;
            await using (var cancelled = session.OpenWriteStream("工作区/取消替换.bin", truncate: true))
            {
                await cancelled.WriteAsync(partialReplacementBytes);
                using var cancellation = new CancellationTokenSource();
                cancellation.Cancel();
                try
                {
                    await cancelled.WriteAsync(partialReplacementBytes, cancellation.Token);
                }
                catch (OperationCanceledException) { cancellationObserved = true; }
            }
            Assert(cancellationObserved, "部分替换检查没有实际进入取消路径。");
            await AssertFileFilledAsync(
                session,
                "工作区/取消替换.bin",
                originalCancellationBytes.Length,
                0x31,
                "替换中途取消后，原文件没有保持完整不变。");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(originalCancellationBytes);
            CryptographicOperations.ZeroMemory(partialReplacementBytes);
        }
    }

    private static async Task<VaultSession> UnlockAsync(NrVaultService service, string vaultPath)
    {
        using var password = SensitivePassword.FromString(Password);
        using var request = new UnlockVaultRequest(vaultPath, password);
        return await service.UnlockAsync(request);
    }

    private static void AssertEncryptedStorageDoesNotExposePlaintext(string vaultPath, string secretText)
    {
        if (File.Exists(vaultPath))
        {
            Assert(!FileContainsSequence(vaultPath, Encoding.UTF8.GetBytes(secretText)), "单文件保险箱泄露了明文内容。");
            Assert(!FileContainsSequence(vaultPath, Encoding.UTF8.GetBytes("原始资料")), "单文件保险箱泄露了原始名称。");
            return;
        }
        var allNames = Directory.EnumerateFileSystemEntries(vaultPath, "*", SearchOption.AllDirectories)
            .Select(Path.GetFileName)
            .ToArray();
        Assert(!allNames.Any(name => name?.Contains("说明", StringComparison.Ordinal) == true ||
                                     name?.Contains("原始资料", StringComparison.Ordinal) == true),
            "保险箱真实目录泄露了原始名称。");

        foreach (var file in Directory.EnumerateFiles(vaultPath, "*", SearchOption.AllDirectories))
        {
            var stored = File.ReadAllBytes(file);
            Assert(!Encoding.UTF8.GetString(stored).Contains(secretText, StringComparison.Ordinal),
                "保险箱真实文件泄露了明文内容。");
        }
    }

    private static async Task VerifyCancellationLeavesNoPartialVaultAsync(
        NrVaultService service,
        string root,
        string sourcePath)
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await ExpectFailureAsync(async () =>
        {
            using var password = SensitivePassword.FromString(Password);
            using var request = new CreateVaultRequest(
                Path.Combine(root, "取消保险箱"), password, sourcePaths: [sourcePath],
                fixedCapacityBytes: NewVaultCapacity);
            await service.CreateAsync(request, cancellationToken: cancellation.Token);
        }, "取消创建时应停止操作。");

        Assert(!Directory.EnumerateFileSystemEntries(root, ".取消保险箱-*.part").Any(),
            "取消创建后留下了未完成的保险箱。");
    }

    private static async Task VerifyMidCreationCancellationLeavesNoPartialVaultAsync(NrVaultService service, string root)
    {
        var target = Path.Combine(root, "创建途中取消保险箱");
        using var cancellation = new CancellationTokenSource();
        using var password = SensitivePassword.FromString(Password);
        using var request = new CreateVaultRequest(
            target, password, fixedCapacityBytes: NewVaultCapacity);
        var progress = new InlineProgress(value =>
        {
            if (value.Stage == CryptoStage.Encrypting && value.CompletedBytes >= 8L * 1024 * 1024)
                cancellation.Cancel();
        });
        await ExpectFailureAsync(
            () => service.CreateAsync(request, progress, cancellation.Token),
            "创建途中取消后应停止操作。");
        Assert(!File.Exists(target), "创建途中取消后留下了目标保险箱。");
        Assert(!Directory.EnumerateFileSystemEntries(root, ".创建途中取消保险箱-*.part").Any(),
            "创建途中取消后留下了未完成文件。");
    }

    private static async Task VerifyDualWorkspaceAsync(
        NrVaultService service,
        string root,
        string ordinaryVaultPath)
    {
        const string dailyPasswordText = "Daily space check 8.0.1!";
        const string hiddenPasswordText = "Hidden space check 9.7.3#";
        const string dailyText = "这是日常空间里的公开测试资料。";
        const string hiddenText = "这是只能由秘密密码打开的隐蔽测试资料。";
        var dailySource = Path.Combine(root, "日常资料.txt");
        var hiddenSource = Path.Combine(root, "隐蔽资料.txt");
        await File.WriteAllTextAsync(dailySource, dailyText, Encoding.UTF8);
        await File.WriteAllTextAsync(hiddenSource, hiddenText, Encoding.UTF8);

        var similarTarget = Path.Combine(root, "相似密码不应创建");
        await ExpectFailureAsync(async () =>
        {
            using var dailyPassword = SensitivePassword.FromString("Similar password 8.0.1!");
            using var hiddenPassword = SensitivePassword.FromString("Similar password 8.0.1!1");
            using var request = new CreateDualVaultRequest(
                similarTarget, dailyPassword, hiddenPassword, fixedCapacityBytes: NewVaultCapacity);
            await service.CreateDualAsync(request);
        }, "日常密码与秘密密码过于相似时不应创建双层保险箱。");
        Assert(!File.Exists(similarTarget), "相似密码校验失败后留下了保险箱文件。");

        var dualPath = Path.Combine(root, "双层保险箱");
        using (var dailyPassword = SensitivePassword.FromString(dailyPasswordText))
        using (var hiddenPassword = SensitivePassword.FromString(hiddenPasswordText))
        using (var request = new CreateDualVaultRequest(
                   dualPath,
                   dailyPassword,
                   hiddenPassword,
                   dailySourcePaths: [dailySource],
                   hiddenSourcePaths: [hiddenSource],
                   fixedCapacityBytes: NewVaultCapacity,
                   dailyCapacityBytes: 8L * ChunkSize,
                   hiddenCapacityBytes: 8L * ChunkSize))
        {
            var created = await service.CreateDualAsync(request);
            Assert(created.DailyEntryCount == 1 && created.HiddenEntryCount == 1,
                "双层保险箱没有分别写入两套初始资料。");
        }

        var ordinaryInfo = await service.InspectAsync(ordinaryVaultPath);
        var publicInfo = await service.InspectAsync(dualPath);
        Assert(publicInfo.FormatVersion == ordinaryInfo.FormatVersion &&
               publicInfo.CapacityBytes == ordinaryInfo.CapacityBytes &&
               publicInfo.Mode == ordinaryInfo.Mode,
            "普通保险箱与双层保险箱暴露了不同的公开格式特征。");
        var ordinaryHeader = await ReadPrefixAsync(ordinaryVaultPath, WorkspaceVaultContainer.HeaderSize);
        var dualHeader = await ReadPrefixAsync(dualPath, WorkspaceVaultContainer.HeaderSize);
        try
        {
            Assert(ordinaryHeader.AsSpan(0, 16).SequenceEqual(dualHeader.AsSpan(0, 16)) &&
                   ordinaryHeader.AsSpan(32, 2).SequenceEqual(dualHeader.AsSpan(32, 2)) &&
                   ordinaryHeader.AsSpan(56, 72).SequenceEqual(dualHeader.AsSpan(56, 72)),
                "普通保险箱与双层保险箱的公开结构字段不一致。");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ordinaryHeader);
            CryptographicOperations.ZeroMemory(dualHeader);
        }
        Assert(!FileContainsSequence(dualPath, Encoding.UTF8.GetBytes(dailyText)) &&
               !FileContainsSequence(dualPath, Encoding.UTF8.GetBytes(hiddenText)) &&
               !FileContainsSequence(dualPath, Encoding.UTF8.GetBytes("日常资料.txt")) &&
               !FileContainsSequence(dualPath, Encoding.UTF8.GetBytes("隐蔽资料.txt")) &&
               !FileContainsSequence(dualPath, Encoding.UTF8.GetBytes(hiddenPasswordText)),
            "双层保险箱泄露了空间资料、名称或秘密密码的明文。");

        string? wrongMessage = null;
        try
        {
            using var wrongPassword = SensitivePassword.FromString("Neither workspace password 4.2.6!");
            using var request = new UnlockVaultRequest(dualPath, wrongPassword);
            using var ignored = await service.UnlockAsync(request);
        }
        catch (NingRanException exception) { wrongMessage = exception.Message; }
        Assert(wrongMessage == "无法解锁保险箱。密码条件不正确，或保险箱已经损坏。",
            "错误密码没有返回统一且不暴露空间差异的提示。");

        await VerifyWorkspaceUnlockTimingAsync(service, dualPath, dailyPasswordText, hiddenPasswordText);

        int dailySlot;
        using (var daily = await UnlockWithPasswordAsync(service, dualPath, dailyPasswordText))
        {
            Assert(daily.TryGetEntry("日常资料.txt", out var entry) && entry is not null,
                "日常密码没有打开日常资料。");
            Assert(!daily.TryGetEntry("隐蔽资料.txt", out _), "日常密码看到了另一套空间的目录。");
            Assert(daily.WorkspaceCapacityBytes == 8L * ChunkSize && daily.History.Count == 0,
                "日常空间容量或外部历史记录不符合独立空间要求。");
            await AssertTextAsync(daily, "日常资料.txt", dailyText);
            await daily.CreateDirectoryAsync("日常新增");
            await using (var output = daily.OpenWriteStream("日常新增/记录.txt", createNew: true))
            {
                await output.WriteAsync(Encoding.UTF8.GetBytes("日常修改"));
                await output.CommitAsync();
            }
            await AssertWorkspaceCannotBorrowCapacityAsync(daily, "日常越界.bin");
            dailySlot = daily.Catalog.First(entry => !entry.IsDirectory).BlockSlots![0];
            await daily.VerifyAsync();
        }

        int hiddenSlot;
        using (var hidden = await UnlockWithPasswordAsync(service, dualPath, hiddenPasswordText))
        {
            Assert(hidden.TryGetEntry("隐蔽资料.txt", out var entry) && entry is not null,
                "秘密密码没有打开隐蔽资料。");
            Assert(!hidden.TryGetEntry("日常资料.txt", out _) && !hidden.TryGetEntry("日常新增/记录.txt", out _),
                "秘密密码看到了日常空间的目录或修改。");
            Assert(hidden.WorkspaceCapacityBytes == 8L * ChunkSize && hidden.History.Count == 0,
                "隐蔽空间容量或外部历史记录不符合独立空间要求。");
            await AssertTextAsync(hidden, "隐蔽资料.txt", hiddenText);
            await using (var output = hidden.OpenWriteStream("秘密新增.txt", createNew: true))
            {
                await output.WriteAsync(Encoding.UTF8.GetBytes("秘密修改"));
                await output.CommitAsync();
            }
            await AssertWorkspaceCannotBorrowCapacityAsync(hidden, "隐蔽越界.bin");
            hiddenSlot = hidden.Catalog.First(entry => entry.Name == "隐蔽资料.txt").BlockSlots![0];
            await hidden.VerifyAsync();
        }

        using (var daily = await UnlockWithPasswordAsync(service, dualPath, dailyPasswordText))
        {
            Assert(daily.TryGetEntry("日常新增/记录.txt", out _) && !daily.TryGetEntry("秘密新增.txt", out _),
                "隐蔽空间的修改影响了日常空间目录。");
        }
        Assert(new FileInfo(dualPath).Length == NewVaultCapacity, "两套空间修改后保险箱固定总大小发生变化。");
        await VerifyOneWorkspaceCatalogDamageDoesNotExposeOtherAsync(
            service, dualPath, dailyPasswordText, hiddenPasswordText);
        await VerifyCrossWorkspaceBlockSwapIsRejectedAsync(service, dualPath, dailySlot, hiddenSlot, hiddenPasswordText);
    }

    private static async Task VerifyWorkspaceUnlockTimingAsync(
        NrVaultService service,
        string vaultPath,
        string dailyPassword,
        string hiddenPassword)
    {
        var daily = new List<double>();
        var hidden = new List<double>();
        for (var iteration = 0; iteration < 8; iteration++)
        {
            if ((iteration & 1) == 0)
            {
                daily.Add(await MeasureUnlockMillisecondsAsync(service, vaultPath, dailyPassword));
                hidden.Add(await MeasureUnlockMillisecondsAsync(service, vaultPath, hiddenPassword));
            }
            else
            {
                hidden.Add(await MeasureUnlockMillisecondsAsync(service, vaultPath, hiddenPassword));
                daily.Add(await MeasureUnlockMillisecondsAsync(service, vaultPath, dailyPassword));
            }
        }
        daily.Sort();
        hidden.Sort();
        var dailyMedian = (daily[3] + daily[4]) / 2;
        var hiddenMedian = (hidden[3] + hidden[4]) / 2;
        var difference = Math.Abs(dailyMedian - hiddenMedian);
        var ratio = Math.Max(dailyMedian, hiddenMedian) / Math.Max(0.1, Math.Min(dailyMedian, hiddenMedian));
        Assert(difference < 50 || ratio < 1.75,
            $"两套正确密码的解锁耗时差异过大：{dailyMedian:0.##} ms 与 {hiddenMedian:0.##} ms。");
        Console.WriteLine($"双空间解锁耗时中位数检查通过：{dailyMedian:0.##} ms / {hiddenMedian:0.##} ms。");
    }

    private static async Task<double> MeasureUnlockMillisecondsAsync(
        NrVaultService service,
        string vaultPath,
        string password)
    {
        var clock = Stopwatch.StartNew();
        using var session = await UnlockWithPasswordAsync(service, vaultPath, password);
        clock.Stop();
        return clock.Elapsed.TotalMilliseconds;
    }

    private static async Task VerifyOneWorkspaceCatalogDamageDoesNotExposeOtherAsync(
        NrVaultService service,
        string vaultPath,
        string dailyPassword,
        string hiddenPassword)
    {
        var catalogBase = WorkspaceVaultContainer.HeaderSize +
                          2L * WorkspaceVaultContainer.KeyAreaSize;
        var offsets = new[]
        {
            catalogBase + 2L * WorkspaceVaultContainer.CatalogSlotSize,
            catalogBase + 3L * WorkspaceVaultContainer.CatalogSlotSize,
        };
        var original = new byte[offsets.Length];
        try
        {
            await using (var file = new FileStream(vaultPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None,
                             4096, FileOptions.Asynchronous | FileOptions.RandomAccess | FileOptions.WriteThrough))
            {
                for (var index = 0; index < offsets.Length; index++)
                {
                    file.Position = offsets[index];
                    var one = new byte[1];
                    await file.ReadExactlyAsync(one);
                    original[index] = one[0];
                    one[0] ^= 0x5A;
                    file.Position = offsets[index];
                    await file.WriteAsync(one);
                }
                file.Flush(flushToDisk: true);
            }

            using (var daily = await UnlockWithPasswordAsync(service, vaultPath, dailyPassword))
            {
                Assert(daily.TryGetEntry("日常资料.txt", out _) && !daily.TryGetEntry("隐蔽资料.txt", out _),
                    "另一空间目录损坏后，日常空间未能保持独立或错误显示了另一空间内容。");
            }

            string? message = null;
            try
            {
                using var ignored = await UnlockWithPasswordAsync(service, vaultPath, hiddenPassword);
            }
            catch (NingRanException exception) { message = exception.Message; }
            Assert(message == "无法解锁保险箱。密码条件不正确，或保险箱已经损坏。",
                "当前空间目录损坏后没有使用中性解锁错误，或错误显示成另一空间内容。");
        }
        finally
        {
            await using var file = new FileStream(vaultPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None,
                4096, FileOptions.Asynchronous | FileOptions.RandomAccess | FileOptions.WriteThrough);
            for (var index = 0; index < offsets.Length; index++)
            {
                file.Position = offsets[index];
                await file.WriteAsync(original.AsMemory(index, 1));
            }
            file.Flush(flushToDisk: true);
        }
    }

    private static async Task AssertWorkspaceCannotBorrowCapacityAsync(VaultSession session, string path)
    {
        var failed = false;
        var output = session.OpenWriteStream(path, createNew: true);
        try
        {
            output.SetLength(session.WorkspaceCapacityBytes);
            await output.CommitAsync();
        }
        catch (NingRanException)
        {
            failed = true;
            output.Abandon();
        }
        finally { await output.DisposeAsync(); }
        Assert(failed, "当前空间容量用尽后错误借用了另一套空间或填充区。");
    }

    private static async Task VerifyCrossWorkspaceBlockSwapIsRejectedAsync(
        NrVaultService service,
        string vaultPath,
        int dailySlot,
        int hiddenSlot,
        string hiddenPassword)
    {
        const long dataOffset = WorkspaceVaultContainer.HeaderSize +
                                2L * WorkspaceVaultContainer.KeyAreaSize +
                                4L * WorkspaceVaultContainer.CatalogSlotSize;
        var dailyBlock = new byte[WorkspaceVaultContainer.DataSlotSize];
        var originalHiddenBlock = new byte[WorkspaceVaultContainer.DataSlotSize];
        try
        {
            await using (var file = new FileStream(vaultPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None,
                             ChunkSize, FileOptions.Asynchronous | FileOptions.RandomAccess | FileOptions.WriteThrough))
            {
                file.Position = dataOffset + (long)dailySlot * WorkspaceVaultContainer.DataSlotSize;
                await file.ReadExactlyAsync(dailyBlock);
                file.Position = dataOffset + (long)hiddenSlot * WorkspaceVaultContainer.DataSlotSize;
                await file.ReadExactlyAsync(originalHiddenBlock);
                file.Position = dataOffset + (long)hiddenSlot * WorkspaceVaultContainer.DataSlotSize;
                await file.WriteAsync(dailyBlock);
                file.Flush(flushToDisk: true);
            }
            using var hidden = await UnlockWithPasswordAsync(service, vaultPath, hiddenPassword);
            await ExpectFailureAsync(() => hidden.VerifyAsync(), "跨空间替换数据块后完整检查应失败。");
        }
        finally
        {
            await using var file = new FileStream(vaultPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None,
                ChunkSize, FileOptions.Asynchronous | FileOptions.RandomAccess | FileOptions.WriteThrough);
            file.Position = dataOffset + (long)hiddenSlot * WorkspaceVaultContainer.DataSlotSize;
            await file.WriteAsync(originalHiddenBlock);
            file.Flush(flushToDisk: true);
            CryptographicOperations.ZeroMemory(dailyBlock);
            CryptographicOperations.ZeroMemory(originalHiddenBlock);
        }
        using var restored = await UnlockWithPasswordAsync(service, vaultPath, hiddenPassword);
        await restored.VerifyAsync();
    }

    private static async Task<VaultSession> UnlockWithPasswordAsync(
        NrVaultService service,
        string vaultPath,
        string passwordText)
    {
        using var password = SensitivePassword.FromString(passwordText);
        using var request = new UnlockVaultRequest(vaultPath, password);
        return await service.UnlockAsync(request);
    }

    private static async Task AssertTextAsync(VaultSession session, string path, string expected)
    {
        await using var stream = session.OpenReadStream(path);
        using var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: false);
        Assert(await reader.ReadToEndAsync() == expected, $"保险箱中的“{path}”内容不正确。");
    }

    private static async Task<byte[]> ReadPrefixAsync(string path, int length)
    {
        var result = new byte[length];
        await using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
            length, FileOptions.Asynchronous | FileOptions.SequentialScan);
        await input.ReadExactlyAsync(result);
        return result;
    }

    private static async Task VerifyTamperingIsDetectedAsync(NrVaultService service, string vaultPath)
    {
        if (File.Exists(vaultPath))
        {
            const long dataOffset = 4096L + 2L * 256 * 1024 + 4L * 16 * 1024 * 1024;
            await using (var output = new FileStream(vaultPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
                output.Position = dataOffset + 128;
                var original = output.ReadByte();
                output.Position = dataOffset + 128;
                output.WriteByte((byte)(original ^ 0x01));
                await output.FlushAsync();
            }
            using var reopenedFixed = await UnlockAsync(service, vaultPath);
            await ExpectFailureAsync(() => reopenedFixed.VerifyAsync(), "新版保险箱数据被改动后，完整检查应失败。");
            return;
        }
        var encryptedChunk = Directory.EnumerateFiles(vaultPath, "*.nrc", SearchOption.AllDirectories).First();
        await using (var output = new FileStream(encryptedChunk, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            output.Position = output.Length - 1;
            var original = output.ReadByte();
            output.Position = output.Length - 1;
            output.WriteByte((byte)(original ^ 0x01));
            await output.FlushAsync();
        }

        using var reopened = await UnlockAsync(service, vaultPath);
        await ExpectFailureAsync(() => reopened.VerifyAsync(), "加密内容被改动后，完整检查应失败。");
    }

    private static async Task VerifyFutureFormatIsNotModifiedAsync(NrVaultService service, string vaultPath)
    {
        var infoPath = File.Exists(vaultPath) ? vaultPath : Path.Combine(vaultPath, "vault.info");
        var original = await File.ReadAllBytesAsync(infoPath);
        var altered = original.ToArray();
        BitConverter.GetBytes(File.Exists(vaultPath) ? 4 : 2).CopyTo(altered, 8);
        await File.WriteAllBytesAsync(infoPath, altered);
        try
        {
            await ExpectFailureAsync(async () =>
            {
                using var password = SensitivePassword.FromString(Password);
                using var request = new UnlockVaultRequest(vaultPath, password);
                using var ignored = await service.UnlockAsync(request);
            }, "更高格式版本不应被当前程序打开。 ");
            Assert((await File.ReadAllBytesAsync(infoPath)).AsSpan().SequenceEqual(altered),
                "拒绝未来格式时不应修改保险箱识别信息。");
        }
        finally
        {
            await File.WriteAllBytesAsync(infoPath, original);
            CryptographicOperations.ZeroMemory(original);
            CryptographicOperations.ZeroMemory(altered);
        }
    }

    private static async Task VerifyInterruptedCatalogFallsBackAsync(NrVaultService service, string root, string vaultPath)
    {
        long latestRevision;
        using (var current = await UnlockAsync(service, vaultPath)) latestRevision = current.Revision;
        Assert(latestRevision > 1, "中断恢复检查需要至少两份目录记录。");
        var copy = Path.Combine(root, "目录中断恢复保险箱");
        File.Copy(vaultPath, copy);
        const long catalogAOffset = 4096L + 2L * 256 * 1024;
        const long catalogSlotSize = 16L * 1024 * 1024;
        var activeOffset = catalogAOffset + (latestRevision & 1) * catalogSlotSize;
        await using (var output = new FileStream(copy, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            output.Position = activeOffset + 256;
            var original = output.ReadByte();
            output.Position = activeOffset + 256;
            output.WriteByte((byte)(original ^ 0x01));
            output.Flush(flushToDisk: true);
        }
        using var recovered = await UnlockAsync(service, copy);
        Assert(recovered.Revision < latestRevision, "最新目录损坏后没有回到上一份完整目录。");
        await recovered.VerifyAsync();
    }

    private static async Task VerifyLegacyUpgradeAsync(NrVaultService service, string root)
    {
        var legacyPath = Path.Combine(root, "旧版单文件保险箱");
        var expected = RandomNumberGenerator.GetBytes(ChunkSize * 2 + 12345);
        await CreateLegacyPackedVaultAsync(legacyPath, expected);
        var originalHash = SHA256.HashData(await File.ReadAllBytesAsync(legacyPath));
        var inspected = await service.InspectAsync(legacyPath);
        Assert(inspected.FormatVersion == 1, "旧版单文件保险箱没有直接识别为格式 1。");

        var wrongTarget = Path.Combine(root, "错误密码升级目标");
        await ExpectFailureAsync(async () =>
        {
            using var wrong = SensitivePassword.FromString("Wrong legacy password 8.0.1!");
            using var request = new UpgradeVaultRequest(
                legacyPath, wrongTarget, wrong, fixedCapacityBytes: 64L * 1024 * 1024);
            await service.UpgradeLegacyAsync(request);
        }, "错误密码不应能够升级旧保险箱。");
        Assert(!File.Exists(wrongTarget), "错误密码升级后留下了目标文件。");

        var upgradedPath = Path.Combine(root, "升级后的新版保险箱");
        var progressValues = new List<CryptoProgress>();
        using (var password = SensitivePassword.FromString(Password))
        using (var request = new UpgradeVaultRequest(
                   legacyPath, upgradedPath, password, fixedCapacityBytes: 64L * 1024 * 1024))
        {
            var result = await service.UpgradeLegacyAsync(request, new InlineProgress(value => progressValues.Add(value)));
            Assert(result.SourceInfo.FormatVersion == 1 && result.UpgradedInfo.FormatVersion == 2,
                "升级结果没有保留旧格式来源并生成新版格式。");
            Assert(result.SourceInfo.VaultId == result.UpgradedInfo.VaultId,
                "升级时错误改变了保险箱内部编号。");
        }
        Assert(progressValues.Any(value => value.Stage == CryptoStage.Encrypting) &&
               progressValues.Any(value => value.Stage == CryptoStage.Verifying) &&
               progressValues[^1].Fraction == 1,
            "旧保险箱升级没有报告完整的写入、检查和完成进度。");
        Assert(new FileInfo(upgradedPath).Length == 64L * 1024 * 1024,
            "升级后的保险箱没有保持所选固定容量。");
        Assert(SHA256.HashData(await File.ReadAllBytesAsync(legacyPath)).AsSpan().SequenceEqual(originalHash),
            "升级过程修改了原保险箱。");
        using (var upgraded = await UnlockAsync(service, upgradedPath))
        {
            Assert(upgraded.TryGetEntry("旧版资料.bin", out var entry) && entry?.Length == expected.Length,
                "升级后没有找到原有文件。");
            await using var input = upgraded.OpenReadStream("旧版资料.bin");
            var actual = new byte[expected.Length];
            await input.ReadExactlyAsync(actual);
            Assert(actual.AsSpan().SequenceEqual(expected), "升级后的文件内容与旧保险箱不一致。");
            await upgraded.VerifyAsync();
            CryptographicOperations.ZeroMemory(actual);
        }

        var cancelledTarget = Path.Combine(root, "取消升级目标");
        using (var cancellation = new CancellationTokenSource())
        using (var password = SensitivePassword.FromString(Password))
        using (var request = new UpgradeVaultRequest(
                   legacyPath, cancelledTarget, password, fixedCapacityBytes: 64L * 1024 * 1024))
        {
            var cancellingProgress = new InlineProgress(value =>
            {
                if (value.Stage == CryptoStage.Encrypting && value.CompletedBytes >= 8L * 1024 * 1024)
                    cancellation.Cancel();
            });
            await ExpectFailureAsync(
                () => service.UpgradeLegacyAsync(request, cancellingProgress, cancellation.Token),
                "升级中取消后应停止操作。");
        }
        Assert(!File.Exists(cancelledTarget), "取消升级后留下了目标保险箱。");
        Assert(!Directory.EnumerateFileSystemEntries(root, ".取消升级目标-*.upgrade.part").Any(),
            "取消升级后留下了未完成文件。");
        Assert(SHA256.HashData(await File.ReadAllBytesAsync(legacyPath)).AsSpan().SequenceEqual(originalHash),
            "取消升级后原保险箱发生了变化。");

        var tamperedLegacy = Path.Combine(root, "被改动的旧版保险箱");
        File.Copy(legacyPath, tamperedLegacy);
        using (var archive = System.IO.Compression.ZipFile.Open(tamperedLegacy, System.IO.Compression.ZipArchiveMode.Update))
        {
            var encrypted = archive.Entries.First(entry => entry.FullName.EndsWith(".nrc", StringComparison.Ordinal));
            await using var stream = encrypted.Open();
            stream.Position = stream.Length - 1;
            var original = stream.ReadByte();
            stream.Position = stream.Length - 1;
            stream.WriteByte((byte)(original ^ 0x01));
        }
        var tamperedTarget = Path.Combine(root, "损坏旧版升级目标");
        await ExpectFailureAsync(async () =>
        {
            using var password = SensitivePassword.FromString(Password);
            using var request = new UpgradeVaultRequest(
                tamperedLegacy, tamperedTarget, password, fixedCapacityBytes: 64L * 1024 * 1024);
            await service.UpgradeLegacyAsync(request);
        }, "旧保险箱加密分段被改动后，升级必须失败。");
        Assert(!File.Exists(tamperedTarget), "损坏旧保险箱升级失败后留下了目标文件。");

        var upgradeTempRoot = Path.Combine(Path.GetTempPath(), "NingRanVaultUpgrade");
        Assert(!Directory.Exists(upgradeTempRoot) || !Directory.EnumerateDirectories(upgradeTempRoot).Any(),
            "升级结束后仍留有加密分段临时目录。");
        CryptographicOperations.ZeroMemory(expected);
        CryptographicOperations.ZeroMemory(originalHash);
    }

    private static async Task CreateLegacyPackedVaultAsync(string containerPath, byte[] content)
    {
        var directory = Path.Combine(Path.GetDirectoryName(containerPath)!, $"legacy-{Guid.NewGuid():N}");
        Directory.CreateDirectory(Path.Combine(directory, "catalog"));
        Directory.CreateDirectory(Path.Combine(directory, "data"));
        var info = new VaultInfo(
            directory,
            Guid.NewGuid(),
            EncryptionMode.Standard,
            VaultSizeProtection.HideExactSize,
            DateTimeOffset.UtcNow,
            VaultFormat.CurrentVersion);
        ArchiveHeader? header = null;
        byte[]? dataKey = null;
        try
        {
            await VaultFormat.WriteInfoAsync(Path.Combine(directory, "vault.info"), info, CancellationToken.None);
            using var password = SensitivePassword.FromString(Password);
            var created = await ArchiveHeader.CreateAsync(
                password,
                ReadOnlyMemory<byte>.Empty,
                EncryptionMode.Standard,
                hideExactSize: false,
                KdfParameters.Testing,
                CancellationToken.None);
            header = created.Header;
            dataKey = created.DataKey;
            await File.WriteAllBytesAsync(Path.Combine(directory, "vault.keys"), header.Bytes);
            var entry = new VaultCatalogEntry(
                Guid.NewGuid(),
                Guid.Empty,
                "旧版资料.bin",
                false,
                content.Length,
                DateTime.UtcNow.Ticks,
                checked((content.Length + ChunkSize - 1) / ChunkSize));
            await using var source = new MemoryStream(content, writable: false);
            await VaultFormat.WriteFileAsync(
                directory, info, entry, source, dataKey, [entry], null, CancellationToken.None);
            await VaultFormat.WriteCatalogAsync(directory, info, [entry], 7, dataKey, CancellationToken.None);
            VaultContainer.Pack(directory, containerPath);
        }
        finally
        {
            try { if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true); } catch { }
            if (dataKey is not null) CryptographicOperations.ZeroMemory(dataKey);
            if (header is not null)
            {
                CryptographicOperations.ZeroMemory(header.Bytes);
                CryptographicOperations.ZeroMemory(header.PayloadNoncePrefix);
                CryptographicOperations.ZeroMemory(header.HeaderHash);
            }
        }
    }

    private static bool FileContainsSequence(string path, byte[] sequence)
    {
        using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var buffer = new byte[1024 * 1024 + sequence.Length];
        var carry = 0;
        while (true)
        {
            var read = input.Read(buffer, carry, buffer.Length - carry);
            if (read == 0) return false;
            var available = carry + read;
            if (buffer.AsSpan(0, available).IndexOf(sequence) >= 0) return true;
            carry = Math.Min(sequence.Length - 1, available);
            buffer.AsSpan(available - carry, carry).CopyTo(buffer);
        }
    }

    private static async Task ExpectFailureAsync(Func<Task> action, string message)
    {
        try
        {
            await action();
        }
        catch (Exception)
        {
            return;
        }
        throw new InvalidOperationException(message);
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    private static void TryDeleteTestFolder(string root)
    {
        try
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
        catch
        {
            // 只清理由本程序创建的随机临时目录；删除失败时不影响检查结果。
        }
    }

    private sealed class InlineProgress(Action<CryptoProgress> report) : IProgress<CryptoProgress>
    {
        public void Report(CryptoProgress value) => report(value);
    }

    private sealed class SparseTailReadStream(long length, byte[] tail) : Stream
    {
        private readonly long _tailStart = checked(length - tail.Length);
        private long _position;
        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => length;
        public override long Position
        {
            get => _position;
            set => _position = value is >= 0 && value <= length
                ? value
                : throw new ArgumentOutOfRangeException(nameof(value));
        }
        public override int Read(byte[] buffer, int offset, int count) =>
            Read(buffer.AsSpan(offset, count));
        public override int Read(Span<byte> buffer)
        {
            var amount = checked((int)Math.Min(buffer.Length, length - _position));
            var destination = buffer[..amount];
            destination.Clear();
            var copyStart = Math.Max(_position, _tailStart);
            var copyEnd = Math.Min(_position + amount, length);
            if (copyEnd > copyStart)
            {
                tail.AsSpan(checked((int)(copyStart - _tailStart)), checked((int)(copyEnd - copyStart)))
                    .CopyTo(destination[checked((int)(copyStart - _position))..]);
            }
            _position += amount;
            return amount;
        }
        public override long Seek(long offset, SeekOrigin origin)
        {
            Position = origin switch
            {
                SeekOrigin.Begin => offset,
                SeekOrigin.Current => checked(_position + offset),
                SeekOrigin.End => checked(length + offset),
                _ => throw new ArgumentOutOfRangeException(nameof(origin)),
            };
            return _position;
        }
        public override void Flush() { }
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class ZeroReadStream(long length) : Stream
    {
        private long _position;
        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => length;
        public override long Position { get => _position; set => _position = value is >= 0 && value <= length ? value : throw new ArgumentOutOfRangeException(nameof(value)); }
        public override int Read(byte[] buffer, int offset, int count)
        {
            var amount = checked((int)Math.Min(count, length - _position));
            buffer.AsSpan(offset, amount).Clear();
            _position += amount;
            return amount;
        }
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var amount = checked((int)Math.Min(buffer.Length, length - _position));
            buffer.Span[..amount].Clear();
            _position += amount;
            return ValueTask.FromResult(amount);
        }
        public override long Seek(long offset, SeekOrigin origin)
        {
            Position = origin switch
            {
                SeekOrigin.Begin => offset,
                SeekOrigin.Current => checked(_position + offset),
                SeekOrigin.End => checked(length + offset),
                _ => throw new ArgumentOutOfRangeException(nameof(origin)),
            };
            return _position;
        }
        public override void Flush() { }
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
