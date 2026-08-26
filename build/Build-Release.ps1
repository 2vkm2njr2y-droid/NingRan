[CmdletBinding()]
param(
    [ValidateSet("win-x64")]
    [string]$RuntimeIdentifier = "win-x64",
    [string]$OutputDirectory,
    [ValidateSet("Encryption", "MediaPlayer")]
    [string]$ProductFlavor = "Encryption"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# The build-time dotnet host is itself managed.  Remove every supported
# startup/profiling/host override before invoking it, then disable diagnostics
# explicitly.  The shipped NativeAOT bootstrap repeats this before each
# elevated managed child is created.
foreach ($entry in @(Get-ChildItem Env:)) {
    $name = $entry.Name
    if ($name.StartsWith("DOTNET_", [System.StringComparison]::OrdinalIgnoreCase) -or
        $name.StartsWith("CORECLR_", [System.StringComparison]::OrdinalIgnoreCase) -or
        $name.StartsWith("COMPlus_", [System.StringComparison]::OrdinalIgnoreCase) -or
        $name.StartsWith("COR_", [System.StringComparison]::OrdinalIgnoreCase) -or
        $name.IndexOf("STARTUP_HOOK", [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or
        $name.IndexOf("PROFILER", [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        [System.Environment]::SetEnvironmentVariable($name, $null, "Process")
    }
}
$env:DOTNET_EnableDiagnostics = "0"
$env:DOTNET_EnableDiagnostics_IPC = "0"
$env:DOTNET_EnableDiagnostics_Debugger = "0"
$env:DOTNET_EnableDiagnostics_Profiler = "0"
$env:CORECLR_ENABLE_PROFILING = "0"
$env:COR_ENABLE_PROFILING = "0"

if (-not ("System.IO.Compression.ZipFile" -as [type])) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
}

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $repositoryRoot "dist"
}

$outputRoot = [System.IO.Path]::GetFullPath($OutputDirectory)
$artifactRoot = [System.IO.Path]::GetFullPath((Join-Path $repositoryRoot "artifacts\release"))
$repositoryPrefix = $repositoryRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
if (-not $artifactRoot.StartsWith($repositoryPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "The release workspace is outside the repository."
}

$setupModels = Get-Content -LiteralPath (Join-Path $repositoryRoot "src\NingRan.Setup.Core\SetupModels.cs") -Raw
$versionMatch = [regex]::Match($setupModels, 'public const string Version = "(?<version>[0-9]+\.[0-9]+\.[0-9]+)";')
if (-not $versionMatch.Success) {
    throw "Could not read the product version from SetupModels.cs."
}

$version = $versionMatch.Groups["version"].Value
$workRoot = Join-Path $artifactRoot "$ProductFlavor-$version-$RuntimeIdentifier"
$workRoot = [System.IO.Path]::GetFullPath($workRoot)
$artifactPrefix = $artifactRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
if (-not $workRoot.StartsWith($artifactPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "The release workspace is outside the artifact directory."
}
$payloadRoot = Join-Path $workRoot "payload"
$componentRoot = Join-Path $workRoot "components"
$setupVerificationRoot = Join-Path $workRoot "setup-verification"
$setupPublishRoot = Join-Path $workRoot "setup"
$payloadArchive = Join-Path $workRoot "payload.zip"

if (Test-Path -LiteralPath $workRoot) {
    $resolvedWorkRoot = [System.IO.Path]::GetFullPath($workRoot)
    if (-not $resolvedWorkRoot.StartsWith($artifactPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to clean a path outside the release workspace."
    }

    Remove-Item -LiteralPath $resolvedWorkRoot -Recurse -Force
}

New-Item -ItemType Directory -Path $payloadRoot, $componentRoot, $setupVerificationRoot, $setupPublishRoot, $outputRoot -Force | Out-Null

# Keep the deliverable directory unambiguous: a release run owns only its
# versioned installer and checksum, while older artifacts remain untouched.
if ($ProductFlavor -eq "MediaPlayer") {
    $productId = "NingRan.MediaPlayer"
    $productName = -join @([char]0x51DD, [char]0x7136, [char]0x5A92, [char]0x4F53, [char]0x64AD, [char]0x653E, [char]0x5668)
    $setupFlavorArguments = @("-p:SetupFlavor=MediaPlayer")
}
else {
    $productId = "NingRan.Encryption"
    $productName = -join @([char]0x51DD, [char]0x7136, [char]0x52A0, [char]0x5BC6)
    $setupFlavorArguments = @()
}
$installerLabel = -join @([char]0x5B89, [char]0x88C5, [char]0x7A0B, [char]0x5E8F)
$finalExecutable = Join-Path $outputRoot "$productName-$version-$installerLabel.exe"
$finalChecksum = "$finalExecutable.sha256"
foreach ($ownedOutput in @($finalExecutable, $finalChecksum)) {
    if (Test-Path -LiteralPath $ownedOutput) {
        Remove-Item -LiteralPath $ownedOutput -Force
    }
}

function Invoke-DotNet {
    param([Parameter(Mandatory)][string[]]$Arguments)

    & dotnet @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet failed: dotnet $($Arguments -join ' ')"
    }
}

function Copy-PublishTree {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination
    )

    foreach ($file in Get-ChildItem -LiteralPath $Source -File -Recurse) {
        if ($file.Extension -ieq ".pdb") {
            continue
        }

        $relativePath = Get-RelativePath -BasePath $Source -TargetPath $file.FullName
        $target = Join-Path $Destination $relativePath
        $targetDirectory = Split-Path -Parent $target
        New-Item -ItemType Directory -Path $targetDirectory -Force | Out-Null
        if (Test-Path -LiteralPath $target -PathType Leaf) {
            $sourceHash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
            $targetHash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
            if (-not [string]::Equals($sourceHash, $targetHash, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "Publish trees contain different files at the same path: $relativePath"
            }
            continue
        }
        Copy-Item -LiteralPath $file.FullName -Destination $target
    }
}

function Assert-PublishComponent {
    param(
        [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)][string]$AssemblyName
    )

    foreach ($suffix in @(".exe", ".dll", ".deps.json", ".runtimeconfig.json")) {
        $file = Join-Path $Directory "$AssemblyName$suffix"
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
            throw "Published component is incomplete: $file"
        }
    }
}

function Assert-SingleFileComponent {
    param(
        [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)][string]$ExecutableName
    )

    $expected = Join-Path $Directory $ExecutableName
    if (-not (Test-Path -LiteralPath $expected -PathType Leaf)) {
        throw "Published single-file component is missing: $expected"
    }
    $unexpected = @(Get-ChildItem -LiteralPath $Directory -File |
        Where-Object { -not [string]::Equals($_.FullName, $expected,
            [System.StringComparison]::OrdinalIgnoreCase) })
    if ($unexpected.Count -ne 0) {
        throw "Published helper is not a single-file component: $ExecutableName"
    }
}

function Get-RelativePath {
    param(
        [Parameter(Mandatory)][string]$BasePath,
        [Parameter(Mandatory)][string]$TargetPath
    )

    $baseFullPath = [System.IO.Path]::GetFullPath($BasePath).TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    $targetFullPath = [System.IO.Path]::GetFullPath($TargetPath)
    $baseUri = [Uri]::new($baseFullPath)
    $targetUri = [Uri]::new($targetFullPath)
    if (-not [string]::Equals($baseUri.Scheme, $targetUri.Scheme, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Cannot create a relative path across drives or URI schemes."
    }

    return [Uri]::UnescapeDataString($baseUri.MakeRelativeUri($targetUri).ToString()).Replace(
        [System.IO.Path]::AltDirectorySeparatorChar,
        [System.IO.Path]::DirectorySeparatorChar)
}

function Write-NativeBootstrapBundle {
    param(
        [Parameter(Mandatory)][string]$Bootstrap,
        [Parameter(Mandatory)][string]$Payload,
        [Parameter(Mandatory)][string]$Destination
    )

    Copy-Item -LiteralPath $Bootstrap -Destination $Destination -Force
    $payloadFile = Get-Item -LiteralPath $Payload
    $payloadHash = (Get-FileHash -LiteralPath $Payload -Algorithm SHA256).Hash
    $hashBytes = New-Object byte[] 32
    for ($index = 0; $index -lt $hashBytes.Length; $index++) {
        $hashBytes[$index] = [Convert]::ToByte($payloadHash.Substring($index * 2, 2), 16)
    }
    $magic = [System.Text.Encoding]::ASCII.GetBytes("NRSETUP1")
    $lengthBytes = [System.BitConverter]::GetBytes([Int64]$payloadFile.Length)
    $destinationStream = [System.IO.File]::Open(
        $Destination,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None)
    $payloadStream = $null
    try {
        [void]$destinationStream.Seek(0, [System.IO.SeekOrigin]::End)
        $payloadStream = [System.IO.File]::OpenRead($Payload)
        $payloadStream.CopyTo($destinationStream)
        $destinationStream.Write($magic, 0, $magic.Length)
        $destinationStream.Write($lengthBytes, 0, $lengthBytes.Length)
        $destinationStream.Write($hashBytes, 0, $hashBytes.Length)
        $destinationStream.Flush()
    }
    finally {
        if ($null -ne $payloadStream) { $payloadStream.Dispose() }
        $destinationStream.Dispose()
    }
}

Push-Location $repositoryRoot
try {
    Invoke-DotNet @("restore", "NingRan.sln", "--locked-mode", "-r", $RuntimeIdentifier)
    Invoke-DotNet @("restore", "src\NingRan.NativeBootstrap\NingRan.NativeBootstrap.csproj",
        "--locked-mode", "-r", $RuntimeIdentifier)

    $commonPublishArguments = @(
        "-c", "Release",
        "-r", $RuntimeIdentifier,
        "--self-contained", "true",
        "--no-restore",
        "-p:DebugSymbols=false",
        "-p:DebugType=None"
    )

    $strictMonitorPublish = Join-Path $componentRoot "strict-monitor"
    $mediaPlayerPublish = Join-Path $componentRoot "media-player"
    $nativeBootstrapPublish = Join-Path $componentRoot "native-bootstrap"
    $nativeBootstrapArguments = @(
        "publish", "src\NingRan.NativeBootstrap\NingRan.NativeBootstrap.csproj",
        "-c", "Release",
        "-r", $RuntimeIdentifier,
        "--self-contained", "true",
        "--no-restore",
        "-p:DebugSymbols=false",
        "-p:DebugType=None"
    ) + $setupFlavorArguments + @("-o", $nativeBootstrapPublish)
    Invoke-DotNet $nativeBootstrapArguments

    if ($ProductFlavor -eq "Encryption") {
        Invoke-DotNet (@("publish", "src\NingRan.StrictMonitor\NingRan.StrictMonitor.csproj") +
            $commonPublishArguments + @("-o", $strictMonitorPublish))
        Invoke-DotNet (@("publish", "src\NingRan.Windows\NingRan.Windows.csproj") +
            $commonPublishArguments + @(
                "-p:PublishSingleFile=false",
                "-p:SkipBundledHelperCopy=true",
                "-o", $payloadRoot))

        # NuGet may copy WebView2 API documentation next to a single-file helper.
        # These XML files are development documentation, not runtime dependencies.
        Get-ChildItem -LiteralPath $strictMonitorPublish, $nativeBootstrapPublish -Filter "*.xml" -File |
            Remove-Item -Force
        Get-ChildItem -LiteralPath $nativeBootstrapPublish -Filter "*.pdb" -File | Remove-Item -Force

        # The ordinary project build keeps framework-dependent helper launchers
        # beside NingRan.exe for developer runs. Replace the monitor launcher
        # with its independently published self-contained executable. The
        # independent media player deliberately does not belong in this package.
        Get-ChildItem -LiteralPath $payloadRoot -File |
            Where-Object { $_.Name -like "NingRan.StrictMonitor.*" -or
                           $_.Name -like "NingRan.MediaPlayer.*" } |
            Remove-Item -Force

        Assert-SingleFileComponent -Directory $strictMonitorPublish -ExecutableName "NingRan.StrictMonitor.exe"
        Assert-SingleFileComponent -Directory $nativeBootstrapPublish -ExecutableName "NingRan.NativeBootstrap.exe"
        Assert-PublishComponent -Directory $payloadRoot -AssemblyName "NingRan"
        Copy-PublishTree -Source $strictMonitorPublish -Destination $payloadRoot
        Copy-Item -LiteralPath (Join-Path $nativeBootstrapPublish "NingRan.NativeBootstrap.exe") `
            -Destination (Join-Path $payloadRoot "NingRan.SecurityLauncher.exe")
        $requiredPayloadFiles = @(
            "NingRan.exe",
            "NingRan.Core.dll",
            "NingRan.StrictMonitor.exe",
            "NingRan.SecurityLauncher.exe"
        )
    }
    else {
        Invoke-DotNet (@("publish", "src\NingRan.MediaPlayer\NingRan.MediaPlayer.csproj") +
            $commonPublishArguments + @("-p:PublishSingleFile=false", "-o", $mediaPlayerPublish))
        Get-ChildItem -LiteralPath $mediaPlayerPublish, $nativeBootstrapPublish -Filter "*.xml" -File |
            Remove-Item -Force
        Get-ChildItem -LiteralPath $nativeBootstrapPublish -Filter "*.pdb" -File | Remove-Item -Force

        Assert-SingleFileComponent -Directory $nativeBootstrapPublish -ExecutableName "NingRan.NativeBootstrap.exe"
        Assert-PublishComponent -Directory $mediaPlayerPublish -AssemblyName "NingRan.MediaPlayer"
        if (-not (Test-Path -LiteralPath (Join-Path $mediaPlayerPublish "libvlc\win-x64\libvlc.dll") -PathType Leaf) -or
            -not (Test-Path -LiteralPath (Join-Path $mediaPlayerPublish "libvlc\win-x64\plugins") -PathType Container)) {
            throw "The media player publish is missing its LibVLC decoder or plugins."
        }
        Copy-PublishTree -Source $mediaPlayerPublish -Destination $payloadRoot
        $requiredPayloadFiles = @(
            "NingRan.MediaPlayer.exe",
            "NingRan.MediaPlayer.dll",
            "NingRan.MediaPlayer.deps.json",
            "NingRan.MediaPlayer.runtimeconfig.json",
            "libvlc\win-x64\libvlc.dll"
        )
    }
    foreach ($requiredFile in $requiredPayloadFiles) {
        if (-not (Test-Path -LiteralPath (Join-Path $payloadRoot $requiredFile) -PathType Leaf)) {
            throw "The payload is missing $requiredFile."
        }
    }

    Get-ChildItem -LiteralPath $payloadRoot -Filter "*.pdb" -File -Recurse | Remove-Item -Force

    $manifestFiles = @(
        Get-ChildItem -LiteralPath $payloadRoot -File -Recurse |
            Where-Object { -not [string]::Equals($_.FullName,
                (Join-Path $payloadRoot "payload-manifest.json"),
                [System.StringComparison]::OrdinalIgnoreCase) } |
            Sort-Object FullName |
            ForEach-Object {
                [ordered]@{
                    Path = (Get-RelativePath -BasePath $payloadRoot -TargetPath $_.FullName).Replace('\', '/')
                    Size = $_.Length
                    Sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
                }
            }
    )
    $manifest = [ordered]@{
        ProductId = $productId
        Version = $version
        Files = $manifestFiles
    }
    $manifestJson = $manifest | ConvertTo-Json -Depth 5
    [System.IO.File]::WriteAllText(
        (Join-Path $payloadRoot "payload-manifest.json"),
        $manifestJson,
        [System.Text.UTF8Encoding]::new($false))

    [System.IO.Compression.ZipFile]::CreateFromDirectory(
        $payloadRoot,
        $payloadArchive,
        [System.IO.Compression.CompressionLevel]::Optimal,
        $false)

    # The installer EXE manifest requests elevation. Run the same installer DLL
    # through the ordinary dotnet host to verify its embedded payload without UAC.
    Invoke-DotNet (@(
        "publish", "src\NingRan.Setup\NingRan.Setup.csproj",
        "-c", "Release",
        "-r", $RuntimeIdentifier,
        "--self-contained", "false",
        "--no-restore",
        "-p:PublishSingleFile=false",
        "-p:DebugSymbols=false",
        "-p:DebugType=None"
    ) + $setupFlavorArguments + @(
        "-p:InstallerPayload=$payloadArchive",
        "-o", $setupVerificationRoot
    ))
    $verificationAssembly = Join-Path $setupVerificationRoot "NingRanSetup.dll"
    & dotnet $verificationAssembly --verify-payload
    if ($LASTEXITCODE -ne 0) {
        throw "Embedded payload verification failed with exit code $LASTEXITCODE."
    }

    $builtSetupAssembly = Join-Path $repositoryRoot "src\NingRan.Setup\bin\Release\net10.0-windows\$RuntimeIdentifier\NingRanSetup.dll"
    if (-not (Test-Path -LiteralPath $builtSetupAssembly -PathType Leaf) -or
        -not [string]::Equals(
            (Get-FileHash -LiteralPath $verificationAssembly -Algorithm SHA256).Hash,
            (Get-FileHash -LiteralPath $builtSetupAssembly -Algorithm SHA256).Hash,
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "The verified installer assembly is not the build output selected for bundling."
    }

    $setupArguments = @(
        "publish", "src\NingRan.Setup\NingRan.Setup.csproj",
        "-c", "Release",
        "-r", $RuntimeIdentifier,
        "--self-contained", "true",
        "--no-restore",
        # The verification publish above intentionally creates a framework-
        # dependent build. Do not reuse that apphost when creating the shipped
        # installer: publish must rebuild the apphost as self-contained.
        "-p:DebugSymbols=false",
        "-p:DebugType=None",
        "-p:SelfContained=true",
        "-p:PublishSelfContained=true"
    ) + $setupFlavorArguments + @(
        "-p:InstallerPayload=$payloadArchive",
        "-o", $setupPublishRoot
    )
    Invoke-DotNet $setupArguments

    $setupExecutable = Join-Path $setupPublishRoot "NingRanSetup.exe"
    if (-not (Test-Path -LiteralPath $setupExecutable -PathType Leaf)) {
        throw "The installer executable was not generated."
    }
    $unexpectedSetupFiles = @(Get-ChildItem -LiteralPath $setupPublishRoot -File |
        Where-Object { -not [string]::Equals($_.FullName, $setupExecutable,
            [System.StringComparison]::OrdinalIgnoreCase) })
    if ($unexpectedSetupFiles.Count -ne 0) {
        throw "The single-file installer publish produced unexpected sidecar files."
    }
    $setupVersion = (Get-Item -LiteralPath $setupExecutable).VersionInfo.FileVersion
    if (-not $setupVersion.StartsWith("$version", [System.StringComparison]::Ordinal)) {
        throw "The installer file version does not match $version."
    }

$nativeBootstrapExecutable = Join-Path $nativeBootstrapPublish "NingRan.NativeBootstrap.exe"
    Write-NativeBootstrapBundle -Bootstrap $nativeBootstrapExecutable -Payload $setupExecutable `
        -Destination $finalExecutable

    $originalStartupHooks = [System.Environment]::GetEnvironmentVariable("DOTNET_STARTUP_HOOKS", "Process")
    try {
        $env:DOTNET_STARTUP_HOOKS = "C:\NingRan-Malicious-StartupHook-Should-Not-Load.dll"
        $sanitizationTest = Start-Process -FilePath $nativeBootstrapExecutable `
            -ArgumentList "--self-test-sanitize" -Wait -PassThru -WindowStyle Hidden
        if ($sanitizationTest.ExitCode -ne 0) {
            throw "The native bootstrap did not sanitize a malicious .NET startup-hook environment."
        }
    }
    finally {
        [System.Environment]::SetEnvironmentVariable("DOTNET_STARTUP_HOOKS", $originalStartupHooks, "Process")
    }

    $overlayTest = Start-Process -FilePath $finalExecutable -ArgumentList "--self-test-overlay" `
        -Wait -PassThru -WindowStyle Hidden
    if ($overlayTest.ExitCode -ne 0) {
        throw "The final native installer wrapper failed its embedded-payload integrity test."
    }

    $hash = (Get-FileHash -LiteralPath $finalExecutable -Algorithm SHA256).Hash
    [System.IO.File]::WriteAllText(
        $finalChecksum,
        "$hash  $([System.IO.Path]::GetFileName($finalExecutable))`r`n",
        [System.Text.UTF8Encoding]::new($false))

    Write-Host "Installer: $finalExecutable"
    Write-Host "SHA-256: $hash"
}
finally {
    Pop-Location
}
