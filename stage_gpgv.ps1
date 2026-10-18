param(
    [string]$Destination = "dist\gnupg",
    [string]$InstallerCachePath = ""
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest

# Feathered stages the official GnuPG Windows installer directly. The requested
# HTTPS origin and exact upstream SHA-256 are pinned; installer bytes are not
# trusted until the hash check below succeeds.
$Version = '2.5.22'
$InstallerName = 'gnupg-w32-2.5.22_20260831.exe'
$InstallerSha256 = '2E5841E345D56F05199351BFCF585D28C6DC2326C8F76962F1E402F41F6D10E9'
$InstallerUrl = "https://www.gnupg.org/ftp/gcrypt/binary/$InstallerName"
$ExpectedInstallerHost = 'www.gnupg.org'

$uri = [Uri]$InstallerUrl
if ($uri.Scheme -ne 'https' -or $uri.Host -ne $ExpectedInstallerHost) {
    throw "GnuPG installer source violates the pinned HTTPS host policy: $InstallerUrl"
}

function Test-WritableRoot([string]$Candidate) {
    if ([string]::IsNullOrWhiteSpace($Candidate)) { return $null }
    try {
        New-Item -ItemType Directory -Path $Candidate -Force | Out-Null
        $probe = Join-Path $Candidate ('.feathered-write-' + [Guid]::NewGuid().ToString('N'))
        [IO.File]::WriteAllText($probe, 'probe')
        Remove-Item -LiteralPath $probe -Force
        return (Get-Item -LiteralPath $Candidate).FullName
    }
    catch {
        return $null
    }
}

# Do not assume a standard user can create C:\feathered-build. Prefer writable
# per-user locations, including paths with spaces, and allow an explicit override.
$candidates = @()
if ($env:FEATHERED_BUILD_TEMP) { $candidates += $env:FEATHERED_BUILD_TEMP }
if ($env:TEMP) { $candidates += (Join-Path $env:TEMP 'FeatheredBuild') }
if ($env:LOCALAPPDATA) { $candidates += (Join-Path $env:LOCALAPPDATA 'FeatheredBuild') }
if ($env:PUBLIC) { $candidates += (Join-Path $env:PUBLIC 'FeatheredBuild') }
$volumeRoot = [IO.Path]::GetPathRoot([IO.Path]::GetTempPath())
if ($volumeRoot) { $candidates += (Join-Path $volumeRoot 'feathered-build') }

$tempRoot = $null
foreach ($candidate in $candidates) {
    $resolved = Test-WritableRoot $candidate
    if ($resolved) { $tempRoot = $resolved; break }
}
if (-not $tempRoot) {
    throw 'No writable verifier staging directory was found. Set FEATHERED_BUILD_TEMP to a writable path and retry.'
}

$temp = Join-Path $tempRoot ("gpg-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp -Force | Out-Null
try {
    $installer = Join-Path $temp $InstallerName
    if ($env:FEATHERED_GNUPG_INSTALLER) {
        $supplied = [IO.Path]::GetFullPath($env:FEATHERED_GNUPG_INSTALLER)
        if (-not (Test-Path -LiteralPath $supplied -PathType Leaf)) {
            throw "FEATHERED_GNUPG_INSTALLER does not name a file: $supplied"
        }
        Write-Host "Using caller-supplied GnuPG installer: $supplied"
        Copy-Item -LiteralPath $supplied -Destination $installer
    }
    else {
        Write-Host "Downloading pinned GnuPG $Version installer from $ExpectedInstallerHost ..."
        $curl = (Get-Command curl.exe -CommandType Application -ErrorAction Stop).Source
        $downloaded = $false
        $lastDownloadError = $null
        foreach ($attempt in 1..3) {
            try {
                # curl bounds the complete transfer; legacy Invoke-WebRequest
                # can hang while consuming a response after its request timeout.
                & $curl --fail --show-error --silent --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 --output $installer $InstallerUrl
                if ($LASTEXITCODE -ne 0) { throw "curl.exe exited with code $LASTEXITCODE" }
                $downloaded = $true
                break
            }
            catch {
                $lastDownloadError = $_
                Remove-Item -LiteralPath $installer -Force -ErrorAction SilentlyContinue
                if ($attempt -lt 3) { Start-Sleep -Seconds 2 }
            }
        }
        if (-not $downloaded) {
            throw "Could not download GnuPG installer after 3 attempts. Set FEATHERED_GNUPG_INSTALLER to a local copy of $InstallerName to build offline. Last error: $lastDownloadError"
        }
    }

    $actual = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToUpperInvariant()
    if ($actual -ne $InstallerSha256) {
        throw "GnuPG installer SHA-256 mismatch. Expected $InstallerSha256, got $actual."
    }
    Write-Host "Authenticated pinned GnuPG $Version installer SHA-256: $actual"
    if (-not [string]::IsNullOrWhiteSpace($InstallerCachePath)) {
        Copy-Item -LiteralPath $installer -Destination ([IO.Path]::GetFullPath($InstallerCachePath))
    }

    $installRoot = Join-Path $temp 'installed'
    New-Item -ItemType Directory -Path $installRoot | Out-Null
    $sevenZip = Join-Path $env:ProgramFiles '7-Zip\7z.exe'
    if (-not (Test-Path -LiteralPath $sevenZip -PathType Leaf)) {
        $sevenZip = (Get-Command 7z.exe -CommandType Application -ErrorAction Stop).Source
    }
    Write-Host "Extracting authenticated GnuPG verifier into $installRoot"
    $extractLog = Join-Path $temp 'extract.log'
    & $sevenZip x -y "-o$installRoot" $installer > $extractLog 2>&1
    if ($LASTEXITCODE -ne 0) { throw "7-Zip could not extract the authenticated installer: $(Get-Content $extractLog -Tail 12 | Out-String)" }

    $gpgv = Get-ChildItem -LiteralPath $installRoot -Filter gpgv.exe -File -Recurse | Select-Object -First 1
    if ($null -eq $gpgv) { throw 'Extracted GnuPG payload did not contain gpgv.exe.' }
    $bin = $gpgv.Directory.FullName

    if (Test-Path -LiteralPath $Destination) { Remove-Item -LiteralPath $Destination -Recurse -Force }
    New-Item -ItemType Directory -Path $Destination | Out-Null
    Copy-Item -LiteralPath $gpgv.FullName -Destination (Join-Path $Destination 'gpgv.exe')
    $dlls = @(Get-ChildItem -LiteralPath $bin -Filter '*.dll' -File)
    if ($dlls.Count -eq 0) { throw "No runtime DLLs were found beside gpgv.exe in $bin." }
    $dlls | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $Destination $_.Name)
    }

    & (Join-Path $Destination 'gpgv.exe') --version | Set-Content -LiteralPath (Join-Path $Destination 'VERIFIER-VERSION.txt') -Encoding ascii
    if ($LASTEXITCODE -ne 0) { throw 'Staged gpgv.exe could not execute with its staged DLLs.' }
    Write-Host "Staged pinned GnuPG $Version verifier into $Destination"
}
finally {
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
