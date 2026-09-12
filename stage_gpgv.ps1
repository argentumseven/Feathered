param(
    [string]$Destination = "dist\gnupg"
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Feathered stages the official GnuPG Windows installer directly. The requested
# HTTPS origin and exact upstream SHA-256 are pinned; installer bytes are not
# trusted until the hash check below succeeds.
$Version = '2.5.21'
$InstallerName = 'gnupg-w32-2.5.21_20260702.exe'
$InstallerSha256 = '6246C925A73167253444AFC24A0DEB83A3F43B7D636AF84D6AAF48A98A62F024'
$InstallerUrl = "https://www.gnupg.org/ftp/gcrypt/binary/$InstallerName"
$ExpectedInstallerHost = 'www.gnupg.org'

$uri = [Uri]$InstallerUrl
if ($uri.Scheme -ne 'https' -or $uri.Host -ne $ExpectedInstallerHost) {
    throw "GnuPG installer source violates the pinned HTTPS host policy: $InstallerUrl"
}

function Test-WritableSpaceFreeRoot([string]$Candidate) {
    if ([string]::IsNullOrWhiteSpace($Candidate) -or $Candidate -match '\s') { return $null }
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

# NSIS /D= must be unquoted and last, so its destination may not contain spaces.
# Do not assume a standard user can create C:\feathered-build. Prefer writable
# per-user/public locations and allow an explicit override for unusual systems.
$candidates = @()
if ($env:FEATHERED_BUILD_TEMP) { $candidates += $env:FEATHERED_BUILD_TEMP }
if ($env:TEMP) { $candidates += (Join-Path $env:TEMP 'FeatheredBuild') }
if ($env:LOCALAPPDATA) { $candidates += (Join-Path $env:LOCALAPPDATA 'FeatheredBuild') }
if ($env:PUBLIC) { $candidates += (Join-Path $env:PUBLIC 'FeatheredBuild') }
$volumeRoot = [IO.Path]::GetPathRoot([IO.Path]::GetTempPath())
if ($volumeRoot) { $candidates += (Join-Path $volumeRoot 'feathered-build') }

$tempRoot = $null
foreach ($candidate in $candidates) {
    $resolved = Test-WritableSpaceFreeRoot $candidate
    if ($resolved) { $tempRoot = $resolved; break }
}
if (-not $tempRoot) {
    throw 'No writable space-free verifier staging directory was found. Set FEATHERED_BUILD_TEMP to a writable path containing no spaces and retry.'
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
        $downloaded = $false
        $lastDownloadError = $null
        foreach ($attempt in 1..3) {
            try {
                Invoke-WebRequest -Uri $InstallerUrl -OutFile $installer -UseBasicParsing -MaximumRedirection 3
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

    $installRoot = Join-Path $temp 'installed'
    New-Item -ItemType Directory -Path $installRoot | Out-Null
    # /D= must remain the final NSIS argument and must not be quoted.
    $proc = Start-Process -FilePath $installer -ArgumentList @('/S', "/D=$installRoot") -Wait -PassThru
    if ($proc.ExitCode -ne 0) { throw "Pinned GnuPG installer exited with code $($proc.ExitCode)." }

    $gpgv = Get-ChildItem -LiteralPath $installRoot -Filter gpgv.exe -File -Recurse | Select-Object -First 1
    if ($null -eq $gpgv) { throw 'Installed GnuPG payload did not contain gpgv.exe.' }
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
