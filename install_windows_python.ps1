$ErrorActionPreference = 'Stop'

$Version = '3.13.14'
$ExpectedSha256 = 'c54d9b9bbb8a36e6489363ddd01139707fd781d72f1f9e90c7ec65d0061368e0'
$InstallerUrl = "https://www.python.org/ftp/python/$Version/python-$Version-amd64.exe"

if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
    throw 'RUNNER_TEMP is required; this bootstrap is intended for GitHub Actions.'
}
if ([string]::IsNullOrWhiteSpace($env:GITHUB_ENV) -or
    [string]::IsNullOrWhiteSpace($env:GITHUB_PATH)) {
    throw 'GITHUB_ENV/GITHUB_PATH are required; this bootstrap is intended for GitHub Actions.'
}

$Installer = Join-Path $env:RUNNER_TEMP "python-$Version-amd64.exe"
$Target = Join-Path $env:RUNNER_TEMP "feathered-python-$Version"

Write-Host "Downloading authenticated CPython $Version from python.org..."
Invoke-WebRequest -Uri $InstallerUrl -OutFile $Installer

$ActualSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $Installer).Hash.ToLowerInvariant()
if ($ActualSha256 -ne $ExpectedSha256) {
    throw "python.org installer SHA-256 mismatch. Expected $ExpectedSha256, got $ActualSha256"
}

if (Test-Path -LiteralPath $Target) {
    Remove-Item -LiteralPath $Target -Recurse -Force
}

$Arguments = @(
    '/quiet',
    'InstallAllUsers=0',
    "TargetDir=$Target",
    'Include_launcher=0',
    'Include_test=0',
    'Include_tcltk=1',
    'Include_pip=1',
    'AssociateFiles=0',
    'PrependPath=0',
    'Shortcuts=0'
)

$Process = Start-Process -FilePath $Installer -ArgumentList $Arguments -Wait -PassThru
if ($Process.ExitCode -ne 0) {
    throw "python.org installer failed with exit code $($Process.ExitCode)"
}

$Python = Join-Path $Target 'python.exe'
if (-not (Test-Path -LiteralPath $Python)) {
    throw "Installed python.exe was not found at $Python"
}

$InitTcl = Get-ChildItem -LiteralPath (Join-Path $Target 'tcl') -Filter init.tcl -Recurse -File |
    Select-Object -First 1
$TkTcl = Get-ChildItem -LiteralPath (Join-Path $Target 'tcl') -Filter tk.tcl -Recurse -File |
    Select-Object -First 1

if (-not $InitTcl) {
    throw "The full python.org installation did not contain Tcl init.tcl under $Target\tcl"
}
if (-not $TkTcl) {
    throw "The full python.org installation did not contain Tk tk.tcl under $Target\tcl"
}

Write-Host "Validating interpreter and Tcl/Tk before running Feathered tests..."
& $Python -c "import struct,sys,tkinter as tk; assert sys.version_info[:3] == (3,13,14); assert struct.calcsize('P')*8 == 64; r=tk.Tk(); print('CPython',sys.version.split()[0],'Tcl',r.tk.call('info','patchlevel')); r.destroy()"
if ($LASTEXITCODE -ne 0) {
    throw 'Official CPython Tcl/Tk startup validation failed.'
}

"FEATHERED_RELEASE_PYTHON=$Python" | Out-File -FilePath $env:GITHUB_ENV -Encoding utf8 -Append
"TCL_LIBRARY=$($InitTcl.Directory.FullName)" | Out-File -FilePath $env:GITHUB_ENV -Encoding utf8 -Append
"TK_LIBRARY=$($TkTcl.Directory.FullName)" | Out-File -FilePath $env:GITHUB_ENV -Encoding utf8 -Append

# GITHUB_PATH changes take effect for subsequent workflow steps.
$Target | Out-File -FilePath $env:GITHUB_PATH -Encoding utf8 -Append
(Join-Path $Target 'Scripts') | Out-File -FilePath $env:GITHUB_PATH -Encoding utf8 -Append

Write-Host "Authenticated CPython ready: $Python"
Write-Host "TCL_LIBRARY=$($InitTcl.Directory.FullName)"
Write-Host "TK_LIBRARY=$($TkTcl.Directory.FullName)"
