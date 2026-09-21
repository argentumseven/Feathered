$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Version = '3.13.15'
$ExpectedSha256 = 'edec09c4853aeae9ac36efb8c9f95b6b8e2fee65eee56d9767a8b7c69c574403'
$InstallerUrl = "https://www.python.org/ftp/python/$Version/python-$Version-amd64.exe"
if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
    throw 'RUNNER_TEMP is required; this bootstrap is intended for GitHub Actions.'
}
if ([string]::IsNullOrWhiteSpace($env:GITHUB_ENV) -or
    [string]::IsNullOrWhiteSpace($env:GITHUB_PATH)) {
    throw 'GITHUB_ENV/GITHUB_PATH are required; this bootstrap is intended for GitHub Actions.'
}
$Diagnostics = Join-Path $env:RUNNER_TEMP 'feathered-python-diagnostics'
New-Item -ItemType Directory -Path $Diagnostics -Force | Out-Null
Start-Transcript -Path (Join-Path $Diagnostics 'bootstrap.log') -Force | Out-Null
try {
$Installer = Join-Path $env:RUNNER_TEMP "python-$Version-amd64.exe"
$Target = Join-Path $env:RUNNER_TEMP "feathered-python-$Version"
Write-Host "Downloading authenticated CPython $Version from python.org..."
$DownloadError = $null
for ($Attempt = 1; $Attempt -le 3; $Attempt++) {
    try {
        Remove-Item -LiteralPath $Installer -Force -ErrorAction SilentlyContinue
        Invoke-WebRequest -Uri $InstallerUrl -OutFile $Installer
        $DownloadError = $null
        break
    } catch {
        $DownloadError = $_
        Write-Warning "python.org download attempt $Attempt failed: $($_.Exception.Message)"
        if ($Attempt -lt 3) { Start-Sleep -Seconds (2 * $Attempt) }
    }
}
if ($null -ne $DownloadError) {
    throw "Could not download CPython $Version from python.org after 3 attempts: $($DownloadError.Exception.Message)"
}
$ActualSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $Installer).Hash.ToLowerInvariant()
if ($ActualSha256 -ne $ExpectedSha256) {
    throw "python.org installer SHA-256 mismatch. Expected $ExpectedSha256, got $ActualSha256"
}

if (Test-Path -LiteralPath $Target) {
    Remove-Item -LiteralPath $Target -Recurse -Force
}
$InstallerLog = Join-Path $Diagnostics 'installer.log'
$Arguments = @(
    '/quiet',
    '/log',
    "`"$InstallerLog`"",
    'InstallAllUsers=0',
    "TargetDir=`"$Target`"",
    'Include_launcher=0',
    'Include_test=0',
    'Include_tcltk=1',
    'Include_pip=1',
    'Include_dev=1',
    'Include_exe=1',
    'Include_lib=1',
    'Include_tools=1',
    'Include_doc=0',
    'Include_debug=0',
    'Include_symbols=0',
    'Include_freethreaded=0',
    'AssociateFiles=0',
    'PrependPath=0',
    'AppendPath=0',
    'CompileAll=0',
    'Shortcuts=0'
)
$Process = Start-Process -FilePath $Installer -ArgumentList $Arguments -Wait -PassThru
if ($Process.ExitCode -ne 0) {
    if (Test-Path -LiteralPath $InstallerLog) {
        Write-Host '--- python.org installer log tail ---'
        Get-Content -LiteralPath $InstallerLog -Tail 120 | Write-Host
        Write-Host '--- end installer log tail ---'
    }
    throw "python.org installer failed with exit code $($Process.ExitCode)"
}
$Python = Join-Path $Target 'python.exe'
if (-not (Test-Path -LiteralPath $Python)) {
    if (Test-Path -LiteralPath $InstallerLog) {
        Write-Host '--- python.org installer log tail ---'
        Get-Content -LiteralPath $InstallerLog -Tail 120 | Write-Host
        Write-Host '--- end installer log tail ---'
    }
    throw "Installed python.exe was not found at $Python"
}
$Python3 = Join-Path $Target 'python3.exe'
# Git Bash looks specifically for `python3` when exercising the generated
# Linux installer. The official Windows installer ships python.exe but not a
# python3.exe command name, so without this alias Git Bash can fall through to
# Windows' App Execution Alias instead of the authenticated interpreter.
Copy-Item -LiteralPath $Python -Destination $Python3 -Force
if (-not (Test-Path -LiteralPath $Python3)) {
    throw "python3.exe compatibility alias was not created at $Python3"
}
$PythonHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Python).Hash
$Python3Hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Python3).Hash
if ($PythonHash -ne $Python3Hash) {
    throw 'python3.exe compatibility alias is not byte-identical to python.exe.'
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
# GITHUB_ENV affects later steps only. The validation below must use this
# installation's Tcl/Tk now, not settings inherited from the runner.
$env:TCL_LIBRARY = $InitTcl.Directory.FullName
$env:TK_LIBRARY = $TkTcl.Directory.FullName
Write-Host "TCL_LIBRARY=$env:TCL_LIBRARY"
Write-Host "TK_LIBRARY=$env:TK_LIBRARY"
Write-Host "Validating interpreter and Tcl/Tk before running Feathered tests..."
& $Python -c "import struct,sys,tkinter as tk; assert sys.version_info[:3] == (3,13,15); assert struct.calcsize('P')*8 == 64; r=tk.Tk(); print('CPython',sys.version.split()[0],'Tcl',r.tk.call('info','patchlevel')); r.destroy()"
if ($LASTEXITCODE -ne 0) {
    throw 'Official CPython Tcl/Tk startup validation failed.'
}
# GITHUB_PATH is applied to later workflow steps. Also update this process now
# and prove the exact command used by tests/test_installer_paths.py resolves to
# this authenticated installation when launched through Git Bash.
$env:Path = "$Target;$env:Path"
$env:FEATHERED_EXPECTED_PYTHON3 = $Python3
# Windows also ships a WSL bash.exe launcher on some hosts. It is not Git Bash
# and fails when no WSL distribution is installed. Prefer bash from the Git
# installation, then validate every candidate before using it.
$BashCandidates = @()
$GitCommand = Get-Command git.exe -ErrorAction SilentlyContinue
if ($GitCommand) {
    $GitCmdDirectory = Split-Path -Parent $GitCommand.Source
    $GitRoot = Split-Path -Parent $GitCmdDirectory
    $BashCandidates += (Join-Path $GitRoot 'bin\bash.exe')
    $BashCandidates += (Join-Path $GitRoot 'usr\bin\bash.exe')
}
$PathBash = Get-Command bash.exe -ErrorAction SilentlyContinue
if ($PathBash) { $BashCandidates += $PathBash.Source }
$Bash = $null
foreach ($Candidate in ($BashCandidates | Select-Object -Unique)) {
    if (-not (Test-Path -LiteralPath $Candidate -PathType Leaf)) { continue }
    $VersionOutput = @(& $Candidate --version 2>&1)
    $VersionExitCode = $LASTEXITCODE
    $VersionText = ($VersionOutput | ForEach-Object { "$_" }) -join "`n"
    if ($VersionExitCode -eq 0 -and $VersionText -match 'GNU bash') {
        $Bash = (Resolve-Path -LiteralPath $Candidate).Path
        break
    }
}
if (-not $Bash) {
    throw 'A real GNU Bash installation was not found. Git for Windows is required by the release gate.'
}
Write-Host "Validating Git Bash python3 resolution through $Bash ..."
$BashProbe = @'
set -euo pipefail
resolved="$(command -v python3)"
expected="$(cygpath -u "$FEATHERED_EXPECTED_PYTHON3")"
resolved="${resolved%.exe}"
expected="${expected%.exe}"
printf '%s\n' "$resolved"
test "$resolved" = "$expected"
python3 --version
'@
$BashProbePath = Join-Path (Get-Location) '.feathered_bash_probe.sh'
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$BashProbeText = ($BashProbe -replace "`r`n", "`n") + "`n"
[System.IO.File]::WriteAllText($BashProbePath, $BashProbeText, $Utf8NoBom)
try {
    $BashOutput = @(
        & $Bash './.feathered_bash_probe.sh' 2>&1
    )
    $BashExitCode = $LASTEXITCODE
} finally {
    Remove-Item -LiteralPath $BashProbePath -Force -ErrorAction SilentlyContinue
}
$BashOutput | ForEach-Object { Write-Host $_ }
if ($BashExitCode -ne 0) {
    throw 'Git Bash could not execute the authenticated python3 compatibility alias.'
}
$BashText = ($BashOutput | ForEach-Object { "$_" }) -join "`n"
$ExpectedPythonVersionPattern = '(?m)^Python ' + [regex]::Escape($Version) + '(?:\s|$)'
if ($BashText -notmatch $ExpectedPythonVersionPattern) {
    throw "Git Bash resolved python3, but it did not report Python $Version."
}
Remove-Item Env:FEATHERED_EXPECTED_PYTHON3 -ErrorAction SilentlyContinue

"FEATHERED_RELEASE_PYTHON=$Python" | Out-File -FilePath $env:GITHUB_ENV -Encoding utf8 -Append
"TCL_LIBRARY=$($InitTcl.Directory.FullName)" | Out-File -FilePath $env:GITHUB_ENV -Encoding utf8 -Append
"TK_LIBRARY=$($TkTcl.Directory.FullName)" | Out-File -FilePath $env:GITHUB_ENV -Encoding utf8 -Append
# GITHUB_PATH changes take effect for subsequent workflow steps.
$Target | Out-File -FilePath $env:GITHUB_PATH -Encoding utf8 -Append
(Join-Path $Target 'Scripts') | Out-File -FilePath $env:GITHUB_PATH -Encoding utf8 -Append

Write-Host "Authenticated CPython ready: $Python"
Write-Host "TCL_LIBRARY=$($InitTcl.Directory.FullName)"
Write-Host "TK_LIBRARY=$($TkTcl.Directory.FullName)"

} finally {
    Stop-Transcript | Out-Null
}
