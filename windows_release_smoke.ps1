param(
    [Parameter(Mandatory=$true)][string]$IsoPath,
    [string]$PythonExe = ''
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Production gate: exercise Feathered's actual _mount_disc_image implementation
# on the Windows release builder, then independently re-query and dismount the
# fixture so a failure cannot leave a stray mounted image behind.

$resolved = (Resolve-Path -LiteralPath $IsoPath).Path
$probe = Join-Path $PSScriptRoot 'windows_media_mount_smoke.py'
if (-not (Test-Path -LiteralPath $probe -PathType Leaf)) {
    throw "Missing Windows mount probe: $probe"
}

try {
    if ($PythonExe) {
        $resolvedPython = (Resolve-Path -LiteralPath $PythonExe).Path
        & $resolvedPython $probe --iso $resolved
    }
    elseif (Get-Command py -ErrorAction SilentlyContinue) {
        & py -3.13 $probe --iso $resolved
    }
    else {
        & python $probe --iso $resolved
    }
    if ($LASTEXITCODE -ne 0) {
        throw "Feathered _mount_disc_image smoke probe exited with status $LASTEXITCODE."
    }

    $disk = Get-DiskImage -ImagePath $resolved -ErrorAction Stop
    if (-not $disk.Attached) {
        throw 'Feathered smoke probe returned success but the ISO is not attached.'
    }
    $volume = $disk | Get-Volume -ErrorAction Stop
    if (-not $volume -or -not $volume.DriveLetter) {
        throw 'Mounted ISO did not expose a drive letter after Feathered returned success.'
    }
    Write-Host "Feathered mount smoke test confirmed $resolved at $($volume.DriveLetter):"
}
finally {
    # Query the real attachment state even when the Python probe failed. This
    # catches the case where mounting succeeded but later parsing/UI-free probe
    # validation failed.
    try {
        $disk = Get-DiskImage -ImagePath $resolved -ErrorAction SilentlyContinue
        if ($disk -and $disk.Attached) {
            Dismount-DiskImage -ImagePath $resolved -ErrorAction Stop | Out-Null
        }
    }
    catch {
        Write-Warning "Failed to dismount $resolved : $_"
    }
}
