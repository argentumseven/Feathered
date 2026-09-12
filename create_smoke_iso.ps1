param(
    [Parameter(Mandatory=$true)][string]$SourceDirectory,
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [string]$VolumeName = 'FEATHERED_SMOKE'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Build a small, standards-compliant ISO using the Windows IMAPI2 file-system
# image API already present on supported Windows release builders.  This avoids
# introducing an unsigned third-party ISO generator into the production gate.
$source = (Resolve-Path -LiteralPath $SourceDirectory).Path
$output = [System.IO.Path]::GetFullPath($OutputPath)
$outputParent = Split-Path -Parent $output
if ($outputParent -and -not (Test-Path -LiteralPath $outputParent)) {
    New-Item -ItemType Directory -Path $outputParent -Force | Out-Null
}

if (-not ('FeatheredIsoStreamWriter' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;

public static class FeatheredIsoStreamWriter
{
    public static void Write(string path, object streamObject, int blockSize, int totalBlocks)
    {
        IStream input = (IStream)streamObject;
        byte[] buffer = new byte[blockSize];
        IntPtr bytesReadPointer = Marshal.AllocHGlobal(sizeof(int));
        try
        {
            using (FileStream output = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                for (int block = 0; block < totalBlocks; block++)
                {
                    Marshal.WriteInt32(bytesReadPointer, 0);
                    input.Read(buffer, blockSize, bytesReadPointer);
                    int bytesRead = Marshal.ReadInt32(bytesReadPointer);
                    if (bytesRead <= 0)
                        throw new EndOfStreamException("IMAPI2 image stream ended before the advertised block count.");
                    output.Write(buffer, 0, bytesRead);
                }
                output.Flush(true);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(bytesReadPointer);
        }
    }
}
'@
}

$image = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
# 1 = CDROM. ChooseImageDefaultsForMediaType establishes a zero-session image
# suitable for saving as an ISO; ISO9660 alone is sufficient for this fixture.
$image.ChooseImageDefaultsForMediaType(1)
$image.FileSystemsToCreate = 1
$image.VolumeName = $VolumeName
$image.Root.AddTree($source, $false)
$result = $image.CreateResultImage()
[FeatheredIsoStreamWriter]::Write(
    $output, $result.ImageStream, [int]$result.BlockSize, [int]$result.TotalBlocks)

$created = Get-Item -LiteralPath $output
if ($created.Length -le 0) {
    throw "IMAPI2 produced an empty ISO: $output"
}
Write-Host "Created smoke ISO: $($created.FullName) ($($created.Length) bytes)"
