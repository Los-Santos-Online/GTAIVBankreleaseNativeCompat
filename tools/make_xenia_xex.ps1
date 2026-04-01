param(
    [Parameter(Mandatory = $true)]
    [string]$InputXex,

    [Parameter(Mandatory = $true)]
    [string]$OutputXex,

    [string[]]$SectionName = @(),

    [switch]$AllDataToCode,

    [string]$XexToolPath = ""
)

function Find-PeOffsets {
    param([byte[]]$Bytes)

    for ($i = 0; $i -lt $Bytes.Length - 0x40; $i++) {
        if ($Bytes[$i] -ne 0x4D -or $Bytes[$i + 1] -ne 0x5A) {
            continue
        }

        $e_lfanew = [BitConverter]::ToInt32($Bytes, $i + 0x3C)
        if ($e_lfanew -lt 0) {
            continue
        }

        $pe = $i + $e_lfanew
        if ($pe + 4 -ge $Bytes.Length) {
            continue
        }

        if ($Bytes[$pe] -eq 0x50 -and $Bytes[$pe + 1] -eq 0x45 -and $Bytes[$pe + 2] -eq 0x00 -and $Bytes[$pe + 3] -eq 0x00) {
            return @($i, $pe)
        }
    }

    return $null
}

function Write-UInt32 {
    param(
        [byte[]]$Bytes,
        [int]$Offset,
        [uint32]$Value
    )
    $raw = [BitConverter]::GetBytes($Value)
    [System.Array]::Copy($raw, 0, $Bytes, $Offset, 4)
}

if (-not (Test-Path -LiteralPath $InputXex)) {
    $altXex = [System.IO.Path]::ChangeExtension($InputXex, ".xex")
    if (Test-Path -LiteralPath $altXex) {
        $InputXex = $altXex
    } else {
        throw "Input xex not found: $InputXex"
    }
}

if ([System.IO.Path]::GetExtension($InputXex).ToLowerInvariant() -ne ".xex") {
    Write-Host "Warning: input is not .xex ($InputXex). Attempting to proceed anyway."
}

function Resolve-XexToolPath {
    param([string]$ExplicitPath)

    if ($ExplicitPath -and (Test-Path -LiteralPath $ExplicitPath)) {
        return $ExplicitPath
    }

    if ($env:XEXTOOL_PATH -and (Test-Path -LiteralPath $env:XEXTOOL_PATH)) {
        return $env:XEXTOOL_PATH
    }

    $scriptDir = Split-Path -Parent $PSCommandPath
    $local = Join-Path $scriptDir "xextool.exe"
    if (Test-Path -LiteralPath $local) {
        return $local
    }

    $guess = Join-Path (Resolve-Path (Join-Path $scriptDir "..\\..")).Path "CyprusV Xbox Plugin\\CyprusV\\Release\\xextool.exe"
    if (Test-Path -LiteralPath $guess) {
        return $guess
    }

    $cmd = Get-Command xextool.exe -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Path
    }

    return $null
}

if ((Resolve-Path -LiteralPath $InputXex).Path -ne (Resolve-Path -LiteralPath $OutputXex -ErrorAction SilentlyContinue).Path) {
    Copy-Item -LiteralPath $InputXex -Destination $OutputXex -Force
}

[byte[]]$bytes = [System.IO.File]::ReadAllBytes($OutputXex)
$offsets = Find-PeOffsets -Bytes $bytes
if (-not $offsets) {
    $xextool = Resolve-XexToolPath -ExplicitPath $XexToolPath
    if (-not $xextool) {
        throw "Failed to locate embedded PE header in xex and xextool.exe was not found. Set XEXTOOL_PATH or pass -XexToolPath."
    }

    Write-Host "Embedded PE not found; recreating unencrypted/uncompressed xex via xextool..."
    & $xextool -e u -c u -o $OutputXex $InputXex | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "xextool failed with exit code $LASTEXITCODE"
    }

    $bytes = [System.IO.File]::ReadAllBytes($OutputXex)
    $offsets = Find-PeOffsets -Bytes $bytes
    if (-not $offsets) {
        throw "Failed to locate embedded PE header in xex after xextool conversion."
    }
}

$peOffset = $offsets[1]
$numSections = [BitConverter]::ToUInt16($bytes, $peOffset + 6)
$optHeaderSize = [BitConverter]::ToUInt16($bytes, $peOffset + 20)
$sectionTable = $peOffset + 24 + $optHeaderSize

$patched = @()
$skipped = @()

for ($i = 0; $i -lt $numSections; $i++) {
    $secOffset = $sectionTable + ($i * 40)
    if ($secOffset + 40 -gt $bytes.Length) {
        break
    }

    $name = [System.Text.Encoding]::ASCII.GetString($bytes, $secOffset, 8).Trim([char]0)
    $charsOffset = $secOffset + 36
    $chars = [BitConverter]::ToUInt32($bytes, $charsOffset)

    $hasData = (($chars -band 0x00000040) -ne 0) -or (($chars -band 0x00000080) -ne 0)
    $hasExec = ($chars -band 0x20000000) -ne 0
    $exclude = @('.rsrc', '.reloc') -contains $name

    $shouldPatch = $false
    if ($SectionName.Count -gt 0) {
        $shouldPatch = $SectionName -contains $name
    } elseif ($AllDataToCode) {
        $shouldPatch = $hasData -and -not $hasExec -and -not $exclude
    }

    if ($shouldPatch) {
        $chars = $chars -bor 0x00000020 -bor 0x20000000
        Write-UInt32 -Bytes $bytes -Offset $charsOffset -Value $chars
        $patched += $name
    } else {
        $skipped += $name
    }
}

[System.IO.File]::WriteAllBytes($OutputXex, $bytes)

Write-Host "Xenia patch: wrote $OutputXex"
if ($patched.Count -gt 0) {
    Write-Host "Patched sections: $($patched -join ', ')"
} else {
    Write-Host "No sections patched. Use -AllDataToCode or -SectionName to select sections."
}