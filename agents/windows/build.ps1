[CmdletBinding()]
param(
    [string]$SourceRoot = $PSScriptRoot,
    [Parameter(Mandatory = $true)][string]$WinDivertRoot,
    [Parameter(Mandatory = $true)][string]$WinDivertBinaryRoot,
    [Parameter(Mandatory = $true)][string]$OpenSslRoot,
    [Parameter(Mandatory = $true)][string]$VcVars,
    [string]$OutputRoot = (Join-Path $PSScriptRoot 'build'),
    [string]$DemoRoot = (Join-Path $PSScriptRoot 'dist')
)

$ErrorActionPreference = 'Stop'
if (-not $SourceRoot) {
    $SourceRoot = $PSScriptRoot
}
$vcvars = $VcVars
$source = Join-Path $SourceRoot 'tcpra_agent_c.c'
$guardianSource = Join-Path $SourceRoot 'guardian_client.c'
$windivertInclude = Join-Path $WinDivertRoot 'include'
$windivertLib = Join-Path $WinDivertBinaryRoot 'WinDivert.lib'
$opensslLib = Join-Path $OpenSslRoot 'libcrypto.lib'

foreach ($path in @($vcvars, $source, (Join-Path $windivertInclude 'windivert.h'),
        $windivertLib, $opensslLib, (Join-Path $OpenSslRoot 'openssl\evp.h'))) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Missing build input: $path"
    }
}

New-Item -ItemType Directory -Force -Path $OutputRoot, $DemoRoot | Out-Null
$object = Join-Path $OutputRoot 'tcpra_agent_c.obj'
$binary = Join-Path $OutputRoot 'tcpra_worker.exe'
$pdb = Join-Path $OutputRoot 'tcpra_agent_c.pdb'
$guardianObject = Join-Path $OutputRoot 'guardian.obj'
$compile = @(
    'cl.exe', '/nologo', '/c', '/TC', '/std:c11', '/W4', '/WX-',
    '/O2', '/Ob3', '/Oi', '/Ot', '/GL', '/Gy', '/Gw', '/GS', '/guard:cf',
    '/MT',
    ('/I"{0}"' -f $windivertInclude), ('/I"{0}"' -f $OpenSslRoot),
    ('/Fo"{0}"' -f $object), ('"{0}"' -f $source),
    '&&', 'cl.exe', '/nologo', '/c', '/TC', '/std:c11', '/W4', '/O2', '/MT',
    ('/Fo"{0}"' -f $guardianObject), ('"{0}"' -f $guardianSource),
    '&&', 'link.exe', '/nologo', '/LTCG', '/OPT:REF', '/OPT:ICF', '/guard:cf',
    ('/OUT:"{0}"' -f $binary), ('/PDB:"{0}"' -f $pdb),
    ('"{0}"' -f $object), ('"{0}"' -f $guardianObject), ('"{0}"' -f $windivertLib), ('"{0}"' -f $opensslLib),
    'ws2_32.lib', 'bcrypt.lib', 'crypt32.lib', 'advapi32.lib', 'user32.lib'
) -join ' '

$command = ('call "{0}" >nul && {1}' -f $vcvars, $compile)
cmd.exe /d /s /c $command
if ($LASTEXITCODE -ne 0) {
    throw "MSVC build failed with exit code $LASTEXITCODE"
}

Copy-Item -Force -LiteralPath $binary -Destination (Join-Path $DemoRoot 'tcpra_worker.exe')
foreach ($target in @(
    @{ Name = 'tcpra_agent_c'; Source = 'guardian.c'; Libraries = 'kernel32.lib' },
    @{ Name = 'tcpra_firewall'; Source = 'firewall_helper.c'; Libraries = 'kernel32.lib ws2_32.lib ole32.lib oleaut32.lib uuid.lib iphlpapi.lib' }
)) {
    $smallObject = Join-Path $OutputRoot ($target.Name + '.obj')
    $smallBinary = Join-Path $OutputRoot ($target.Name + '.exe')
    $smallSource = Join-Path $SourceRoot $target.Source
    $smallCompile = 'cl.exe /nologo /c /TC /std:c11 /W4 /O2 /GL /Gy /Gw /GS /guard:cf /MT /Fo"{0}" "{1}" && link.exe /nologo /LTCG /OPT:REF /OPT:ICF /guard:cf /OUT:"{2}" "{0}" {3}' -f $smallObject, $smallSource, $smallBinary, $target.Libraries
    cmd.exe /d /s /c ('call "{0}" >nul && {1}' -f $vcvars, $smallCompile)
    if ($LASTEXITCODE -ne 0) {
        throw "Build failed: $($target.Name)"
    }
    Copy-Item -Force -LiteralPath $smallBinary -Destination $DemoRoot
}
foreach ($driverFile in 'WinDivert.dll', 'WinDivert64.sys') {
    $sourceDriver = Join-Path $WinDivertBinaryRoot $driverFile
    $targetDriver = Join-Path $DemoRoot $driverFile
    $copy = -not (Test-Path -LiteralPath $targetDriver)
    if (-not $copy) {
        $copy = (Get-FileHash -Algorithm SHA256 -LiteralPath $sourceDriver).Hash -ne
            (Get-FileHash -Algorithm SHA256 -LiteralPath $targetDriver).Hash
    }
    if ($copy) {
        Copy-Item -Force -LiteralPath $sourceDriver -Destination $targetDriver
    }
}
$hash = Get-FileHash -Algorithm SHA256 -LiteralPath $binary
[pscustomobject]@{
    Binary = $binary
    DemoBinary = (Join-Path $DemoRoot 'tcpra_worker.exe')
    Launcher = (Join-Path $DemoRoot 'tcpra_agent_c.exe')
    FirewallHelper = (Join-Path $DemoRoot 'tcpra_firewall.exe')
    Length = (Get-Item -LiteralPath $binary).Length
    SHA256 = $hash.Hash.ToLowerInvariant()
    Compiler = (& cmd.exe /d /s /c ('call "{0}" >nul && cl.exe 2>&1' -f $vcvars) |
        Select-Object -First 1)
} | Format-List
