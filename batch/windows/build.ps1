param(
    [Parameter(Mandatory = $true)][string]$OpenSslRoot,
    [Parameter(Mandatory = $true)][string]$VcVars
)

$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    $cmd = 'call "' + $VcVars + '" >nul && cl /nologo /O2 /MT /LD /std:c11 /I"' + $OpenSslRoot + '" proof_bridge.c crypto_bridge.c /Fe:proof_bridge.dll /link /LIBPATH:"' + $OpenSslRoot + '" libcrypto.lib ws2_32.lib bcrypt.lib crypt32.lib advapi32.lib user32.lib'
    cmd /d /s /c $cmd
    if ($LASTEXITCODE -ne 0) {
        throw 'Build failed'
    }
} finally {
    Pop-Location
}
