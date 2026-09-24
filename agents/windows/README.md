# Windows client

`tcpra_agent_c.c` and `guardian_client.c` build the worker. `guardian.c` builds the public launcher. `firewall_helper.c` builds the firewall/TCP cleanup helper. Keep all three executables in the same administrator-controlled directory and launch `tcpra_agent_c.exe`, not the worker.

## Build

Use Windows x64, MSVC Build Tools, WinDivert 2.2.2 headers/library and matching driver/DLL, and an OpenSSL 1.1.1-series static development package. These dependencies are not bundled.

```powershell
.\build.ps1 -WinDivertRoot C:\deps\WinDivert-source `
  -WinDivertBinaryRoot C:\deps\WinDivert\x64 `
  -OpenSslRoot C:\deps\openssl-1.1.1 `
  -VcVars 'C:\path\to\VC\Auxiliary\Build\vcvars64.bat'
```

The OpenSSL root must directly contain `openssl\evp.h` and `libcrypto.lib`. The WinDivert source root must contain `include\windivert.h`. Outputs go to `build/`; the deployable set is assembled in `dist/`. Provide a properly signed driver for the target system.

## Run

In an elevated PowerShell session, configure independently validated trust values:

```powershell
$env:CSV_RA_TRUSTED_PEK='<128 hex characters>'
$env:CSV_RA_TRUSTED_MEASURE='<64 hex characters>'
.\dist\tcpra_agent_c.exe --mode conditional --ra true --server-ip 192.0.2.10 --main-port 19443 --ra-port 19442 --expected 100 --workers 8 --output agent.csv
```

Start the Linux server first. Wait for `TCPRA_AGENT_READY` before starting business connections, and stop creating connections at the declared count. The worker inherits trust configuration from the launcher environment. Keep normal business TLS validation enabled.

Windows Firewall/BFE must be enabled and local policy modifications must be effective. If the agent creates an endpoint quarantine rule, stop business traffic before recovery. The persistent rule is named `TLSLatch-Quarantine-IP-PORT`; restart does not remove it. After investigation and with business traffic stopped, remove only the intended endpoint rule.