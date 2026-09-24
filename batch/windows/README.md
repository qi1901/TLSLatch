# Windows one-way Batch client

Pair this client with the one-way server in `batch/linux`. Requirements: x64 Python, Npcap at the standard `System32/Npcap` path, MSVC, and OpenSSL 1.1.1 static development files. This mode does not use a WinDivert gate.

```powershell
.\build.ps1 -OpenSslRoot C:\deps\openssl-1.1.1 -VcVars 'C:\path\to\vcvars64.bat'
$env:CSV_RA_TRUSTED_PEK='<128 hex characters>'
$env:CSV_RA_TRUSTED_MEASURE='<64 hex characters>'
python batch.py client --iface '\Device\NPF_{YOUR-ADAPTER-GUID}' --server-ip 192.0.2.10 --client-ip 192.0.2.20 --epoch unique-session-id --out C:\logs\tlslatch-batch-client
```

Keep `proof_bridge.dll` beside `native_proof.py`. The OpenSSL layout is the same as for the Windows agent. Replace the Npcap device name with the actual business adapter and run with capture privileges. Windows cannot generate CSV reports.

After business traffic drains, Ctrl+C requests tail completion. Alternatively, create an empty file in the output directory:

```powershell
New-Item C:\logs\tlslatch-batch-client\STOP -ItemType File
```

Wait for normal client exit before stopping the Linux server. Do not use TaskKill for a normal flush.
