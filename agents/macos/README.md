# macOS client

`Host.swift` manages the Network System Extension. `Provider.swift` observes TLS and holds unverified outbound data. `ffi/` provides Rust parsing and CSV SM2 verification. No Linux CSV binary is needed on macOS.

## Build configuration

Requirements: macOS 13+, Xcode command-line tools, Rust, and a signing/entitlement environment suitable for a Network Extension.

Create a private `deployment.local.json`:

```json
{
  "server_ip": "192.0.2.10",
  "main_port": 19443,
  "control_port": 19442,
  "trusted_pek": "<128 hex characters>",
  "trusted_measurement": "<64 hex characters>"
}
```

Replace all placeholders. Missing or malformed configuration rejects the build.

```sh
export TLSLATCH_CONFIG="$PWD/deployment.local.json"
export CODESIGN_IDENTITY='your signing identity'
./build.sh
```

The builder generates `build/Deployment.swift` and `build/provider/main.swift`. Configuration is compiled into the provider, so a target change requires a rebuild. `CODESIGN_IDENTITY=-` is for an already configured local development environment, not a general installation procedure. Bundle IDs are `com.qi.tcpra.local` and `com.qi.tcpra.local.filter`; signing, entitlements, and provisioning must agree.

Additional arguments to `build.sh` are passed to Cargo, allowing an offline source configuration consistent with `Cargo.lock` when needed.

## Enable and stop

Place `build/TcpraLocal.app` in an application location accepted by the OS. Invoke its `Contents/MacOS/TcpraLocal activate`, approve the extension through the OS if requested, then invoke the same host with `enable` to install the filter configuration. Confirm provider startup and server readiness before starting business traffic. Verification failure or timeout drops the protected flow.

For maintenance, first stop business traffic, then use `remove` to remove filter configuration and `deactivate` to deactivate the extension. Disabling the extension is not an automatic failure-recovery policy. Only the configured IPv4/TCP service is protected. This client does not generate CSV reports or implement mutual RA.

For Batch, use the separate [macOS Batch client](../../batch/macos/README.md) without enabling this filter.
