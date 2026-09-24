# macOS one-way Batch client

Pair this client with `batch/linux/batch.py server`. Do not enable the strict Network Extension for this mode.

Build the verifier with `cargo build --release --locked` in `agents/macos/ffi`, then configure:

```sh
export TCPRA_VERIFY_DYLIB=/absolute/path/to/tlslatch-en/agents/macos/ffi/target/release/libtcpra_pf_ffi.dylib
export CSV_RA_TRUSTED_PEK='<128 hex characters>'
export CSV_RA_TRUSTED_MEASURE='<64 hex characters>'
python3 batch.py client --iface en0 --server-ip 192.0.2.10 --client-ip 192.0.2.20 --epoch unique-session-id --out /var/log/tlslatch-batch-client
```

Use a capture-capable account and preserve the configuration environment in the process that is actually launched. The recorder uses system libpcap. `en0` is an example: identify the correct business interface on the target device. macOS is verifier-only.

No extension installation or activation is required for Batch. Follow the [common shutdown steps](../README.md) and wait for tail completion.
