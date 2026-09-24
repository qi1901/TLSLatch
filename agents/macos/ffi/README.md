# Rust parser and verifier library

Build with `cargo build --release --locked`. On macOS the cdylib is `libtcpra_pf_ffi.dylib`, used by the provider and macOS Batch.

C ABI:

- `tcpra_hello(data, len, is_client, out64)` parses a Hello binding.
- `tcpra_verify(report2548, binding64, pek64, measurement32)` verifies a report.

The caller must supply readable/writable buffers of the stated sizes. No external pointers are retained. Return values are 1 for success, 0 for rejection/no match, and -1 for invalid pointer/size arguments checked at the boundary.

Run the parser tests with `cargo test --locked`.
