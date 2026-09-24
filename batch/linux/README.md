# Linux one-way Batch

The server generates reports and the client verifies them. The server needs a CSV VM; the client uses the library's verifier without requiring hardware report generation.

## Build

```sh
./build.sh
../../csv/linux/build.sh
```

Requirements: C compiler, OpenSSL development files, glibc, and runtime libpcap. Keep `proof_worker` beside `native_proof.py`.

## Run

Configure `CSV_RA_LIB`, `CSV_RA_TRUSTED_PEK`, and `CSV_RA_TRUSTED_MEASURE` as described in [CSV configuration](../../csv/README.md).

```sh
# Server: replace addresses and interface with deployment values.
python3 batch.py server --iface eth0 --server-ip 192.0.2.10 --client-ip 192.0.2.20 --main-port 19443 --control-port 19447 --epoch unique-session-id --out /var/log/tlslatch-batch-server
# Client: use the same epoch.
python3 batch.py client --iface eth0 --server-ip 192.0.2.10 --client-ip 192.0.2.20 --main-port 19443 --control-port 19447 --epoch unique-session-id --out /var/log/tlslatch-batch-client
```

Run with capture privileges. The output directories must not exist yet; create their parents in advance. Restrict the control port to the intended client. Wait for both ready files before traffic. Follow the [common shutdown steps](../README.md).

Optionally set `TCPRA_BATCH_EXPECTED=N` to require at least the expected number of observations during a bounded, at-most-30-second shutdown drain.
