# Linux agents

## Build

Requirements: a C11 compiler, glibc, pkg-config, and development packages for OpenSSL, libpcap, libnetfilter_queue, libmnl, and libnftnl. Runtime rule management requires nftables.

```sh
./build.sh
../../csv/linux/build.sh
```

Outputs: `build/server-agent` and `build/client-agent`. Set `CC`, `OUTPUT_DIR`, or `PKG_CONFIG_PATH` as needed.

## Configure and run

Run the following from a root shell. Replace the documentation address and interface with your deployment values. Both agents require the variables described in [CSV configuration](../../csv/README.md).

```sh
export CSV_RA_LIB=/absolute/path/to/tlslatch-en/csv/linux/build/libcsv_fd_fixed.so
export CSV_RA_TRUSTED_PEK='<128 hex characters>'
export CSV_RA_TRUSTED_MEASURE='<64 hex characters>'
export TCPRA_PCAP_DEVICE=eth0
./build/server-agent --mode nira --server-ip 192.0.2.10 \
  --main-port 19443 --ra-port 19442 --expected 100 \
  --csv /var/log/tlslatch-server.csv --ready-file /run/tlslatch-server.ready
```

The server runs in the foreground. Create log parent directories first, and check that the ready file was created by this invocation. Permit the control port only from intended clients using your existing firewall management system.

Install the client gate **before starting business traffic**:

```sh
./install-gate.sh 192.0.2.10 19443 62
./build/client-agent --mode nfqset --server 192.0.2.10 \
  --main-port 19443 --ra-port 19442 --queue 62 --expected 100 --workers 8 \
  --flow-bpf tcpra_nfqset_19443 --pin-dir pending_flows \
  --csv /var/log/tlslatch-client.csv --ready-file /run/tlslatch-client.ready
```

`--flow-bpf` and `--pin-dir` are legacy names for an nftables table and set; they do not identify eBPF objects. Wait for readiness, then run the declared number of connections and stop creating new connections. `--workers` controls client verification workers, not server report-generation parallelism. `--csv` names an audit log, not the CSV shared library.

For mutual RA, add `--mutual-ra` on **both** sides. The client must also support real CSV report generation. Each endpoint's trust configuration identifies its peer. Business TLS remains server-authenticated TLS; this option does not enable TLS client-certificate authentication.

## Stop and restart

- Use the non-loopback Ethernet interface carrying the protected IPv4 endpoint. `any`, raw/TUN capture, local TLS proxies, NAT, and forwarding deployments are outside the supported observer model.
- Reserve skb/conntrack mark `0x544c0001`; do not reuse it in unrelated rules. Flow/cache capacities are bounded at 8192.
- Preserve the gate across agent restarts. Failure can add the service to `tlslatch_quarantine`; restart does not clear it.
- The server owns `tlslatch_origin_PORT`, which blocks forwarding of traffic for this endpoint. Do not add unrelated rules to that table.
- Stop business sockets and agents before maintenance removal of their exact gate/origin tables. After investigating a failure, use `quarantine-endpoint.sh recover IP PORT` only for the endpoint intentionally being restored. Never reset the whole firewall.
- Reboot persistence is an operator responsibility: restore required gate/quarantine rules before protected applications start.
- `TCPRA_PROFILE` optionally enables internal diagnostics; timing collection is disabled by default.