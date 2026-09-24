# TLSLatch-Batch

| Directory | Component |
|---|---|
| [linux](linux/README.md) | One-way Linux server/client |
| [windows](windows/README.md) | One-way Windows client, paired with the Linux one-way server |
| [macos](macos/README.md) | One-way macOS client, paired with the Linux one-way server |
| [mutual](mutual/README.md) | Linux mutual Batch, using a separate protocol |

One-way implementations share a wire protocol. Mutual clients and servers must both use `mutual`; they cannot be mixed with the one-way protocol.

## Common operating rules

- Use Python 3 without `-O` or `PYTHONOPTIMIZE`. Protocol assertions are verification checks; the entry point refuses optimized execution.
- Use the same unique `--epoch`, endpoint IPs, business port, and control port on both sides. Defaults are business port 19443, control port 19447, and period 5 seconds.
- `--iface` must identify the Ethernet/Npcap interface carrying business traffic. Capture privileges are required.
- Use a new `--out` directory with an existing parent. Wait for both `READY` files before starting traffic.
- Stop new traffic and drain in-flight handshakes, then stop the client gracefully and wait for its tail confirmation. Stop the server afterwards. Use SIGINT/SIGTERM on Unix; on Windows use Ctrl+C or the documented `STOP` file. Do not force-kill to perform a normal tail flush.
- Check both `batches.json` files, each batch error, `unassigned`, capture drop counters in `observations.json`, and manifest/report coverage. Treat missing records or errors as incomplete confirmation.
