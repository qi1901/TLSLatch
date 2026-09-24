# TLSLatch agents

| Directory | Component |
|---|---|
| [linux](linux/README.md) | Linux observer/report server and Linux client gate; one-way or mutual RA |
| [windows](windows/README.md) | Windows client launcher, worker, and firewall helper |
| [macos](macos/README.md) | macOS client Network Extension and Rust verifier |

Applications retain their own TLS implementations, certificates, and protocols. Linux is the attesting server; Windows and macOS are verifier-only clients. Mutual RA requires CSV-capable Linux endpoints on both sides.

Configure the endpoints and start both agents before business traffic. Follow the build, run, and shutdown steps in the platform README.
