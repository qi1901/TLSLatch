# Hygon CSV setup

Linux requires `vendor/csv/linux-x86_64/libcsv.so` and the wrapper built below.

## Configuration

On Linux, run `linux/build.sh` and set `CSV_RA_LIB` to the absolute path of the generated `libcsv_fd_fixed.so`.

Linux processes and Windows verifiers use:

- `CSV_RA_TRUSTED_PEK`: a 64-byte public key encoded as 128 hex characters, preserving the report PEK x/y field byte order.
- `CSV_RA_TRUSTED_MEASURE`: a 32-byte measurement encoded as 64 hex characters.

For strict one-way RA the client trusts the server; the Linux server library initialization also requires valid trust values. For mutual RA/Batch each endpoint configures its peer's values. The strict macOS provider receives equivalent values at build time; macOS Batch receives them through the environment.

Real report generation requires a matching Linux x86-64 CSV environment. Windows and macOS are verifier-only and must not load the Linux ELF.
