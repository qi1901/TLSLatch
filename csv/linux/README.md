# Linux CSV wrapper

Build from this directory, then configure the library path:

```sh
./build.sh
export CSV_RA_LIB="$PWD/build/libcsv_fd_fixed.so"
```

Use Linux x86-64 with glibc and a C compiler. The build requires the supplied `vendor/csv/linux-x86_64/libcsv.so` and checks its SHA256. Preserve the repository directory layout when deploying the wrapper.
