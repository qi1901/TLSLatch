#!/usr/bin/env bash
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
vendor=$(cd "$here/../../vendor/csv/linux-x86_64" && pwd)
(cd "$vendor" && sha256sum -c SHA256SUMS)
mkdir -p "$here/build"

${CC:-cc} -std=c11 -O2 -Wall -Wextra -Werror -fPIC -shared -pthread "$here/csv_fd_fix.c" \
    -L"$vendor" -Wl,--no-as-needed -lcsv -Wl,--as-needed \
    '-Wl,-rpath,$ORIGIN/../../../vendor/csv/linux-x86_64' -ldl -o "$here/build/libcsv_fd_fixed.so"
