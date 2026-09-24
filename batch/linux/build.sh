#!/usr/bin/env bash
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
read -r -a ssl <<<"$(pkg-config --cflags --libs openssl)"
${CC:-cc} -std=c11 -D_POSIX_C_SOURCE=200809L -O2 -Wall -Wextra -Werror -pthread -I"$here" \
    "$here/proof_worker.c" "$here/csv_attestation.c" "${ssl[@]}" -ldl -o "$here/proof_worker"
