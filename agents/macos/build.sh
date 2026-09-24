#!/bin/bash
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
test "$(uname -s)" = Darwin || {
    echo 'Build on macOS with Xcode CLI tools and Rust.' >&2
    exit 1
}
cargo build --release --locked --manifest-path "$here/ffi/Cargo.toml" "$@"
python3 "$here/build.py"
