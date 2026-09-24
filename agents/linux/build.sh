#!/usr/bin/env bash
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
output=${OUTPUT_DIR:-$here/build}
compiler=${CC:-cc}
mkdir -p "$output"
read -r -a ssl <<<"$(pkg-config --cflags --libs openssl)"
read -r -a client <<<"$(pkg-config --cflags --libs libnetfilter_queue libmnl libnftnl)"
read -r -a server <<<"$(pkg-config --cflags --libs libpcap)"
flags=(-std=c11 -D_POSIX_C_SOURCE=200809L -O2 -Wall -Wextra -Werror -pthread -I"$here"
    -DTCPRA_DYNAMIC_MODE_NAME='"nfqset"' -DTCPRA_MUTUAL_MODE_NAME='"nfqset-early-mra"' -DTCPRA_SELECTOR_CLOSE_CLEANUP=1)
common=("$here/csv_attestation.c" "$here/profile.c" "$here/packet_view.c" "$here/tls_parse.c" "$here/wire_io.c")
"$compiler" "${flags[@]}" "$here/tcpra_client_agent.c" "$here/flow_selector_nft.c" "${common[@]}" "${client[@]}" "${ssl[@]}" -ldl -o "$output/client-agent"
"$compiler" "${flags[@]}" "$here/tcpra_server_agent.c" "$here/pcap_observer.c" "${common[@]}" "${server[@]}" "${ssl[@]}" -ldl -o "$output/server-agent"
