#!/usr/bin/env bash
# netscan.sh — NetScan bash wrapper
# Sudo'yu otomatik ekler, her argümanı main.py'ye iletir.
#
# Kullanım örnekleri:
#   ./netscan.sh
#   ./netscan.sh --ports 22,80,443 --output rapor --format pdf
#   ./netscan.sh --update-db
#   ./netscan.sh --dhcp-only

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $EUID -ne 0 ]]; then
    exec sudo python3 "$SCRIPT_DIR/main.py" "$@"
else
    exec python3 "$SCRIPT_DIR/main.py" "$@"
fi
