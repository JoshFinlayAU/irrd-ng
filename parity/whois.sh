#!/usr/bin/env bash
# Send one whois query and print the raw response: whois.sh <host> <port> <query>
set -euo pipefail
exec 3<>"/dev/tcp/$1/$2"
printf '%s\n' "$3" >&3
timeout 30 cat <&3
