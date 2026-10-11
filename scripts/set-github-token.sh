#!/usr/bin/env bash
set -euo pipefail

TARGET_DIR="/var/lib/joe-mcp-work/.secrets"
TARGET_FILE="$TARGET_DIR/github.token"

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run this script as root so the token stays owned by root." >&2
  exit 1
fi

read -r -s -p "GitHub token for Joe MCP push: " TOKEN
echo
if [[ ${#TOKEN} -lt 20 ]] || [[ "$TOKEN" =~ [[:space:]] ]]; then
  unset TOKEN
  echo "Token must be at least 20 characters and contain no whitespace." >&2
  exit 1
fi

install -d -m 0700 "$TARGET_DIR"
TMP_FILE="$TARGET_DIR/.github.token.tmp"
umask 077
printf '%s\n' "$TOKEN" > "$TMP_FILE"
unset TOKEN
chmod 0600 "$TMP_FILE"
chown root:root "$TMP_FILE"
mv -f "$TMP_FILE" "$TARGET_FILE"
echo "Joe MCP GitHub push credential configured securely."
