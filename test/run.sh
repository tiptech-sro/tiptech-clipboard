#!/usr/bin/env bash
# Spin up a throwaway server.py and run the e2e suite against it.
set -e
cd "$(dirname "$0")/.."
TMP="$(mktemp -d)"
export CLIPBOARD_PORT=8471 CLIPBOARD_CAPTCHA=0 CLIPBOARD_DATA_DIR="$TMP" CLIPBOARD_MAX_MB=20
python3 server.py >/tmp/clip_test_server.log 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null; rm -rf "$TMP"' EXIT
# wait for it to listen
for i in $(seq 1 30); do
  curl -s -o /dev/null "http://127.0.0.1:8471/api/config" && break
  sleep 0.2
done
BASE="http://127.0.0.1:8471" node test/e2e.mjs
