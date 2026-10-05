#!/usr/bin/env bash
# End-to-end demo: issue, verify offline, fetch receipt by serial, tamper rejection.
set -euo pipefail
cd "$(dirname "$0")/.."

PY=.venv/bin/python
export TSA_DATA_DIR="${TSA_DATA_DIR:-data}"
HOST=127.0.0.1
PORT=8016
BASE="http://$HOST:$PORT"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"; kill "$SERVER_PID" 2>/dev/null || true' EXIT

echo "== start server (generates demo PKI in $TSA_DATA_DIR on first run) =="
"$PY" -m uvicorn signature_evidence210.main:app --host "$HOST" --port "$PORT" &
SERVER_PID=$!
for _ in $(seq 1 50); do
  curl -fsS "$BASE/tsa/cert" -o "$WORK/tsa.pem" 2>/dev/null && break
  sleep 0.2
done
curl -fsS "$BASE/tsa/chain" -o "$WORK/chain.pem"
awk 'BEGIN{n=0} /BEGIN CERT/{n++} {print > ("'$WORK'/cert" n ".pem")}' "$WORK/chain.pem"
cp "$WORK/cert2.pem" "$WORK/ca.pem"   # second cert in chain file is the root CA

echo "== build query for a message digest =="
echo "archive-summary-v1" > "$WORK/msg.txt"
openssl ts -query -data "$WORK/msg.txt" -sha256 -cert -out "$WORK/req.tsq"

echo "== POST /tsa =="
curl -fsS -X POST "$BASE/tsa" \
  -H "Content-Type: application/timestamp-query" \
  --data-binary @"$WORK/req.tsq" \
  -o "$WORK/resp.tsr"
openssl ts -reply -in "$WORK/resp.tsr" -text | sed -n '1,20p'

echo "== offline verify with openssl =="
openssl ts -verify -data "$WORK/msg.txt" -in "$WORK/resp.tsr" -CAfile "$WORK/ca.pem"

SERIAL_HEX=$(openssl ts -reply -in "$WORK/resp.tsr" -text | awk '/Serial number/{print $3}')
SERIAL=$(printf '%d' "$SERIAL_HEX")
echo "== fetch original receipt by serial $SERIAL =="
curl -fsS "$BASE/tsa/receipt/$SERIAL" -o "$WORK/byserial.tsr"
cmp "$WORK/resp.tsr" "$WORK/byserial.tsr" && echo "receipt matches issued token"

echo "== tampered token must be rejected =="
"$PY" - "$WORK/resp.tsr" "$WORK/bad.tsr" <<'EOF'
import sys
data = bytearray(open(sys.argv[1], "rb").read())
data[-20] ^= 0xFF
open(sys.argv[2], "wb").write(bytes(data))
EOF
if openssl ts -verify -data "$WORK/msg.txt" -in "$WORK/bad.tsr" -CAfile "$WORK/ca.pem" 2>/dev/null; then
  echo "ERROR: tampered token verified!" >&2; exit 1
else
  echo "tampered token rejected as expected"
fi

echo "== unknown policy is refused with PKIStatusInfo =="
openssl ts -query -data "$WORK/msg.txt" -sha256 -tspolicy 1.2.3.4 -out "$WORK/badpol.tsq"
curl -fsS -X POST "$BASE/tsa" \
  -H "Content-Type: application/timestamp-query" \
  --data-binary @"$WORK/badpol.tsq" -o "$WORK/badpol.tsr"
openssl ts -reply -in "$WORK/badpol.tsr" -text | sed -n '1,6p'
echo "== demo done =="
