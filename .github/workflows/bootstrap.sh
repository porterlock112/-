#!/usr/bin/env bash
set -euo pipefail

API="${API:-http://localhost:8000}"
TEST_ID="${TEST_ID:-msg_demo_001}"
TEST_THREAD="${TEST_THREAD:-th_alpha}"

if [ ! -f .env ]; then
  cp .env.sample .env
  echo "[ΔAUTORUN] Wrote .env from sample."
fi

docker compose up -d --build

echo -n "[ΔAUTORUN] Waiting for API"
for i in $(seq 1 60); do
  if curl -sf "$API/health" >/dev/null; then echo " ok"; break; fi
  echo -n "."; sleep 1
done

BODY="{\"type\":\"thread.message.created\",\"data\":{\"id\":\"$TEST_ID\",\"thread_id\":\"$TEST_THREAD\",\"role\":\"user\",\"created\":$(date +%s)}}"
SIG=$(python - "$BODY" <<'PY'
import os,sys,hmac,hashlib,json
secret=os.environ.get("OPENAI_WEBHOOK_SECRET","change-me").encode()
body=sys.argv[1].encode()
print(hmac.new(secret, body, hashlib.sha256).hexdigest())
PY
)

curl -sS -X POST "$API/hooks/openai" -H "Content-Type: application/json" -H "openai-signature: $SIG" -d "$BODY" | sed 's/.*/[ΔAUTORUN] hook -> &/'

docker compose exec -T redis sh -lc 'redis-cli KEYS "qph:plan:*" | while read k; do id="${k#qph:plan:}"; redis-cli ZADD qph:schedule $(date +%s) "$id" >/dev/null; done'
echo "[ΔAUTORUN] Forced ticks."

sleep 2
echo "[ΔAUTORUN] Scope:"
curl -sS "$API/qph/scope" || true

echo "[ΔAUTORUN] Search:"
curl -sS "$API/qph/search?q=$TEST_ID" || true
