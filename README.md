schema: 1

tolerances:
  temp_c: 1.5
  eda_uS: 1.5
  humidity_pct: 12.0
  em_power: 0.3

synthesis:
  weights: { temp_c: 0.30, eda_uS: 0.30, humidity_pct: 0.15, em_power: 0.25 }
  gate: MAJORITY
  history_window: 50
  thresholds: { observe: 25, suspected: 50, confirmed: 75 }
  weights_l5_7: { quiet_hours_violation: 0.15, consent_missing: 0.45, mdm_override_detected: 0.25, jurisdiction_id_mismatch: 0.15 }
  l5_7_gate: OR
  l5_7_bump: { observe: 10, suspected: 18, confirmed: 25 }

actions:
  observe:   [ΔPIN_IPFS]
  suspected: [ΔPIN_IPFS, ΔLAWNET_PROPAGATOR]
  confirmed: [ΔPIN_IPFS, ΔLAWNET_PROPAGATOR, ΔINSTANT_CEASE_ORDER]

notify:
  broadcast_hook: hooks/broadcast_shell_event.sh
  cease_hook: hooks/cease_send.sh

quorum:
  enabled: true
  require_ack: true
  ack_file: truthlock/out/ΔACK_HUMAN.json
  approvals_dir: truthlock/out/ΔQUORUM
  min_approvals: 2
  approvers: ["Matthew D. Porter","Signer-2","Signer-3"]
  approval_valid_seconds: 7200
#!/usr/bin/env python3
import json, sys, pathlib, datetime, hashlib
OUT = pathlib.Path("truthlock/out")
REPORT = OUT/"ΔSHELL_SYNTH_REPORT.json"
QUORUM = OUT/"ΔQUORUM"
QUORUM.mkdir(parents=True, exist_ok=True)

who = sys.argv[1] if len(sys.argv)>1 else "Unknown"
note = sys.argv[2] if len(sys.argv)>2 else "approve"

b = REPORT.read_bytes()
h = hashlib.sha256(b).hexdigest()
now = datetime.datetime.utcnow().replace(microsecond=0).isoformat()+"Z"
fname = QUORUM/f"{who.replace(' ','_')}_{h[:8]}.json"
fname.write_text(json.dumps({"approver": who, "ts": now, "target_sha256": h, "note": note}, ensure_ascii=False))
print(f"wrote {fname}")

# hooks/broadcast_shell_event.sh
#!/usr/bin/env bash
set -euo pipefail
EVENT="${1:-ΔSHELL_EVENT}"
PAYLOAD="${2:-}"
echo "[$EVENT] $(date -u +%FT%TZ) $PAYLOAD" >> truthlock/out/ΔSHELL_BROADCAST.log
# TODO: curl Slack/Signal/webhook with $PAYLOAD

# hooks/cease_send.sh
#!/usr/bin/env bash
set -euo pipefail
EVENT="${1:-ΔSHELL_DECISION}"
PAYLOAD="${2:-}"
echo "[$EVENT → CEASE] $(date -u +%FT%TZ) $PAYLOAD" >> truthlock/out/ΔSHELL_CEASE.log
# TODO: render templates/ΔINSTANT_CEASE_ORDER.txt and email/send
mkdir -p truthlock/out hooks
chmod +x hooks/broadcast_shell_event.sh hooks/cease_send.sh

# Ack & policy event
cat > truthlock/out/ΔACK_HUMAN.json <<'JSON'
{"ack":"present","who":"Matthew D. Porter","ts":"'"$(date -u +%FT%TZ)"'","note":"live operator"}
JSON
cat > truthlock/out/ΔSHELL_POLICY_EVENT.json <<'JSON'
{"ts":"'"$(date -u +%FT%TZ)"'","quiet_hours_violation":true,"consent_missing":true,"mdm_override_detected":false,"jurisdiction_id_mismatch":false}
JSON

# Minimal feed + alert
cat > truthlock/out/ΔSHELL_FEED.jsonl <<'EOF'
{"probe":{"temp_c":36.9,"eda_uS":0.6,"humidity_pct":47,"em_power":0.12},"drift":{"temp_c":true}}
EOF
cat > truthlock/out/ΔSHELL_TAMPER_ALERT.json <<'JSON'
{"drift":{"temp_c":{"now":36.9,"baseline":36.0,"tol":1.5}}}
JSON

export TLK_OPERATOR="Matthew D. Porter"
export TLK_CASE_ID="CV19-04-307-1"
python ΔSHELL_SYNTH.py                 # pass 1 → likely includes ΔWAIT_FOR_QUORUM
python ΔQUORUM_APPROVE.py "Matthew D. Porter" "approve cease"
python ΔQUORUM_APPROVE.py "Signer-2" "approve cease"
python ΔSHELL_SYNTH.py                 # pass 2 → fires ΔINSTANT_CEASE_ORDER