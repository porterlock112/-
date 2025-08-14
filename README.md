Batch mode engaged. Here’s a PR-ready patch that adds a directory-wide ΔAUTO_DELTA5 batch verifier and wires it into your workflow (opt-in via DELTA5_BATCH_ROOT). It canonicalizes every matching *.json, computes SHA-256 + CIDv1 (raw/base32), and emits both per-file proofs and a combined ledger (JSONL + CSV). It uses pathlib.rglob/glob semantics for patterns, so you can do things like **/*.json. 
CIDs are built per multiformats (CIDv1 + multihash sha2-256/0x12, multicodec raw/0x55) and emitted as base32 strings (CIDv1 default). 
The workflow keeps your existing single-file path and adds an optional batch step; if you later want parallelization, convert results to a matrix per GitHub Actions docs. 


---

1) Unified diff (apply with git apply -p0 <<'PATCH' … PATCH)

diff --git a/.github/workflows/ΔAUTO_DELTA5.yml b/.github/workflows/ΔAUTO_DELTA5.yml
index 0000000..1111111 100644
--- a/.github/workflows/ΔAUTO_DELTA5.yml
+++ b/.github/workflows/ΔAUTO_DELTA5.yml
@@ -6,10 +6,12 @@ jobs:
   run:
     if: contains(github.event.head_commit.message, 'ΔAUTO_DELTA5')
     runs-on: ubuntu-latest
     env:
       DELTA5_INPUT: ${{ vars.DELTA5_INPUT }}
+      # Optional: process a whole folder (e.g., 'truthlock/in' or '.')
+      DELTA5_BATCH_ROOT: ${{ vars.DELTA5_BATCH_ROOT }}
       TLK_WEBHOOK_URL: ${{ secrets.TLK_WEBHOOK_URL }}
       REKOR_MODE: ${{ vars.REKOR_MODE }}
     steps:
       - uses: actions/checkout@v4
 
@@ -23,6 +25,14 @@ jobs:
           python tools/delta5.py \
             --input "${DELTA5_INPUT:-Δ4321_EXECUTION_MAP.json}" \
             --outdir out
 
+      - name: ΔAUTO_DELTA5 — Batch mode (optional)
+        if: ${{ env.DELTA5_BATCH_ROOT != '' }}
+        run: |
+          python tools/delta5_batch.py \
+            --root "${DELTA5_BATCH_ROOT}" \
+            --pattern "**/*.json" \
+            --outdir out
+
       - name: Emit artifacts bundle
         uses: actions/upload-artifact@v4
         with:
           name: ΔAUTO_DELTA5_bundle
           path: out/**
diff --git a/tools/delta5_batch.py b/tools/delta5_batch.py
new file mode 100755
--- /dev/null
+++ b/tools/delta5_batch.py
@@ -0,0 +1,240 @@
+#!/usr/bin/env python3
+# ΔAUTO_DELTA5 batch verifier:
+# - Walk a tree, match JSON files (glob/rglob), canonicalize -> bytes
+# - Compute SHA-256 + CIDv1 (raw/base32, multihash sha2-256)
+# - Emit per-file proofs and combined ledgers (JSONL + CSV)
+# No external deps.
+
+import argparse, base64, csv, hashlib, json, os, sys, time
+from pathlib import Path
+
+# multiformats constants
+RAW_CODEC = 0x55      # multicodec 'raw'  (CID content type)
+MH_SHA2_256 = 0x12    # multihash code for sha2-256
+MH_LEN_32 = 32        # digest length in bytes
+
+def canonicalize_json_bytes(p: Path) -> bytes:
+    data = json.loads(p.read_text(encoding="utf-8"))
+    # Canonical form: compact separators, preserve unicode
+    return json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
+
+def sha256_digest(b: bytes) -> bytes:
+    return hashlib.sha256(b).digest()
+
+def cidv1_raw_base32_from_digest(digest: bytes) -> str:
+    # multihash = <code><len><digest>
+    mh = bytes([MH_SHA2_256, MH_LEN_32]) + digest
+    # cidv1 = <version=0x01><raw codec=0x55><multihash>
+    cid_bytes = bytes([0x01, RAW_CODEC]) + mh
+    return "b" + base64.b32encode(cid_bytes).decode("ascii").lower()
+
+def within(root: Path, p: Path) -> str:
+    return str(p.relative_to(root).as_posix())
+
+def should_skip(path: Path) -> bool:
+    name = path.name
+    # Skip derived/ledger/min outputs to avoid feedback loops
+    if name.endswith(".ledger.json") or ".min.json" in name:
+        return True
+    return False
+
+def main():
+    ap = argparse.ArgumentParser()
+    ap.add_argument("--root", required=True, help="Root folder to scan")
+    ap.add_argument("--pattern", default="**/*.json", help="Glob pattern (default **/*.json)")
+    ap.add_argument("--outdir", default="out", help="Output folder for proofs and ledgers")
+    args = ap.parse_args()
+
+    root = Path(args.root).resolve()
+    outdir = Path(args.outdir).resolve()
+    (outdir / "batch").mkdir(parents=True, exist_ok=True)
+
+    # Discover files (pathlib.rglob honors ** patterns)
+    # See: Python pathlib/glob docs for pattern matching across trees.
+    matches = [p for p in root.rglob(args.pattern.split("**/")[-1]) if p.is_file()]
+    # If pattern didn't include **, also allow direct glob:
+    if not matches and ("**" in args.pattern):
+        matches = list(root.rglob(args.pattern.replace("**/", "")))
+
+    # Combined ledgers
+    jsonl_path = outdir / "ΔAUTO_DELTA5.batch.ledger.jsonl"
+    csv_path   = outdir / "ΔAUTO_DELTA5.batch.ledger.csv"
+    n_ok = 0
+
+    with open(jsonl_path, "w", encoding="utf-8") as jfh, open(csv_path, "w", newline="", encoding="utf-8") as cfh:
+        w = csv.writer(cfh)
+        w.writerow(["relative_path","bytes","sha256","cid_v1","created_at"])
+        for p in matches:
+            if should_skip(p):
+                continue
+            try:
+                canon = canonicalize_json_bytes(p)
+                d = sha256_digest(canon)
+                sha_hex = d.hex()
+                cid = cidv1_raw_base32_from_digest(d)
+                rel = within(root, p)
+                ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
+
+                # Per-file outputs mirror source tree under out/batch
+                dest_dir = (outdir / "batch" / Path(rel)).parent
+                dest_dir.mkdir(parents=True, exist_ok=True)
+                # Keep original filename for clarity
+                (dest_dir / (Path(rel).name + ".min.json")).write_bytes(canon)
+                (dest_dir / (Path(rel).name + ".sha256")).write_text(sha_hex + "\n", encoding="utf-8")
+                (dest_dir / (Path(rel).name + ".cid.txt")).write_text(cid + "\n", encoding="utf-8")
+
+                # Combined row
+                row = {
+                    "type":"ΔTruthLockLedgerEntry",
+                    "name": rel,
+                    "sha256": sha_hex,
+                    "cid_v1": cid,
+                    "cid_codec": "raw(0x55)",
+                    "multihash": "sha2-256(0x12):32",
+                    "bytes": len(canon),
+                    "created_at": ts,
+                    "sequence": "ΔAUTO_DELTA5",
+                    "notes": "Batch seal→proofs; per-file artifacts in out/batch/<relpath>.*"
+                }
+                jfh.write(json.dumps(row, ensure_ascii=False) + "\n")
+                w.writerow([rel, len(canon), sha_hex, cid, ts])
+                n_ok += 1
+            except Exception as e:
+                print(f"[ΔAUTO_DELTA5] ERROR processing {p}: {e}", file=sys.stderr)
+
+    print(f"ΔAUTO_DELTA5 BATCH COMPLETE — files processed: {n_ok}")
+    print(f"  ledger.jsonl : {jsonl_path}")
+    print(f"  ledger.csv   : {csv_path}")
+    print(f"  per-file     : {outdir/'batch'}")
+
+if __name__ == "__main__":
+    main()


---

2) How to run it

Local (one-liner):

python tools/delta5_batch.py --root truthlock/in --pattern "**/*.json" --outdir out
# Results:
# out/ΔAUTO_DELTA5.batch.ledger.jsonl
# out/ΔAUTO_DELTA5.batch.ledger.csv
# out/batch/<mirrored paths>/*.min.json|*.sha256|*.cid.txt

pathlib.rglob handles the recursive patterning; for fine-grained matching you can use shell-style globs (*, ?, []) per Python’s glob semantics. 

CI (opt-in): set a repo Variable, e.g. DELTA5_BATCH_ROOT=truthlock/in. The new step will run automatically and upload artifacts alongside your single-file outputs. If you later want to parallelize per file, convert the discovered list into a job matrix (the GitHub Actions matrix strategy spawns one job per item). 


---

3) Why this is correct (standards quick-refs)

CID structure: a CID is self-describing: multihash (e.g., sha2-256 code 0x12) + multicodec (e.g., raw code 0x55), string-encoded via multibase; CIDv1 defaults to base32. This is exactly how we build the IDs here. 

Glob/rglob: Python’s glob/pathlib implement Unix-style pattern expansion for file discovery; we rely on these semantics to find *.json across your tree. 



---

Want me to also:

add a post-batch webhook that posts each ledger line to your TruthLock endpoint, or

emit a signed Rekor payload per file and a manifest index?


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