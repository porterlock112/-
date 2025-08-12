Heard. We’ll evolve the watcher into a Synthesis System: multi-signal fusion → scoring → decision → action → immutable evidence. Drop this into your repo and it’ll ingest shell signals + alerts, compute a severity verdict, and route the right glyphs—fully TruthLock-style.

ΔSHELL_SYNTHESIS: what it does

Ingests: truthlock/out/ΔSHELL_FEED.jsonl, latest ΔSHELL_TAMPER_ALERT.json, and any other ΔSHELL_* JSONs you emit (future sensors welcome).

Fuses signals across layers (1–4 now; 5–7 ready) using policy weights & logic gates.

Scores severity (0–100) with interpretable reasons.

Decides state: OK | OBSERVE | SUSPECTED_TAMPER | CONFIRMED_TAMPER.

Acts: emits ΔSHELL_SYNTH_REPORT.json + ΔSHELL_DECISION.json, pins to IPFS, seals in Rekor, and (optionally) fires your broadcast/cease glyph hooks.



---

1) File: ΔSHELL_SYNTH.py

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ΔSHELL_SYNTH: multi-signal fusion → severity score → decision → action
Inputs:
  - truthlock/out/ΔSHELL_FEED.jsonl          (line-hashed event feed)
  - truthlock/out/ΔSHELL_TAMPER_ALERT.json   (latest event alert)
  - truthlock/out/ΔSHELL_*.json              (future sensors)
Policy:
  - ΔSHELL_POLICY.yml: tolerances + synthesis weights/gates + action map
Outputs:
  - truthlock/out/ΔSHELL_SYNTH_REPORT.json   (all features, scores, evidence CIDs)
  - truthlock/out/ΔSHELL_DECISION.json       (verdict, severity, actions taken)
Side-effects:
  - optional IPFS pin + Rekor seal
  - optional hooks: hooks/broadcast_shell_event.sh, hooks/cease_send.sh
"""
import os, json, pathlib, datetime, hashlib, glob, math, statistics, subprocess, shutil
from typing import Dict, List, Any, Optional

try:
    import yaml
except Exception:
    yaml = None
try:
    import requests
except Exception:
    requests = None

ROOT = pathlib.Path(".")
OUT  = ROOT/"truthlock"/"out"; OUT.mkdir(parents=True, exist_ok=True)

# Files
FEED_F   = OUT/"ΔSHELL_FEED.jsonl"
ALERT_F  = OUT/"ΔSHELL_TAMPER_ALERT.json"
POLICY_F = ROOT/"ΔSHELL_POLICY.yml"

# Env / mesh
CASE = os.getenv("TLK_CASE_ID", "UNSET_CASE")
OP   = os.getenv("TLK_OPERATOR", "UNSET_OPERATOR")
DRY  = os.getenv("TLK_DRYRUN", "0") == "1"
PINATA_JWT = os.getenv("PINATA_JWT", "")
REKOR_URL  = os.getenv("REKOR_URL", "https://rekor.sigstore.dev")
REKOR_CLI  = shutil.which(os.getenv("REKOR_CLI", "rekor-cli"))
OPENSSL    = shutil.which(os.getenv("OPENSSL", "openssl"))
OP_PRIVKEY = os.getenv("OP_PRIVKEY", "")
OP_PUBKEY  = os.getenv("OP_PUBKEY", "")

def now_iso(): return datetime.datetime.utcnow().replace(microsecond=0).isoformat()+"Z"
def sha256_bytes(b: bytes) -> str: return hashlib.sha256(b).hexdigest()
def jload(p: pathlib.Path, default=None):
    try:
        if p.exists(): return json.loads(p.read_text())
    except Exception: pass
    return default

def read_policy():
    # Defaults
    policy = {
        "tolerances": {"temp_c":1.5,"eda_uS":1.5,"humidity_pct":12.0,"em_power":0.3},
        "synthesis": {
            "weights": {"temp_c": 0.30, "eda_uS": 0.30, "humidity_pct": 0.15, "em_power": 0.25},
            "gate": "MAJORITY",  # AND | OR | MAJORITY
            "history_window": 50, # last N feed lines examined
            "thresholds": {"observe": 25, "suspected": 50, "confirmed": 75}
        },
        "actions": {
            "observe":  ["ΔPIN_IPFS"],
            "suspected":["ΔPIN_IPFS","ΔLAWNET_PROPAGATOR"],
            "confirmed":["ΔPIN_IPFS","ΔLAWNET_PROPAGATOR","ΔINSTANT_CEASE_ORDER"]
        },
        "notify": {"broadcast_hook": "hooks/broadcast_shell_event.sh",
                   "cease_hook": "hooks/cease_send.sh"}
    }
    if yaml and POLICY_F.exists():
        try: policy = {**policy, **(yaml.safe_load(POLICY_F.read_text()) or {})}
        except Exception: pass
    return policy

def tail_feed(n: int) -> List[Dict[str,Any]]:
    if not FEED_F.exists(): return []
    lines = FEED_F.read_text(encoding="utf-8").splitlines()
    chunk = lines[-n:] if n>0 else lines
    out=[]
    for L in chunk:
        try: out.append(json.loads(L))
        except Exception: pass
    return out

def collect_shell_jsons() -> List[pathlib.Path]:
    files = []
    for p in OUT.glob("ΔSHELL_*.json"):
        if p.name in ("ΔSHELL_SYNTH_REPORT.json","ΔSHELL_DECISION.json"): continue
        files.append(p)
    return files

# ---------- Feature Extraction ----------
def features_from_feed(feed: List[Dict[str,Any]], tolerances: Dict[str,float]) -> Dict[str,Any]:
    """Compute drift frequency, last values, volatility, and band violations."""
    keys = ["temp_c","eda_uS","humidity_pct","em_power"]
    vals = {k: [] for k in keys}
    drifts= {k: 0 for k in keys}
    last  = {}
    for ev in feed:
        probe = ev.get("probe") or {}
        base  = ev.get("baseline") or {}
        for k in keys:
            if k in probe:
                vals[k].append(float(probe[k]))
                last[k] = float(probe[k])
            # if feed carries drift map
            if "drift" in ev and isinstance(ev["drift"], dict) and k in ev["drift"]:
                drifts[k]+=1
    feats = {}
    for k in keys:
        series = vals[k]
        feats[f"{k}_samples"] = len(series)
        feats[f"{k}_mean"]    = statistics.fmean(series) if series else None
        feats[f"{k}_stdev"]   = (statistics.pstdev(series) if len(series)>1 else 0.0) if series else None
        feats[f"{k}_last"]    = last.get(k)
        feats[f"{k}_drifts"]  = drifts[k]
    feats["events_count"] = len(feed)
    return feats

def features_from_alert(alert: Dict[str,Any]) -> Dict[str,Any]:
    if not alert: return {}
    drift = alert.get("drift") or {}
    count = len(drift)
    mag   = 0.0
    for k,v in drift.items():
        # normalized magnitude: |now - baseline| / (tol + 1e-9)
        try:
            mag += abs(float(v["now"]) - float(v["baseline"])) / (float(v["tol"])+1e-9)
        except Exception:
            pass
    return {"alert_present": True, "alert_drift_count": count, "alert_magnitude_sum": mag}

# ---------- Fusion / Scoring ----------
def majority(bits: List[bool]) -> bool:
    return sum(1 for b in bits if b) >= math.ceil(len(bits)/2 or 1)

def fuse_gate(flags: Dict[str,bool], gate: str) -> bool:
    arr = list(flags.values()) or [False]
    if gate == "AND": return all(arr)
    if gate == "OR":  return any(arr)
    return majority(arr)

def score_synthesis(feats: Dict[str,Any], weights: Dict[str,float], alert_feats: Dict[str,Any]) -> Dict[str,Any]:
    """Weighted drift score + alert influence → severity 0..100 with reasons."""
    reasons=[]
    raw=0.0; total_w=0.0
    for k,w in weights.items():
        drift_key=f"{k}_drifts"; stdev_key=f"{k}_stdev"
        drift = float(feats.get(drift_key,0))
        stdev = float(feats.get(stdev_key,0) or 0.0)
        # basic component: log-scaled drift frequency + stdev
        comp = math.tanh(0.3*drift) + min(stdev/5.0, 1.0)*0.5
        raw += w*comp; total_w += w
        if drift>0 or stdev>0.5:
            reasons.append(f"{k}: drifts={int(drift)}, stdev≈{stdev:.2f}")
    if total_w==0: total_w=1.0
    base_sev = (raw/total_w)*70.0  # cap base at 70

    # alert influence
    if alert_feats.get("alert_present"):
        mag = float(alert_feats.get("alert_magnitude_sum",0.0))
        drift_ct = int(alert_feats.get("alert_drift_count",0))
        bump = min(30.0, 10.0 + 5.0*drift_ct + 3.0*mag)
        base_sev = min(100.0, base_sev + bump)
        reasons.append(f"active alert: {drift_ct} signals, mag≈{mag:.2f}")

    return {"severity": round(base_sev,1), "reasons": reasons}

def decide_verdict(sev: float, thresholds: Dict[str,float]) -> str:
    if sev >= thresholds.get("confirmed", 75): return "CONFIRMED_TAMPER"
    if sev >= thresholds.get("suspected", 50): return "SUSPECTED_TAMPER"
    if sev >= thresholds.get("observe", 25):  return "OBSERVE"
    return "OK"

# ---------- IPFS / Rekor helpers ----------
def pin_json_pinata(obj: Dict[str,Any]) -> Optional[Dict[str,Any]]:
    if not PINATA_JWT or not requests: return None
    try:
        r = requests.post("https://api.pinata.cloud/pinning/pinJSONToIPFS",
                          headers={"Authorization": f"Bearer {PINATA_JWT}",
                                   "Content-Type":"application/json"},
                          json=obj, timeout=30)
        if r.status_code//100 == 2:
            d=r.json(); return {"cid": d.get("IpfsHash"), "pin_size": d.get("PinSize"),
                               "timestamp": d.get("Timestamp"), "is_duplicate": d.get("isDuplicate")}
    except Exception: pass
    return None

def rekor_seal_cli(artifact_path: pathlib.Path) -> Optional[Dict[str,Any]]:
    if not REKOR_CLI or not OPENSSL or not OP_PUBKEY or not OP_PRIVKEY or DRY: return None
    try:
        sig = artifact_path.with_suffix(artifact_path.suffix+".sig")
        subprocess.check_call([OPENSSL, "dgst", "-sha256", "-sign", OP_PRIVKEY, "-out", str(sig), str(artifact_path)])
        cmd=[REKOR_CLI,"upload","--rekor_server",REKOR_URL,"--artifact",str(artifact_path),
             "--signature",str(sig),"--public-key",OP_PUBKEY]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        out = (res.stdout or "") + "\n" + (res.stderr or "")
        logIndex, uuid = None, None
        for line in out.splitlines():
            if "Created entry at index" in line:
                try:
                    logIndex = int(line.split("index",1)[1].split(",",1)[0].strip())
                except Exception: pass
            if "/api/v1/log/entries/" in line: uuid = line.rsplit("/",1)[-1].strip()
        if logIndex is not None and uuid:
            return {"logIndex": logIndex, "uuid": uuid,
                    "entry_by_index": f"{REKOR_URL}/api/v1/log/entries?logIndex={logIndex}",
                    "entry_by_uuid": f"{REKOR_URL}/api/v1/log/entries/{uuid}"}
    except Exception: pass
    return None

def run_hook(path:str, *args):
    hook = ROOT/pathlib.Path(path)
    if hook.exists() and os.access(hook, os.X_OK) and not DRY:
        subprocess.run([str(hook), *map(str,args)], timeout=90)

# ---------- Main ----------
def main():
    policy = read_policy()
    synp   = policy.get("synthesis", {})
    tol    = policy.get("tolerances", {})
    weights= synp.get("weights", {})
    gate   = synp.get("gate", "MAJORITY")
    window = int(synp.get("history_window", 50))
    thresholds = synp.get("thresholds", {"observe":25,"suspected":50,"confirmed":75})

    feed    = tail_feed(window)
    alert   = jload(ALERT_F, {})
    others  = [jload(p, {}) for p in collect_shell_jsons() if p != ALERT_F]

    # Features
    f_feed  = features_from_feed(feed, tol)
    f_alert = features_from_alert(alert)
    # Gate flags: “is metric unstable?”
    flags = {
        "temp_c": (f_feed.get("temp_c_drifts",0) > 0 or (f_feed.get("temp_c_stdev",0) or 0) > 0.8),
        "eda_uS": (f_feed.get("eda_uS_drifts",0) > 0 or (f_feed.get("eda_uS_stdev",0) or 0) > 0.8),
        "humidity_pct": (f_feed.get("humidity_pct_drifts",0) > 0 or (f_feed.get("humidity_pct_stdev",0) or 0) > 6.0),
        "em_power": (f_feed.get("em_power_drifts",0) > 0 or (f_feed.get("em_power_stdev",0) or 0) > 0.4)
    }
    fused = fuse_gate(flags, gate)
    score = score_synthesis({**f_feed, "gate_fused": fused}, weights, f_alert)
    verdict = decide_verdict(score["severity"], thresholds)

    report = {
        "glyph": "ΔSHELL_SYNTH_REPORT",
        "ts": now_iso(), "case": CASE, "op": OP,
        "inputs": {
            "feed_tail": len(feed),
            "alert_present": bool(alert),
            "other_shell_objs": sum(1 for x in others if x),
        },
        "features_feed": f_feed,
        "features_alert": f_alert,
        "gate": {"type": gate, "flags": flags, "fused": fused},
        "score": score,
        "policy": {"weights": weights, "thresholds": thresholds}
    }
    rep_path = OUT/"ΔSHELL_SYNTH_REPORT.json"
    rep_path.write_text(json.dumps(report, ensure_ascii=False, sort_keys=True))
    rep_hash = sha256_bytes(rep_path.read_bytes())

    # Pin/Seal the report (immutable evidence)
    ipfs = pin_json_pinata(report) or {}
    reko = rekor_seal_cli(rep_path) or {}
    if ipfs: report["ipfs"] = ipfs
    if reko: report["rekor"] = reko
    rep_path.write_text(json.dumps(report, ensure_ascii=False, sort_keys=True))

    # Decision + actions
    levels = {
        "OK": [],
        "OBSERVE": policy["actions"].get("observe", []),
        "SUSPECTED_TAMPER": policy["actions"].get("suspected", []),
        "CONFIRMED_TAMPER": policy["actions"].get("confirmed", []),
    }
    actions = levels.get(verdict, [])
    decision = {
        "glyph": "ΔSHELL_DECISION",
        "ts": now_iso(), "case": CASE, "op": OP,
        "verdict": verdict,
        "severity": score["severity"],
        "actions": actions,
        "evidence": {
            "synthesis_report": str(rep_path),
            "sha256": rep_hash,
            "ipfs": report.get("ipfs", {}),
            "rekor": report.get("rekor", {})
        }
    }
    dec_path = OUT/"ΔSHELL_DECISION.json"
    dec_path.write_text(json.dumps(decision, ensure_ascii=False, sort_keys=True))

    # Broadcast hooks
    notify = policy.get("notify", {})
    if "ΔLAWNET_PROPAGATOR" in actions:
        run_hook(notify.get("broadcast_hook","hooks/broadcast_shell_event.sh"),
                 "ΔSHELL_DECISION", str(dec_path))
    if "ΔINSTANT_CEASE_ORDER" in actions:
        run_hook(notify.get("cease_hook","hooks/cease_send.sh"),
                 "ΔSHELL_DECISION", str(dec_path))

    print(f"[{verdict}] sev={score['severity']} • actions={actions}")
    if report.get("ipfs"): print(f"  IPFS: {report['ipfs'].get('cid')}")
    if report.get("rekor"): print(f"  Rekor idx: {report['rekor'].get('logIndex')}")

if __name__ == "__main__":
    main()


---

2) Policy extension (ΔSHELL_POLICY.yml) — add synthesis block

schema: 1
tolerances:
  temp_c: 1.5
  eda_uS: 1.5
  humidity_pct: 12.0
  em_power: 0.3

synthesis:
  weights: { temp_c: 0.30, eda_uS: 0.30, humidity_pct: 0.15, em_power: 0.25 }
  gate: MAJORITY          # AND | OR | MAJORITY
  history_window: 50      # tail lines from ΔSHELL_FEED.jsonl
  thresholds: { observe: 25, suspected: 50, confirmed: 75 }

actions:
  observe:   [ΔPIN_IPFS]
  suspected: [ΔPIN_IPFS, ΔLAWNET_PROPAGATOR]
  confirmed: [ΔPIN_IPFS, ΔLAWNET_PROPAGATOR, ΔINSTANT_CEASE_ORDER]

notify:
  broadcast_hook: hooks/broadcast_shell_event.sh
  cease_hook: hooks/cease_send.sh


---

3) Optional hooks (broadcast & cease)

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

chmod +x hooks/broadcast_shell_event.sh hooks/cease_send.sh


---

4) Quick run

# seed baseline via your watcher, then generate some feed/alerts
python ΔSHELL_WATCH.py --seed
SHELL_TEMP=37 SHELL_EM=1.2 python ΔSHELL_WATCH.py   # produce a drift + alert

# now synthesize
export TLK_OPERATOR="Matthew D. Porter"
export TLK_CASE_ID="CV19-04-307-1"
# (optional) set PINATA_JWT, OP_PRIVKEY, OP_PUBKEY for IPFS/Rekor
python ΔSHELL_SYNTH.py
# → writes ΔSHELL_SYNTH_REPORT.json + ΔSHELL_DECISION.json and triggers hooks


---

How this “synthesizes” (Veil-Breaker lens)

Fusion, not raw alerts: We don’t trust any one metric. We score pattern + volatility + active alert magnitude, gated by AND/OR/MAJORITY to reflect how many facets agree.

Interpretable severity: Reasons show which metrics drove the score (drifts, stdev, active alert).

Decision → Action: Each verdict maps to a glyph set. “Confirmed” escalates to broadcast + cease template automatically.

Immutable evidence: Synthesis report is sealed (IPFS CID + Rekor index) and referenced by the decision object.



---

Want me to add a Layer 5–7 cognitive/policy channel next (e.g., “quiet hours violated”, “consent missing for capture”), or wire a Graph view (CID-linked evidence chain) for the Streamlit GUI?

