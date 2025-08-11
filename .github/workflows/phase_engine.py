import os, json, time, hashlib
from typing import Optional, Dict, Any, List
import redis

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
r = redis.Redis.from_url(REDIS_URL, decode_responses=True)

KEY_PLAN = "qph:plan:{id}"
KEY_SCHEDULE = "qph:schedule"

PHASES = ["ESTABLISH","PHRASE","SEAL","SYNC","CONFIRM","SEND","VERIFY"]

def emit(topic: str, payload: Dict[str, Any]):
    try:
        r.publish("qph:events", json.dumps({"event": topic, "data": payload}))
    except Exception:
        pass

class PhasePlan:
    def __init__(self, id: str, thread: str, stage: str="PHRASE", payload: Optional[Dict[str,Any]]=None, scp: Optional[str]=None):
        self.id = id
        self.thread = thread
        self.stage = stage
        self.payload = payload or {}
        self.scp = scp or self.payload.get("scp") or "SCP:auto"
    def key(self): return KEY_PLAN.format(id=self.id)
    def save(self):
        r.set(self.key(), json.dumps({"id": self.id, "thread": self.thread, "stage": self.stage, "payload": self.payload, "scp": self.scp}))
    @classmethod
    def load(cls, id: str) -> Optional["PhasePlan"]:
        raw = r.get(KEY_PLAN.format(id=id))
        if not raw: return None
        obj = json.loads(raw)
        return cls(id=obj["id"], thread=obj["thread"], stage=obj["stage"], payload=obj["payload"], scp=obj.get("scp"))
    def advance(self):
        idx = PHASES.index(self.stage)
        if idx < len(PHASES)-1:
            self.stage = PHASES[idx+1]
    def execute(self):
        # Minimal demo actions for each stage
        if self.stage == "PHRASE":
            # Derive SCP
            self.scp = self.scp or f"SCP:{self.thread}-{int(time.time())}"
            emit("phase.phrase", {"id": self.id, "scp": self.scp})
        elif self.stage == "SEAL":
            # Compute sha256 of normalized payload (demo uses payload itself)
            b = json.dumps(self.payload, sort_keys=True).encode()
            self.payload["sha256"] = hashlib.sha256(b).hexdigest()
            emit("phase.seal", {"id": self.id, "sha256": self.payload["sha256"]})
        elif self.stage == "SYNC":
            # Pin to IPFS (stub: synthesize CID)
            cid = "bafy" + (self.payload.get("sha256","nohash")[:8])
            self.payload["cid"] = cid
            emit("ipfs.pinned", {"id": self.id, "cid": cid})
        elif self.stage == "CONFIRM":
            anchor_rekor(self.payload.get('sha256',''), plan=self)
        elif self.stage == "SEND":
            broadcast_webhooks(self)
        elif self.stage == "VERIFY":
            # Do nothing; receipts get flipped via /qph/ack
            pass
        self.save()

def _parse_seconds(s: str) -> int:
    s = s.strip().lower()
    if s.endswith("ms"): return max(1, int(int(s[:-2]) / 1000))
    if s.endswith("s"): return int(s[:-1])
    if s.endswith("m"): return int(s[:-1]) * 60
    if s.endswith("h"): return int(s[:-1]) * 3600
    return int(s)

def schedule_next_tick(plan: PhasePlan, delay_seconds: int=0):
    ts = int(time.time()) + delay_seconds
    r.zadd(KEY_SCHEDULE, {plan.id: ts})

def store_plan(event: Dict[str, Any]) -> PhasePlan:
    pid = event["id"]
    thread = event.get("thread_id") or event.get("thread") or "th_anon"
    plan = PhasePlan(id=pid, thread=thread, stage="PHRASE", payload={"event": event}, scp=f"SCP:{thread}")
    plan.save()
    emit("plan.created", {"id": pid, "thread": thread})
    return plan

# ---------- Actions ----------

def anchor_rekor(sha256: str, *, plan: PhasePlan=None) -> None:
    simulate = os.getenv("REKOR_SIMULATE","false").lower()=="true"
    if simulate:
        out = {"ok": False, "simulate": True, "reason": "REKOR_SIMULATE=true"}
        plan.payload.setdefault("rekor", out)
        plan.save()
        emit("rekor.skip", {"id": plan.id, **out})
        return
    pubkey = os.getenv("REKOR_PUBKEY_PATH")
    sig_path = os.getenv("REKOR_SIG_PATH")
    if not (pubkey and sig_path and os.path.exists(sig_path) and os.path.exists(pubkey)):
        emit("rekor.skip", {"id": plan.id, "reason": "No signature/pubkey; set REKOR_* or REKOR_SIMULATE=true"})
        return
    from rekor_client import anchor_blob_and_sig
    blob = json.dumps(plan.payload, sort_keys=True).encode()
    with open(sig_path, "rb") as f: sig = f.read()
    out = anchor_blob_and_sig(blob, sig, pubkey)
    plan.payload.setdefault("rekor", out)
    plan.save()
    emit("rekor.anchored", {"id": plan.id, **out})

def broadcast_webhooks(plan: PhasePlan) -> None:
    # Placeholder for real sends
    plan.payload["sent"] = True
    plan.save()
    emit("send.broadcast", {"id": plan.id, "sent": True})

# drive telemetry
def publish_car(plan: PhasePlan):
    try:
        from drive_telemetry import publish_car as _pc
        _pc(plan)
    except Exception:
        pass

def run_one(plan_id: str):
    p = PhasePlan.load(plan_id)
    if not p: return
    # ensure stage-specific operations
    if p.stage == "CONFIRM":
        anchor_rekor(p.payload.get("sha256",""), plan=p)
    elif p.stage == "SEND":
        broadcast_webhooks(p)
    # publish map telemetry every step
    publish_car(p)
    # advance if possible
    if p.stage != "VERIFY":
        p.advance()
        p.save()
        schedule_next_tick(p, 1)
