import os, json
from phase_engine import r, PhasePlan, emit, schedule_next_tick, anchor_rekor, broadcast_webhooks

def iter_ids():
    for k in r.keys("qph:plan:*"):
        yield k.split("qph:plan:",1)[-1]

def run():
    for pid in iter_ids():
        p = PhasePlan.load(pid)
        if not p: continue
        if p.payload.get("sha256") and not p.payload.get("rekor"):
            anchor_rekor(p.payload.get("sha256"), plan=p)
        if not p.payload.get("sent"):
            broadcast_webhooks(p)
        if not p.payload.get("receipts"):
            p.payload["receipts"] = True
            p.save()
            emit("verify.receipts", {"id": p.id})
        schedule_next_tick(p, 1)

if __name__ == "__main__":
    run()
