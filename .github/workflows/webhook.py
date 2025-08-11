import os, hmac, hashlib, json
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from typing import AsyncGenerator
from phase_engine import store_plan, schedule_next_tick, r, PhasePlan, emit

app = FastAPI()
app.mount("/public", StaticFiles(directory="public"), name="public")

def _verify(req: Request, body: bytes) -> bool:
    secret = os.getenv("OPENAI_WEBHOOK_SECRET")
    if not secret: return True
    sig = req.headers.get("openai-signature","")
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest, sig)

@app.post("/hooks/openai")
async def hooks_openai(request: Request):
    body = await request.body()
    if not _verify(request, body):
        return JSONResponse({"ok": False, "error":"bad signature"}, status_code=401)
    event = json.loads(body.decode())
    data = event.get("data") or {}
    ev = {"id": data.get("id") or f"evt_{hash(body)}", "thread_id": data.get("thread_id") or "th_demo", "event": event.get("type"), "role": data.get("role","user"), "created": data.get("created",0)}
    plan = store_plan(ev)
    schedule_next_tick(plan, 1)
    return {"status":"planned","id":plan.id,"thread":plan.thread}

@app.post("/qph/ack")
async def qph_ack(payload: dict):
    pid = payload.get("id")
    if not pid: return {"ok": False, "error": "missing id"}
    plan = PhasePlan.load(pid)
    if not plan: return {"ok": False, "error":"not found"}
    plan.payload["receipts"] = True
    plan.save()
    emit("verify.receipts", {"id": plan.id})
    return {"ok": True}

@app.get("/qph/stream")
def qph_stream() -> StreamingResponse:
    def gen():
        ps = r.pubsub()
        ps.subscribe("qph:events", "qph:feedback")
        for m in ps.listen():
            if m.get("type")=="message":
                yield f"event: plan\ndata: {m['data']}\n\n"
    return StreamingResponse(gen(), media_type="text/event-stream")

@app.get("/qph/scope")
def qph_scope():
    keys = r.keys("qph:plan:*")
    totals = {"all": len(keys), "by_stage": {}}
    unfinished = []
    for k in keys:
        obj = json.loads(r.get(k))
        st = obj["stage"]
        totals["by_stage"][st] = totals["by_stage"].get(st,0)+1
        if st != "VERIFY": unfinished.append(obj["id"])
    return {"totals": totals, "unfinished": unfinished, "generated_at": __import__("time").time()}

@app.get("/qph/search")
def qph_search(q: str):
    raw = r.get(f"qph:plan:{q}")
    if not raw: return {"results":[]}
    obj = json.loads(raw)
    # shape like your card
    card = {
        "id": obj["id"],
        "thread": obj["thread"],
        "stage": obj["stage"],
        "scp": obj.get("scp") or obj["payload"].get("scp"),
        "sha256": obj["payload"].get("sha256"),
        "cid": obj["payload"].get("cid"),
        "rekor": obj["payload"].get("rekor"),
        "sent": obj["payload"].get("sent", False),
        "receipts": obj["payload"].get("receipts", False),
        "next": []
    }
    return {"results":[card]}

@app.get("/health")
def health():
    try:
        r.ping()
        return {"ok": True, "redis":"up"}
    except Exception as e:
        return {"ok": False, "error": str(e)}
