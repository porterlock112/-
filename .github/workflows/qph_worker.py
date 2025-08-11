import os, time
from phase_engine import r, schedule_next_tick, run_one, PhasePlan, KEY_SCHEDULE, emit

SLEEP = int(os.getenv("QPH_WORKER_SLEEP","5") or "5")
IDLE = os.getenv("QPH_IDLE","15m")
def _now(): import time; return int(time.time())

def _parse_seconds(s: str) -> int:
    s=s.strip().lower()
    if s.endswith("ms"): return max(1, int(int(s[:-2])/1000))
    if s.endswith("s"): return int(s[:-1])
    if s.endswith("m"): return int(s[:-1])*60
    if s.endswith("h"): return int(s[:-1])*3600
    return int(s)

def check_boot():
    import os
    if os.getenv("QPH_BOOT_TICK_ALL","false").lower()=="true":
        keys = r.keys("qph:plan:*")
        for k in keys:
            pid = k.split("qph:plan:",1)[-1]
            r.zadd(KEY_SCHEDULE, {pid: _now()})
        emit("boot.tick_all", {"count": len(keys)})

check_boot()

while True:
    now = _now()
    ids = r.zrangebyscore(KEY_SCHEDULE, "-inf", now)
    if ids:
        # remove due ids and run
        for pid in ids:
            r.zrem(KEY_SCHEDULE, pid)
            try:
                run_one(pid)
            except Exception as e:
                emit("worker.error", {"id": pid, "error": str(e)})
    time.sleep(SLEEP)
