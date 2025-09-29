import os, time, hashlib, requests, json
from sqlalchemy import create_engine, text
from google.cloud import pubsub_v1
from common.config import DATABASE_URL, PROJECT_ID, PUBSUB_TOPIC
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
publisher = pubsub_v1.PublisherClient()
topic_path = publisher.topic_path(PROJECT_ID, PUBSUB_TOPIC)

ARK_URL = os.getenv("ARKADIYT_WILDCARDS_URL","https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/wildcards.txt")
COOLDOWN_SEC = int(os.getenv("SCAN_COOLDOWN_SEC","86400"))
MAX_BATCH = int(os.getenv("MAX_PARALLEL_QUEUED","100"))

def normalize(p):
    p=p.strip()
    if not p or p.startswith("#"): return None
    seed = p[2:] if p.startswith("*.") else (p.split(".",1)[1] if p.startswith("*-") and "." in p else p.lstrip("*."))
    return p, seed

def merge_targets():
    try:
        r = requests.get(ARK_URL, timeout=20); r.raise_for_status()
        lines = r.text.splitlines()
    except Exception:
        lines = []
    with engine.begin() as con:
        for ln in lines:
            nz = normalize(ln)
            if not nz: continue
            pat, seed = nz
            con.execute(text("INSERT INTO targets(pattern,seed) VALUES(:p,:s) ON CONFLICT DO NOTHING"),
                        {"p": pat, "s": seed})
            con.execute(text("INSERT INTO scope(pattern) VALUES(:p) ON CONFLICT DO NOTHING"),
                        {"p": pat})

def enqueue_due():
    sel = text("""
      SELECT id, pattern, seed, last_scanned
      FROM targets
      WHERE enabled=true AND (last_scanned IS NULL OR EXTRACT(EPOCH FROM (now() - last_scanned)) > :cd)
      ORDER BY (last_scanned IS NOT NULL), last_scanned ASC
      LIMIT :lim
    """)
    with engine.begin() as con:
        rows = con.execute(sel, {"cd": COOLDOWN_SEC, "lim": MAX_BATCH}).fetchall()
        for r in rows:
            tid = hashlib.sha1(f"{r.id}-{time.time()}".encode()).hexdigest()[:12]
            con.execute(text("""
              INSERT INTO tasks(id,target,created_at,status,note)
              VALUES(:id,:t,now(),'queued',:note)
              ON CONFLICT DO NOTHING
            """), {"id": tid, "t": r.seed, "note": f"auto: {r.pattern}"})
            publisher.publish(topic_path, json.dumps({"task_id": tid, "target": r.seed}).encode())

if __name__ == "__main__":
    merge_targets()
    enqueue_due()
