#!/usr/bin/env python3
import os, sqlite3, time, threading, subprocess, sys

DB_PATH = os.getenv("DB_PATH", "/data/bugdash.db")
CONCURRENCY = int(os.getenv("WORKER_CONCURRENCY", "3"))
POLL_SEC = int(os.getenv("WORKER_POLL_SEC", "2"))

def log(msg):
    print(msg, flush=True)

def db():
    con = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None)  # autocommit
    con.execute("PRAGMA journal_mode=WAL;")
    con.execute("""CREATE TABLE IF NOT EXISTS tasks(
        id TEXT PRIMARY KEY, target TEXT, created_at INTEGER, status TEXT, note TEXT
    )""")
    con.execute("""CREATE TABLE IF NOT EXISTS targets(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pattern TEXT UNIQUE, seed TEXT, last_scanned INTEGER DEFAULT 0, enabled INTEGER DEFAULT 1
    )""")
    return con

def claim_tasks(n):
    claimed = []
    with db() as con:
        rows = con.execute(
            "SELECT id,target FROM tasks WHERE status='queued' ORDER BY created_at ASC LIMIT ?",
            (n,)
        ).fetchall()
        for tid, tgt in rows:
            cur = con.execute("UPDATE tasks SET status='running', note='starting' WHERE id=? AND status='queued'", (tid,))
            if cur.rowcount == 1:
                claimed.append((tid, tgt))
    return claimed

def mark_done(task_id, ok=True, msg="complete"):
    with db() as con:
        con.execute("UPDATE tasks SET status=?, note=? WHERE id=?",
                    ("done" if ok else "error", msg, task_id))

def update_target_last_scanned(seed):
    now = int(time.time())
    with db() as con:
        con.execute("UPDATE targets SET last_scanned=? WHERE seed=?", (now, seed))

def run_one(task_id, target):
    log(f"[supervisor] run start task={task_id} target={target}")
    try:
        p = subprocess.run(["python3","/usr/local/bin/run_pipeline.py", task_id, target], check=False)
        ok = (p.returncode == 0)
        mark_done(task_id, ok, "complete" if ok else f"exit:{p.returncode}")
        update_target_last_scanned(target)
        log(f"[supervisor] run done  task={task_id} rc={p.returncode}")
    except Exception as e:
        mark_done(task_id, False, f"err:{e}")
        log(f"[supervisor] run error task={task_id} err={e}")

def main():
    log(f"[supervisor] starting, concurrency={CONCURRENCY}, poll={POLL_SEC}s, db={DB_PATH}")
    running = set()
    beat = 0
    while True:
        try:
            # reap finished
            for t in list(running):
                if not t.is_alive():
                    running.remove(t)
            # claim new
            cap = CONCURRENCY - len(running)
            if cap > 0:
                for tid, tgt in claim_tasks(cap):
                    th = threading.Thread(target=run_one, args=(tid, tgt), daemon=True)
                    th.start()
                    running.add(th)
            # heartbeat every ~10s
            beat += 1
            if beat % max(1, (10 // max(1, POLL_SEC))) == 0:
                log(f"[supervisor] heartbeat running={len(running)} cap={CONCURRENCY - len(running)}")
        except Exception as e:
            log(f"[supervisor] loop error: {e}")
        time.sleep(POLL_SEC)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log(f"[supervisor] FATAL: {e}")
        sys.exit(1)
