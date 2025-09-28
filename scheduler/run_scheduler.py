import os, time, sqlite3, subprocess, hashlib, requests

DB_PATH = os.getenv("DB_PATH", "/data/bugdash.db")
MERGE_INTERVAL = int(os.getenv("MERGE_WILDCARDS_INTERVAL_SEC","1800"))
ENQUEUE_INTERVAL = int(os.getenv("ENQUEUE_INTERVAL_SEC","120"))
COOLDOWN = int(os.getenv("SCAN_COOLDOWN_SEC","86400"))
MAX_PARALLEL_QUEUED = int(os.getenv("MAX_PARALLEL_QUEUED","3"))
ARK_URL = os.getenv("ARKADIYT_WILDCARDS_URL","https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/wildcards.txt")
LOCAL_USER_WC = "/data/user-wildcards.txt"

def db():
    con = sqlite3.connect(DB_PATH)
    con.execute("""CREATE TABLE IF NOT EXISTS targets(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pattern TEXT UNIQUE, seed TEXT, last_scanned INTEGER DEFAULT 0, enabled INTEGER DEFAULT 1
    )""")
    con.execute("""CREATE TABLE IF NOT EXISTS scope(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pattern TEXT UNIQUE
    )""")
    con.execute("""CREATE TABLE IF NOT EXISTS tasks(
        id TEXT PRIMARY KEY, target TEXT, created_at INTEGER, status TEXT, note TEXT
    )""")
    return con

def normalize(line):
    line = line.strip()
    if not line or line.startswith("#"): return None
    if line.startswith("*.") and "." in line:
        seed = line[2:]
    elif line.startswith("*-") and "." in line:
        seed = line.split(".",1)[1]
    else:
        seed = line.lstrip("*.")
    return (line, seed)

def merge_targets():
    try:
        ark = requests.get(ARK_URL, timeout=20)
        ark.raise_for_status()
        ark_lines = ark.text.splitlines()
    except Exception as e:
        ark_lines = []
        print("[scheduler] arkadiyt fetch failed:", e)

    try:
        with open(LOCAL_USER_WC, "r") as f:
            user_lines = f.read().splitlines()
    except FileNotFoundError:
        user_lines = []

    lines = ark_lines + user_lines
    added = 0
    with db() as con:
        for ln in lines:
            nz = normalize(ln)
            if not nz: continue
            pat, seed = nz
            try:
                con.execute("INSERT OR IGNORE INTO targets(pattern,seed) VALUES(?,?)",(pat,seed))
                con.execute("INSERT OR IGNORE INTO scope(pattern) VALUES(?)",(pat,))
            except Exception:
                pass
        con.commit()
        # sqlite's total_changes is cumulative per connection; we won't rely on it here
    print(f"[scheduler] merge complete: {len(lines)} lines processed")

def queued_or_running():
    with db() as con:
        rows = con.execute("SELECT COUNT(*) FROM tasks WHERE status IN ('queued','running')").fetchone()
        return rows[0]

def enqueue_due():
    now = int(time.time())
    enq = 0
    with db() as con:
        cur = con.execute(
            """SELECT id,pattern,seed,last_scanned
               FROM targets
               WHERE enabled=1 AND (last_scanned IS NULL OR ? - last_scanned > ?)
               ORDER BY (last_scanned IS NOT NULL), last_scanned ASC
               LIMIT ?""",
            (now, COOLDOWN, MAX_PARALLEL_QUEUED)
        )
        rows = cur.fetchall()
        for tid, pat, seed, last in rows:
            task_id = hashlib.sha1(f"{tid}-{now}".encode()).hexdigest()[:12]
            con.execute("INSERT OR IGNORE INTO tasks(id,target,created_at,status,note) VALUES(?,?,?,?,?)",
                        (task_id, seed, now, "queued", f"auto: {pat}"))
            # do NOT touch targets.last_scanned here
            enq += 1
        con.commit()
    if enq:
        print(f"[scheduler] enqueued {enq} task(s)")
    return enq

def main():
    last_merge = 0
    while True:
        now = time.time()
        try:
            if now - last_merge > MERGE_INTERVAL:
                merge_targets()
                last_merge = now
            enqueue_due()
        except Exception as e:
            print("[scheduler] loop error:", e)
        time.sleep(ENQUEUE_INTERVAL)

if __name__ == "__main__":
    main()
