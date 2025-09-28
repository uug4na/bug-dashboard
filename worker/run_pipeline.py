#!/usr/bin/env python3
import os, sys, subprocess, json, sqlite3, hashlib, time, tempfile, shlex, re

DB_PATH = os.getenv("DB_PATH", "/data/bugdash.db")
NUCLEI_TEMPLATES_DIR = os.getenv("NUCLEI_TEMPLATES_DIR", "/data/nuclei-templates")
CUSTOM_TEMPLATES_DIR = os.getenv("CUSTOM_TEMPLATES_DIR", "/data/custom-templates")

def db():
    con = sqlite3.connect(DB_PATH)
    con.execute("""CREATE TABLE IF NOT EXISTS tasks(
        id TEXT PRIMARY KEY, target TEXT, created_at INTEGER, status TEXT, note TEXT
    )""")
    con.execute("""CREATE TABLE IF NOT EXISTS assets(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id TEXT, kind TEXT, value TEXT,
        UNIQUE(task_id, kind, value)
    )""")
    con.execute("""CREATE TABLE IF NOT EXISTS findings(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id TEXT, tool TEXT, fingerprint TEXT, title TEXT, detail TEXT, severity TEXT, label TEXT,
        raw JSON, UNIQUE(task_id, tool, fingerprint)
    )""")
    con.execute("""CREATE TABLE IF NOT EXISTS targets(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pattern TEXT UNIQUE, seed TEXT, last_scanned INTEGER DEFAULT 0, enabled INTEGER DEFAULT 1
    )""")
    con.execute("""CREATE TABLE IF NOT EXISTS scope(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pattern TEXT UNIQUE
    )""")
    return con

def normalize_wildcard(line):
    line = line.strip()
    if not line or line.startswith("#"): return None, None
    p = line
    if p.startswith("*.") and p.count(".")>=1:
        seed = p[2:]
    elif p.startswith("*-") and "." in p:
        parts = p.split(".", 1)
        seed = parts[1]
    else:
        seed = p.lstrip("*.") if p.startswith("*.") else p
    return p, seed

def in_scope(url_or_host, patterns):
    host = url_or_host
    if host.startswith("http"):
        try:
            host = re.sub(r"^https?://", "", host).split("/")[0]
        except Exception:
            pass
    host = host.lower()
    for pat in patterns:
        pat = pat.lower()
        pat_re = re.escape(pat).replace(r"\*\.", r"(?:[^.]+\.)").replace(r"\*", r"[^.]*")
        if re.fullmatch(pat_re, host) or host.endswith("." + pat.lstrip("*.")):
            return True
    return False

def get_scope_patterns():
    with db() as con:
        rows = con.execute("SELECT pattern FROM scope").fetchall()
    return [r[0] for r in rows]

def sh(cmd, inp=None):
    p = subprocess.run(cmd, input=inp, text=True, shell=True, capture_output=True)
    return p.stdout

def hashit(*parts):
    h = hashlib.sha1()
    for p in parts: h.update(str(p).encode())
    return h.hexdigest()

def up_status(task_id, status, note=""):
    with db() as con:
        con.execute("UPDATE tasks SET status=?, note=? WHERE id=?", (status, note, task_id))
        con.commit()

def insert_asset(task_id, kind, value, scope_pats):
    if not in_scope(value, scope_pats): return
    with db() as con:
        con.execute("INSERT OR IGNORE INTO assets(task_id,kind,value) VALUES(?,?,?)",
                    (task_id, kind, value))
        con.commit()

def insert_finding(task_id, tool, fp, title, detail, severity, label, raw, scope_pats):
    if not in_scope(detail, scope_pats): return
    with db() as con:
        con.execute("""INSERT OR IGNORE INTO findings(task_id,tool,fingerprint,title,detail,severity,label,raw)
                       VALUES(?,?,?,?,?,?,?,?)""",
                    (task_id, tool, fp, title, detail, severity, label, json.dumps(raw)))
        con.commit()

def label_for(sev):
    s = (sev or "").lower()
    if s in ("critical","high"): return "likely-bug"
    if s in ("medium",): return "sus"
    return "info"

def run(task_id, target):
    scope_pats = get_scope_patterns() or [f"*.{target}" if "." in target else target]
    up_status(task_id, "running", "starting recon")

    # 1) subfinder → dnsx
    up_status(task_id, "running", "subfinder")
    subs = sh(f"subfinder -silent -d {shlex.quote(target)}")
    r = sh("dnsx -silent", inp=subs) if subs.strip() else ""
    hosts = set([h.strip() for h in r.splitlines() if h.strip()])
    for h in hosts: insert_asset(task_id, "host", h, scope_pats)

    # 2) httpx
    up_status(task_id, "running", "httpx")
    httpx_out = sh("httpx -silent -json -follow-host-redirects -no-color -ports 80,443,8080,8443",
                   inp="\n".join(hosts))
    urls = set()
    for line in httpx_out.splitlines():
        try:
            j = json.loads(line); u = j.get("url")
            if u and in_scope(u, scope_pats):
                urls.add(u); insert_asset(task_id, "url", u, scope_pats)
        except json.JSONDecodeError:
            pass

    # 3) katana + GAU + waybackurls
    up_status(task_id, "running", "katana/gau/wayback")
    kat = sh("katana -silent -jc -ef png,jpg,svg,css,woff,ico -d 2 -kf", inp="\n".join(urls))
    for line in kat.splitlines():
        try:
            j = json.loads(line)
            u = j.get("request","").split(" ")[1] if "request" in j else j.get("url") or j.get("source")
            if u and in_scope(u, scope_pats):
                urls.add(u); insert_asset(task_id, "url", u, scope_pats)
        except Exception:
            pass
    gau_out = sh(f"gau --threads 20 --subs --providers wayback,commoncrawl,otx {shlex.quote(target)}")
    wb_out  = sh(f"waybackurls {shlex.quote(target)}")
    for u in (gau_out.splitlines() + wb_out.splitlines()):
        if u.startswith("http") and in_scope(u, scope_pats):
            urls.add(u.strip()); insert_asset(task_id, "url", u.strip(), scope_pats)

    # 4) nuclei
    up_status(task_id, "running", "nuclei")
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write("\n".join(sorted(urls)))
        inlist = f.name
    all_templates = f"-templates {NUCLEI_TEMPLATES_DIR} -templates {CUSTOM_TEMPLATES_DIR}"
    nuc = sh(f"nuclei -silent -jsonl -rate-limit 200 -retry 1 {all_templates} -list {inlist}")

    for line in nuc.splitlines():
        try:
            j = json.loads(line)
            name = j.get("info",{}).get("name","")
            sev  = j.get("info",{}).get("severity","info")
            matched = j.get("matched-at") or j.get("host") or j.get("url") or ""
            if matched and in_scope(matched, scope_pats):
                tid = j.get("template-id",""); fp = hashit(tid, matched)
                insert_finding(task_id, "nuclei", fp, name, matched, sev, label_for(sev), j, scope_pats)
        except Exception:
            pass

    up_status(task_id, "done", "complete")
    return 0

if __name__ == "__main__":
    task_id, target = sys.argv[1], sys.argv[2]
    run(task_id, target)
