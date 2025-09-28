#!/usr/bin/env python3
import os, sys, subprocess, json, sqlite3, hashlib, time, tempfile, shlex, re, urllib.parse, random

DB_PATH = os.getenv("DB_PATH", "/data/bugdash.db")
NUCLEI_TEMPLATES_DIR = os.getenv("NUCLEI_TEMPLATES_DIR", "/data/nuclei-templates")
CUSTOM_TEMPLATES_DIR = os.getenv("CUSTOM_TEMPLATES_DIR", "/data/custom-templates")
LOG_DIR = "/var/log/bugdash"

# ---------- DB helpers (WAL + retries) ----------
def db():
    con = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None)  # autocommit
    con.execute("PRAGMA journal_mode=WAL;")
    con.execute("PRAGMA synchronous=NORMAL;")
    con.execute("PRAGMA busy_timeout=10000;")
    # tables
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
        raw JSON, score INTEGER DEFAULT 0, reasons TEXT DEFAULT '',
        UNIQUE(task_id, tool, fingerprint)
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

def _exec_retry(con, sql, params=(), attempts=10):
    for i in range(attempts):
        try:
            return con.execute(sql, params)
        except sqlite3.OperationalError as e:
            msg = str(e).lower()
            if "database is locked" in msg or "database is busy" in msg:
                time.sleep((0.025 * (2 ** i)) + random.uniform(0, 0.010))
                continue
            raise
    return con.execute(sql, params)

def up_status(task_id, status, note=""):
    with db() as con:
        _exec_retry(con, "UPDATE tasks SET status=?, note=? WHERE id=?", (status, note, task_id))

def insert_asset(task_id, kind, value, scope_pats):
    if not in_scope(value, scope_pats): return
    with db() as con:
        _exec_retry(con, "INSERT OR IGNORE INTO assets(task_id,kind,value) VALUES(?,?,?)",
                    (task_id, kind, value))

def insert_finding(task_id, tool, fp, title, detail, severity, label, raw, scope_pats, score=0, reasons=""):
    if not in_scope(detail, scope_pats): return
    with db() as con:
        _exec_retry(con,
            """INSERT OR IGNORE INTO findings(task_id,tool,fingerprint,title,detail,severity,label,raw,score,reasons)
               VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (task_id, tool, fp, title, detail, severity, label, json.dumps(raw), int(score), reasons)
        )

# ---------- utils ----------
def log_start(task_id):
    os.makedirs(LOG_DIR, exist_ok=True)
    with open(f"{LOG_DIR}/task-{task_id}.log", "w") as f:
        f.write(f"[{time.strftime('%F %T')}] task {task_id} start\n")

def log(task_id, msg):
    with open(f"{LOG_DIR}/task-{task_id}.log", "a") as f:
        f.write(f"[{time.strftime('%F %T')}] {msg}\n")

def sh(task_id, desc, cmd, inp=None):
    """Run a shell command, tee stderr to the task log, return stdout (text)."""
    log(task_id, f"$ {cmd}")
    p = subprocess.run(cmd, input=inp, text=True, shell=True, capture_output=True)
    if p.stderr:
        log(task_id, p.stderr.strip())
    if p.returncode != 0:
        log(task_id, f"{desc} exited rc={p.returncode} (continuing)")
    return p.stdout or ""

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
        pat = pat.lower().strip()
        if not pat: continue
        pat_re = re.escape(pat).replace(r"\*\.", r"(?:[^.]+\.)").replace(r"\*", r"[^.]*")
        if re.fullmatch(pat_re, host) or host.endswith("." + pat.lstrip("*.")):
            return True
    return False

def get_scope_patterns():
    with db() as con:
        rows = con.execute("SELECT pattern FROM scope").fetchall()
    return [r[0] for r in rows]

def hashit(*parts):
    h = hashlib.sha1()
    for p in parts: h.update(str(p).encode())
    return h.hexdigest()

def label_for(sev):
    s = (sev or "").lower()
    if s in ("critical","high"): return "likely-bug"
    if s in ("medium",): return "sus"
    return "info"

# --- suspicious score heuristics (unchanged) ---
RISKY_PATH_BITS = ["/.git","/.env","/.DS_Store","/config","/backup","/.svn","/wp-admin","/phpinfo","/server-status","/swagger","/graphql","/actuator","/admin","/dashboard","/debug","/v1","/v2","/internal"]
RISKY_PARAMS = ["token","key","secret","signature","redirect","next","callback","SAMLResponse","assertion","code","state","access_token","jwt"]
ENV_WORDS_DEV = ["dev","staging","stage","test","uat","preprod","qa"]
ENV_WORDS_PROD = ["prod","production","live","edge"]

def calc_score_and_reasons(nuc_json, httpx_meta):
    score = 0; reasons = []
    sev = (nuc_json.get("info",{}).get("severity","") or "").lower()
    base = {"critical":90, "high":70, "medium":45, "low":20, "info":5}.get(sev, 0)
    score += base
    if base: reasons.append(f"severity:{sev}(+{base})")
    tags = nuc_json.get("info",{}).get("tags","") or ""
    tags_join = ",".join(tags) if isinstance(tags, list) else str(tags)
    tl = tags_join.lower()
    if "takeover" in tl: score += 30; reasons.append("tag:takeover(+30)")
    if "exposure" in tl or "exposures" in tl: score += 12; reasons.append("tag:exposures(+12)")
    if "misconfig" in tl: score += 8; reasons.append("tag:misconfig(+8)")
    if "default-cred" in tl or "weak-auth" in tl: score += 10; reasons.append("auth-weak(+10)")
    matched = nuc_json.get("matched-at") or nuc_json.get("url") or nuc_json.get("host") or ""
    url = matched if matched.startswith("http") else ("http://" + matched if matched else "")
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        parsed = None
    if parsed:
        path = parsed.path or "/"
        q = urllib.parse.parse_qs(parsed.query or "", keep_blank_values=True)
        for bit in RISKY_PATH_BITS:
            if bit in path.lower():
                score += 15; reasons.append(f"path:{bit}(+15)"); break
        for k in q.keys():
            kl = k.lower()
            if kl in RISKY_PARAMS:
                score += 6; reasons.append(f"param:{kl}(+6)")
        host_l = (parsed.hostname or "").lower()
        for w in ENV_WORDS_DEV:
            if w in host_l: score += 8; reasons.append(f"host:{w}(+8)"); break
        for w in ENV_WORDS_PROD:
            if w in host_l: score += 4; reasons.append(f"host:{w}(+4)"); break
    if httpx_meta:
        title = (httpx_meta.get("title") or "").lower()
        status = int(httpx_meta.get("status-code") or 0)
        clen = int(httpx_meta.get("content-length") or 0)
        tech = ",".join([t.lower() for t in (httpx_meta.get("tech") or [])])
        if "index of /" in title: score += 12; reasons.append("index-of(+12)")
        if status in (200,201,202,204,301,302): score += 3; reasons.append(f"status:{status}(+3)")
        if "swagger" in title or "openapi" in title: score += 10; reasons.append("swagger(+10)")
        if "graphql" in title: score += 10; reasons.append("graphql(+10)")
        if "kibana" in title or "jenkins" in title or "gitlab" in title: score += 10; reasons.append("admin-app(+10)")
        if 0 < clen <= 300: score += 4; reasons.append(f"tiny-body({clen})(+4)")
        if clen >= 2_000_000: score += 4; reasons.append("huge-body(+4)")
        if "s3" in tech or "minio" in tech: score += 6; reasons.append("object-store(+6)")
        if "nginx" in tech and "autoindex" in title: score += 8; reasons.append("nginx-autoindex(+8)")
        if "apache" in tech and "directory listing" in title: score += 8; reasons.append("apache-listing(+8)")
    return max(0, min(100, score)), ", ".join(reasons)

# ---------- main pipeline ----------
def run(task_id, target):
    os.makedirs(LOG_DIR, exist_ok=True)
    log_start(task_id)
    log(task_id, f"target={target}")
    scope_pats = get_scope_patterns() or [f"*.{target}" if "." in target else target]
    up_status(task_id, "running", "starting recon")

    # 0) subdomains (assetfinder + subfinder)
    up_status(task_id, "running", "assetfinder/subfinder")
    subs_af = sh(task_id, "assetfinder", f"assetfinder --subs-only {shlex.quote(target)}")
    subs_sf = sh(task_id, "subfinder", f"subfinder -silent -d {shlex.quote(target)}")
    subs_all = set(s.strip() for s in (subs_af.splitlines() + subs_sf.splitlines()) if s.strip())

    # 1) resolve with dnsx
    up_status(task_id, "running", "dnsx")
    r = sh(task_id, "dnsx", "dnsx -silent", inp="\n".join(sorted(subs_all))) if subs_all else ""
    hosts = set(h.strip() for h in r.splitlines() if h.strip())
    for h in hosts: insert_asset(task_id, "host", h, scope_pats)

    # 2) httpx
    up_status(task_id, "running", "httpx")
    httpx_cmd = ("httpx -silent -json -follow-host-redirects -no-color "
                 "-tech-detect -status-code -content-length -title -web-server -tls-probe "
                 "-ports 80,443,8080,8443")
    httpx_out = sh(task_id, "httpx", httpx_cmd, inp="\n".join(hosts))
    urls = set(); httpx_map = {}
    for line in httpx_out.splitlines():
        try:
            j = json.loads(line); u = j.get("url")
            if u and in_scope(u, scope_pats):
                urls.add(u); httpx_map[u] = j; insert_asset(task_id, "url", u, scope_pats)
        except json.JSONDecodeError:
            pass

    # 3) katana + gau + wayback
    up_status(task_id, "running", "katana/gau/wayback")
    kat = sh(task_id, "katana", "katana -silent -jc -ef png,jpg,svg,css,woff,ico -d 2 -kf", inp="\n".join(urls))
    for line in kat.splitlines():
        try:
            j = json.loads(line)
            u = j.get("request","").split(" ")[1] if "request" in j else j.get("url") or j.get("source")
            if u and in_scope(u, scope_pats):
                urls.add(u); insert_asset(task_id, "url", u, scope_pats)
        except Exception:
            pass
    gau_out = sh(task_id, "gau", f"gau --threads 20 --subs --providers wayback,commoncrawl,otx {shlex.quote(target)}")
    wb_out  = sh(task_id, "waybackurls", f"waybackurls {shlex.quote(target)}")
    for u in (gau_out.splitlines() + wb_out.splitlines()):
        if u.startswith("http") and in_scope(u, scope_pats):
            uu = u.strip(); urls.add(uu); insert_asset(task_id, "url", uu, scope_pats)

    # 4) nuclei
    up_status(task_id, "running", "nuclei")
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write("\n".join(sorted(urls)))
        inlist = f.name
    all_templates = f"-templates {NUCLEI_TEMPLATES_DIR} -templates {CUSTOM_TEMPLATES_DIR}"
    nuc = sh(task_id, "nuclei", f"nuclei -silent -jsonl -rate-limit 200 -retry 1 {all_templates} -list {inlist}")

    for line in nuc.splitlines():
        try:
            j = json.loads(line)
            name = j.get("info",{}).get("name","")
            sev  = j.get("info",{}).get("severity","info")
            matched = j.get("matched-at") or j.get("host") or j.get("url") or ""
            if not matched or not in_scope(matched, scope_pats): continue
            hmeta = httpx_map.get(matched) or httpx_map.get(j.get("url","")) or {}
            score, reasons = calc_score_and_reasons(j, hmeta)
            tid = j.get("template-id",""); fp = hashit(tid, matched)
            insert_finding(task_id, "nuclei", fp, name, matched, sev, label_for(sev), j, scope_pats, score, reasons)
        except Exception as e:
            log(task_id, f"[parse nuclei] {e}")

    up_status(task_id, "done", "complete")
    log(task_id, "task complete")
    return 0

if __name__ == "__main__":
    try:
        task_id, target = sys.argv[1], sys.argv[2]
    except Exception:
        print("usage: run_pipeline.py <task_id> <target>")
        sys.exit(2)
    try:
        sys.exit(run(task_id, target))
    except Exception as e:
        # If anything unexpected bubbles up, log it so UI can show it
        os.makedirs(LOG_DIR, exist_ok=True)
        with open(f"{LOG_DIR}/task-{task_id}.log","a") as f:
            f.write(f"[{time.strftime('%F %T')}] FATAL: {e}\n")
        raise
