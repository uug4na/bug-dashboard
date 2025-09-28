import os, sqlite3, time, uuid, subprocess, os.path
from fastapi import FastAPI, Request, Form, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, TemplateNotFound
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.status import HTTP_401_UNAUTHORIZED
from base64 import b64decode

AUTH_USER = os.getenv("AUTH_USERNAME", "admin")
AUTH_PASS = os.getenv("AUTH_PASSWORD", "change-me")
DB_PATH   = os.getenv("DB_PATH", "/data/bugdash.db")
CUSTOM_TEMPLATES_DIR = os.getenv("CUSTOM_TEMPLATES_DIR", "/data/custom-templates")

app = FastAPI(title="BugDash")
app.mount("/static", StaticFiles(directory="static"), name="static")
env = Environment(loader=FileSystemLoader("templates"))

def render(tpl_name, ctx):
    try:
        template = env.get_template(tpl_name)
        return HTMLResponse(template.render(**ctx))
    except TemplateNotFound:
        raise HTTPException(500, "template missing")

def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    # tables (and upgrades handled in worker too)
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
        task_id TEXT, tool TEXT, fingerprint TEXT, title TEXT, detail TEXT, severity TEXT, label TEXT, raw JSON,
        score INTEGER DEFAULT 0, reasons TEXT DEFAULT '',
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
    # upgrades
    try:
        con.execute("ALTER TABLE findings ADD COLUMN score INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    try:
        con.execute("ALTER TABLE findings ADD COLUMN reasons TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        pass
    return con

class BasicAuth(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        hdr = request.headers.get("authorization")
        if not hdr or not hdr.lower().startswith("basic "):
            return self._challenge()
        try:
            u,p = b64decode(hdr.split(" ",1)[1]).decode().split(":",1)
        except Exception:
            return self._challenge()
        if u != AUTH_USER or p != AUTH_PASS:
            return self._challenge()
        return await call_next(request)
    def _challenge(self):
        from starlette.responses import Response
        r = Response("Auth required", status_code=HTTP_401_UNAUTHORIZED)
        r.headers["WWW-Authenticate"] = 'Basic realm="BugDash"'
        return r

app.add_middleware(BasicAuth)

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    with db() as con:
        # running → queued → done → error → (anything else)
        tasks = con.execute("""
            SELECT * FROM tasks
            ORDER BY
              CASE status
                WHEN 'running' THEN 0
                WHEN 'queued'  THEN 1
                WHEN 'done'    THEN 2
                WHEN 'error'   THEN 3
                ELSE 4
              END,
              created_at DESC
            LIMIT 100
        """).fetchall()
        tcount  = con.execute("SELECT COUNT(*) c FROM targets WHERE enabled=1").fetchone()["c"]
        running = con.execute("SELECT COUNT(*) c FROM tasks WHERE status='running'").fetchone()["c"]
    return render("index.html", {"request": request, "tasks": tasks, "tcount": tcount, "running": running})

@app.post("/scan")
def scan(target: str = Form(...)):
    import uuid, time
    task_id = uuid.uuid4().hex[:12]
    now = int(time.time())
    with db() as con:
        con.execute("INSERT INTO tasks(id,target,created_at,status,note) VALUES(?,?,?,?,?)",
                    (task_id, target, now, "queued", ""))
        con.execute("INSERT OR IGNORE INTO scope(pattern) VALUES(?)", (f"*.{target}",))
        con.commit()
    return RedirectResponse(url=f"/task/{task_id}", status_code=303)

@app.get("/task/{task_id}", response_class=HTMLResponse)
def task_view(request: Request, task_id: str):
    with db() as con:
        t = con.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        if not t: raise HTTPException(404)
        assets = con.execute("SELECT * FROM assets WHERE task_id=? ORDER BY id DESC LIMIT 500", (task_id,)).fetchall()
        # aggregated view (for quick dedupe glance)
        agg = con.execute("""SELECT title,detail,severity,label, COUNT(*) as c
                             FROM findings WHERE task_id=?
                             GROUP BY title,detail,severity,label ORDER BY c DESC""", (task_id,)).fetchall()
        # top scored view
        tops = con.execute("""SELECT title,detail,severity,label,score,reasons
                              FROM findings WHERE task_id=? ORDER BY score DESC, id DESC LIMIT 200""",
                           (task_id,)).fetchall()
    return render("task.html", {"request": request, "t": t, "assets": assets, "findings": agg, "tops": tops})

@app.get("/task/{task_id}/raw", response_class=PlainTextResponse)
def task_raw(task_id: str):
    with db() as con:
        rows = con.execute("SELECT raw FROM findings WHERE task_id=?", (task_id,)).fetchall()
    return "\n".join([r["raw"] for r in rows if r["raw"]])

@app.get("/targets", response_class=HTMLResponse)
def targets_view(request: Request):
    with db() as con:
        targets = con.execute("SELECT * FROM targets ORDER BY enabled DESC, seed").fetchall()
    return render("targets.html", {"request": request, "targets": targets})

@app.post("/targets/add")
def targets_add(pattern: str = Form(...)):
    p = pattern.strip()
    seed = p[2:] if p.startswith("*.") else (p.split(".",1)[1] if p.startswith("*-") else p)
    with db() as con:
        con.execute("INSERT OR IGNORE INTO targets(pattern,seed) VALUES(?,?)", (p, seed))
        con.execute("INSERT OR IGNORE INTO scope(pattern) VALUES(?)", (p,))
        con.commit()
    return RedirectResponse(url="/targets", status_code=303)

@app.post("/upload-template")
async def upload_template(file: UploadFile = File(...)):
    os.makedirs(CUSTOM_TEMPLATES_DIR, exist_ok=True)
    if not (file.filename.endswith(".yaml") or file.filename.endswith(".yml")):
        raise HTTPException(400, "Must be a nuclei YAML template")
    dest = os.path.join(CUSTOM_TEMPLATES_DIR, file.filename)
    with open(dest, "wb") as f:
        f.write(await file.read())
    return RedirectResponse(url="/templates", status_code=303)

@app.get("/templates", response_class=HTMLResponse)
def list_templates(request: Request):
    os.makedirs(CUSTOM_TEMPLATES_DIR, exist_ok=True)
    files = sorted(os.listdir(CUSTOM_TEMPLATES_DIR))
    return render("templates.html", {"request": request, "files": files})
