import os, uuid, time, base64
from fastapi import FastAPI, Request, Form, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.status import HTTP_401_UNAUTHORIZED
from jinja2 import Environment, FileSystemLoader, TemplateNotFound

from google.cloud import pubsub_v1
from common.config import AUTH_USERNAME, AUTH_PASSWORD, PROJECT_ID, PUBSUB_TOPIC
from common.db import init_schema, list_tasks, get_task, list_targets, insert_task
from common.storage import signed_log_url

app = FastAPI(title="BugDash")
app.mount("/static", StaticFiles(directory="static"), name="static")
env = Environment(loader=FileSystemLoader("templates"))

publisher = pubsub_v1.PublisherClient()
topic_path = publisher.topic_path(PROJECT_ID, PUBSUB_TOPIC)

def render(tpl, ctx):
    try:
        return HTMLResponse(env.get_template(tpl).render(**ctx))
    except TemplateNotFound:
        raise HTTPException(500, "template missing")

class BasicAuth(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        hdr = request.headers.get("authorization","")
        if not hdr.lower().startswith("basic "):
            return self._challenge()
        try:
            u,p = base64.b64decode(hdr.split(" ",1)[1]).decode().split(":",1)
        except Exception:
            return self._challenge()
        if u != AUTH_USERNAME or p != AUTH_PASSWORD:
            return self._challenge()
        return await call_next(request)
    def _challenge(self):
        from starlette.responses import Response
        r = Response("Auth required", status_code=HTTP_401_UNAUTHORIZED)
        r.headers["WWW-Authenticate"] = 'Basic realm="BugDash"'
        return r

app.add_middleware(BasicAuth)

@app.on_event("startup")
def _startup():
    init_schema()

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    tasks = list_tasks(100)
    return render("index.html", {"request": request, "tasks": tasks})

@app.post("/scan")
def scan(target: str = Form(...)):
    task_id = uuid.uuid4().hex[:12]
    insert_task(task_id, target, note="manual")
    publisher.publish(topic_path, f'{{"task_id":"{task_id}","target":"{target}"}}'.encode())
    return RedirectResponse(url=f"/task/{task_id}", status_code=303)

@app.get("/task/{task_id}", response_class=HTMLResponse)
def task_view(request: Request, task_id: str):
    t = get_task(task_id)
    if not t: raise HTTPException(404)
    log_url = signed_log_url(task_id)  # may be None
    return render("task.html", {"request": request, "t": t, "log_url": log_url})

@app.get("/targets", response_class=HTMLResponse)
def targets(request: Request):
    return render("targets.html", {"request": request, "targets": list_targets()})

@app.get("/task/{task_id}/log", response_class=PlainTextResponse)
def task_log(task_id: str):
    return PlainTextResponse("This deployment stores logs in GCS. Use the signed link from the task page.")
