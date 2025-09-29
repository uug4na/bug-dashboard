import os, json, subprocess, threading
from google.cloud import pubsub_v1
from common.db import claim_tasks, up_status
from common.storage import upload_task_log
from common.config import PROJECT_ID, SUBSCRIPTION

CONCURRENCY = int(os.getenv("WORKER_CONCURRENCY","4"))
LOG_DIR = "/var/log/bugdash"

def run_pipeline(task_id, target):
    rc = subprocess.run(
        ["python3","/usr/local/bin/run_pipeline.py", task_id, target]
    ).returncode
    up_status(task_id, "done" if rc==0 else "error", f"exit:{rc}")
    log_path = f"{LOG_DIR}/task-{task_id}.log"
    upload_task_log(task_id, log_path)

def handle_message(msg):
    try:
        data = json.loads(msg.data.decode())
        run_pipeline(data["task_id"], data["target"])
        msg.ack()
    except Exception:
        msg.nack()

def main():
    # warm start: claim any DB queued
    for row in claim_tasks(CONCURRENCY):
        threading.Thread(target=run_pipeline, args=(row["id"], row["target"]), daemon=True).start()

    # long-running subscription
    sub = pubsub_v1.SubscriberClient()
    path = sub.subscription_path(PROJECT_ID, SUBSCRIPTION)
    sub.subscribe(path, callback=handle_message).result()

if __name__ == "__main__":
    main()
