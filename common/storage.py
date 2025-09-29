import os
from google.cloud import storage
from .config import GCS_BUCKET

_storage = storage.Client()
_bucket = _storage.bucket(GCS_BUCKET) if GCS_BUCKET else None

def upload_task_log(task_id: str, path: str):
    if not _bucket or not os.path.exists(path):
        return
    blob = _bucket.blob(f"logs/{task_id}.log")
    blob.upload_from_filename(path)

def signed_log_url(task_id: str, ttl_seconds=3600):
    if not _bucket:
        return None
    blob = _bucket.blob(f"logs/{task_id}.log")
    if not blob.exists():
        return None
    return blob.generate_signed_url(expiration=ttl_seconds)
