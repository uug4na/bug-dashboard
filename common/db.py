from sqlalchemy import create_engine, text
from sqlalchemy.pool import NullPool
from .config import DATABASE_URL

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=5,
    max_overflow=10
)

def init_schema():
    with engine.begin() as con:
        # minimal safe re-run schema
        con.exec_driver_sql(open("common/schema.sql","r").read())

def claim_tasks(n: int):
    sql = text("""
    WITH c AS (
      SELECT id, target
      FROM tasks
      WHERE status='queued'
      ORDER BY created_at
      FOR UPDATE SKIP LOCKED
      LIMIT :n
    )
    UPDATE tasks t
      SET status='running', note='starting', heartbeat=now()
    FROM c WHERE t.id=c.id
    RETURNING t.id AS id, t.target AS target
    """)
    with engine.begin() as con:
        return [dict(r) for r in con.execute(sql, {"n": n}).fetchall()]

def up_status(task_id, status, note=""):
    with engine.begin() as con:
        con.execute(text(
            "UPDATE tasks SET status=:s, note=:n, heartbeat=now() WHERE id=:id"
        ), {"s": status, "n": note, "id": task_id})

def insert_task(task_id, target, note=""):
    with engine.begin() as con:
        con.execute(text("""
          INSERT INTO tasks(id, target, created_at, status, note)
          VALUES(:id, :t, now(), 'queued', :note)
          ON CONFLICT (id) DO NOTHING
        """), {"id": task_id, "t": target, "note": note})

def list_tasks(limit=100):
    with engine.begin() as con:
        return con.execute(text("""
          SELECT * FROM tasks
          ORDER BY CASE status
            WHEN 'running' THEN 0
            WHEN 'queued'  THEN 1
            WHEN 'done'    THEN 2
            WHEN 'error'   THEN 3
            ELSE 4 END, created_at DESC
          LIMIT :lim
        """), {"lim": limit}).mappings().all()

def get_task(task_id):
    with engine.begin() as con:
        r = con.execute(text("SELECT * FROM tasks WHERE id=:id"), {"id": task_id}).mappings().first()
        return r

def list_targets():
    with engine.begin() as con:
        return con.execute(text("SELECT * FROM targets ORDER BY enabled DESC, seed")).mappings().all()
