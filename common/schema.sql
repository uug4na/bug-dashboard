CREATE TABLE IF NOT EXISTS tasks(
  id TEXT PRIMARY KEY,
  target TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  status TEXT NOT NULL CHECK (status IN ('queued','running','done','error')),
  note TEXT DEFAULT '',
  heartbeat TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS tasks_status_created ON tasks (status, created_at);

CREATE TABLE IF NOT EXISTS targets(
  id BIGSERIAL PRIMARY KEY,
  pattern TEXT UNIQUE,
  seed TEXT,
  last_scanned TIMESTAMPTZ,
  enabled BOOLEAN DEFAULT TRUE
);
CREATE INDEX IF NOT EXISTS targets_enabled_last ON targets (enabled, last_scanned);

CREATE TABLE IF NOT EXISTS scope(
  id BIGSERIAL PRIMARY KEY,
  pattern TEXT UNIQUE
);

CREATE TABLE IF NOT EXISTS assets(
  id BIGSERIAL PRIMARY KEY,
  task_id TEXT REFERENCES tasks(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  value TEXT NOT NULL,
  UNIQUE(task_id, kind, value)
);

CREATE TABLE IF NOT EXISTS findings(
  id BIGSERIAL PRIMARY KEY,
  task_id TEXT REFERENCES tasks(id) ON DELETE CASCADE,
  tool TEXT,
  fingerprint TEXT,
  title TEXT,
  detail TEXT,
  severity TEXT,
  label TEXT,
  raw JSONB,
  score INT DEFAULT 0,
  reasons TEXT DEFAULT '',
  UNIQUE(task_id, tool, fingerprint)
);
CREATE INDEX IF NOT EXISTS findings_sev_score ON findings (severity, score DESC);
CREATE INDEX IF NOT EXISTS findings_raw_gin ON findings USING GIN (raw);
