import os

PROJECT_ID        = os.getenv("GOOGLE_CLOUD_PROJECT", "")
REGION            = os.getenv("REGION", "asia-southeast1")

# Cloud SQL (use unix socket path in Cloud Run)
CLOUDSQL_INSTANCE = os.getenv("CLOUDSQL_INSTANCE", "")  # e.g. the-bird-473108-k2:asia-southeast1:bugdash-sql
DB_NAME           = os.getenv("DB_NAME", "bugdash")
DB_USER           = os.getenv("DB_USER", "postgres")
DB_PASS           = os.getenv("DB_PASS", "")
DATABASE_URL      = os.getenv("DATABASE_URL") or (
    f"postgresql+psycopg://{DB_USER}:{DB_PASS}@/{DB_NAME}"
    f"?host=/cloudsql/{CLOUDSQL_INSTANCE}"
)

# Pub/Sub
PUBSUB_TOPIC      = os.getenv("PUBSUB_TOPIC", "bugdash-tasks")
SUBSCRIPTION      = os.getenv("SUBSCRIPTION", "bugdash-worker-pull")

# Storage
GCS_BUCKET        = os.getenv("GCS_BUCKET", "")

# Auth for API (use Secret Manager to inject)
AUTH_USERNAME     = os.getenv("AUTH_USERNAME", "admin")
AUTH_PASSWORD     = os.getenv("AUTH_PASSWORD", "change-me")
