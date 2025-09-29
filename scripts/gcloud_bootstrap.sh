#!/usr/bin/env bash
set -euo pipefail
PROJECT_ID="${PROJECT_ID:-the-bird-473108-k2}"
REGION="${REGION:-asia-southeast1}"
DB_PASS="${DB_PASS:-ChangeMe123!}"

gcloud config set project "$PROJECT_ID"
gcloud services enable run.googleapis.com sqladmin.googleapis.com pubsub.googleapis.com secretmanager.googleapis.com cloudscheduler.googleapis.com

# Cloud SQL (Enterprise custom)
gcloud sql instances create bugdash-sql \
  --database-version=POSTGRES_16 \
  --edition=ENTERPRISE \
  --region="$REGION" \
  --cpu=1 --memory=3840MiB \
  --storage-auto-increase

gcloud sql databases create bugdash --instance=bugdash-sql
gcloud sql users set-password postgres --instance=bugdash-sql --password "$DB_PASS"

CONN_NAME="$(gcloud sql instances describe bugdash-sql --format='value(connectionName)')"
echo "CLOUDSQL_INSTANCE=$CONN_NAME"

# Pub/Sub
gcloud pubsub topics create bugdash-tasks || true
gcloud pubsub subscriptions create bugdash-worker-pull --topic bugdash-tasks --ack-deadline 60 || true

# GCS
gsutil mb -l "$REGION" gs://bugdash-artifacts-$PROJECT_ID || true
