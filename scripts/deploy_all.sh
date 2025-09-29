#!/usr/bin/env bash
set -euo pipefail
PROJECT_ID="${PROJECT_ID:-the-bird-473108-k2}"
REGION="${REGION:-asia-southeast1}"
DB_PASS="${DB_PASS:-ChangeMe123!}"
BUCKET="bugdash-artifacts-$PROJECT_ID"
CONN_NAME="$(gcloud sql instances describe bugdash-sql --format='value(connectionName)')"

gcloud builds submit --tag gcr.io/$PROJECT_ID/bugdash-api ./api
gcloud builds submit --tag gcr.io/$PROJECT_ID/bugdash-worker ./worker
gcloud builds submit --tag gcr.io/$PROJECT_ID/bugdash-scheduler ./scheduler

gcloud run deploy bugdash-api --image gcr.io/$PROJECT_ID/bugdash-api \
  --region $REGION --allow-unauthenticated \
  --add-cloudsql-instances $CONN_NAME \
  --set-env-vars CLOUDSQL_INSTANCE=$CONN_NAME,DB_NAME=bugdash,DB_USER=postgres,DB_PASS=$DB_PASS \
  --set-env-vars GOOGLE_CLOUD_PROJECT=$PROJECT_ID,REGION=$REGION \
  --set-env-vars PUBSUB_TOPIC=bugdash-tasks,GCS_BUCKET=$BUCKET \
  --cpu 1 --memory 512Mi --max-instances 3

gcloud run deploy bugdash-worker --image gcr.io/$PROJECT_ID/bugdash-worker \
  --region $REGION --no-allow-unauthenticated \
  --add-cloudsql-instances $CONN_NAME \
  --set-env-vars CLOUDSQL_INSTANCE=$CONN_NAME,DB_NAME=bugdash,DB_USER=postgres,DB_PASS=$DB_PASS \
  --set-env-vars GOOGLE_CLOUD_PROJECT=$PROJECT_ID,REGION=$REGION \
  --set-env-vars SUBSCRIPTION=bugdash-worker-pull,GCS_BUCKET=$BUCKET,WORKER_CONCURRENCY=4 \
  --cpu 2 --memory 2Gi --max-instances 10

gcloud run jobs create bugdash-scheduler --image gcr.io/$PROJECT_ID/bugdash-scheduler \
  --region $REGION \
  --add-cloudsql-instances $CONN_NAME \
  --set-env-vars CLOUDSQL_INSTANCE=$CONN_NAME,DB_NAME=bugdash,DB_USER=postgres,DB_PASS=$DB_PASS \
  --set-env-vars GOOGLE_CLOUD_PROJECT=$PROJECT_ID,REGION=$REGION,PUBSUB_TOPIC=bugdash-tasks \
  --tasks 1 --cpu 1 --memory 512Mi || true

# every 30 minutes
gcloud scheduler jobs create http bugdash-sched \
  --schedule "*/30 * * * *" \
  --uri "$(gcloud run jobs describe bugdash-scheduler --region $REGION --format='value(latestJobUri)')" \
  --http-method POST \
  --oidc-service-account-email "$(gcloud projects describe $PROJECT_ID --format='value(projectNumber)')-compute@developer.gserviceaccount.com" || true
