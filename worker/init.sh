#!/usr/bin/env bash
set -euo pipefail

: "${NUCLEI_TEMPLATES_DIR:=/data/nuclei-templates}"
mkdir -p "$NUCLEI_TEMPLATES_DIR" /var/log/bugdash

if [ ! -d "$NUCLEI_TEMPLATES_DIR/.git" ]; then
  echo "[init] Cloning nuclei-templates..."
  git clone --depth=1 https://github.com/projectdiscovery/nuclei-templates.git "$NUCLEI_TEMPLATES_DIR" || true
else
  echo "[init] Updating nuclei-templates..."
  git -C "$NUCLEI_TEMPLATES_DIR" pull --ff-only || true
fi
