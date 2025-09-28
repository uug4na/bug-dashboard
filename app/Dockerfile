FROM python:3.11-slim

WORKDIR /app
RUN apt-get update && apt-get install -y sqlite3 curl ca-certificates && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# --- add a static Docker client so /scan can run `docker exec` ---
ARG DOCKER_CLI_VER=26.1.4
RUN curl -fsSL https://download.docker.com/linux/static/stable/x86_64/docker-${DOCKER_CLI_VER}.tgz \
 | tar -xz -C /usr/local/bin --strip-components=1 docker/docker
# ----------------------------------------------------------------

COPY app.py /app/app.py
COPY templates /app/templates
COPY static /app/static

ENV PYTHONUNBUFFERED=1
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
