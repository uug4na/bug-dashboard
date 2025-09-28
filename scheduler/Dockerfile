FROM python:3.11-slim
WORKDIR /app

# minimal deps for downloading the docker client + requests for HTTP
RUN apt-get update && apt-get install -y curl ca-certificates && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir requests==2.32.3

# install a static docker client binary
# pin a recent version to avoid surprise breaks
ARG DOCKER_CLI_VER=26.1.4
RUN curl -fsSL https://download.docker.com/linux/static/stable/x86_64/docker-${DOCKER_CLI_VER}.tgz \
 | tar -xz -C /usr/local/bin --strip-components=1 docker/docker

COPY run_scheduler.py /app/run_scheduler.py
ENV PYTHONUNBUFFERED=1
CMD ["python","/app/run_scheduler.py"]
