# ---- builder for recon tools ----
FROM golang:1.24.3 AS builder
ENV CGO_ENABLED=0 GOFLAGS="-buildvcs=false"
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go install github.com/projectdiscovery/pdtm/cmd/pdtm@latest && \
    /go/bin/pdtm -install subfinder,dnsx,httpx,naabu,katana,nuclei && \
    go install github.com/tomnomnom/assetfinder@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest

# ---- runtime ----
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates curl git python3 python3-pip jq && rm -rf /var/lib/apt/lists/*
COPY --from=builder /go/bin/* /usr/local/bin/

WORKDIR /app
COPY worker/requirements.txt /app/requirements.txt
RUN pip3 install --no-cache-dir -r /app/requirements.txt
COPY common /app/common
COPY worker/worker_main.py /usr/local/bin/worker_main.py
COPY worker/run_pipeline.py /usr/local/bin/run_pipeline.py
COPY worker/init.sh /init.sh
RUN chmod +x /init.sh /usr/local/bin/worker_main.py /usr/local/bin/run_pipeline.py
ENV PYTHONUNBUFFERED=1
CMD ["/bin/bash","-lc","/init.sh || true; exec python3 /usr/local/bin/worker_main.py"]