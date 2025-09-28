# syntax=docker/dockerfile:1

############################
# Stage 1: build PD + go tools with Go 1.24.x
############################
FROM golang:1.24.3 AS builder

# Speed up go builds with caches
ENV CGO_ENABLED=0 GOFLAGS="-buildvcs=false"
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go install github.com/projectdiscovery/pdtm/cmd/pdtm@latest && \
    /go/bin/pdtm -install -tools subfinder,dnsx,httpx,naabu,katana,nuclei && \
    go install github.com/tomnomnom/assetfinder@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest

############################
# Stage 2: slim runtime
############################
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    ca-certificates curl wget git unzip jq python3 python3-pip \
    dnsutils netcat-openbsd openssl \
 && rm -rf /var/lib/apt/lists/*

# Copy statically built tools from builder
COPY --from=builder /go/bin/* /usr/local/bin/

# Templates initializer + pipeline
COPY init.sh /init.sh
RUN chmod +x /init.sh

COPY run_pipeline.py /usr/local/bin/run_pipeline.py
RUN chmod +x /usr/local/bin/run_pipeline.py
COPY supervisor.py /usr/local/bin/supervisor.py
RUN chmod +x /usr/local/bin/supervisor.py

WORKDIR /data

CMD ["/bin/bash","-lc","/init.sh || true; exec python3 /usr/local/bin/supervisor.py"]
