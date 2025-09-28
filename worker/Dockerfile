FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    curl wget git unzip jq python3 python3-pip ca-certificates build-essential \
    dnsutils netcat-openbsd openssl golang-go \
 && rm -rf /var/lib/apt/lists/*

# ProjectDiscovery tool manager + tools
RUN go install github.com/projectdiscovery/pdtm/cmd/pdtm@latest && \
    /root/go/bin/pdtm -install -tools subfinder,dnsx,httpx,naabu,katana,nuclei

# tomnomnom + gau
RUN go install github.com/tomnomnom/assetfinder@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest

ENV PATH="/root/go/bin:${PATH}"

COPY init.sh /init.sh
RUN chmod +x /init.sh

COPY run_pipeline.py /usr/local/bin/run_pipeline.py
RUN chmod +x /usr/local/bin/run_pipeline.py

WORKDIR /data
CMD ["/bin/bash", "-lc", "/init.sh && tail -f /dev/null"]
