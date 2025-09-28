# BugDash — Attack Surface Crawler + Dashboard

Minimal, efficient bug hunting stack:
- Simple web UI (FastAPI + Basic Auth) to start scans and view progress
- Active scheduler that pulls scopes from arkadiyt **and** your `user-wildcards.txt`
- Recon pipeline: subfinder → dnsx → httpx → katana/gau/waybackurls → nuclei
- De-duped SQLite storage; findings labeled: `likely-bug`, `sus`, `info`
- Upload Nuclei templates at runtime (UI), plus mounted folder
- Docker Compose one-liner

> **Only scan authorized targets.** Respect each bounty program’s scope/rules.

---

## Quick start (Debian on Google Cloud)

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg git
# Docker Engine + Compose plugin
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/debian $(. /etc/os-release; echo $VERSION_CODENAME) stable" \
| sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker $USER
newgrp docker

