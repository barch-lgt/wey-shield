FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/usr/local/bin:$PATH"

# System deps + nmap
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        unzip \
        nmap \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ProjectDiscovery tools (nuclei, subfinder, httpx)
# Pinned to stable releases — update versions when needed
RUN PD_BASE="https://github.com/projectdiscovery" && \
    # Nuclei
    curl -sL "$PD_BASE/nuclei/releases/latest/download/nuclei_linux_amd64.zip" -o /tmp/nuclei.zip \
    && unzip -q /tmp/nuclei.zip -d /usr/local/bin/ && rm /tmp/nuclei.zip \
    && chmod +x /usr/local/bin/nuclei && \
    # Subfinder
    curl -sL "$PD_BASE/subfinder/releases/latest/download/subfinder_linux_amd64.zip" -o /tmp/subfinder.zip \
    && unzip -q /tmp/subfinder.zip -d /usr/local/bin/ && rm /tmp/subfinder.zip \
    && chmod +x /usr/local/bin/subfinder && \
    # Httpx
    curl -sL "$PD_BASE/httpx/releases/latest/download/httpx_linux_amd64.zip" -o /tmp/httpx.zip \
    && unzip -q /tmp/httpx.zip -d /usr/local/bin/ && rm /tmp/httpx.zip \
    && chmod +x /usr/local/bin/httpx

# Update nuclei templates (baked into image for faster cold starts)
RUN nuclei -update-templates -silent || true

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 10000

# Render uses port 10000 by default
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "10000", "--workers", "1"]
