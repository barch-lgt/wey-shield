FROM projectdiscovery/nuclei:latest AS pd-tools

FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/usr/local/bin:$PATH"

COPY --from=pd-tools /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=pd-tools /usr/local/bin/subfinder /usr/local/bin/subfinder
COPY --from=pd-tools /usr/local/bin/httpx /usr/local/bin/httpx

RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 10000
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "10000", "--workers", "1"]
