FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    OPA_VERSION=1.20.2 \
    OPA_URL=http://127.0.0.1:8181 \
    FIREWALL_DB=/app/cybercity.db \
    FIREWALL_MODE=full

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Install OPA binary (linux/amd64). The host Windows Application Control
# policy blocks running OPA outside a container, so we ship it inside.
RUN curl -fsSL -o /usr/local/bin/opa \
        "https://openpolicyagent.org/downloads/v${OPA_VERSION}/opa_linux_amd64_static" \
    && chmod +x /usr/local/bin/opa \
    && /usr/local/bin/opa version

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000 8181

CMD ["/app/run.sh"]
