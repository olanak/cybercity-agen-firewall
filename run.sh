#!/usr/bin/env bash
# Boot script for the CyberCity demo. Starts OPA in the background, seeds
# the SQLite database if empty, then hands the terminal to uvicorn.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

: "${OPA_URL:=http://127.0.0.1:8181}"
: "${FIREWALL_MODE:=full}"
: "${FIREWALL_DB:=$HERE/cybercity.db}"
export OPA_URL FIREWALL_MODE FIREWALL_DB

start_opa() {
    if ! command -v opa >/dev/null 2>&1; then
        echo "!! opa binary not found on PATH. Install OPA or use the docker setup." >&2
        return 1
    fi
    echo ">> starting opa at $OPA_URL"
    opa run --server --addr :8181 \
        --set decision_logs.console=true \
        "$HERE/policy" &
    OPA_PID=$!
    trap 'kill $OPA_PID 2>/dev/null || true' EXIT
    for i in $(seq 1 30); do
        if curl -fs "$OPA_URL/health" >/dev/null 2>&1; then
            echo ">> opa ready"
            return 0
        fi
        sleep 0.2
    done
    echo "!! opa did not become ready" >&2
    return 1
}

seed_if_empty() {
    if [ ! -f "$FIREWALL_DB" ] || [ ! -s "$FIREWALL_DB" ]; then
        echo ">> seeding database at $FIREWALL_DB"
        python seed.py
    fi
}

start_opa || echo "!! continuing without OPA server; gateway will use opa eval fallback"
seed_if_empty

echo ">> starting uvicorn on 0.0.0.0:8000"
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 \
    --proxy-headers --forwarded-allow-ips '*'
