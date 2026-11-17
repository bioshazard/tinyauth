#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p tls
if [[ ! -f tls/key.pem ]]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout tls/key.pem -out tls/cert.pem -subj /CN=auth.localtest.me \
    -addext subjectAltName=DNS:auth.localtest.me,DNS:localhost
fi
trap 'docker compose down' EXIT
docker compose up -d --build lldap demo
docker compose exec -T demo python -c 'import time,requests
for _ in range(30):
 try:
  if requests.get("http://lldap:17170/health",timeout=2).status_code<500: break
 except requests.RequestException: pass
 time.sleep(1)
else: raise SystemExit("LLDAP unavailable")'
docker compose exec -T demo python bootstrap.py /demo/directory.yaml
docker compose up -d --build tinyauth
docker compose exec -T demo python -c 'import time,requests
for _ in range(30):
 try:
  if requests.get("http://tinyauth:3000/api/healthz",timeout=2).status_code==200: break
 except requests.RequestException: pass
 time.sleep(1)
else: raise SystemExit("Tinyauth unavailable")'
docker compose exec -T demo python checks.py
docker compose restart tinyauth
docker compose exec -T demo python -c 'import time,requests
for _ in range(30):
 try:
  if requests.get("http://tinyauth:3000/api/healthz",timeout=2).status_code==200: break
 except requests.RequestException: pass
 time.sleep(1)
else: raise SystemExit("Tinyauth unavailable")'
docker compose exec -T demo python checks.py after-restart
docker compose stop lldap
docker compose exec -T demo python checks.py outage
