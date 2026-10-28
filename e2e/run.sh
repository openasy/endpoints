#!/bin/bash
# End-to-end: a real osqueryd on Debian enrols with Endpoints through a TLS proxy, as a laptop would, runs the query pack
# from the setup page and sends its results; Endpoints checks the device and lists its software. A removed device enrols
# again; one whose secret is revoked cannot (ADR 0065). Needs Docker and openssl, and the image to test (default
# endpoints:dev). Exits non-zero on failure.
set -eu
IMAGE=${1:-endpoints:dev}
OSQUERY=5.24.0
D=$(mktemp -d)
cleanup() { docker rm -f e2e-endpoints e2e-endpoints-tls e2e-osquery >/dev/null 2>&1 || true; docker network rm e2e-endpoints >/dev/null 2>&1 || true; }
cleanup
trap cleanup EXIT
docker network create e2e-endpoints >/dev/null
openssl rand -hex 32 > "$D/kek"
chmod 644 "$D/kek"

# A CA of the test's own and a certificate for the proxy, as an install with an internal CA has (ADR 0026).
mkdir -p "$D/certs" "$D/osquery"
openssl req -x509 -sha256 -newkey rsa:2048 -nodes -days 2 -subj "/CN=e2e CA" -addext "basicConstraints=critical,CA:TRUE" \
  -keyout "$D/certs/ca.key" -out "$D/certs/ca.pem" 2>/dev/null
openssl req -sha256 -newkey rsa:2048 -nodes -subj "/CN=endpoints-tls" -keyout "$D/certs/server.key" -out "$D/certs/server.csr" 2>/dev/null
printf "subjectAltName=DNS:endpoints-tls\n" > "$D/certs/ext.cnf"
openssl x509 -sha256 -req -in "$D/certs/server.csr" -CA "$D/certs/ca.pem" -CAkey "$D/certs/ca.key" -CAcreateserial -days 2 \
  -extfile "$D/certs/ext.cnf" -out "$D/certs/server.pem" 2>/dev/null
chmod 644 "$D/certs/"*
printf 'endpoints-tls:8443 {\n  tls /certs/server.pem /certs/server.key\n  reverse_proxy e2e-endpoints:8080\n}\n' > "$D/Caddyfile"

docker run -d --name e2e-endpoints --network e2e-endpoints -p 127.0.0.1:18065:8080 -e ENDPOINTS_PUBLIC_URL=https://endpoints-tls:8443 \
  -v "$D/kek:/run/secrets/openasy-kek:ro" "$IMAGE" >/dev/null
docker run -d --name e2e-endpoints-tls --network e2e-endpoints --network-alias endpoints-tls -v "$D/Caddyfile:/etc/caddy/Caddyfile:ro" -v "$D/certs:/certs:ro" caddy:2.11.7 >/dev/null
# A plain Debian with osquery's own package, as a Linux workstation. It waits for its three files.
docker run -d --name e2e-osquery --network e2e-endpoints -v "$D/osquery:/etc/osquery-files:ro" debian:trixie-slim sh -c \
  "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends curl ca-certificates >/dev/null \
   && curl -sfLo /tmp/osquery.deb https://github.com/osquery/osquery/releases/download/$OSQUERY/osquery_$OSQUERY-1.linux_\$(dpkg --print-architecture).deb \
   && apt-get install -y -qq /tmp/osquery.deb >/dev/null && touch /ready && sleep infinity" >/dev/null
for _ in $(seq 1 30); do curl -sf localhost:18065/readyz >/dev/null && break; sleep 1; done
for _ in $(seq 1 240); do docker exec e2e-osquery test -f /ready 2>/dev/null && break; sleep 1; done
docker exec e2e-osquery test -f /ready || { echo "FAIL osquery was not installed"; docker logs e2e-osquery; exit 1; }
SETUP=$(docker logs e2e-endpoints 2>&1 | grep -o 'https://endpoints-tls:8443/?setup=[A-Za-z0-9_-]*' | tail -1)
node "$(dirname "$0")/flow.ts" "http://localhost:18065" "$SETUP" "$D"
