#!/usr/bin/env bash
# raycert against Pebble, Let's Encrypt's ACME test server: account, order, http-01, finalize,
# download; then `renew --force` with a hook, and the chains checked with raycert and openssl.
#
# Pebble runs from a local binary (PEBBLE=path, default `pebble` on the PATH), built with
#   GOBIN=$PWD/bin go install github.com/letsencrypt/pebble/v2/cmd/pebble@v2.6.0
# and its test certificates (PEBBLE_CERTS=dir with pebble.minica.pem and localhost/{cert,key}.pem;
# default: the Go module cache). With PEBBLE_DOCKER=1 it runs `docker run --rm` instead, in the
# foreground of a backgrounded shell, stopped by that shell's PID.
#
# Pebble listens on random high ports; it is stopped by its own PID ($!), never by name.
set -uo pipefail

RAYCERT=${RAYCERT:-./raycert}
PEBBLE=${PEBBLE:-pebble}
if [ -z "${PEBBLE_CERTS:-}" ] && command -v go >/dev/null; then
    PEBBLE_CERTS="$(go env GOMODCACHE)/github.com/letsencrypt/pebble/v2@v2.6.0/test/certs"
fi
OUT=$(mktemp -d "${TMPDIR:-/tmp}/raycert-pebble.XXXXXX")
PEBBLE_PID=""
cleanup() {
    if [ -n "$PEBBLE_PID" ]; then
        kill "$PEBBLE_PID" 2>/dev/null
        wait "$PEBBLE_PID" 2>/dev/null
    fi
    rm -rf "$OUT"
}
trap cleanup EXIT

PASS=0
FAIL=0
ok() { echo "ok    $*"; PASS=$((PASS + 1)); }
ko() { echo "FAIL  $*"; FAIL=$((FAIL + 1)); }
free_base() {
    local p
    for _ in 1 2 3 4 5 6 7 8; do
        p=$((RANDOM % 20000 + 30000))
        if ! nc -z 127.0.0.1 "$p" 2>/dev/null && ! nc -z 127.0.0.1 $((p + 1)) 2>/dev/null &&
            ! nc -z 127.0.0.1 $((p + 2)) 2>/dev/null; then
            echo "$p"
            return 0
        fi
    done
    echo "no free ports found" >&2
    exit 1
}

if [ ! -f "${PEBBLE_CERTS:-}/pebble.minica.pem" ]; then
    echo "pebble test certificates not found (set PEBBLE_CERTS)" >&2
    exit 2
fi
cp "$PEBBLE_CERTS/localhost/cert.pem" "$PEBBLE_CERTS/localhost/key.pem" "$PEBBLE_CERTS/pebble.minica.pem" "$OUT/"

BASE=$(free_base)
API=$BASE
MGMT=$((BASE + 1))
HTTP01=$((BASE + 2))
cat >"$OUT/pebble.json" <<EOF
{"pebble": {"listenAddress": "0.0.0.0:$API", "managementListenAddress": "0.0.0.0:$MGMT",
  "certificate": "cert.pem", "privateKey": "key.pem", "httpPort": $HTTP01, "tlsPort": $((BASE + 3)),
  "ocspResponderURL": "", "externalAccountBindingRequired": false,
  "retryAfter": {"authz": 1, "order": 1}, "certificateValidityPeriod": 7776000}}
EOF

if [ "${PEBBLE_DOCKER:-0}" = "1" ]; then
    # Pebble in Docker reaches the host's http-01 responder through host.docker.internal.
    (cd "$OUT" && exec docker run --rm -e PEBBLE_VA_NOSLEEP=1 -p "$API:$API" -p "$MGMT:$MGMT" \
        -v "$OUT:/cfg" -w /cfg ghcr.io/letsencrypt/pebble:latest -config /cfg/pebble.json -strict \
        >"$OUT/pebble.log" 2>&1) &
    PEBBLE_PID=$!
    NAME=host.docker.internal
else
    (cd "$OUT" && PEBBLE_VA_NOSLEEP=1 exec "$PEBBLE" -config pebble.json -strict >"$OUT/pebble.log" 2>&1) &
    PEBBLE_PID=$!
    NAME=localhost
fi
for _ in $(seq 1 100); do
    if nc -z 127.0.0.1 "$API" 2>/dev/null; then break; fi
    sleep 0.1
done

DIR="https://localhost:$API/dir"
H="$OUT/home"
export SSL_CERT_FILE="$OUT/pebble.minica.pem"
echo "== pebble on :$API (http-01 on :$HTTP01), directory $DIR"

for t in p256 rsa; do
    if "$RAYCERT" acme "web-$t" --home "$H" --directory "$DIR" --san "$NAME" --type "$t" \
        --http-port "$HTTP01" --http-host "::" >"$OUT/acme-$t.log" 2>&1; then
        ok "acme: certificate for $NAME with a $t key"
    else
        ko "acme: certificate for $NAME with a $t key"
        sed 's/^/        /' "$OUT/acme-$t.log" | tail -5
    fi
done

ED_OUT=$("$RAYCERT" acme web-ed --home "$H" --directory "$DIR" --san "$NAME" --type ed25519 2>&1)
if [[ "$ED_OUT" == *"only RSA and ECDSA"* ]]; then
    ok "acme: an Ed25519 certificate key is refused before talking to the CA"
else
    ko "acme: Ed25519 refusal"
fi

# Pebble's root changes on every start: fetch it from the management API.
curl -sk "https://localhost:$MGMT/roots/0" >"$OUT/pebble-root.pem"
if [ -s "$H/certs/web-p256/chain.pem" ]; then
    if openssl verify -CAfile "$OUT/pebble-root.pem" -untrusted "$H/certs/web-p256/chain.pem" \
        "$H/certs/web-p256/cert.pem" >/dev/null 2>&1; then
        ok "openssl verify: the Pebble chain up to Pebble's root"
    else
        ko "openssl verify: the Pebble chain up to Pebble's root"
    fi
    if "$RAYCERT" inspect "$H/certs/web-p256/chain.pem" --ca "$OUT/pebble-root.pem" | grep -q '#2 signed by .*: valid'; then
        ok "raycert inspect: Pebble chain verified against Pebble's root"
    else
        ko "raycert inspect: Pebble chain verified against Pebble's root"
    fi
fi

BEFORE=$(openssl x509 -in "$H/certs/web-p256/cert.pem" -noout -serial 2>/dev/null)
if "$RAYCERT" renew web-p256 --home "$H" --force --hook "echo \"\$RAYCERT_NAME \$RAYCERT_CHAIN\" > '$OUT/hook.out'" \
    >"$OUT/renew.log" 2>&1; then
    ok "renew --force: re-issued over ACME"
else
    ko "renew --force"
    sed 's/^/        /' "$OUT/renew.log" | tail -5
fi
AFTER=$(openssl x509 -in "$H/certs/web-p256/cert.pem" -noout -serial 2>/dev/null)
if [ -n "$AFTER" ] && [ "$BEFORE" != "$AFTER" ]; then ok "renew: a new certificate ($AFTER)"; else ko "renew: same serial"; fi
if grep -q "web-p256 $H/certs/web-p256/chain.pem" "$OUT/hook.out" 2>/dev/null; then ok "renew: the hook ran with the paths"; else ko "renew: hook"; fi
if "$RAYCERT" renew --home "$H" --within 30 | grep -q "web-rsa: kept"; then ok "renew --within 30: 90-day certificates kept"; else ko "renew --within 30"; fi
"$RAYCERT" list --home "$H"

echo
echo "pebble: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
