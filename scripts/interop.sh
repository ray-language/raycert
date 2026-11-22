#!/usr/bin/env bash
# raycert against openssl, the oracle: what raycert writes, openssl reads and verifies; what
# openssl writes, raycert reads with the same values; real TLS handshakes with raycert's
# certificates on openssl s_server and on raylang's own TLS server.
#
# Usage: scripts/interop.sh            (expects ./raycert: `make build` first)
# Servers run on random high ports and are stopped by their own PID ($!), never by name.
set -uo pipefail

RAYCERT=${RAYCERT:-./raycert}
OUT=$(mktemp -d "${TMPDIR:-/tmp}/raycert-interop.XXXXXX")
PIDS=()
cleanup() {
    for p in "${PIDS[@]:-}"; do
        if [ -n "$p" ]; then kill "$p" 2>/dev/null; wait "$p" 2>/dev/null; fi
    done
    rm -rf "$OUT"
}
trap cleanup EXIT

PASS=0
FAIL=0
ok() { echo "ok    $*"; PASS=$((PASS + 1)); }
ko() { echo "FAIL  $*"; FAIL=$((FAIL + 1)); }
check() {
    local name=$1
    shift
    if "$@" >"$OUT/last.log" 2>&1; then ok "$name"; else ko "$name"; sed 's/^/        /' "$OUT/last.log" | head -5; fi
}
same() {
    if [ "$2" = "$3" ]; then ok "$1"; else ko "$1"; echo "        '$2' != '$3'"; fi
}
free_port() {
    local p
    for _ in 1 2 3 4 5 6 7 8; do
        p=$((RANDOM % 20000 + 30000))
        if ! nc -z 127.0.0.1 "$p" 2>/dev/null; then echo "$p"; return 0; fi
    done
    echo "no free port found" >&2
    exit 1
}
wait_port() {
    for _ in $(seq 1 100); do
        if nc -z 127.0.0.1 "$1" 2>/dev/null; then return 0; fi
        sleep 0.1
    done
    return 1
}
stop_pid() {
    if [ -n "$1" ]; then
        kill "$1" 2>/dev/null
        wait "$1" 2>/dev/null
    fi
}
sha256_of() { openssl x509 -in "$1" -noout -fingerprint -sha256 | cut -d= -f2; }
raycert_sha256() { "$RAYCERT" inspect "$1" | awk '/SHA-256:/ {print $2; exit}'; }
mode_of() { stat -f %Lp "$1" 2>/dev/null || stat -c %a "$1"; }

echo "== raycert writes, openssl reads"
for t in ed25519 p256 rsa; do
    H="$OUT/home-$t"
    "$RAYCERT" ca init --home "$H" --type "$t" --subject "CN=Interop CA $t,O=raycert,C=ES" >/dev/null
    "$RAYCERT" issue web --home "$H" --san localhost,127.0.0.1,::1 --type p256 >/dev/null
    "$RAYCERT" issue api --home "$H" --san api.localhost --type rsa >/dev/null
    check "$t CA: openssl verify leaf (p256 key)" openssl verify -CAfile "$H/ca/ca.pem" "$H/certs/web/cert.pem"
    check "$t CA: openssl verify leaf (rsa key)" openssl verify -CAfile "$H/ca/ca.pem" "$H/certs/api/cert.pem"
    check "$t CA: openssl verify self-signed CA" openssl verify -CAfile "$H/ca/ca.pem" "$H/ca/ca.pem"
    check "$t CA: openssl pkey reads the CA key" openssl pkey -in "$H/ca/key.pem" -noout
    same "$t CA: SHA-256 fingerprint" "$(raycert_sha256 "$H/ca/ca.pem")" "$(sha256_of "$H/ca/ca.pem")"
    same "$t CA: SAN as openssl prints it" \
        "$(openssl x509 -in "$H/certs/web/cert.pem" -noout -ext subjectAltName | tail -1 | xargs)" \
        "DNS:localhost, IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1"
    same "$t CA: key.pem is 0600" "$(mode_of "$H/certs/web/key.pem")" "600"
    same "$t CA: ca dir is 0700" "$(mode_of "$H/ca")" "700"
done

H="$OUT/home-p256"
for t in ed25519 p256 rsa; do
    "$RAYCERT" key new --type "$t" -o "$OUT/k-$t.pem" 2>/dev/null
    check "key new $t: openssl pkey" openssl pkey -in "$OUT/k-$t.pem" -noout
    "$RAYCERT" csr --key "$OUT/k-$t.pem" --san csr.test,www.csr.test -o "$OUT/csr-$t.pem"
    check "csr $t: openssl req -verify" openssl req -in "$OUT/csr-$t.pem" -noout -verify
    same "csr $t: requested SANs" "$(openssl req -in "$OUT/csr-$t.pem" -noout -text | grep -A1 'Subject Alternative Name' | tail -1 | xargs)" "DNS:csr.test, DNS:www.csr.test"
done

echo "== openssl writes, raycert reads"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$OUT/o.key" -out "$OUT/o.pem" \
    -days 10 -subj "/C=ES/O=Oracle/CN=oracle.test" -addext "subjectAltName=DNS:oracle.test,IP:10.1.2.3,email:a@b.test" 2>/dev/null
same "openssl cert: SHA-256 fingerprint" "$(raycert_sha256 "$OUT/o.pem")" "$(sha256_of "$OUT/o.pem")"
same "openssl cert: SANs" "$("$RAYCERT" inspect "$OUT/o.pem" | awk -F'SANs: *' '/SANs:/ {print $2}')" "DNS:oracle.test, IP:10.1.2.3, email:a@b.test"
check "openssl cert: self-signature valid" sh -c "'$RAYCERT' inspect '$OUT/o.pem' | grep -q 'signed by .*: valid'"
openssl x509 -in "$OUT/o.pem" -outform DER -out "$OUT/o.der"
same "openssl DER: SHA-256 fingerprint" "$(raycert_sha256 "$OUT/o.der")" "$(sha256_of "$OUT/o.pem")"
for spec in "rsa:2048" "ed25519"; do
    openssl req -new -newkey "$spec" -nodes -keyout "$OUT/x.key" -out "$OUT/x.csr" -subj "/CN=ext.test" \
        -addext "subjectAltName=DNS:ext.test" 2>/dev/null
    "$RAYCERT" issue ext --home "$H" --csr "$OUT/x.csr" >/dev/null
    check "openssl CSR ($spec) signed by raycert: openssl verify" openssl verify -CAfile "$H/ca/ca.pem" "$H/certs/ext/cert.pem"
    same "openssl CSR ($spec): leaf key is the CSR's" \
        "$(openssl x509 -in "$H/certs/ext/cert.pem" -noout -pubkey | openssl sha256)" \
        "$(openssl req -in "$OUT/x.csr" -noout -pubkey | openssl sha256)"
done

echo "== openssl chains beyond P-256/SHA-256"
# P-384 root (ecdsa-with-SHA384) -> RSA intermediate -> leaves signed sha384WithRSA and sha512WithRSA.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 -sha384 -nodes -keyout "$OUT/r384.key" \
    -out "$OUT/r384.pem" -days 10 -subj "/CN=Oracle P-384 Root" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" 2>/dev/null
openssl req -new -newkey rsa:3072 -nodes -keyout "$OUT/irsa.key" -out "$OUT/irsa.csr" -subj "/CN=Oracle RSA Intermediate" 2>/dev/null
printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\n' >"$OUT/ca.ext"
openssl x509 -req -in "$OUT/irsa.csr" -CA "$OUT/r384.pem" -CAkey "$OUT/r384.key" -sha384 -days 10 \
    -extfile "$OUT/ca.ext" -out "$OUT/irsa.pem" 2>/dev/null
for h in sha384 sha512; do
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$OUT/l-$h.key" -out "$OUT/l-$h.csr" \
        -subj "/CN=leaf-$h.test" 2>/dev/null
    openssl x509 -req -in "$OUT/l-$h.csr" -CA "$OUT/irsa.pem" -CAkey "$OUT/irsa.key" -"$h" -days 10 -out "$OUT/l-$h.pem" 2>/dev/null
    cat "$OUT/l-$h.pem" "$OUT/irsa.pem" "$OUT/r384.pem" >"$OUT/chain-$h.pem"
    check "openssl chain (leaf ${h}WithRSA): openssl verify" openssl verify -CAfile "$OUT/r384.pem" -untrusted "$OUT/irsa.pem" "$OUT/l-$h.pem"
    same "openssl chain (leaf ${h}WithRSA, RSA under ecdsa-with-SHA384 P-384): raycert verifies all 3 links" \
        "$("$RAYCERT" inspect "$OUT/chain-$h.pem" 2>&1 | grep -c ': valid')" "3"
done

echo "== TLS with openssl s_server"
for proto in -tls1_2 ""; do
    P=$(free_port)
    openssl s_server -accept "$P" -cert "$H/certs/web/chain.pem" -key "$H/certs/web/key.pem" $proto -www -quiet \
        >"$OUT/s_server.log" 2>&1 &
    PID=$!
    PIDS+=("$PID")
    if wait_port "$P"; then
        check "s_server ${proto:-default}: openssl s_client verifies against the raycert CA" sh -c \
            "echo | openssl s_client -connect 127.0.0.1:$P -servername localhost -CAfile '$H/ca/ca.pem' -verify_return_error -verify_hostname localhost 2>&1 | grep -q 'Verify return code: 0'"
        same "s_server ${proto:-default}: raycert inspect reads the served leaf" \
            "$("$RAYCERT" inspect "127.0.0.1:$P" --ca "$H/ca/ca.pem" 2>&1 | awk '/SHA-256:/ {print $2; exit}')" \
            "$(sha256_of "$H/certs/web/cert.pem")"
    else
        ko "s_server ${proto:-default} did not start"
    fi
    stop_pid "$PID"
done
P=$(free_port)
openssl s_server -accept "$P" -cert "$H/certs/web/chain.pem" -key "$H/certs/web/key.pem" -tls1_3 -www -quiet \
    >"$OUT/s_server13.log" 2>&1 &
PID=$!
PIDS+=("$PID")
if wait_port "$P"; then
    # s_server -cert sends only the leaf: one link, the leaf against the --ca anchor.
    "$RAYCERT" inspect "127.0.0.1:$P" --ca "$H/ca/ca.pem" >"$OUT/inspect13.log" 2>&1
    same "TLS 1.3-only server: raycert inspect reads the served leaf" \
        "$(awk '/SHA-256:/ {print $2; exit}' "$OUT/inspect13.log")" "$(sha256_of "$H/certs/web/cert.pem")"
    same "TLS 1.3-only server: the leaf verifies against the raycert CA" \
        "$(grep -c 'signed by .*: valid' "$OUT/inspect13.log")" "1"
else
    ko "TLS 1.3-only s_server did not start"
fi
stop_pid "$PID"

echo "== TLS with raylang's own server (net/webserver over rustls)"
for t in ed25519 p256 rsa; do
    HT="$OUT/home-$t"
    PF="$OUT/port-$t"
    ray run scripts/tls_server.ray "$HT/certs/web/chain.pem" "$HT/certs/web/key.pem" "$PF" >"$OUT/tls-$t.log" 2>&1 &
    PID=$!
    PIDS+=("$PID")
    for _ in $(seq 1 100); do [ -s "$PF" ] && break; sleep 0.1; done
    P=$(cat "$PF" 2>/dev/null)
    if [ -n "$P" ] && wait_port "$P"; then
        # openssl, not the system curl: macOS curl's LibreSSL 3.3 cannot verify Ed25519 signatures.
        same "raylang TLS ($t CA): HTTPS GET verified against the raycert CA" \
            "$(printf 'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n' | openssl s_client -quiet -connect "127.0.0.1:$P" \
                -servername localhost -CAfile "$HT/ca/ca.pem" -verify_return_error -verify_hostname localhost 2>/dev/null | tail -1)" \
            "hello from raylang tls"
        same "raylang TLS ($t CA): raycert inspect reads its chain" \
            "$("$RAYCERT" inspect "127.0.0.1:$P" --ca "$HT/ca/ca.pem" 2>&1 | grep -c ': valid')" "2"
    else
        ko "raylang TLS ($t CA) did not start: $(head -3 "$OUT/tls-$t.log")"
    fi
    stop_pid "$PID"
done

echo
echo "interop: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
