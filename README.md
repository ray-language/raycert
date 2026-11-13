# raycert

Certificados para el ecosistema de [raylang](https://github.com/ray-language/raylang): inspecciona
certificados X.509 y cadenas (de un archivo o de un servidor TLS), lleva una **CA de desarrollo** que
emite certificados de hoja, y es un pequeño **cliente ACME** (RFC 8555) que obtiene y renueva
certificados para `raygate`/`raylb` — el punto 8 de §9 de `IDEAS-APPS.md`.

```
$ raycert ca init --type ed25519
$ raycert issue web --san localhost,127.0.0.1
$ raycert inspect ~/.raycert/certs/web/chain.pem
Certificate 1 of 2
  Subject:     CN=localhost
  Issuer:      CN=raycert development CA, O=raycert
  Serial:      77:5C:4F:5A:45:5D:F5:D0:3E:DB:3F:6F:F4:FC:AE:87
  Validity:    2026-11-13T16:22:37Z → 2027-02-11T17:22:37Z (89 days left)
  Key:         EC P-256
  Signature:   Ed25519
  SANs:        DNS:localhost, IP:127.0.0.1
  CA:          no
  Key usage:   digitalSignature
  Ext. usage:  serverAuth, clientAuth
  …
  SHA-256:     74:60:F9:CB:74:AB:DB:69:40:18:54:13:EF:09:78:0B:FB:31:89:25:44:94:6F:66:56:94:2D:B2:32:C8:FA:12
Certificate 2 of 2
  …
Chain:
  #1 signed by #2: valid
  #2 signed by CN=raycert development CA, O=raycert: valid
```

```
$ raycert inspect letsencrypt.org:443
letsencrypt.org:443 presented 4 certificate(s) (TLS 1.2 handshake, read by hand)
…
Chain:
  #1 signed by #2: not checked (ecdsa-with-SHA384 on P-384: std/crypto has no verifier for it)
  #2 signed by #3: not checked (ecdsa-with-SHA384 on P-384: std/crypto has no verifier for it)
  #3 signed by #4: not checked (ecdsa-with-SHA384 on P-384: std/crypto has no verifier for it)
  #4 signed by C=US, O=Internet Security Research Group, CN=ISRG Root X1: valid
```

Es una app de *dogfooding*: ejercita lo que las demás apps apenas tocan — **`std/pem`** (ninguna lo
usaba), **`std/crypto`** con firmas Ed25519/P-256/RSA, **`std/bigint`**-adyacente (enteros DER sin
signo), **`std/base64`** (base64url de JWS), `std/json`, trabajo de bits sobre `bytes` y
**`BytesBuilder`**, `std/time` (UTCTime/GeneralizedTime), cliente `net/http` y servidor
`net/webserver` (http-01), **`std/keychain`**, **`std/qr`**, `std/fs` con permisos privados, y un
**trait propio con genéricos** (`DerEncode` + `seq_of<T: DerEncode>` + `sign_envelope<T>`) — y
anota lo que falta (ver [Hallazgos](#hallazgos-de-dogfood)).

## Uso

```
raycert inspect FILE|HOST:PORT [--ca FILE] [--qr]
raycert der FILE
raycert key new [--type T] [-o FILE]
raycert csr --key FILE --san NOMBRES [-o FILE]
raycert ca init [--type T] [--subject DN] [--days N] [--keychain SERVICIO] [--force]
raycert ca show [--qr]
raycert ca remove
raycert issue NOMBRE --san NOMBRES [--type T] [--days N] [--csr FILE]
raycert acme NOMBRE --directory URL --san NOMBRES [--email E] [--http-port P] [--http-host H]
             [--type p256|rsa] [--insecure] [-v]
raycert list
raycert renew [NOMBRE…] [--within DÍAS] [--force] [--hook CMD] [--insecure] [-v]
```

| Orden | Qué hace |
|---|---|
| `inspect` | certificados de un PEM (cadena) o un DER, o los que presenta `HOST:PORT`: sujeto, emisor, serie, validez y días que quedan, tipo de clave, algoritmo de firma, SANs, restricciones básicas, usos, SKI/AKI, extensiones y huellas SHA-256/SHA-1; después, cada eslabón de la cadena verificado contra el siguiente (el último contra sí mismo, `--ca` o el almacén del sistema). Salida 2 si una firma no verifica. `--qr` dibuja la huella SHA-256 como QR para cotejarla por otro canal |
| `der` | el esquema ASN.1 de cualquier DER/PEM (como `openssl asn1parse`) |
| `key new` | una clave PKCS#8 (`ed25519`, `p256`, `rsa`, `rsa3072`, `rsa4096`) en un archivo 0600 |
| `csr` | una petición PKCS#10 con los SANs, firmada por la clave |
| `ca init` | la CA de desarrollo en `~/.raycert/ca/` (o `--home`, o `$RAYCERT_HOME`): clave en `key.pem` 0600 dentro de un directorio 0700, o en el **llavero del sistema** con `--keychain SERVICIO` |
| `issue` | un certificado de servidor/cliente TLS firmado por la CA, con clave nueva; o, con `--csr`, para la clave de una petición ajena (sin ver la clave privada). Escribe `key.pem` (0600), `cert.pem`, `chain.pem` y `meta.json` en `certs/NOMBRE/` |
| `acme` | cuenta, pedido, reto http-01 (sirve el token en `--http-host`:`--http-port`, por defecto `[::]:80`), CSR, finalización y descarga de la cadena; la clave de cuenta (P-256) queda en `acme/account.key.pem` |
| `list` | los certificados guardados y los días que les quedan |
| `renew` | vuelve a emitir (CA local o ACME, según `meta.json`) los que caducan antes de `--within` días (30 por defecto), y ejecuta `--hook` con `sh -c` por cada uno, con `RAYCERT_NAME`, `RAYCERT_DIR`, `RAYCERT_CERT`, `RAYCERT_CHAIN`, `RAYCERT_KEY` en el entorno: ahí se copian a raygate/raylb y se les pide recargar |

Los archivos se escriben por un temporal y `rename`, así un servidor que recarga nunca lee medio
archivo. Contra Pebble (o un ACME con CA propia) es mejor `SSL_CERT_FILE=raíz.pem` que `--insecure`:
raylang **añade** esa raíz a las del sistema y mantiene la verificación.

## Cómo está hecho

| Módulo | Qué |
|---|---|
| `der.ray` | DER a mano: decodificador **estricto** (longitudes mínimas, sin longitud indefinida, nada sobrante) a `Node { tag, body, raw }` — `raw` son los octetos exactos que cubre una firma —; el árbol `Asn1` para codificar; el **trait `DerEncode`** y los genéricos `seq_of<T: DerEncode>` / `set_of<T>` (SET OF ordenado por codificación); INTEGER en complemento a dos mínimo, OID base-128, UTCTime/GeneralizedTime según el año |
| `x509.ray` | `Cert`, `Name`, `Spki`, `AlgId`, `Ext` leídos del DER; `impl DerEncode` para `Name`, `Attr`, `AlgId`, `Ext`; SANs (DNS, IP v4/v6, email, URI), BasicConstraints, KeyUsage, ExtKeyUsage, SKI/AKI, huellas |
| `keys.ray` | Ed25519, P-256 y RSA como PKCS#8 (`std/crypto` da P-256 y RSA en PKCS#8 pero Ed25519 como semilla: el sobre RFC 8410 se pone y se quita aquí); SubjectPublicKeyInfo; firmas en forma X.509 (ECDSA en DER) y JWS (`r‖s`) |
| `issue.ray` | `Tbs` (TBSCertificate) y `RequestInfo` (PKCS#10) con `impl DerEncode`, firmados por **un solo genérico** `sign_envelope<T: DerEncode>`; CA autofirmada, hoja con SAN/EKU/AKI, CSR y su lectura |
| `verify.ray` | firma de un certificado contra la clave del emisor (sha256WithRSA, ecdsa-with-SHA256 en P-256, Ed25519) y la cadena eslabón a eslabón; lo demás se marca «not checked» con el motivo |
| `tlsprobe.ray` | la cadena del servidor con un **ClientHello TLS 1.2 hecho a mano**: lee registros hasta el mensaje Certificate (en claro en TLS 1.2) y corta; un `Reader` puro, probado con vuelos enlatados partidos en trozos |
| `jws.ray` | JWK (ES256/RS256/EdDSA) con solo los miembros obligatorios en orden, huella RFC 7638, cabecera protegida con `jwk` o `kid`, JWS aplanado, autorización de clave |
| `acme.ray` | directorio, nonces (`Replay-Nonce`, reintento con `badNonce`), cuenta, pedido, autorizaciones, retos, finalización, descarga; errores RFC 7807 legibles |
| `obtain.ray` | el flujo entero; el respondedor http-01 es `net/webserver` sobre un listener propio en una fibra, que se para cerrando un canal |
| `store.ray` | el almacén: directorios 0700, claves 0600 (o en `std/keychain`), escritura atómica, `meta.json` |
| `ops.ray`, `report.ray`, `cli.ray`, `main.ray` | las operaciones sin E/S de consola (las usan los tests), la presentación y la CLI |

## Interoperabilidad

`openssl` (3.5.9) es el oráculo de todo lo que se lee y se escribe; Pebble, el del ACME.

| Prueba | Resultado |
|---|---|
| `make interop` — `openssl verify` de CA y hojas con CA Ed25519, P-256 y RSA y hojas P-256/RSA; `openssl pkey` de cada clave; `openssl req -verify` de cada CSR; huellas y SANs iguales a los de `openssl x509`; certificados, DER y CSRs de openssl leídos y firmados por raycert; permisos 0600/0700 | **52/52** |
| TLS real: `openssl s_server` con la cadena de raycert, verificada por `s_client -verify_return_error -verify_hostname` en TLS 1.2 y 1.3; `raycert inspect 127.0.0.1:PORT` lee la hoja servida | ✓ |
| TLS real con el **servidor TLS de raylang** (`net/webserver` + rustls, `scripts/tls_server.ray`) cargando las cadenas de raycert con CA Ed25519, P-256 y RSA: GET HTTPS verificado por openssl | ✓ (los tres) |
| `make pebble` — Pebble 2.6.0 (**binario local** compilado con Go; el demonio de Docker no estaba en marcha): cuenta, pedido, http-01, finalización con CSR P-256 y RSA, descarga; `openssl verify` hasta la raíz de Pebble; `renew --force` con gancho; `renew --within 30` conserva los de 90 días | **9/9** |
| `inspect` de github.com, letsencrypt.org, www.google.com, example.com | cadenas completas leídas (14 eslabones); 6 verificados, 8 sin verificador en `std/crypto` (ver hallazgo 2) |

Con `PEBBLE_DOCKER=1`, `scripts/pebble.sh` lanza `docker run --rm ghcr.io/letsencrypt/pebble` en
primer plano de una subshell en segundo plano y la para por su PID; ese camino **no se ha probado**
(Docker no estaba disponible).

## Estado

| Qué | Estado |
|---|---|
| DER, X.509, claves, JWS, emisión, almacén, sonda TLS, ACME, CLI | **42 tests** en VM y nativo (`make test`, `make test-native`), raylang 1.27.95 |
| ACME sin red | un servidor ACME **guionizado** dentro del test (estado en un actor, comprueba cada JWS — firma, nonce, url, jwk/kid —, valida http-01 pidiéndolo al respondedor, firma el CSR) recorre el cliente entero, también en nativo |
| Llavero | `make test-keychain`: CA con la clave en el llavero (servicio `raycert-test-<aleatorio>`, borrado al final), VM y nativo |
| Binario nativo | `make build`: 3,8 MB, `--release` |
| openssl / Pebble | `make interop` 52/52, `make pebble` 9/9 |

Pendiente: reto `tls-alpn-01` y `dns-01`; revocación (`revokeCert`) y CRL/OCSP; claves de CA
intermedias (la CA de desarrollo es de un nivel); comprobar nombres de host y restricciones de nombre
al verificar una cadena (hoy solo firmas y nombres de emisor); y leer la cadena de un servidor
**solo TLS 1.3**, que necesita lo que pide el hallazgo 1.

## Hallazgos de dogfood

Borradores para `ray-apps/findings/` (campaña `raycert-1.27.95`), con su reproducción mínima en
raylang 1.27.95 release. Los rodeos están marcados en el código.

1. **[E] `net.tls_peer_cert` no da el DER ni la cadena.** `PeerCert` trae sujeto, emisor, fechas y
   SANs de la hoja; no hay forma de sacar la huella, el tipo de clave, la firma, las extensiones ni
   los intermedios. raycert habla TLS 1.2 a mano (`tlsprobe.ray`, ~200 líneas) para leer el mensaje
   Certificate en claro — y con un servidor solo TLS 1.3 no hay manera. Propuesta:
   `net.tls_peer_chain(h) -> Result<[bytes], string>` (DER, hoja primero).
2. **[E] `std/crypto` no verifica P-384 ni RSA con SHA-384/512.** Solo hay ecdsa-with-SHA256 en
   P-256, RS256/PS256 y Ed25519. En las cadenas públicas de github.com, letsencrypt.org,
   www.google.com y example.com, 8 de 14 eslabones son ecdsa-with-SHA384 sobre P-384 y no se pueden
   verificar (ring, debajo, tiene `ECDSA_P384_SHA384_ASN1` y `RSA_PKCS1_2048_8192_SHA384/512`).
   Propuesta: `ecdsa_verify_asn1(curve, pub, msg, sig)` y `rsa_pkcs1_verify_with(hash, …)`.
3. **[E] Ed25519 va por semilla y P-256/RSA por PKCS#8.** `p256_generate`/`rsa_generate` devuelven
   PKCS#8 y `p256_sign`/`rsa_pkcs1_sign` lo aceptan; `ed25519_sign` quiere la semilla de 32 octetos y
   devuelve `None` con el PKCS#8 de `openssl genpkey -algorithm ed25519` (48 octetos), y no hay
   `ed25519_generate`. Hay que poner y quitar el sobre RFC 8410 a mano. Propuesta: aceptar PKCS#8 en
   las funciones Ed25519 (o `ed25519_generate() -> PKCS#8` + `ed25519_seed_of`).
4. **[E] `std/fs` no puede crear un archivo con permisos.** `write_file` crea con 0644 (umask 022) y
   no hay `write_file_mode`, `open` con modo ni umask: una clave privada nace legible por todos hasta
   el `chmod`. Rodeo: crear vacío, `chmod 0o600`, escribir (`store.write_private`). Propuesta:
   `fs.write_file_mode(path, data, mode)` (O_CREAT|O_EXCL con el modo) y `fs.mkdir_mode`.
5. **[D] `llms.txt` no dice que haya firmas P-256/RSA, ni qué hacen `std/pem`, `std/keychain`,
   `std/qr` y `std/bigint`.** La línea de `std/crypto` nombra `ed25519_*` y nada más; los cuatro
   módulos aparecen solo por su nombre en la lista de módulos. Quien lea solo `llms.txt` concluye que
   no hay ECDSA ni RSA. `reference.md` y `ray_doc` sí los documentan bien.

Lo que salió bien a la primera: **el trait propio con genéricos** (`impl DerEncode` para un enum
recursivo y cinco structs, `seq_of<T: DerEncode>`, `sign_envelope<T: DerEncode>` firmando a la vez
certificados y CSRs) en VM **y nativo**, sin tocar ninguno de #352–#362; los **42 tests en nativo a la
primera**, incluido el servidor ACME con actor y fibras; `std/pem` (cadenas, etiquetas, 64 columnas
idénticas a openssl); P-256 y RSA de `std/crypto` interoperan con openssl en los dos sentidos (PKCS#8
de `openssl genpkey` aceptado; RSA 2048 en ~0,2 s); el patrón con payload anidado
`Result.Ok(Option.Some((ca, path)))`; `json.obj()` conserva el orden de inserción y anida objetos
(justo lo que pide la huella RFC 7638, cuyo vector oficial pasa); `net/http` con `HEAD`, cabeceras
`Location`/`Replay-Nonce` y `SSL_CERT_FILE` aditivo; el servidor TLS de raylang sirve cadenas con CA
Ed25519, P-256 y RSA; `std/keychain` y `std/qr` sin sorpresas; y las 128 raíces de
`/etc/ssl/cert.pem` se leen todas con el decodificador estricto.

## Desarrollo

```
make            # lista las tareas
make test       # VM
make test-native
make build      # ./raycert nativo
make interop    # contra openssl
make pebble PEBBLE=/ruta/a/pebble
```
