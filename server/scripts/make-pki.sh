#!/usr/bin/env bash
# Creates UniLearn's small PKI with OpenSSL (DECISIONS D40, SETUP_GUIDE 6.10). Run it ONCE, in Git Bash:
#   bash server/scripts/make-pki.sh
# Public certificates  → server/pki/            (safe to commit: certificates are public)
# Private keys         → ~/unilearn-pki-private/ (NEVER commit; back them up in your password manager)
set -euo pipefail
# Git Bash would otherwise turn "/CN=..." into a Windows path
export MSYS_NO_PATHCONV=1

PUBLIC_DIR="$(cd "$(dirname "$0")/.." && pwd)/pki"
PRIVATE_DIR="${1:-$HOME/unilearn-pki-private}"
mkdir -p "$PUBLIC_DIR" "$PRIVATE_DIR"
# OpenSSL on Windows needs Windows-style paths (C:/Users/...), not Git Bash ones (/c/Users/...)
if command -v cygpath > /dev/null; then
  PUBLIC_DIR="$(cygpath -m "$PUBLIC_DIR")"
  PRIVATE_DIR="$(cygpath -m "$PRIVATE_DIR")"
fi

if [ -f "$PUBLIC_DIR/unilearn-root-ca.crt" ]; then
  echo "UniLearn certificates already exist in $PUBLIC_DIR. Stopping so they aren't overwritten."
  exit 1
fi

# 1. Root CA: a self-signed certificate that says "I am the UniLearn Root CA". Valid 5 years.
#    Its private key only ever signs other certificates, and it stays on this PC (offline).
openssl req -x509 -new -newkey rsa:3072 -nodes -sha256 -days 1825 \
  -keyout "$PRIVATE_DIR/root-ca.key" \
  -subj "/CN=UniLearn Root CA/O=UniLearn" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$PUBLIC_DIR/unilearn-root-ca.crt"

# 2. The server's signing key pair (RSA 3072). The server signs receipts and grades with it.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$PRIVATE_DIR/signing.key"

# 3. Certificate request, then the root CA issues the signing certificate. Valid 1 year.
openssl req -new -key "$PRIVATE_DIR/signing.key" -subj "/CN=UniLearn Signing Service/O=UniLearn" \
  -out "$PRIVATE_DIR/signing.csr"
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n' > "$PRIVATE_DIR/signing.ext"
openssl x509 -req -sha256 -days 365 -in "$PRIVATE_DIR/signing.csr" \
  -CA "$PUBLIC_DIR/unilearn-root-ca.crt" -CAkey "$PRIVATE_DIR/root-ca.key" -CAcreateserial \
  -extfile "$PRIVATE_DIR/signing.ext" -out "$PUBLIC_DIR/unilearn-signing.crt"
rm -f "$PRIVATE_DIR/signing.csr" "$PRIVATE_DIR/signing.ext" "$PUBLIC_DIR/unilearn-root-ca.srl" "$PRIVATE_DIR/unilearn-root-ca.srl"

# 4. The signing key as ONE line (base64), ready to paste into .env and Render as SIGNING_PRIVATE_KEY
base64 -w 0 "$PRIVATE_DIR/signing.key" > "$PRIVATE_DIR/SIGNING_PRIVATE_KEY.txt"

# 5. Check the chain, the same way the server does at startup
openssl verify -CAfile "$PUBLIC_DIR/unilearn-root-ca.crt" "$PUBLIC_DIR/unilearn-signing.crt"

echo
echo "Done."
echo "  Public certificates (commit these): $PUBLIC_DIR"
echo "  Private keys (never commit, back up): $PRIVATE_DIR"
echo "  Next: copy the one line in $PRIVATE_DIR/SIGNING_PRIVATE_KEY.txt into server/.env and Render (SETUP_GUIDE 6.10)."
