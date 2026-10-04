#!/usr/bin/env bash
#
# Generate a local TLS certificate for the demo domains using mkcert.
# The certificate is a single SAN cert valid for both:
#   - auth.example.test
#   - keycloak.auth.example.test
#
# Output:
#   certs/fullchain.pem   (leaf certificate + mkcert root CA)
#   certs/privkey.pem     (private key)
#
# mkcert installs its local root CA into the OS trust store, so browsers
# trust the generated certificate automatically.

set -euo pipefail

DOMAINS=(
  "auth.example.test"
  "keycloak.auth.example.test"
)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERTS_DIR="${ROOT_DIR}/certs"

if ! command -v mkcert >/dev/null 2>&1; then
  echo "ERROR: mkcert is not installed." >&2
  echo "Install it with:  brew install mkcert   (macOS)" >&2
  echo "Then run:         mkcert -install" >&2
  exit 1
fi

mkdir -p "${CERTS_DIR}"

if [[ -f "${CERTS_DIR}/fullchain.pem" && -f "${CERTS_DIR}/privkey.pem" ]]; then
  echo "Certificates already exist in ${CERTS_DIR} — skipping generation."
  echo "To regenerate them, delete the .pem files and re-run this script."
  exit 0
fi

echo "Installing the local mkcert root CA into the OS trust store..."
mkcert -install

echo "Generating certificate for: ${DOMAINS[*]}"
mkcert \
  -key-file  "${CERTS_DIR}/privkey.pem" \
  -cert-file "${CERTS_DIR}/cert.pem" \
  "${DOMAINS[@]}"

# nginx serves leaf + root CA so the chain is complete.
cat "${CERTS_DIR}/cert.pem" "$(mkcert -CAROOT)/rootCA.pem" > "${CERTS_DIR}/fullchain.pem"

echo
echo "Done. Certificate written to: ${CERTS_DIR}/fullchain.pem"
echo "Private key written to:       ${CERTS_DIR}/privkey.pem"
