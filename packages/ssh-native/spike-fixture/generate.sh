#!/usr/bin/env bash
# THROWAWAY SPIKE (issue #254): generates every key, CA and certificate the
# spike suite needs into a target directory, plus the Docker build context.
#
# Usage: generate.sh <out-dir>
# Env:   SPIKE_CERT_PRINCIPALS  user-cert principals (default: paratix)
#        SPIKE_HOST_PRINCIPALS  host-cert principals (default: localhost,127.0.0.1,sshd)
set -euo pipefail

out="${1:?usage: generate.sh <out-dir>}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
user_principals="${SPIKE_CERT_PRINCIPALS:-paratix}"
host_principals="${SPIKE_HOST_PRINCIPALS:-localhost,127.0.0.1,sshd}"

mkdir -p "$out"
cd "$out"
rm -f ./*_ca ./*_ca.pub ./key_* ./cert_user* ./host_* authorized_keys manifest.json

keygen() { ssh-keygen -q "$@" -C "spike" >/dev/null; }

# Certificate authorities.
keygen -t ed25519 -N '' -f user_ca
keygen -t ed25519 -N '' -f host_ca

# H1: key that is ONLY usable through its user certificate (never in authorized_keys).
keygen -t ed25519 -N '' -f cert_user_ed25519
ssh-keygen -q -s user_ca -I spike-user -n "$user_principals" -V -5m:+1d cert_user_ed25519.pub

# Host keys; only ed25519 gets a host certificate.
keygen -t ed25519 -N '' -f host_ed25519
keygen -t ecdsa -b 256 -N '' -f host_ecdsa
keygen -t rsa -b 3072 -N '' -f host_rsa
ssh-keygen -q -s host_ca -I spike-host -h -n "$host_principals" -V -5m:+1d host_ed25519.pub

# Key-format matrix (soft criterion). Each entry: file, label.
keygen -t ed25519 -N '' -f key_ed25519_openssh
keygen -t rsa -b 3072 -N '' -f key_rsa_openssh
keygen -t rsa -b 3072 -N '' -m PEM -f key_rsa_pem_pkcs1
keygen -t ecdsa -b 256 -N '' -f key_ecdsa_p256_openssh
keygen -t ecdsa -b 256 -N '' -m PEM -f key_ecdsa_p256_pem_sec1
keygen -t rsa -b 3072 -N '' -m PKCS8 -f key_rsa_pkcs8
keygen -t ecdsa -b 256 -N '' -m PKCS8 -f key_ecdsa_p256_pkcs8

# ed25519 as PKCS#8 cannot be written by ssh-keygen; use openssl when present.
if command -v openssl >/dev/null 2>&1; then
  openssl genpkey -algorithm ed25519 -out key_ed25519_pkcs8 2>/dev/null
  chmod 600 key_ed25519_pkcs8
  # Derive the OpenSSH public line with Node (ssh-keygen may not read PEM ed25519).
  node -e '
    const { createPublicKey } = require("node:crypto")
    const fs = require("node:fs")
    const jwk = createPublicKey(fs.readFileSync(process.argv[1])).export({ format: "jwk" })
    const raw = Buffer.from(jwk.x, "base64url")
    const str = (b) => { const l = Buffer.alloc(4); l.writeUInt32BE(b.length); return Buffer.concat([l, b]) }
    const blob = Buffer.concat([str(Buffer.from("ssh-ed25519")), str(raw)])
    fs.writeFileSync(process.argv[1] + ".pub", "ssh-ed25519 " + blob.toString("base64") + " spike\n")
  ' key_ed25519_pkcs8
fi

# Encrypted key (expects ENCRYPTED_KEY) and a key that is never authorized.
keygen -t ed25519 -N 'spike-passphrase' -f key_ed25519_encrypted
keygen -t ed25519 -N '' -f key_unauthorized

# authorized_keys: all matrix keys, never the certificate key or the unauthorized one.
: > authorized_keys
for pub in key_*.pub; do
  case "$pub" in
    key_unauthorized.pub) ;;
    *) cat "$pub" >> authorized_keys ;;
  esac
done

chmod 600 user_ca host_ca cert_user_ed25519 host_ed25519 host_ecdsa host_rsa key_*[!b]
chmod 644 ./*.pub authorized_keys

# Docker build context.
cp "$here/Dockerfile" "$here/sshd_config" .

cat > manifest.json <<JSON
{
  "userPrincipals": "$user_principals",
  "hostPrincipals": "$host_principals",
  "matrix": [
    { "id": "ed25519-openssh", "file": "key_ed25519_openssh" },
    { "id": "rsa-openssh", "file": "key_rsa_openssh" },
    { "id": "rsa-pem-pkcs1", "file": "key_rsa_pem_pkcs1" },
    { "id": "ecdsa-p256-openssh", "file": "key_ecdsa_p256_openssh" },
    { "id": "ecdsa-p256-pem-sec1", "file": "key_ecdsa_p256_pem_sec1" },
    { "id": "rsa-pkcs8", "file": "key_rsa_pkcs8" },
    { "id": "ecdsa-p256-pkcs8", "file": "key_ecdsa_p256_pkcs8" },
    { "id": "ed25519-pkcs8", "file": "key_ed25519_pkcs8" }
  ]
}
JSON
echo "spike fixtures written to $out"
