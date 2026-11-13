#!/bin/sh
# Regenerates the offline RSA material used by the signedAttrs regression suite.
# Output is deterministic enough for regression use; only the public certs are
# needed at test time, the private keys live alongside for local regeneration.
set -eu
cd "$(dirname "$0")"

for name in signer countersigner; do
  openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
      -out "${name}_key.pem"
  openssl req -new -x509 -key "${name}_key.pem" -days 3650 \
      -subj "/CN=CMS signedAttrs regression ${name}" \
      -out "${name}_cert.pem"
  openssl x509 -in "${name}_cert.pem" -outform DER -out "${name}_cert.der"
done
