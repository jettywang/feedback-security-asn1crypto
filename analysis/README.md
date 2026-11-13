# PKCS#12 SafeBag evidence analysis

This directory contains an evidence workflow for **already-decrypted** PKCS#12
material. It inventories nested `SafeContents`, retains every metadata source,
and only reports a key/certificate pair when the public key material matches.
It never asks for a password and never emits private key components.

## Usage

```sh
python -m analysis.cli path/to/decrypted.p12
python -m analysis.cli --json path/to/decrypted.p12
```

Generate the two demonstration containers (both are fully decrypted and use
toy RSA values):

```sh
python -m analysis.generate_samples "$TMPDIR/pkcs12-evidence" --report
```

- `name-collision.p12`: a key and two certificates share the friendlyName
  `Collision Identity`. Only one certificate shares the key's public key
  material; the other is retained as a metadata-only candidate and an orphan.
- `missing-local-key-id.p12`: a key and certificate have no `localKeyId` on
  either side, yet their SubjectPublicKeyInfo bytes match exactly.

Because both samples are fully decrypted and MAC-free, tools such as
`openssl pkcs12 -legacy` can list their bags for cross-checking. Neither sample
contains a real secret; the private values are toy RSA components.

## Evidence model

Each bag is addressed by a stable path such as
`auth_safe[0]/bag[0]/contents/bag[1]`. Paths include the enclosing
`SafeContents` hop so nested containers are not flattened.

The report keeps four separate sections:

- `bags`: kind, path, metadata values and their value-level source paths,
  public key fingerprint and public key source.
- `pairs`: only fingerprint-backed matches. Each pair records the SPKI source
  for both sides and whether the exact SPKI encodings match.
- `candidates`: metadata-only links (shared `localKeyId` or `friendlyName`)
  whose public keys differ or are unavailable. `ambiguous` is true when the
  same metadata value points at more than one key or certificate.
- `orphans`: bags with no public-key match, retaining their candidate ids and
  metadata sources.

`conflicts` collects `localKeyId` collisions, friendly-name collisions,
repeated attributes, byte-identical duplicate bags, and bags that share the
same value with different attributes. `sources` records which
`AuthenticatedSafe` entries were walked and which encrypted entries were left
opaque.

## Non-goals

- No password recovery, decryption of `encrypted_data`, or decoding of
  `pkcs8_shrouded_key_bag` material.
- Friendly names, certificate subject names, and certificate chain order are
  never sufficient proof of a key/certificate pair.
- Private key DER/OCTET STRING contents are not serialized into reports.
