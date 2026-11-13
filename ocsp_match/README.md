# ocsp_match

Associate OCSP `SingleResponse` entries back to the requests that asked for
them and to the real issuer certificates they describe. Built on
[asn1crypto](https://github.com/wbond/asn1crypto) DER types plus `hashlib`.

The library is deliberately **association only**. It never verifies a
response signature, checks the responder certificate, or judges
`thisUpdate`/`nextUpdate` freshness. It recomputes `CertId` values from real
certificate material, performs byte-level matching, keeps every candidate
issuer that fits, and hands the evidence to an upper layer that owns the trust
decision.

## CertId boundaries

RFC 6960 §4.1.1 defines two distinct hashes, and the DER boundary is different
for each one:

- `issuerNameHash` = digest of the DER encoding of the issuer's `Name`.
- `issuerKeyHash` = digest of the **BIT STRING payload** of the issuer's
  `SubjectPublicKeyInfo.subjectPublicKey`. The leading unused-bits octet, the
  BIT STRING tag and its length are excluded, as is the surrounding SPKI
  `SEQUENCE`.

Concretely, for an octet-aligned key the key hash is
`hash(spki['public_key'].contents[1:])`. Note that `.native` is the wrong
accessor on a `ParsableOctetBitString`, because it returns the parsed inner
structure (e.g. an `RSAPublicKey`) rather than the on-the-wire key bytes.
Hashing a display name or the whole SPKI produces different digests and is
rejected by the test vectors.

## Main entry point

```python
from ocsp_match import match_ocsp

report = match_ocsp(
    requests=[(source_label, ocsp_request_or_der), ...],
    responses=[ocsp_response_or_der, ...],
    candidate_issuers=[(label, certificate_or_der), ...],
    digest_algorithms=('sha1', 'sha256'),
)
```

Candidate issuers may be `Certificate` objects, DER bytes, `(label, cert)`
tuples, or prebuilt `IssuerFingerprint` objects. Inputs can also be passed
positionally without labels; the positional index then becomes the source or
label.

## Outcomes (per request)

`report.requests` holds one `RequestReport` per request entry. Equivalent
requests (identical `CertId` DER) share their response set but each keeps its
own source, so no batch origin is lost. `report.groups` groups them by CertId.

| `MatchStatus` | Meaning |
| --- | --- |
| `matched` | Exactly one candidate issuer reproduces both hashes and a response answers the CertId. |
| `ambiguous` | More than one distinct issuer certificate reproduces both hashes (e.g. a re-issued issuer with the same key); no input-order winner is picked. |
| `mismatch` | A response exists but either no issuer reproduces both hashes, or duplicate responses contradict each other. |
| `missing_response` | No `SingleResponse` carries the CertId, or the OCSP response was non-successful. |
| `unsupported_digest` | The CertId names a digest OID the recomputation table does not support. |
| `invalid_algorithm_parameters` | The digest algorithm parameters are not NULL/absent, or hash lengths are wrong. Distinct from an unsupported digest. |

Convenience tuples on `MatchReport` (`matched`, `ambiguous`, `mismatched`,
`missing`, `unsupported`, `invalid_parameters`) contain the same reports
partitioned by status.

## Response-level surfaces

- `report.duplicate_responses`: multiple `SingleResponse` entries share a
  CertId that a request carried. `DuplicateResponseReport.disposition` is
  `duplicate_consistent` when statuses agree or `duplicate_conflict` when they
  contradict. The request report still retains every copy and its evidence.
- `report.unmatched_responses`: responses whose CertId no request carried.
  `orphan` means no issuer reproduces either hash; `near_miss` means one of the
  two hashes partially matches a candidate, with per-issuer
  `name_hash_equal`/`key_hash_equal` hints attached.
- `report.non_successful_responses`: OCSP-level statuses such as `try_later`
  or `unauthorized`, recorded with their message index.

## Evidence retained

Each `SingleResponseEvidence` keeps the parsed `SingleResponse`, `CertIdData`,
`status_name`, revocation time/reason, `this_update`, `next_update`, and the
`(message_index, index)` location. `IssuerFingerprint` / `HashEvidence` keep
the exact `name_der` and BIT STRING payload that were hashed, so an auditor can
re-derive every digest independently.

## Error handling

Unparseable DER raises `OcspMatchError` (a `ValueError` subclass). Semantic
problems that apply to one entry — unsupported digest, illegal parameters,
missing answer, conflict — are returned as statuses on the report rather than
raised, so one bad entry never aborts a batch.
