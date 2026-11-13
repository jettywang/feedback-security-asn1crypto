#!/usr/bin/env python3
"""Recompute RFC 3161 timestamp ordering claims with asn1crypto.

The lab builds and parses local, self-signed CMS time-stamp tokens and keeps
four questions separate:

1. Does the CMS signature verify with the embedded signer certificate?
2. Does TSTInfo.messageImprint bind the evidence we have?
3. What wall-clock interval does TSTInfo actually constrain?
4. What can two tokens prove about their relative order?

A parsed genTime is never reported as "verified trusted time" here.  A local
self-signed token proves internal consistency, not that a public TSA issued
it, that its clock was correct, or that its certificate was valid/EKU-eligible.
"""

from __future__ import annotations

import hashlib
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from asn1crypto import cms, core, keys, pem, tsp, x509  # noqa: E402


UTC = timezone.utc


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def load_fixture_key(name: str = "test"):
    """Load one of this repository's local RSA demo keys and its certificate.

    These keys are test fixtures, not a public TSA.  Their certificates lack a
    timeStamping EKU and expired in 2025.  A token signed with them is only an
    interoperability/reproducibility artifact.
    """

    cert_path = os.path.join(ROOT, "tests", "fixtures", "keys", name + ".crt")
    key_path = os.path.join(ROOT, "tests", "fixtures", "keys", name + ".key")
    with open(cert_path, "rb") as f:
        cert = x509.Certificate.load(pem.unarmor(f.read())[2])
    with open(key_path, "rb") as f:
        key = keys.RSAPrivateKey.load(pem.unarmor(f.read())[2])
    return cert, key


def load_globalsign_key(name: str = "IssuingCA"):
    """Load the repository's RSA GlobalSign example cert/key pair.

    It is still a test fixture (expired, CA certificate), but it gives the lab
    a genuinely different RSA signing identity for cross-TSA comparisons.
    """

    base = os.path.join(ROOT, "tests", "fixtures", "globalsign_example_keys", name)
    with open(base + ".cer", "rb") as f:
        raw = f.read()
    cert_der = pem.unarmor(raw)[2] if pem.detect(raw) else raw
    with open(base + ".key", "rb") as f:
        key_der = pem.unarmor(f.read())[2]
    return x509.Certificate.load(cert_der), keys.RSAPrivateKey.load(key_der)


def signing_identity(cert: x509.Certificate) -> str:
    return "%s (serial %s)" % (cert.subject.native.get("common_name", "?"), cert.serial_number)


def rsa_pkcs1v15_sign(key: keys.RSAPrivateKey, data: bytes) -> bytes:
    """SHA-256 + PKCS#1 v1.5 using only integer arithmetic.

    This keeps the example dependency-free.  Production code should use a
    vetted crypto library.
    """

    digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + sha256(data)
    n = key["modulus"].native
    d = key["private_exponent"].native
    k = (n.bit_length() + 7) // 8
    encoded = b"\x00\x01" + b"\xff" * (k - len(digest_info) - 3) + b"\x00" + digest_info
    return pow(int.from_bytes(encoded, "big"), d, n).to_bytes(k, "big")


def rsa_pkcs1v15_verify(cert: x509.Certificate, data: bytes, signature: bytes) -> bool:
    pub = cert.public_key.native
    if pub["algorithm"]["algorithm"] != "rsa":
        return False
    n = pub["public_key"]["modulus"]
    e = pub["public_key"]["public_exponent"]
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    recovered = pow(int.from_bytes(signature, "big"), e, n).to_bytes(k, "big")
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + sha256(data)
    expected = b"\x00\x01" + b"\xff" * (k - len(digest_info) - 3) + b"\x00" + digest_info
    return recovered == expected


def signed_attrs_bytes(si: cms.SignerInfo) -> Optional[bytes]:
    """Return the bytes CMS actually signs.

    SignedAttributes are signed as a DER SET OF, while the field in SignerInfo
    is implicitly [0].  Re-encoding the native view performs the necessary
    retagging and set ordering.  Returns None when signed_attrs is absent; in
    that case CMS signs the eContent bytes directly.
    """

    attrs = si["signed_attrs"]
    if isinstance(attrs, core.Void) or attrs.native is None:
        return None
    return cms.CMSAttributes(attrs.native).dump()


def econtent_der(sd: cms.SignedData) -> bytes:
    """Return the inner eContent bytes covered by CMS messageDigest.

    The EncapsulatedContentInfo content is an OCTET STRING wrapper.  For
    TSTInfo, messageDigest must cover the TSTInfo DER inside that wrapper, not
    the wrapper's own TLV.
    """

    content = sd["encap_content_info"]["content"]
    parsed = content.parsed
    if parsed is not None:
        return parsed.dump()
    return content.native


def find_signer_cert(sd: cms.SignedData, si: cms.SignerInfo) -> Optional[x509.Certificate]:
    if sd["certificates"].native is None:
        return None
    sid = si["sid"]
    for choice in sd["certificates"]:
        if choice.name != "certificate":
            continue
        cert = choice.chosen
        if sid.name == "issuer_and_serial_number":
            if cert.subject == sid.chosen["issuer"] and cert.serial_number == sid.chosen["serial_number"].native:
                return cert
        else:
            if cert.key_identifier == sid.chosen.native:
                return cert
    return None


def verify_cms(token: cms.ContentInfo) -> Dict[str, object]:
    """Verify a local token's CMS structure and signature.

    This deliberately reports only structural/signature facts.  It does not
    establish TSA trust, EKU suitability, certificate validity, revocation, or
    clock accuracy.
    """

    if token["content_type"].native != "signed_data":
        return {"ok": False, "reason": "not CMS SignedData"}
    sd = token["content"]
    if len(sd["signer_infos"]) != 1:
        return {"ok": False, "reason": "expected one SignerInfo"}
    si = sd["signer_infos"][0]
    cert = find_signer_cert(sd, si)
    if cert is None:
        return {"ok": False, "reason": "signer certificate not embedded"}

    econtent = econtent_der(sd)
    if si["digest_algorithm"]["algorithm"].native != "sha256":
        return {"ok": False, "reason": "unsupported CMS digest"}
    attrs = signed_attrs_bytes(si)
    if attrs is not None:
        digest_ok = False
        ctype_ok = False
        for attr in si["signed_attrs"]:
            if attr["type"].native == "message_digest":
                digest_ok = attr["values"][0].native == sha256(econtent)
            elif attr["type"].native == "content_type":
                ctype_ok = attr["values"][0].native == sd["encap_content_info"]["content_type"].native
        if not (digest_ok and ctype_ok):
            return {
                "ok": False,
                "reason": "signed attributes do not bind eContent",
                "signer_cert": cert,
            }
        signed = attrs
    else:
        signed = econtent

    ok = rsa_pkcs1v15_verify(cert, signed, si["signature"].native)
    return {
        "ok": ok,
        "reason": "local RSA PKCS#1 v1.5 verification",
        "signer_cert": cert,
        "has_signed_attrs": attrs is not None,
    }


class TokenReport:
    """Facts about a token, kept distinct from interpretations of those facts."""

    def __init__(
        self,
        label: str,
        token: cms.ContentInfo,
        evidence: Optional[bytes] = None,
        request_nonce: Optional[int] = None,
    ):
        self.label = label
        self.token = token
        sd = token["content"]
        self.signer = sd["signer_infos"][0]
        self.cms = verify_cms(token)
        self.cert = self.cms.get("signer_cert")
        self.identity = signing_identity(self.cert) if self.cert is not None else None
        self.tst = sd["encap_content_info"]["content"].parsed
        self.policy = self.tst["policy"].native
        self.serial = self.tst["serial_number"].native
        self.gen_time = self.tst["gen_time"].native
        self.accuracy = self.tst["accuracy"].native
        self.ordering = bool(self.tst["ordering"].native)
        self.nonce = self.tst["nonce"].native
        self.request_nonce = request_nonce
        self.imprint_algorithm = self.tst["message_imprint"]["hash_algorithm"]["algorithm"].native
        self.imprint = self.tst["message_imprint"]["hashed_message"].native
        self.evidence = evidence
        self.imprint_ok = (
            evidence is not None
            and self.imprint_algorithm == "sha256"
            and self.imprint == sha256(evidence)
        )

    def nonce_status(self) -> str:
        if self.nonce is None:
            return "absent"
        if self.request_nonce is None:
            return "unchecked"
        return "match" if self.nonce == self.request_nonce else "mismatch"

    def accuracy_delta(self) -> Optional[timedelta]:
        """Declared maximum error from TSTInfo.accuracy.

        Missing components mean zero (OpenSSL documents the same TSA
        configuration semantics).  If accuracy itself is absent, the TSA
        claims no bound; callers must not substitute "exact to genTime's
        printed digits".
        """

        if self.accuracy is None:
            return None
        return timedelta(
            seconds=self.accuracy.get("seconds") or 0,
            milliseconds=self.accuracy.get("millis") or 0,
            microseconds=self.accuracy.get("micros") or 0,
        )

    def interval(self) -> Optional[Tuple[datetime, datetime]]:
        delta = self.accuracy_delta()
        if delta is None:
            return None
        return self.gen_time - delta, self.gen_time + delta

    def summary(self) -> str:
        interval = self.interval()
        interval_text = (
            "unbounded(no accuracy)" if interval is None
            else "[%s..%s]" % (interval[0].isoformat(), interval[1].isoformat())
        )
        return (
            "%s tsa=%s serial=%s policy=%s gen=%s acc=%s interval=%s ordering=%s "
            "nonce=%s(%s) imprint=%s sig=%s"
            % (
                self.label,
                self.identity,
                self.serial,
                self.policy,
                self.gen_time.isoformat(),
                self.accuracy,
                interval_text,
                self.ordering,
                self.nonce,
                self.nonce_status(),
                "match" if self.imprint_ok else "no",
                "ok" if self.cms["ok"] else "FAIL:%s" % self.cms.get("reason"),
            )
        )


def compare(a: TokenReport, b: TokenReport) -> Dict[str, object]:
    """Order two tokens using only what their evidence can support.

    Layered result:
    - nominal: relation of the two genTime strings;
    - interval: relation of their claimed accuracy intervals;
    - ordering_pair: one TSA asserting ordering=true for both tokens;
    - evidence: strongest defensible order.

    Notes:
    - Different signer identities never share a sequence authority.  Two
      disjoint claims remain two independent claims, not one measured order.
    - ordering=true covers responses from the *same* TSA, even when the time
      difference is smaller than the sum of accuracies.  It cannot order
      another TSA's token.
    - Nonce mismatch means the token is not an answer to the request we rely
      on; its genTime must not be attached to that request.
    """

    if a.gen_time < b.gen_time:
        nominal = "a_before_b"
    elif b.gen_time < a.gen_time:
        nominal = "b_before_a"
    else:
        nominal = "equal"

    ia, ib = a.interval(), b.interval()
    if ia is None or ib is None:
        interval = "unknown_no_accuracy"
    elif ia[1] < ib[0]:
        interval = "a_before_b"
    elif ib[1] < ia[0]:
        interval = "b_before_a"
    else:
        interval = "overlap"

    same_tsa = a.identity == b.identity
    nonce_ok = a.nonce_status() != "mismatch" and b.nonce_status() != "mismatch"
    ordering_pair = same_tsa and a.ordering and b.ordering

    if not nonce_ok:
        evidence = "invalid_for_request"
    elif not a.cms["ok"] or not b.cms["ok"]:
        evidence = "unverified_signature"
    elif not same_tsa:
        evidence = "no_common_authority"
    elif ordering_pair:
        # Same TSA, both tokens assert ordering.  Use the TSA's declared
        # sequence; only the TSA's own serial/ordering claim supports this.
        if a.serial < b.serial:
            evidence = "ordered_by_tsa:a_before_b"
        elif b.serial < a.serial:
            evidence = "ordered_by_tsa:b_before_a"
        else:
            evidence = "indeterminate_same_serial"
    elif interval in ("a_before_b", "b_before_a"):
        evidence = interval
    elif interval == "overlap":
        evidence = "indeterminate_overlap"
    else:
        evidence = "indeterminate_no_accuracy"

    return {
        "nominal": nominal,
        "interval": interval,
        "same_tsa": same_tsa,
        "ordering_pair": ordering_pair,
        "nonce_ok": nonce_ok,
        "evidence": evidence,
    }


def build_tst_info(
    policy: str,
    evidence: bytes,
    serial: int,
    gen_time: datetime,
    accuracy: Optional[Dict[str, int]] = None,
    ordering: bool = False,
    nonce: Optional[int] = None,
    tsa_name: str = "Demo TSA",
) -> tsp.TSTInfo:
    tst = tsp.TSTInfo()
    tst["version"] = "v1"
    tst["policy"] = policy
    tst["message_imprint"] = {
        "hash_algorithm": {"algorithm": "sha256"},
        "hashed_message": sha256(evidence),
    }
    tst["serial_number"] = serial
    tst["gen_time"] = gen_time
    if accuracy is not None:
        tst["accuracy"] = accuracy
    tst["ordering"] = ordering
    if nonce is not None:
        tst["nonce"] = nonce
    if tsa_name is not None:
        tst["tsa"] = {"directory_name": x509.Name.build({"common_name": tsa_name})}
    return tst


def build_token(tst: tsp.TSTInfo, cert: x509.Certificate, key: keys.RSAPrivateKey) -> cms.ContentInfo:
    """Build a CMS SignedData with TSTInfo eContent and signed attributes."""

    tst_der = tst.dump()
    ci = cms.ContentInfo()
    ci["content_type"] = "signed_data"
    sd = cms.SignedData()
    sd["version"] = "v3"
    sd["digest_algorithms"] = [{"algorithm": "sha256"}]
    sd["encap_content_info"] = {
        "content_type": "tst_info",
        "content": core.ParsableOctetString(tst_der),
    }
    sd["certificates"] = [cert]

    si = cms.SignerInfo()
    si["version"] = "v1"
    si["sid"] = {
        "issuer_and_serial_number": {
            "issuer": cert.subject,
            "serial_number": cert.serial_number,
        }
    }
    si["digest_algorithm"] = {"algorithm": "sha256"}
    si["signed_attrs"] = [
        {"type": "content_type", "values": ["tst_info"]},
        {"type": "message_digest", "values": [sha256(tst_der)]},
    ]
    si["signature_algorithm"] = {"algorithm": "rsassa_pkcs1v15"}
    si["signature"] = b"\x00" * ((key["modulus"].native.bit_length() + 7) // 8)
    sd["signer_infos"] = [si]
    ci["content"] = sd

    attrs = cms.CMSAttributes(si["signed_attrs"].native).dump()
    si["signature"] = rsa_pkcs1v15_sign(key, attrs)
    ci["content"] = sd
    return ci


def wrap_in_outer_signature(
    inner: cms.ContentInfo,
    cert: x509.Certificate,
    key: keys.RSAPrivateKey,
    signing_time: datetime,
) -> cms.ContentInfo:
    """Wrap token bytes as data in another CMS signature.

    This models "timestamp token inside another signature" (e.g. an
    archival/signature wrapper).  The wrapper proves the wrapper key signed
    the inner token bytes at its claimed signing_time.  It does not prove when
    the inner TSA measured the event, and it does not improve the inner
    token's accuracy.
    """

    inner_der = inner.dump()
    ci = cms.ContentInfo()
    ci["content_type"] = "signed_data"
    sd = cms.SignedData()
    sd["version"] = "v3"
    sd["digest_algorithms"] = [{"algorithm": "sha256"}]
    sd["encap_content_info"] = {
        "content_type": "data",
        "content": core.ParsableOctetString(inner_der),
    }
    sd["certificates"] = [cert]

    si = cms.SignerInfo()
    si["version"] = "v1"
    si["sid"] = {
        "issuer_and_serial_number": {
            "issuer": cert.subject,
            "serial_number": cert.serial_number,
        }
    }
    si["digest_algorithm"] = {"algorithm": "sha256"}
    si["signature_algorithm"] = {"algorithm": "rsassa_pkcs1v15"}
    si["signed_attrs"] = [
        {"type": "content_type", "values": ["data"]},
        {
            "type": "signing_time",
            "values": [cms.Time({"generalized_time": signing_time})],
        },
        {"type": "message_digest", "values": [sha256(inner_der)]},
    ]
    si["signature"] = b"\x00" * ((key["modulus"].native.bit_length() + 7) // 8)
    sd["signer_infos"] = [si]
    ci["content"] = sd

    attrs = cms.CMSAttributes(si["signed_attrs"].native).dump()
    si["signature"] = rsa_pkcs1v15_sign(key, attrs)
    ci["content"] = sd
    return ci


def verify_outer_wrapper(wrapper: cms.ContentInfo) -> bool:
    sd = wrapper["content"]
    si = sd["signer_infos"][0]
    cert = find_signer_cert(sd, si)
    if cert is None:
        return False
    econtent = econtent_der(sd)
    digest_ok = any(
        attr["type"].native == "message_digest"
        and attr["values"][0].native == sha256(econtent)
        for attr in si["signed_attrs"]
    )
    return digest_ok and rsa_pkcs1v15_verify(cert, signed_attrs_bytes(si), si["signature"].native)


def main() -> int:
    evidence_a = b"evidence A: document created first\n"
    evidence_b = b"evidence B: document created later\n"

    cert, key = load_fixture_key("test")
    cert2, key2 = load_globalsign_key("IssuingCA")
    if signing_identity(cert) == signing_identity(cert2):
        raise SystemExit("demo identities must differ")

    policy = "1.3.6.1.4.1.99999.1"
    base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)

    def make(label, ev, serial, gen_time, accuracy, ordering=False,
             nonce=None, request_nonce=None, signer=(cert, key)):
        tst = build_tst_info(policy, ev, serial, gen_time, accuracy, ordering, nonce)
        return TokenReport(label, build_token(tst, *signer), ev, request_nonce)

    # 1. Same TSA, +/- 1 hour accuracy, nominal times 10 minutes apart.
    #    This is the central "nominal order is clear, evidence is not" case.
    a1 = make("A/coarse", evidence_a, 1001, base, {"seconds": 3600})
    b1 = make("B/coarse", evidence_b, 1002, base + timedelta(minutes=10), {"seconds": 3600})

    # 2. Accuracy absent.  Do not infer precision from genTime's printed
    #    seconds.  Without an accuracy claim the interval is unbounded.
    a2 = make("A/no-accuracy", evidence_a, 1101, base, None)
    b2 = make("B/no-accuracy", evidence_b, 1102, base + timedelta(minutes=10), None)

    # 3. Same TSA, disjoint claimed intervals.  This supports an order only
    #    conditional on trusting the TSA and its accuracy declaration.
    a3 = make("A/disjoint", evidence_a, 1201, base, {"seconds": 1})
    b3 = make("B/disjoint", evidence_b, 1202, base + timedelta(minutes=10), {"seconds": 1})

    # 4. Same nominal relation as #1, different TSAs.  No common authority.
    a4 = make("A/tsa1", evidence_a, 1301, base, {"seconds": 60}, signer=(cert, key))
    b4 = make("B/tsa2", evidence_b, 1302, base + timedelta(minutes=10),
              {"seconds": 60}, signer=(cert2, key2))

    # 5. Same TSA, both ordering=true, overlapping accuracy.  OpenSSL's TSA
    #    docs: ordering responses can be ordered even if the time difference
    #    is less than the sum of accuracies.  The claim is restricted to the
    #    same TSA's own responses.
    a5 = make("A/ordering", evidence_a, 1401, base, {"seconds": 3600}, ordering=True)
    b5 = make("B/ordering", evidence_b, 1402, base + timedelta(minutes=10), {"seconds": 3600}, ordering=True)

    # 6. Same TSA, ordering=false, overlapping accuracy.  No ordering claim.
    a6 = make("A/no-ordering", evidence_a, 1501, base, {"seconds": 3600}, ordering=False)
    b6 = make("B/no-ordering", evidence_b, 1502, base + timedelta(minutes=10), {"seconds": 3600}, ordering=False)

    # 7. Nonce mismatch: structure is fine, but not an answer to nonce 999.
    n1 = make("N/nonce-mismatch", evidence_a, 1601, base, {"seconds": 60}, nonce=111, request_nonce=999)

    # 8. Token wrapped in another signature.  Inner token can be verified
    #    independently; the wrapper proves only outer-key possession over the
    #    token bytes, not the original event time.
    inner_tst = build_tst_info(policy, evidence_a, 1701, base, {"seconds": 60}, nonce=222)
    inner = build_token(inner_tst, cert, key)
    wrapped = wrap_in_outer_signature(inner, cert, key, base + timedelta(days=2))

    reports = [a1, b1, a2, b2, a3, b3, a4, b4, a5, b5, a6, b6, n1]
    print("== Parsed token facts (local demo keys; not trusted time) ==")
    for report in reports:
        print(report.summary())

    print("\n== Pairwise conclusions ==")
    pairs = [
        ("same TSA / overlap / ordering=false", a1, b1),
        ("same TSA / no accuracy / ordering=false", a2, b2),
        ("same TSA / disjoint / ordering=false", a3, b3),
        ("different TSA / disjoint-ish", a4, b4),
        ("same TSA / overlap / ordering=true both", a5, b5),
        ("same TSA / overlap / ordering=false both", a6, b6),
    ]
    results = {}
    for name, left, right in pairs:
        result = compare(left, right)
        results[name] = result
        print(
            "%s\n  nominal=%s interval=%s same_tsa=%s ordering_pair=%s -> evidence=%s"
            % (name, result["nominal"], result["interval"], result["same_tsa"],
               result["ordering_pair"], result["evidence"])
        )

    print("\n== Nonce and nested-wrapper boundary ==")
    print("nonce: %s (token=%s request=%s)" % (n1.nonce_status(), n1.nonce, n1.request_nonce))
    print("compare nonce-mismatch token with B/coarse: evidence=%s"
          % compare(n1, b1)["evidence"])
    print("inner token CMS verify: %s" % ("ok" if verify_cms(inner)["ok"] else "FAIL"))
    print("outer wrapper verify: %s" % ("ok" if verify_outer_wrapper(wrapped) else "FAIL"))
    outer_time = wrapped["content"]["signer_infos"][0]["signed_attrs"][1]["values"][0].native
    print("outer signing_time: %s" % outer_time.isoformat())
    print("inner token report: %s" % TokenReport("inner", inner, evidence_a).summary())
    print("boundary: outer proves only that wrapper key signed inner-token bytes;")
    print("          inner genTime remains the inner TSA's unverified claim.")

    print("\n== Assertions (recomputation checks) ==")
    r = results["same TSA / overlap / ordering=false"]
    assert r["nominal"] == "a_before_b" and r["interval"] == "overlap"
    assert r["evidence"] == "indeterminate_overlap"

    r = results["same TSA / no accuracy / ordering=false"]
    assert r["nominal"] == "a_before_b" and r["interval"] == "unknown_no_accuracy"
    assert r["evidence"] == "indeterminate_no_accuracy"

    r = results["same TSA / disjoint / ordering=false"]
    assert r["interval"] == "a_before_b" and r["evidence"] == "a_before_b"

    r = results["different TSA / disjoint-ish"]
    assert r["same_tsa"] is False and r["evidence"] == "no_common_authority"

    r = results["same TSA / overlap / ordering=true both"]
    assert r["interval"] == "overlap" and r["ordering_pair"] is True
    assert r["evidence"] == "ordered_by_tsa:a_before_b"

    r = results["same TSA / overlap / ordering=false both"]
    assert r["interval"] == "overlap" and r["ordering_pair"] is False
    assert r["evidence"] == "indeterminate_overlap"

    assert n1.nonce_status() == "mismatch"
    assert compare(n1, b1)["evidence"] == "invalid_for_request"

    for report in reports:
        assert report.cms["ok"] is True
        assert report.cms["has_signed_attrs"] is True
        assert report.imprint_ok is True

    assert verify_cms(inner)["ok"] is True
    assert verify_outer_wrapper(wrapped) is True

    print("all assertions passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
