# coding: utf-8
"""Executable walk-through of indirect/delta CRL composition.

Run:  .venv/bin/python -m crl_engine_demo.demo
"""

from __future__ import unicode_literals

import datetime

from asn1crypto.x509 import Name

from .builder import build_crl, build_idp, make_entry, dn
from .engine import CRLEngine, TrustBoundaryError
from .model import RevocationStatus

NOW = datetime.datetime(2026, 11, 13, 12, 0, 0)

# ---- names ---------------------------------------------------------------
CRL_ISSUER = dn('Indirect CRL Authority', o='Example CA Group')
CA_ALPHA = dn('CA Alpha', o='Example CA Group')
CA_BETA = dn('CA Beta', o='Example CA Group')
DP_URI = 'http://crl.example/group/indirect.crl'


def make_verifier(rejected_serials_of_crl=None, stale_ok=False):
    """Stand-in for PKI signature validation. Real deployment would check the
    CRL signature with the issuer cert named by AKI and validate that cert to a
    trust anchor. Here we accept every well-formed test CRL except an explicit
    blocklist, proving the parsed/trusted separation is enforced."""
    rejected = rejected_serials_of_crl or set()

    def verifier(cert_list):
        number = cert_list.crl_number_value.native
        return number not in rejected
    return verifier


def line(title):
    print('\n' + '=' * 78)
    print(title)
    print('=' * 78)


def show_trace(engine):
    for event in engine.trace:
        print('  trace:', event)
    engine.trace.clear()


def print_verdict(label, verdict):
    print('  %-28s -> %-10s reason=%-18s sourceCRL=%s'
          % (label, verdict.status.value, verdict.reason,
             verdict.source_crl_number))
    for note in verdict.notes:
        print('      note:', note)


# ==========================================================================
# Scenario A — indirect CRL: certificateIssuer inheritance + serial collision
# ==========================================================================
def scenario_a():
    line('A. Indirect CRL: certificateIssuer inheritance, same serial, two issuers')
    idp = build_idp(DP_URI, indirect=True)
    base = build_crl(
        CRL_ISSUER,
        '2026-11-01 00:00:00', '2026-12-01 00:00:00',
        [
            # serial 100 from CA Alpha, with explicit certificateIssuer
            make_entry(100, '2026-11-01 01:00:00', 'key_compromise', CA_ALPHA),
            # serial 100 from CA Beta: different cert, same serial, explicit ext
            make_entry(100, '2026-11-01 02:00:00', 'ca_compromise', CA_BETA),
            # no extension -> inherits CA Beta (last seen issuer)
            make_entry(101, '2026-11-01 03:00:00', 'affiliation_changed'),
            # switch back to Alpha; next extension-less entry inherits Alpha
            make_entry(102, '2026-11-01 04:00:00', 'superseded', CA_ALPHA),
            make_entry(103, '2026-11-01 05:00:00', 'cessation_of_operation'),
        ],
        crl_number=10, idp=idp)

    engine = CRLEngine(make_verifier(), lambda: NOW)
    parsed = engine.ingest(base)

    print('  resolved entries (serial, reason, inherited?):')
    for e in parsed.entries:
        issuer = Name.load(e.key.issuer_der).hashable
        print('    serial=%-3d reason=%-20s inherited=%-5s issuer=%s'
              % (e.key.serial, e.reason, e.inherited_from_previous,
                 issuer.split('\\x1e')[0]))
    show_trace(engine)

    print_verdict('CA Alpha / serial 100', engine.lookup(CA_ALPHA, 100))
    print_verdict('CA Beta  / serial 100', engine.lookup(CA_BETA, 100))
    print_verdict('CA Beta  / serial 101 (inherited)', engine.lookup(CA_BETA, 101))
    print_verdict('CA Alpha / serial 101 (wrong issuer)', engine.lookup(CA_ALPHA, 101))
    print_verdict('CA Alpha / serial 103 (inherited)', engine.lookup(CA_ALPHA, 103))
    print_verdict('CA Beta  / serial 103 (wrong issuer)', engine.lookup(CA_BETA, 103))

    alpha100 = engine.lookup(CA_ALPHA, 100)
    beta100 = engine.lookup(CA_BETA, 100)
    assert alpha100.status == RevocationStatus.REVOKED and alpha100.reason == 'key_compromise'
    assert beta100.status == RevocationStatus.REVOKED and beta100.reason == 'ca_compromise'
    assert engine.lookup(CA_BETA, 101).status == RevocationStatus.REVOKED
    assert engine.lookup(CA_ALPHA, 101).status == RevocationStatus.NOT_LISTED
    assert engine.lookup(CA_ALPHA, 103).status == RevocationStatus.REVOKED
    assert engine.lookup(CA_BETA, 103).status == RevocationStatus.NOT_LISTED
    print('  assertions OK')


# ==========================================================================
# Scenario B — delta CRL: hold, removeFromCRL, definitive reason replacement
# ==========================================================================
def scenario_b():
    line('B. Delta CRL: removeFromCRL state transitions (hold vs definitive)')
    idp = build_idp(DP_URI, indirect=True)
    base = build_crl(
        CRL_ISSUER, '2026-11-01 00:00:00', '2026-12-01 00:00:00',
        [
            make_entry(201, '2026-11-01 01:00:00', 'certificate_hold', CA_ALPHA),
            make_entry(202, '2026-11-01 01:00:00', 'certificate_hold', CA_ALPHA),
            make_entry(203, '2026-11-01 01:00:00', 'key_compromise', CA_BETA),
            make_entry(204, '2026-11-01 01:00:00', 'certificate_hold', CA_ALPHA),
            make_entry(205, '2026-11-01 01:00:00', 'certificate_hold', CA_BETA),
        ],
        crl_number=20, idp=idp)

    delta = build_crl(
        CRL_ISSUER, '2026-11-05 00:00:00', '2026-12-01 00:00:00',
        [
            # legal hold removal -> REMOVED
            make_entry(201, '2026-11-05 01:00:00', 'remove_from_crl', CA_ALPHA),
            # hold replaced by definitive revocation -> stays REVOKED, new reason
            make_entry(202, '2026-11-05 02:00:00', 'key_compromise', CA_ALPHA),
            # removal attempted against a definitive reason -> rejected, stays revoked
            make_entry(203, '2026-11-05 03:00:00', 'remove_from_crl', CA_BETA),
            # removal for a key the base never listed -> no-op
            make_entry(299, '2026-11-05 04:00:00', 'remove_from_crl', CA_ALPHA),
            # inherited-issuer removal: no ext -> last seen issuer in the DELTA
            make_entry(205, '2026-11-05 05:00:00', 'remove_from_crl', CA_BETA),
        ],
        crl_number=21, base_crl_number=20, idp=idp)

    engine = CRLEngine(make_verifier(), lambda: NOW)
    engine.ingest(base)
    engine.ingest(delta)
    show_trace(engine)

    print_verdict('201 hold then removeFromCRL', engine.lookup(CA_ALPHA, 201))
    print_verdict('202 hold then keyCompromise', engine.lookup(CA_ALPHA, 202))
    print_verdict('203 definitive then remove', engine.lookup(CA_BETA, 203))
    print_verdict('299 remove for unknown key', engine.lookup(CA_ALPHA, 299))
    print_verdict('205 inherited-issuer remove', engine.lookup(CA_BETA, 205))
    print_verdict('204 untouched hold', engine.lookup(CA_ALPHA, 204))

    assert engine.lookup(CA_ALPHA, 201).status == RevocationStatus.REMOVED
    v202 = engine.lookup(CA_ALPHA, 202)
    assert v202.status == RevocationStatus.REVOKED and v202.reason == 'key_compromise'
    v203 = engine.lookup(CA_BETA, 203)
    assert v203.status == RevocationStatus.REVOKED and v203.reason == 'key_compromise'
    assert engine.lookup(CA_ALPHA, 299).status == RevocationStatus.NOT_LISTED
    assert engine.lookup(CA_BETA, 205).status == RevocationStatus.REMOVED
    assert engine.lookup(CA_ALPHA, 204).reason == 'certificate_hold'
    print('  assertions OK')


# ==========================================================================
# Scenario C — wrong baseCRLNumber and out-of-order arrival
# ==========================================================================
def scenario_c():
    line('C. Delta referencing an unavailable/wrong base, and ordering stops')
    idp = build_idp(DP_URI, indirect=True)
    base20 = build_crl(CRL_ISSUER, '2026-11-01 00:00:00', '2026-12-01 00:00:00',
                       [make_entry(301, '2026-11-01 01:00:00', 'key_compromise', CA_ALPHA)],
                       crl_number=20, idp=idp)

    delta_future_base = build_crl(
        CRL_ISSUER, '2026-11-05 00:00:00', '2026-12-01 00:00:00',
        [make_entry(301, '2026-11-05 01:00:00', 'remove_from_crl', CA_ALPHA)],
        crl_number=25, base_crl_number=24, idp=idp)

    delta_before_base = build_crl(
        CRL_ISSUER, '2026-11-05 00:00:00', '2026-12-01 00:00:00',
        [make_entry(302, '2026-11-05 01:00:00', 'cessation_of_operation', CA_ALPHA)],
        crl_number=21, base_crl_number=20, idp=idp)

    engine = CRLEngine(make_verifier(), lambda: NOW)

    print('  -- delta with no base at all:')
    try:
        engine.ingest(delta_before_base)
    except TrustBoundaryError as exc:
        print('     STOP:', exc)

    engine.ingest(base20)

    print('  -- delta whose baseCRLNumber(24) > known base(20):')
    try:
        engine.ingest(delta_future_base)
    except TrustBoundaryError as exc:
        print('     STOP:', exc)

    # State must be unchanged: 301 still revoked from base 20.
    v = engine.lookup(CA_ALPHA, 301)
    print_verdict('301 after rejected delta', v)
    assert v.status == RevocationStatus.REVOKED and v.source_crl_number == 20

    print('  -- strict mode: base refreshed to #23, delta still names #20:')
    base23 = build_crl(CRL_ISSUER, '2026-11-03 00:00:00', '2026-12-01 00:00:00',
                       [make_entry(301, '2026-11-03 01:00:00', 'key_compromise', CA_ALPHA)],
                       crl_number=23, idp=idp)
    engine.ingest(base23)
    try:
        engine.ingest(delta_before_base)   # baseCRLNumber 20 != current 23
    except TrustBoundaryError as exc:
        print('     STOP:', exc)

    print('  -- relaxed mode accepts the newer base, ordering still enforced:')
    relaxed = CRLEngine(make_verifier(), lambda: NOW, strict_base=False)
    relaxed.ingest(base23)
    # delta #24 still declares baseCRLNumber 20, but its own number exceeds the
    # current base 23; relaxed linkage accepts it, strict mode would not.
    delta_relaxed = build_crl(
        CRL_ISSUER, '2026-11-07 00:00:00', '2026-12-01 00:00:00',
        [make_entry(302, '2026-11-07 01:00:00', 'cessation_of_operation', CA_ALPHA)],
        crl_number=24, base_crl_number=20, idp=idp)
    relaxed.ingest(delta_relaxed)
    print_verdict('302 added via relaxed delta', relaxed.lookup(CA_ALPHA, 302))
    assert relaxed.lookup(CA_ALPHA, 302).status == RevocationStatus.REVOKED

    print('  -- out-of-order: feed an older delta #22 after #24 applied:')
    delta22 = build_crl(CRL_ISSUER, '2026-11-06 00:00:00', '2026-12-01 00:00:00',
                        [make_entry(303, '2026-11-06 01:00:00', 'superseded', CA_ALPHA)],
                        crl_number=22, base_crl_number=20, idp=idp)
    try:
        relaxed.ingest(delta22)
    except TrustBoundaryError as exc:
        print('     STOP:', exc)
    assert relaxed.lookup(CA_ALPHA, 303).status == RevocationStatus.NOT_LISTED
    print('  assertions OK')


# ==========================================================================
# Scenario D — scope incompatibility (IDP / issuer / cert-type / reason set)
# ==========================================================================
def scenario_d():
    line('D. Incompatible delta scope: different IDP cannot merge into the base')
    base_idp = build_idp('http://crl.example/group/indirect.crl', indirect=True,
                         only_user=True)
    base = build_crl(CRL_ISSUER, '2026-11-01 00:00:00', '2026-12-01 00:00:00',
                     [make_entry(401, '2026-11-01 01:00:00', 'key_compromise', CA_ALPHA)],
                     crl_number=30, idp=base_idp)

    # Same issuer, different distribution point -> different scope stream.
    other_idp = build_idp('http://crl.example/other/indirect.crl', indirect=True,
                          only_user=True)
    delta_wrong_dp = build_crl(
        CRL_ISSUER, '2026-11-05 00:00:00', '2026-12-01 00:00:00',
        [make_entry(401, '2026-11-05 01:00:00', 'remove_from_crl', CA_ALPHA)],
        crl_number=31, base_crl_number=30, idp=other_idp)

    # Same DP, but onlyContainsCAcerts instead of user certs.
    ca_idp = build_idp('http://crl.example/group/indirect.crl', indirect=True,
                       only_ca=True)
    delta_wrong_type = build_crl(
        CRL_ISSUER, '2026-11-05 00:00:00', '2026-12-01 00:00:00',
        [make_entry(402, '2026-11-05 01:00:00', 'key_compromise', CA_ALPHA)],
        crl_number=31, base_crl_number=30, idp=ca_idp)

    engine = CRLEngine(make_verifier(), lambda: NOW)
    engine.ingest(base)

    for label, bad in (('different distribution point', delta_wrong_dp),
                       ('onlyContainsCAcerts vs user certs', delta_wrong_type)):
        try:
            engine.ingest(bad)
        except TrustBoundaryError as exc:
            print('  STOP (%s): %s' % (label, exc))

    v = engine.lookup(CA_ALPHA, 401)
    print_verdict('401 in original user-cert scope', v)
    assert v.status == RevocationStatus.REVOKED and v.source_crl_number == 30
    assert engine.lookup(CA_ALPHA, 402).status == RevocationStatus.NOT_LISTED

    print('  -- onlySomeReasons: reason outside the scope is not authoritative')
    reason_idp = build_idp(DP_URI, indirect=True,
                           only_some_reasons=set(['key_compromise', 'ca_compromise']))
    scoped = build_crl(
        CRL_ISSUER, '2026-11-01 00:00:00', '2026-12-01 00:00:00',
        [make_entry(410, '2026-11-01 01:00:00', 'key_compromise', CA_ALPHA),
         make_entry(411, '2026-11-01 01:00:00', 'certificate_hold', CA_ALPHA)],
        crl_number=40, idp=reason_idp)
    engine2 = CRLEngine(make_verifier(), lambda: NOW)
    engine2.ingest(scoped)
    show_trace(engine2)
    assert engine2.lookup(CA_ALPHA, 410).status == RevocationStatus.REVOKED
    assert engine2.lookup(CA_ALPHA, 411).status == RevocationStatus.NOT_LISTED
    print('  assertions OK')


# ==========================================================================
# Scenario E — parsed vs trusted boundary, signature reject, stale CRL
# ==========================================================================
def scenario_e():
    line('E. Trust boundary: unverified parse never becomes a revocation fact')
    idp = build_idp(DP_URI, indirect=True)
    good = build_crl(CRL_ISSUER, '2026-11-01 00:00:00', '2026-12-01 00:00:00',
                     [make_entry(501, '2026-11-01 01:00:00', 'key_compromise', CA_ALPHA)],
                     crl_number=50, idp=idp)
    tampered = build_crl(
        CRL_ISSUER, '2026-11-05 00:00:00', '2026-12-01 00:00:00',
        [make_entry(502, '2026-11-05 01:00:00', 'ca_compromise', CA_BETA)],
        crl_number=51, base_crl_number=50, idp=idp)
    expired = build_crl(
        CRL_ISSUER, '2026-10-01 00:00:00', '2026-10-20 00:00:00',
        [make_entry(503, '2026-10-01 01:00:00', 'superseded', CA_ALPHA)],
        crl_number=52, idp=idp)

    engine = CRLEngine(make_verifier(rejected_serials_of_crl={51}), lambda: NOW)
    engine.ingest(good)

    parsed_tampered = engine.parse(tampered)   # parsing succeeds...
    print('  tampered CRL parsed at level:', parsed_tampered.trust.value,
          '| entries decoded:',
          [(e.key.serial, e.reason) for e in parsed_tampered.entries])
    try:
        engine.ingest(tampered)                # ...but trust must fail
    except TrustBoundaryError as exc:
        print('  STOP (signature):', exc)
    print_verdict('502 from rejected delta', engine.lookup(CA_BETA, 502))
    assert engine.lookup(CA_BETA, 502).status == RevocationStatus.NOT_LISTED

    try:
        engine.ingest(expired)
    except TrustBoundaryError as exc:
        print('  STOP (staleness):', exc)
    print_verdict('503 from expired CRL', engine.lookup(CA_ALPHA, 503))
    assert engine.lookup(CA_ALPHA, 503).status == RevocationStatus.NOT_LISTED

    print('  -- no input at all is UNKNOWN, never an implicit good:')
    empty = CRLEngine(make_verifier(), lambda: NOW)
    v = empty.lookup(CA_ALPHA, 501)
    print_verdict('lookup with zero CRLs', v)
    assert v.status == RevocationStatus.UNKNOWN
    print('  assertions OK')


def main():
    scenario_a()
    scenario_b()
    scenario_c()
    scenario_d()
    scenario_e()
    line('ALL SCENARIOS PASSED')


if __name__ == '__main__':
    main()
