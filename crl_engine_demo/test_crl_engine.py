# coding: utf-8
"""Regression tests for the indirect/delta CRL composition prototype."""

import datetime

import pytest

from .builder import build_crl, build_idp, make_entry, dn
from .engine import CRLEngine, TrustBoundaryError
from .model import RevocationStatus

NOW = datetime.datetime(2026, 11, 13, 12, 0, 0)
CRL_ISSUER = dn('Indirect CRL Authority', o='Example CA Group')
CA_ALPHA = dn('CA Alpha', o='Example CA Group')
CA_BETA = dn('CA Beta', o='Example CA Group')
DP_URI = 'http://crl.example/group/indirect.crl'


def engine(reject=(), strict=True):
    rejected = set(reject)
    return CRLEngine(
        lambda cl: cl.crl_number_value.native not in rejected,
        lambda: NOW, strict_base=strict)


def idp(**kw):
    return build_idp(DP_URI, indirect=True, **kw)


def test_certificate_issuer_inheritance_and_serial_collision():
    base = build_crl(
        CRL_ISSUER, '2026-11-01 00:00:00', '2026-12-01 00:00:00',
        [
            make_entry(100, '2026-11-01 01:00:00', 'key_compromise', CA_ALPHA),
            make_entry(100, '2026-11-01 02:00:00', 'ca_compromise', CA_BETA),
            make_entry(101, '2026-11-01 03:00:00', 'affiliation_changed'),
            make_entry(102, '2026-11-01 04:00:00', 'superseded', CA_ALPHA),
            make_entry(103, '2026-11-01 05:00:00', 'cessation_of_operation'),
        ], crl_number=10, idp=idp())
    eng = engine()
    parsed = eng.ingest(base)

    flags = [e.inherited_from_previous for e in parsed.entries]
    assert flags == [False, False, True, False, True]

    assert eng.lookup(CA_ALPHA, 100).reason == 'key_compromise'
    assert eng.lookup(CA_BETA, 100).reason == 'ca_compromise'
    assert eng.lookup(CA_BETA, 101).status == RevocationStatus.REVOKED
    assert eng.lookup(CA_ALPHA, 101).status == RevocationStatus.NOT_LISTED
    assert eng.lookup(CA_ALPHA, 103).status == RevocationStatus.REVOKED
    assert eng.lookup(CA_BETA, 103).status == RevocationStatus.NOT_LISTED


def test_delta_remove_from_crl_transitions():
    base = build_crl(
        CRL_ISSUER, '2026-11-01 00:00:00', '2026-12-01 00:00:00',
        [
            make_entry(201, '2026-11-01 01:00:00', 'certificate_hold', CA_ALPHA),
            make_entry(202, '2026-11-01 01:00:00', 'certificate_hold', CA_ALPHA),
            make_entry(203, '2026-11-01 01:00:00', 'key_compromise', CA_BETA),
        ], crl_number=20, idp=idp())
    delta = build_crl(
        CRL_ISSUER, '2026-11-05 00:00:00', '2026-12-01 00:00:00',
        [
            make_entry(201, '2026-11-05 01:00:00', 'remove_from_crl', CA_ALPHA),
            make_entry(202, '2026-11-05 02:00:00', 'key_compromise', CA_ALPHA),
            make_entry(203, '2026-11-05 03:00:00', 'remove_from_crl', CA_BETA),
            make_entry(299, '2026-11-05 04:00:00', 'remove_from_crl', CA_ALPHA),
        ], crl_number=21, base_crl_number=20, idp=idp())
    eng = engine()
    eng.ingest(base)
    eng.ingest(delta)

    assert eng.lookup(CA_ALPHA, 201).status == RevocationStatus.REMOVED
    v202 = eng.lookup(CA_ALPHA, 202)
    assert (v202.status, v202.reason) == (RevocationStatus.REVOKED, 'key_compromise')
    v203 = eng.lookup(CA_BETA, 203)
    assert (v203.status, v203.reason, v203.source_crl_number) == (
        RevocationStatus.REVOKED, 'key_compromise', 20)
    assert eng.lookup(CA_ALPHA, 299).status == RevocationStatus.NOT_LISTED


def test_wrong_and_missing_base_stop_the_judgement():
    base20 = build_crl(
        CRL_ISSUER, '2026-11-01 00:00:00', '2026-12-01 00:00:00',
        [make_entry(301, '2026-11-01 01:00:00', 'key_compromise', CA_ALPHA)],
        crl_number=20, idp=idp())
    orphan_delta = build_crl(
        CRL_ISSUER, '2026-11-05 00:00:00', '2026-12-01 00:00:00',
        [make_entry(302, '2026-11-05 01:00:00', 'superseded', CA_ALPHA)],
        crl_number=21, base_crl_number=20, idp=idp())
    future_delta = build_crl(
        CRL_ISSUER, '2026-11-06 00:00:00', '2026-12-01 00:00:00',
        [make_entry(301, '2026-11-06 01:00:00', 'remove_from_crl', CA_ALPHA)],
        crl_number=25, base_crl_number=24, idp=idp())

    eng = engine()
    with pytest.raises(TrustBoundaryError):
        eng.ingest(orphan_delta)
    eng.ingest(base20)
    with pytest.raises(TrustBoundaryError):
        eng.ingest(future_delta)
    # State unchanged after both rejections.
    verdict = eng.lookup(CA_ALPHA, 301)
    assert (verdict.status, verdict.source_crl_number) == (
        RevocationStatus.REVOKED, 20)


def test_strict_vs_relaxed_base_linkage_and_ordering():
    base23 = build_crl(
        CRL_ISSUER, '2026-11-03 00:00:00', '2026-12-01 00:00:00',
        [make_entry(301, '2026-11-03 01:00:00', 'key_compromise', CA_ALPHA)],
        crl_number=23, idp=idp())
    delta = build_crl(
        CRL_ISSUER, '2026-11-07 00:00:00', '2026-12-01 00:00:00',
        [make_entry(302, '2026-11-07 01:00:00', 'cessation_of_operation', CA_ALPHA)],
        crl_number=24, base_crl_number=20, idp=idp())

    strict = engine()
    strict.ingest(base23)
    with pytest.raises(TrustBoundaryError):
        strict.ingest(delta)

    relaxed = engine(strict=False)
    relaxed.ingest(base23)
    relaxed.ingest(delta)
    assert relaxed.lookup(CA_ALPHA, 302).status == RevocationStatus.REVOKED


def test_incompatible_scope_delta_refused():
    base = build_crl(
        CRL_ISSUER, '2026-11-01 00:00:00', '2026-12-01 00:00:00',
        [make_entry(401, '2026-11-01 01:00:00', 'key_compromise', CA_ALPHA)],
        crl_number=30, idp=build_idp(DP_URI, indirect=True, only_user=True))

    other_dp = build_idp('http://crl.example/other.crl', indirect=True, only_user=True)
    delta = build_crl(
        CRL_ISSUER, '2026-11-05 00:00:00', '2026-12-01 00:00:00',
        [make_entry(401, '2026-11-05 01:00:00', 'remove_from_crl', CA_ALPHA)],
        crl_number=31, base_crl_number=30, idp=other_dp)
    eng = engine()
    eng.ingest(base)
    with pytest.raises(TrustBoundaryError):
        eng.ingest(delta)
    assert eng.lookup(CA_ALPHA, 401).source_crl_number == 30


def test_only_some_reasons_limits_authoritative_entries():
    crl = build_crl(
        CRL_ISSUER, '2026-11-01 00:00:00', '2026-12-01 00:00:00',
        [
            make_entry(410, '2026-11-01 01:00:00', 'key_compromise', CA_ALPHA),
            make_entry(411, '2026-11-01 01:00:00', 'certificate_hold', CA_ALPHA),
        ], crl_number=40,
        idp=build_idp(DP_URI, indirect=True,
                      only_some_reasons=set(['key_compromise', 'ca_compromise'])))
    eng = engine()
    eng.ingest(crl)
    assert eng.lookup(CA_ALPHA, 410).status == RevocationStatus.REVOKED
    assert eng.lookup(CA_ALPHA, 411).status == RevocationStatus.NOT_LISTED


def test_parsed_is_not_trusted_and_stale_is_rejected():
    good = build_crl(
        CRL_ISSUER, '2026-11-01 00:00:00', '2026-12-01 00:00:00',
        [make_entry(501, '2026-11-01 01:00:00', 'key_compromise', CA_ALPHA)],
        crl_number=50, idp=idp())
    bad_delta = build_crl(
        CRL_ISSUER, '2026-11-05 00:00:00', '2026-12-01 00:00:00',
        [make_entry(502, '2026-11-05 01:00:00', 'ca_compromise', CA_BETA)],
        crl_number=51, base_crl_number=50, idp=idp())
    expired = build_crl(
        CRL_ISSUER, '2026-10-01 00:00:00', '2026-10-20 00:00:00',
        [make_entry(503, '2026-10-01 01:00:00', 'superseded', CA_ALPHA)],
        crl_number=52, idp=idp())

    eng = engine(reject={51})
    eng.ingest(good)
    parsed = eng.parse(bad_delta)  # decoding succeeds...
    assert parsed.trust.value == 'parsed'
    with pytest.raises(TrustBoundaryError):
        eng.ingest(bad_delta)       # ...but it never enters trusted state
    assert eng.lookup(CA_BETA, 502).status == RevocationStatus.NOT_LISTED

    with pytest.raises(TrustBoundaryError):
        eng.ingest(expired)

    assert engine().lookup(CA_ALPHA, 501).status == RevocationStatus.UNKNOWN
