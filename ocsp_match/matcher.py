# coding: utf-8

"""
Associate OCSP SingleResponse entries back to the requests and real
certificate material they describe.

The module deliberately performs *no* trust evaluation: it neither verifies
the OCSP response signature nor decides whether thisUpdate/nextUpdate are
fresh.  It only recomposes CertId values from real certificate material
(using the exact DER boundaries RFC 6960 requires), performs byte-level
matching, keeps every candidate issuer that fits, and preserves the evidence
an upper layer needs for its own validation.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import hashlib
from dataclasses import dataclass
from enum import Enum

from asn1crypto.core import (
    Any,
    Integer,
    Null,
    ObjectIdentifier,
    OctetString,
    Sequence,
    SequenceOf,
    Void,
)
from asn1crypto.ocsp import OCSPRequest, OCSPResponse, SingleResponse
from asn1crypto.x509 import Certificate, GeneralName


# hashlib name -> (RFC 4055/3279 digest OID, digest length in bytes)
_DIGEST_OIDS = {
    'md5': ('1.2.840.113549.2.5', 16),
    'sha1': ('1.3.14.3.2.26', 20),
    'sha224': ('2.16.840.1.101.3.4.2.4', 28),
    'sha256': ('2.16.840.1.101.3.4.2.1', 32),
    'sha384': ('2.16.840.1.101.3.4.2.2', 48),
    'sha512': ('2.16.840.1.101.3.4.2.3', 64),
}

_OID_TO_HASHLIB = dict((oid, name) for name, (oid, _) in _DIGEST_OIDS.items())


class OcspMatchError(ValueError):
    """Raised when input DER cannot be parsed at all (not a normal outcome)."""


class _RawDigestAlgorithm(Sequence):
    """
    A DigestAlgorithm view without the NULL-parameters coercion.

    asn1crypto's DigestAlgorithm forces digest OID parameters to Null while
    parsing, which would turn an illegal non-NULL parameter into an exception
    before we could classify it.  Any keeps whatever element the wire carried
    (Null, an OID, something malformed) so it can be classified as data.
    """

    _fields = [
        ('algorithm', ObjectIdentifier),
        ('parameters', Any, {'optional': True}),
    ]


class _RawCertId(Sequence):
    _fields = [
        ('hash_algorithm', _RawDigestAlgorithm),
        ('issuer_name_hash', OctetString),
        ('issuer_key_hash', OctetString),
        ('serial_number', Integer),
    ]


class _RawRequest(Sequence):
    _fields = [
        ('req_cert', _RawCertId),
    ]


class _RawRequests(SequenceOf):
    _child_spec = _RawRequest


class _RawTBSRequest(Sequence):
    _fields = [
        ('requestor_name', GeneralName, {'explicit': 1, 'optional': True}),
        ('request_list', _RawRequests),
    ]


class _RawOCSPRequest(Sequence):
    _fields = [
        ('tbs_request', _RawTBSRequest),
    ]


class MatchStatus(str, Enum):
    MATCHED = 'matched'
    AMBIGUOUS = 'ambiguous'
    MISMATCH = 'mismatch'
    MISSING_RESPONSE = 'missing_response'
    UNSUPPORTED_DIGEST = 'unsupported_digest'
    INVALID_ALGORITHM_PARAMETERS = 'invalid_algorithm_parameters'


class ResponseDisposition(str, Enum):
    MATCHED = 'matched'
    NEAR_MISS = 'near_miss'
    ORPHAN = 'orphan'
    DUPLICATE_CONSISTENT = 'duplicate_consistent'
    DUPLICATE_CONFLICT = 'duplicate_conflict'


@dataclass(frozen=True)
class CertIdData:
    """Normalized view of an OCSP CertId."""

    algorithm_oid: str
    algorithm_name: object
    parameters_kind: str
    name_hash: bytes
    key_hash: bytes
    serial_number: int
    raw_der: bytes
    valid_parameters: bool


@dataclass(frozen=True)
class HashEvidence:
    """A single hash recomputed from real certificate material."""

    algorithm: str
    algorithm_oid: str
    # hashlib digest of the DER encoding of the issuer's Name (full TLV body,
    # i.e. the Name SEQUENCE contents including its inner tagging).
    name_hash: bytes
    # hashlib digest of the BIT STRING payload only: unused-bits octet and the
    # outer tag/length are excluded, the SubjectPublicKey BIT STRING boundary.
    key_hash: bytes
    # DER actually fed into the two hash functions, retained for audit.
    name_der: bytes
    key_bit_string_payload: bytes
    key_unused_bits: int


@dataclass(frozen=True)
class IssuerFingerprint:
    """Recomputed CertId components for one candidate issuer certificate."""

    label: object
    certificate: Certificate
    fingerprints: tuple


@dataclass(frozen=True)
class IssuerMatch:
    label: object
    certificate: Certificate
    name_hash: bytes
    key_hash: bytes


@dataclass(frozen=True)
class SingleResponseEvidence:
    """Everything an upper layer needs to validate one SingleResponse."""

    index: int
    message_index: int
    cert_id: CertIdData
    status_name: str
    status_value: object
    revocation_time: object
    revocation_reason: object
    this_update: object
    next_update: object
    single_response: SingleResponse


@dataclass(frozen=True)
class RequestReport:
    """Outcome for one request entry, including every source it came from."""

    request_index: int
    source: object
    cert_id: CertIdData
    status: MatchStatus
    reason: str
    issuers: tuple
    responses: tuple
    conflict: object


@dataclass(frozen=True)
class UnmatchedResponseReport:
    """A SingleResponse whose CertId no request carries (orphan/near-miss)."""

    index: int
    message_index: int
    disposition: ResponseDisposition
    reason: str
    evidence: SingleResponseEvidence
    near_misses: tuple


@dataclass(frozen=True)
class DuplicateResponseReport:
    """
    Multiple SingleResponses share one CertId that a request did carry.

    The request report keeps every copy too; this surface summarizes whether
    the copies agree (consistent) or contradict each other (conflict).
    """

    disposition: ResponseDisposition
    reason: str
    evidence: tuple
    conflict: object


@dataclass(frozen=True)
class MatchReport:
    matched: tuple
    ambiguous: tuple
    mismatched: tuple
    missing: tuple
    unsupported: tuple
    invalid_parameters: tuple
    duplicate_responses: tuple
    unmatched_responses: tuple
    non_successful_responses: tuple
    requests: tuple

    @property
    def groups(self):
        """All request reports keyed by the equivalent-CertId group id."""
        grouped = {}
        for report in self.requests:
            grouped.setdefault(report.cert_id.raw_der, []).append(report)
        return grouped


def _load(klass, value, noun):
    try:
        return klass.load(value)
    except (ValueError, TypeError) as exc:
        raise OcspMatchError('cannot parse %s DER: %s' % (noun, exc))


def _coerce_certificate(value):
    if isinstance(value, Certificate):
        return value
    if isinstance(value, bytes):
        return _load(Certificate, value, 'issuer certificate')
    raise OcspMatchError(
        'issuer certificate must be an asn1crypto.x509.Certificate or DER bytes, got %s'
        % type(value).__name__
    )


def _coerce_request(value):
    if isinstance(value, OCSPRequest):
        return _RawOCSPRequest.load(value.dump())
    if isinstance(value, bytes):
        return _load(_RawOCSPRequest, value, 'OCSP request')
    raise OcspMatchError(
        'request must be an asn1crypto.ocsp.OCSPRequest or DER bytes, got %s'
        % type(value).__name__
    )


def _coerce_response(value):
    if isinstance(value, OCSPResponse):
        return value
    if isinstance(value, bytes):
        return _load(OCSPResponse, value, 'OCSP response')
    raise OcspMatchError(
        'response must be an asn1crypto.ocsp.OCSPResponse or DER bytes, got %s'
        % type(value).__name__
    )


_ASN1_TAG_NAMES = {
    1: 'Boolean',
    2: 'Integer',
    3: 'BitString',
    4: 'OctetString',
    5: 'Null',
    6: 'ObjectIdentifier',
    10: 'Enumerated',
    12: 'UTF8String',
    16: 'Sequence',
    17: 'Set',
    19: 'PrintableString',
}


def _parameters_kind(parameters):
    if isinstance(parameters, Void):
        return 'absent'
    if isinstance(parameters, Null):
        return 'null'
    header = getattr(parameters, '_header', b'')
    if header:
        # Universal-tag class (top two bits zero); tag number is low nibble
        # for the single-byte tags used inside AlgorithmIdentifier.
        tag = header[0] & 0x1F
        if header[0] == 5:
            return 'null'
        return _ASN1_TAG_NAMES.get(tag, type(parameters).__name__)
    return type(parameters).__name__


def parse_cert_id(cert_id):
    """
    Normalize a CertId without throwing on unsupported/illegal algorithms.

    The value is re-parsed through raw ASN.1 definitions so that a non-NULL
    algorithm parameter reaches this code as data, instead of tripping
    asn1crypto's NULL-coercion for known digest OIDs.

    :param cert_id:
        An asn1crypto.ocsp.CertId object, or raw CertId DER bytes.
    :return: CertIdData
    """

    if isinstance(cert_id, bytes):
        raw = _load(_RawCertId, cert_id, 'CertId')
        raw_der = cert_id
    else:
        raw_der = cert_id.dump()
        raw = _load(_RawCertId, raw_der, 'CertId')

    hash_algorithm = raw['hash_algorithm']
    algorithm_field = hash_algorithm['algorithm']
    oid = algorithm_field.dotted
    parameters = hash_algorithm['parameters']
    kind = _parameters_kind(parameters)

    serial = raw['serial_number'].native
    if serial is not None and serial < 0:
        raise OcspMatchError('CertId serial number must be a non-negative integer')

    name_hash = raw['issuer_name_hash'].native or b''
    key_hash = raw['issuer_key_hash'].native or b''

    hashlib_name = _OID_TO_HASHLIB.get(oid)
    if hashlib_name is None:
        valid_parameters = False
    else:
        # RFC 6960 4.1.1: hash algorithms for CertId use the NULL parameters
        # form (or, equivalently for these OIDs, absent parameters that DER
        # rules normalize to NULL).  Anything else is illegal here.
        valid_parameters = kind in ('null', 'absent')
        if valid_parameters:
            expected_len = _DIGEST_OIDS[hashlib_name][1]
            valid_parameters = (
                len(name_hash) == expected_len and len(key_hash) == expected_len
            )

    return CertIdData(
        algorithm_oid=oid,
        algorithm_name=algorithm_field.native,
        parameters_kind=kind,
        name_hash=name_hash,
        key_hash=key_hash,
        serial_number=serial,
        raw_der=raw_der,
        valid_parameters=valid_parameters,
    )


def issuer_fingerprint(certificate, label=None, algorithms=('sha1', 'sha256')):
    """
    Recompute every CertId hash component from real issuer material.

    The name hash covers the DER of the issuer Name.  The key hash covers the
    SubjectPublicKey BIT STRING payload (RFC 6960 calls this the public key
    itself), excluding the unused-bits octet and the BIT STRING tag/length.
    """

    cert = _coerce_certificate(certificate)
    name = cert.subject
    name_der = name.dump()

    public_key_bit_string = cert['tbs_certificate']['subject_public_key_info']['public_key']
    if not hasattr(public_key_bit_string, 'contents') or public_key_bit_string.tag != 3:
        raise OcspMatchError('issuer SubjectPublicKey is not a BIT STRING')

    # RFC 6960 hashes the BIT STRING payload (the public key itself): the
    # leading unused-bits octet, the tag and the length are all excluded.  We
    # use .contents[1:] rather than .native on purpose - for a
    # ParsableOctetBitString .native yields the parsed inner structure (e.g.
    # an RSAPublicKey tuple), not the on-the-wire key bytes.
    contents = public_key_bit_string.contents
    if not contents:
        raise OcspMatchError('issuer SubjectPublicKey BIT STRING is empty')
    unused_bits = contents[0]
    if unused_bits:
        raise OcspMatchError(
            'issuer SubjectPublicKey BIT STRING has %d unused bits; OCSP key hash '
            'boundary is only defined for octet-aligned keys' % unused_bits
        )
    key_payload = contents[1:]

    fingerprints = []
    for requested in algorithms:
        if requested not in _DIGEST_OIDS:
            raise OcspMatchError('unsupported digest algorithm %r' % requested)
        oid = _DIGEST_OIDS[requested][0]
        name_digest = hashlib.new(requested, name_der).digest()
        key_digest = hashlib.new(requested, key_payload).digest()
        fingerprints.append(
            HashEvidence(
                algorithm=requested,
                algorithm_oid=oid,
                name_hash=name_digest,
                key_hash=key_digest,
                name_der=name_der,
                key_bit_string_payload=key_payload,
                key_unused_bits=unused_bits,
            )
        )

    return IssuerFingerprint(
        label=label,
        certificate=cert,
        fingerprints=tuple(fingerprints),
    )


def _evidence_for_single_response(message_index, index, single_response):
    cert_id = parse_cert_id(single_response['cert_id'])
    cert_status = single_response['cert_status']
    status_name = cert_status.name
    status_value = cert_status.native
    revocation_time = None
    revocation_reason = None
    if status_name == 'revoked':
        revoked_info = cert_status.chosen
        revocation_time = revoked_info['revocation_time'].native
        reason_field = revoked_info['revocation_reason']
        if not isinstance(reason_field, Void):
            revocation_reason = reason_field.native

    return SingleResponseEvidence(
        index=index,
        message_index=message_index,
        cert_id=cert_id,
        status_name=status_name,
        status_value=status_value,
        revocation_time=revocation_time,
        revocation_reason=revocation_reason,
        this_update=single_response['this_update'].native,
        next_update=single_response['next_update'].native,
        single_response=single_response,
    )


def _index_responses(responses):
    """Flatten OCSPResponse messages into entries and non-success notices."""

    entries = []
    non_successful = []
    for message_index, raw_response in enumerate(responses):
        response = _coerce_response(raw_response)
        status = response['response_status'].native
        if status != 'successful':
            non_successful.append(
                {'message_index': message_index, 'response_status': status}
            )
            continue
        basic = response.basic_ocsp_response
        for index, single_response in enumerate(basic['tbs_response_data']['responses']):
            entries.append(
                (
                    (message_index, index),
                    _evidence_for_single_response(message_index, index, single_response),
                )
            )
    return entries, non_successful


def _build_issuer_index(issuers, algorithms):
    fingerprints = []
    for position, item in enumerate(issuers):
        if isinstance(item, IssuerFingerprint):
            fingerprints.append(item)
            continue
        if isinstance(item, tuple):
            label, cert_value = item
            fingerprints.append(issuer_fingerprint(cert_value, label, algorithms))
        else:
            fingerprints.append(issuer_fingerprint(item, position, algorithms))

    # Lookup table keyed by the digest OID.  Serial numbers do not narrow the
    # issuer search because many issuers can each have issued serial N; the
    # two hashes are the discriminating components.  All candidates are
    # retained; input ordering never decides which issuer wins.
    by_oid = {}
    for fingerprint in fingerprints:
        for evidence in fingerprint.fingerprints:
            by_oid.setdefault((evidence.algorithm_oid,), []).append(
                (evidence, fingerprint)
            )
    return fingerprints, by_oid


def _find_issuer_candidates(cert_id_data, issuer_index):
    bucket = issuer_index.get((cert_id_data.algorithm_oid,), [])
    candidates = []
    for evidence, fingerprint in bucket:
        if (
            evidence.name_hash == cert_id_data.name_hash
            and evidence.key_hash == cert_id_data.key_hash
        ):
            candidates.append(
                IssuerMatch(
                    label=fingerprint.label,
                    certificate=fingerprint.certificate,
                    name_hash=evidence.name_hash,
                    key_hash=evidence.key_hash,
                )
            )
    return tuple(candidates)


def _near_miss_hints(cert_id_data, issuer_index):
    bucket = issuer_index.get((cert_id_data.algorithm_oid,), [])
    hints = []
    for evidence, fingerprint in bucket:
        name_hit = evidence.name_hash == cert_id_data.name_hash
        key_hit = evidence.key_hash == cert_id_data.key_hash
        if name_hit or key_hit:
            hints.append(
                {
                    'label': fingerprint.label,
                    'name_hash_equal': name_hit,
                    'key_hash_equal': key_hit,
                }
            )
    return tuple(hints)


def _status_identity(evidence):
    if evidence.status_name != 'revoked':
        return (evidence.status_name, None, None)
    return (
        evidence.status_name,
        evidence.revocation_time,
        evidence.revocation_reason,
    )


def match_ocsp(requests, responses, candidate_issuers, digest_algorithms=('sha1', 'sha256')):
    """
    Match OCSP request CertIds against response SingleResponses and the real
    candidate issuer certificates.

    :param requests:
        A list where each item is an OCSPRequest (or DER bytes), or a
        (source_label, request) tuple so callers can keep track of where each
        request came from.
    :param responses:
        A list of OCSPResponse objects (or DER bytes).
    :param candidate_issuers:
        A list of Certificate objects / DER bytes / (label, cert) tuples /
        prebuilt IssuerFingerprint objects.  Every issuer matching a CertId is
        retained as a candidate rather than picking the first one.
    :param digest_algorithms:
        hashlib names precomputed for the candidate issuers.
    :return:
        MatchReport
    """

    for requested in digest_algorithms:
        if requested not in _DIGEST_OIDS:
            raise OcspMatchError('unsupported digest algorithm %r' % requested)
    precomputed_oids = {_DIGEST_OIDS[name][0] for name in digest_algorithms}

    normalized_requests = []
    for position, item in enumerate(requests):
        if isinstance(item, tuple):
            source, raw_request = item
        else:
            source, raw_request = position, item
        request = _coerce_request(raw_request)
        normalized_requests.append((source, request))

    _, issuer_index = _build_issuer_index(candidate_issuers, digest_algorithms)

    response_entries, non_successful = _index_responses(responses)

    # A request naming a digest we support but did not precompute would always
    # look like a mismatch even when the issuer fits.  Refuse that silent
    # wrong answer and tell the caller which algorithm to add.
    needed_oids = set()
    for _, request in normalized_requests:
        for request_entry in request['tbs_request']['request_list']:
            cert_id_data = parse_cert_id(request_entry['req_cert'])
            if cert_id_data.algorithm_oid in _OID_TO_HASHLIB:
                needed_oids.add(cert_id_data.algorithm_oid)
    missing_oids = needed_oids - precomputed_oids
    if missing_oids:
        missing_names = sorted(_OID_TO_HASHLIB[oid] for oid in missing_oids)
        raise OcspMatchError(
            'requests use digest algorithm(s) %s not present in digest_algorithms; '
            'add them so issuer hashes can be recomputed' % ', '.join(missing_names)
        )

    # First pass over responses: exact CertId grouping, duplicate handling.
    responses_by_certid = {}
    for location, evidence in response_entries:
        responses_by_certid.setdefault(evidence.cert_id.raw_der, []).append(
            (location, evidence)
        )

    consumed_response_keys = set()
    request_reports = []
    matched_reports = []
    ambiguous_reports = []
    mismatch_reports = []
    missing_reports = []
    unsupported_reports = []
    invalid_parameter_reports = []

    # Equivalent requests (identical CertId DER) share the same response set,
    # but each source keeps its own report.
    group_cache = {}

    for request_index, (source, request) in enumerate(normalized_requests):
        for request_entry in request['tbs_request']['request_list']:
            cert_id_data = parse_cert_id(request_entry['req_cert'])
            cache_key = cert_id_data.raw_der

            if cache_key in group_cache:
                cached = group_cache[cache_key]
                report = RequestReport(
                    request_index=request_index,
                    source=source,
                    cert_id=cached.cert_id,
                    status=cached.status,
                    reason=cached.reason,
                    issuers=cached.issuers,
                    responses=cached.responses,
                    conflict=cached.conflict,
                )
                request_reports.append(report)
                _sort_report(report, matched_reports, ambiguous_reports,
                             mismatch_reports, missing_reports,
                             unsupported_reports, invalid_parameter_reports)
                continue

            matching_responses = responses_by_certid.get(cache_key, ())
            consumed_response_keys.add(cache_key)

            hashlib_name = _OID_TO_HASHLIB.get(cert_id_data.algorithm_oid)
            if hashlib_name is None:
                status = MatchStatus.UNSUPPORTED_DIGEST
                reason = 'cert_id uses digest OID %s (%s) which is not supported for recomputation' % (
                    cert_id_data.algorithm_oid, cert_id_data.algorithm_name
                )
                issuers = ()
                conflict = None
            elif not cert_id_data.valid_parameters:
                status = MatchStatus.INVALID_ALGORITHM_PARAMETERS
                reason = (
                    'cert_id digest algorithm parameters are %r; RFC 6960 requires NULL '
                    'parameters and correctly sized hashes' % cert_id_data.parameters_kind
                )
                issuers = ()
                conflict = None
            else:
                issuers = _find_issuer_candidates(cert_id_data, issuer_index)
                conflict = _detect_conflict(matching_responses)
                if not matching_responses:
                    status = MatchStatus.MISSING_RESPONSE
                    reason = 'no SingleResponse present for this CertId'
                elif conflict is not None:
                    status = MatchStatus.MISMATCH
                    reason = conflict
                elif not issuers:
                    status = MatchStatus.MISMATCH
                    reason = (
                        'no candidate issuer reproduces both issuerNameHash and '
                        'issuerKeyHash for serial %s' % cert_id_data.serial_number
                    )
                elif len(issuers) == 1:
                    status = MatchStatus.MATCHED
                    reason = 'single candidate issuer reproduces both hashes'
                else:
                    status = MatchStatus.AMBIGUOUS
                    reason = (
                        '%d distinct candidate issuer certificates reproduce both hashes; '
                        'cannot select one without input ordering' % len(issuers)
                    )

            report = RequestReport(
                request_index=request_index,
                source=source,
                cert_id=cert_id_data,
                status=status,
                reason=reason,
                issuers=issuers,
                responses=tuple(evidence for _, evidence in matching_responses),
                conflict=conflict,
            )
            group_cache[cache_key] = report
            request_reports.append(report)
            _sort_report(report, matched_reports, ambiguous_reports,
                         mismatch_reports, missing_reports,
                         unsupported_reports, invalid_parameter_reports)

    # Second pass: surface duplicates for claimed CertIds separately from
    # responses whose CertId no request ever carried (orphans/near-misses).
    duplicate_reports = []
    unmatched_reports = []
    for cache_key, group in responses_by_certid.items():
        evidence_tuple = tuple(evidence for _, evidence in group)
        if cache_key in consumed_response_keys:
            if len(group) > 1:
                conflict = _detect_conflict(group)
                disposition = (
                    ResponseDisposition.DUPLICATE_CONFLICT
                    if conflict is not None
                    else ResponseDisposition.DUPLICATE_CONSISTENT
                )
                reason = (
                    conflict
                    or '%d equivalent SingleResponses carry identical status' % len(group)
                )
                duplicate_reports.append(
                    DuplicateResponseReport(
                        disposition=disposition,
                        reason=reason,
                        evidence=evidence_tuple,
                        conflict=conflict,
                    )
                )
            continue

        first_evidence = evidence_tuple[0]
        near_misses = _near_miss_hints(first_evidence.cert_id, issuer_index)
        if len(group) > 1:
            conflict = _detect_conflict(group)
            disposition = (
                ResponseDisposition.DUPLICATE_CONFLICT
                if conflict is not None
                else ResponseDisposition.DUPLICATE_CONSISTENT
            )
            reason = conflict or (
                '%d orphaned SingleResponses carry identical status' % len(group)
            )
        elif near_misses:
            disposition = ResponseDisposition.NEAR_MISS
            reason = 'no request carries this CertId; some issuer hashes partially match'
        else:
            disposition = ResponseDisposition.ORPHAN
            reason = 'no request carries this CertId and no issuer reproduces its hashes'

        for evidence in evidence_tuple:
            unmatched_reports.append(
                UnmatchedResponseReport(
                    index=evidence.index,
                    message_index=evidence.message_index,
                    disposition=disposition,
                    reason=reason,
                    evidence=evidence,
                    near_misses=near_misses,
                )
            )

    duplicate_reports.sort(
        key=lambda report: (
            report.evidence[0].message_index,
            report.evidence[0].index,
        )
    )
    unmatched_reports.sort(
        key=lambda report: (report.message_index, report.index)
    )

    return MatchReport(
        matched=tuple(matched_reports),
        ambiguous=tuple(ambiguous_reports),
        mismatched=tuple(mismatch_reports),
        missing=tuple(missing_reports),
        unsupported=tuple(unsupported_reports),
        invalid_parameters=tuple(invalid_parameter_reports),
        duplicate_responses=tuple(duplicate_reports),
        unmatched_responses=tuple(unmatched_reports),
        non_successful_responses=tuple(non_successful),
        requests=tuple(request_reports),
    )


def _detect_conflict(responses_tuple):
    seen = {}
    for _, evidence in responses_tuple:
        identity = _status_identity(evidence)
        seen.setdefault(identity, []).append(evidence)
    if len(seen) <= 1:
        return None
    summary = ', '.join(
        '%s (x%d)' % (identity[0], len(items)) for identity, items in seen.items()
    )
    return 'duplicate SingleResponses for the same CertId disagree on status: %s' % summary


def _sort_report(report, matched, ambiguous, mismatch, missing, unsupported, invalid):
    if report.status == MatchStatus.MATCHED:
        matched.append(report)
    elif report.status == MatchStatus.AMBIGUOUS:
        ambiguous.append(report)
    elif report.status == MatchStatus.MISMATCH:
        mismatch.append(report)
    elif report.status == MatchStatus.MISSING_RESPONSE:
        missing.append(report)
    elif report.status == MatchStatus.UNSUPPORTED_DIGEST:
        unsupported.append(report)
    elif report.status == MatchStatus.INVALID_ALGORITHM_PARAMETERS:
        invalid.append(report)
