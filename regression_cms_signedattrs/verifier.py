# coding: utf-8
"""
A minimal verification adapter that encodes the *rejection rules* a CMS
verifier must apply before (and independently of) cryptographic signature
verification.

The verification pipeline is split into three explicit stages:

1. Structural checks over SignedAttributes / UnsignedAttributes. These reject
   ambiguous or non-conformant encodings and never depend on the signer key.
2. Payload binding with locally computed digests. For an ordinary SignerInfo
   the message-digest attribute is compared against a digest of eContent. For a
   countersignature, which RFC 5652 forbids from carrying a message-digest
   attribute, the DigestInfo is recovered from the PKCS#1 signature and its
   digest is compared against a digest of the parent signature octets.
3. Cryptographic signature verification through a pluggable backend. In this
   offline suite the backend is the test-only PKCS#1 v1.5 code in builder.py.

Parsing an object successfully is NOT treated as a valid signature. A clean
parse only means the bytes are well-formed ASN.1; acceptance additionally
requires zero structural findings, a matching digest binding and a passing
signature backend.

Attribute handling never flattens the SET OF into a dict keyed by attrType,
because that would erase the duplicate attrType occurrences these rules exist
to detect. `index_attributes` keeps an ordered list plus an oid -> [occurrences]
multimap.
"""
from __future__ import unicode_literals, division, absolute_import, print_function

from collections import OrderedDict

import os as _os
import sys as _sys

_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))

import builder

# Stable finding codes; the strings are meant for regression diffing, not UI.
DUP_ATTR_TYPE = 'duplicate_attr_type'
MULTI_VALUE_ATTR = 'multi_value_attribute'
MISSING_REQUIRED_ATTR = 'missing_required_attribute'
CONTENT_TYPE_MISMATCH = 'content_type_econtent_type_mismatch'
DIGEST_MISMATCH = 'message_digest_payload_mismatch'
COUNTER_FORBIDDEN_SIGNED_ATTR = 'countersigner_forbidden_signed_attr'
COUNTER_NOT_UNSIGNED = 'countersignature_must_be_unsigned'

# RFC 5652 11.3: a SignerInfo MUST NOT include duplicate attribute types. The
# countersignature attribute (11.4) is the explicit exception on unsignedAttrs.
RESTRICTED_SINGLE_OCCURRENCE = {
    builder.OID_CONTENT_TYPE,
    builder.OID_MESSAGE_DIGEST,
    builder.OID_SIGNING_TIME,
}

# RFC 5652 11.2: content-type and message-digest each carry exactly one value.
SINGLE_VALUE_TYPES = {
    builder.OID_CONTENT_TYPE,
    builder.OID_MESSAGE_DIGEST,
}

# RFC 5652 11.4: a countersigner's SignedAttributes exclude both attributes.
COUNTERSIGNER_FORBIDDEN = {
    builder.OID_CONTENT_TYPE,
    builder.OID_MESSAGE_DIGEST,
}

# asn1crypto resolves the CMSAttributeType OID map to short names on .native
# (e.g. 'content_type'), so comparisons normalize both spellings to dotted OIDs.
_ATTR_NAME_TO_OID = {
    'content_type': builder.OID_CONTENT_TYPE,
    'message_digest': builder.OID_MESSAGE_DIGEST,
    'signing_time': builder.OID_SIGNING_TIME,
    'counter_signature': builder.OID_COUNTER_SIGNATURE,
}


def _normalize_oid(value):
    if value in _ATTR_NAME_TO_OID:
        return _ATTR_NAME_TO_OID[value]
    return value


class Finding(object):
    def __init__(self, code, location, detail):
        self.code = code
        self.location = location
        self.detail = detail

    def as_dict(self):
        return OrderedDict([('code', self.code), ('location', self.location), ('detail', self.detail)])

    def __repr__(self):
        return 'Finding(%s @ %s: %s)' % (self.code, self.location, self.detail)


class VerificationResult(object):
    def __init__(self, status, findings, digest_ok, signature_status, location='signerInfo'):
        self.status = status
        self.findings = findings
        self.digest_ok = digest_ok
        self.signature_status = signature_status
        self.location = location
        self.countersignature_results = []

    @property
    def accepted(self):
        return self.status == 'accepted'

    def as_dict(self):
        return OrderedDict([
            ('status', self.status),
            ('location', self.location),
            ('findings', [finding.as_dict() for finding in self.findings]),
            ('digest_binding_ok', self.digest_ok),
            ('signature_status', self.signature_status),
            ('countersignatures', [result.as_dict() for result in self.countersignature_results]),
        ])


def index_attributes(attributes):
    """
    Index an attribute SET without flattening duplicates.

    Returns (ordered, occurrences):
      ordered     -> list of (index, oid, attribute) preserving SET order
      occurrences -> OrderedDict oid -> list of attribute occurrences
    A dict comprehension over `.native` would collapse duplicate attrTypes;
    this function deliberately does not.
    """
    ordered = []
    occurrences = OrderedDict()
    if attributes is None:
        return ordered, occurrences
    for index in range(len(attributes)):
        attribute = attributes[index]  # force lazy ASN.1 construction
        oid = _normalize_oid(attribute['type'].native)
        ordered.append((index, oid, attribute))
        occurrences.setdefault(oid, []).append(attribute)
    return ordered, occurrences


def _check_attribute_shape(occurrences, location, findings, allow_duplicate_oids=()):
    """Duplicate attrType and multi-valued single-value attribute checks."""
    allowed_duplicates = set(allow_duplicate_oids)
    for oid, attrs in occurrences.items():
        if len(attrs) > 1 and oid in RESTRICTED_SINGLE_OCCURRENCE and oid not in allowed_duplicates:
            findings.append(Finding(
                DUP_ATTR_TYPE, location,
                'attrType %s appears %d times; RFC 5652 11.3 forbids duplicates' % (oid, len(attrs)),
            ))
        for attribute in attrs:
            value_count = len(attribute['values'])
            if value_count > 1 and oid in SINGLE_VALUE_TYPES:
                findings.append(Finding(
                    MULTI_VALUE_ATTR, location,
                    'attrType %s has %d attribute values; exactly one is required' % (oid, value_count),
                ))


def _check_outer_signer(signer_info, econtent_type, findings):
    """RFC 5652 5.3 structural rules for an ordinary SignerInfo."""
    location = 'signerInfo'
    signed_attrs = signer_info['signed_attrs']
    if signed_attrs is None or len(signed_attrs) == 0:
        # RFC 5652 allows absent SignedAttributes; nothing structural to reject.
        return None, None

    _, occurrences = index_attributes(signed_attrs)
    _check_attribute_shape(occurrences, location, findings)

    content_type_attrs = occurrences.get(builder.OID_CONTENT_TYPE, [])
    if not content_type_attrs:
        findings.append(Finding(MISSING_REQUIRED_ATTR, location, 'signedAttrs lacks content-type'))
    elif len(content_type_attrs[0]['values']) == 1:
        signed_content_type = content_type_attrs[0]['values'][0].native
        if signed_content_type != econtent_type:
            findings.append(Finding(
                CONTENT_TYPE_MISMATCH, location,
                'signed content-type %s != encapContentInfo eContentType %s'
                % (signed_content_type, econtent_type),
            ))

    if builder.OID_MESSAGE_DIGEST not in occurrences:
        findings.append(Finding(MISSING_REQUIRED_ATTR, location, 'signedAttrs lacks message-digest'))

    if builder.OID_COUNTER_SIGNATURE in occurrences:
        findings.append(Finding(
            COUNTER_NOT_UNSIGNED, location,
            'countersignature is an unsigned attribute and cannot appear in signedAttrs (RFC 5652 11.4)',
        ))

    return content_type_attrs, occurrences.get(builder.OID_MESSAGE_DIGEST, [])


def _collect_countersigners(signer_info, findings):
    """
    Return every countersigner SignerInfo across (possibly multiple)
    countersignature unsigned attributes. Multiple countersignature attributes
    are explicitly permitted by RFC 5652 11.4 and must not be rejected.
    """
    location = 'signerInfo.unsignedAttrs'
    unsigned_attrs = signer_info['unsigned_attrs']
    if unsigned_attrs is None:
        return []
    _, occurrences = index_attributes(unsigned_attrs)
    _check_attribute_shape(
        occurrences, location, findings,
        allow_duplicate_oids=(builder.OID_COUNTER_SIGNATURE,),
    )
    countersigners = []
    for attribute in occurrences.get(builder.OID_COUNTER_SIGNATURE, []):
        for counter_signer_info in attribute['values']:
            countersigners.append(counter_signer_info)
    return countersigners


def _certs_by_serial(content_info):
    signed_data = content_info['content']
    by_serial = {}
    certificates = signed_data['certificates']
    if certificates is not None:
        for choice in certificates:
            if choice.name == 'certificate':
                cert = choice.chosen
                by_serial[cert['tbs_certificate']['serial_number'].native] = cert
    return by_serial


def verify_signer_info(content_info, signer_info, cert_index, signature_backend, location='signerInfo'):
    """
    Verify one ordinary SignerInfo. Structural rejection is decided before any
    digest or signature work, so ambiguous attributes can never influence which
    value a later stage happens to pick.
    """
    findings = []
    signed_data = content_info['content']
    econtent_info = signed_data['encap_content_info']
    econtent_type = econtent_info['content_type'].native
    econtent = econtent_info['content'].native if econtent_info['content'] is not None else b''
    digest_oid = signer_info['digest_algorithm']['algorithm'].native

    _, message_digest_attrs = _check_outer_signer(signer_info, econtent_type, findings)
    countersigners = _collect_countersigners(signer_info, findings)

    # Local digest binding: eContent -> message-digest attribute, only when the
    # attribute is present exactly once with exactly one value.
    digest_ok = None
    if message_digest_attrs and len(message_digest_attrs) == 1 \
            and len(message_digest_attrs[0]['values']) == 1:
        expected_digest = builder.digest(digest_oid, econtent)
        digest_ok = (message_digest_attrs[0]['values'][0].native == expected_digest)
        if digest_ok is False:
            findings.append(Finding(
                DIGEST_MISMATCH, 'signerInfo',
                'message-digest does not match local digest of eContent',
            ))

    if findings:
        result = VerificationResult('rejected_structure', findings, digest_ok, 'not_attempted', location)
    else:
        signature_status = _verify_outer_signature(
            signer_info, cert_index, signature_backend, econtent)
        result = VerificationResult(
            'accepted' if signature_status == 'valid' else 'rejected_signature',
            findings, digest_ok, signature_status, location,
        )

    for index, counter_signer_info in enumerate(countersigners):
        result.countersignature_results.append(
            verify_countersigner(signer_info, counter_signer_info, cert_index, index))
    return result


def verify_countersigner(parent_signer_info, counter_signer_info, cert_index, counter_index):
    """
    Verify a countersignature SignerInfo per RFC 5652 11.4. The digest binding
    target is the parent signature value octets, not eContent, and the
    countersigner must not carry content-type or message-digest attributes.
    """
    location = 'countersigner[%d]' % counter_index
    findings = []
    digest_oid = counter_signer_info['digest_algorithm']['algorithm'].native
    parent_signature_octets = parent_signer_info['signature'].native

    signed_attrs = counter_signer_info['signed_attrs']
    if signed_attrs is not None and len(signed_attrs) > 0:
        _, occurrences = index_attributes(signed_attrs)
        _check_attribute_shape(occurrences, location, findings)
        for forbidden in COUNTERSIGNER_FORBIDDEN:
            if forbidden in occurrences:
                findings.append(Finding(
                    COUNTER_FORBIDDEN_SIGNED_ATTR, location,
                    'countersignature signedAttrs must not include %s (RFC 5652 11.4)' % forbidden,
                ))

    if findings:
        return VerificationResult('rejected_structure', findings, None, 'not_attempted', location)

    # Structural layer clean: verify the signature and bind the digest recovered
    # from the PKCS#1 DigestInfo to the parent signature octets.
    cert = _cert_for_signer(counter_signer_info, cert_index)
    if cert is None:
        return VerificationResult('rejected_signature', findings, None, 'no_certificate', location)
    public_key = cert['tbs_certificate']['subject_public_key_info']['public_key'].parsed

    signed_attrs = counter_signer_info['signed_attrs']
    if signed_attrs is not None and len(signed_attrs) > 0:
        signed_input = builder.signed_attrs_der_for_signing(signed_attrs)
    else:
        signed_input = parent_signature_octets

    signature = counter_signer_info['signature'].native
    try:
        recovered_oid, recovered_digest = builder.rsa_pkcs1v15_recover_digest(public_key, signature)
    except builder.BadSignatureError:
        return VerificationResult('rejected_signature', findings, False, 'invalid', location)

    # Local binding first: the digest recovered from the signature must equal a
    # fresh digest of the parent signature octets. This catches a signature that
    # is crypto-valid but was computed over the wrong input.
    expected_parent_digest = builder.digest(digest_oid, parent_signature_octets)
    digest_ok = (recovered_oid in (digest_oid, 'sha256') and recovered_digest == expected_parent_digest)
    if not digest_ok:
        findings.append(Finding(
            DIGEST_MISMATCH, location,
            'digest recovered from countersignature does not match digest of parent signature octets',
        ))

    signature_valid = builder.rsa_pkcs1v15_verify(public_key, digest_oid, signed_input, signature)
    signature_status = 'valid' if signature_valid else 'invalid'
    if not digest_ok or not signature_valid:
        # Structure was conformant; this is a binding/signature failure.
        return VerificationResult('rejected_signature', findings, digest_ok, signature_status, location)
    return VerificationResult('accepted', findings, True, 'valid', location)


def _cert_for_signer(signer_info, cert_index):
    sid = signer_info['sid']
    if sid.name == 'issuer_and_serial_number':
        return cert_index.get(sid.chosen['serial_number'].native)
    return None


def _verify_outer_signature(signer_info, cert_index, signature_backend, econtent):
    cert = _cert_for_signer(signer_info, cert_index)
    if cert is None:
        return 'no_certificate'
    public_key = cert['tbs_certificate']['subject_public_key_info']['public_key'].parsed
    signed_attrs = signer_info['signed_attrs']
    if signed_attrs is not None and len(signed_attrs) > 0:
        signed_input = builder.signed_attrs_der_for_signing(signed_attrs)
    else:
        signed_input = econtent
    valid = signature_backend(
        public_key, signer_info['digest_algorithm']['algorithm'].native,
        signed_input, signer_info['signature'].native,
    )
    return 'valid' if valid else 'invalid'


def verify_content_info(content_info, signature_backend=None):
    """Entry point: verify every SignerInfo in a signedData ContentInfo."""
    if signature_backend is None:
        signature_backend = builder.rsa_pkcs1v15_verify
    if content_info['content_type'].native != 'signed_data':
        raise ValueError('adapter only handles signedData ContentInfo')
    cert_index = _certs_by_serial(content_info)
    signed_data = content_info['content']
    return [
        verify_signer_info(content_info, signer_info, cert_index, signature_backend)
        for signer_info in signed_data['signer_infos']
    ]
