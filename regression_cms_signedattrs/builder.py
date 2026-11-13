# coding: utf-8
"""
Offline builders for CMS SignedData regression material.

Everything here is constructed with asn1crypto at the ASN.1 level so that
"confusing" SignedAttributes (duplicate attrType occurrences, multi-valued
attributes, mismatched content types, malformed countersignatures) survive
encoding and round trips. In particular nothing is ever flattened through a
Python dict, because a dict keyed by attrType would silently erase the
duplicate occurrences that these fixtures exist to exercise.

The RSA/PKCS#1 v1.5 primitives in this module are deliberately tiny and
test-only. They exist so the fixtures carry real, locally verifiable
signatures without requiring a third-party crypto backend. Production
verifiers must use a vetted crypto library, not this code.
"""
from __future__ import unicode_literals, division, absolute_import, print_function

import hashlib
import os

from asn1crypto import algos, cms, core, keys, pem, x509

OID_CONTENT_TYPE = '1.2.840.113549.1.9.3'
OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4'
OID_SIGNING_TIME = '1.2.840.113549.1.9.5'
OID_COUNTER_SIGNATURE = '1.2.840.113549.1.9.6'

OID_DATA = '1.2.840.113549.1.7.1'
OID_TST_INFO = '1.2.840.113549.1.9.16.1.4'

FIXTURES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fixtures')


class BadSignatureError(Exception):
    """Raised when a public-key operation does not yield a valid PKCS#1 block."""

DIGEST_NAME_BY_OID = {
    '2.16.840.1.101.3.4.2.1': 'sha256',
}

# asn1crypto maps the SHA-256 OID to the short name 'sha256' on .native in
# several specs; accept either form at every crypto entry point.
_DIGEST_ALIASES = {
    '2.16.840.1.101.3.4.2.1': 'sha256',
    'sha256': 'sha256',
}


def _digest_name(digest_oid):
    try:
        return _DIGEST_ALIASES[digest_oid]
    except KeyError:
        raise ValueError('unsupported digest algorithm: %s' % digest_oid)


def load_cert(label):
    """Load a DER certificate from the fixtures directory by logical name."""
    path = os.path.join(FIXTURES_DIR, '%s_cert.der' % label)
    with open(path, 'rb') as handle:
        return x509.Certificate.load(handle.read())


def load_private_key(label):
    """Load an RSA private key (PKCS#8 PEM) from the fixtures directory."""
    path = os.path.join(FIXTURES_DIR, '%s_key.pem' % label)
    with open(path, 'rb') as handle:
        _, _, der_bytes = pem.unarmor(handle.read())
    private_key_info = keys.PrivateKeyInfo.load(der_bytes)
    return private_key_info['private_key'].parsed.native


def cert_sid(cert):
    """Build an issuerAndSerialNumber SignerIdentifier for a certificate."""
    return cms.SignerIdentifier({
        'issuer_and_serial_number': {
            'issuer': cert.issuer,
            'serial_number': cert.serial_number,
        },
    })


def attr(attr_type, values):
    """
    Build one CMSAttribute keeping the raw value SET. Values are passed as
    native Python values (OID strings, byte strings, Time tuples, ...) and
    are cast by asn1crypto according to the attrType OID spec.
    """
    return cms.CMSAttribute({'type': attr_type, 'values': values})


def content_type_attr(econtent_type):
    return attr(OID_CONTENT_TYPE, [econtent_type])


def message_digest_attr(digest_value):
    return attr(OID_MESSAGE_DIGEST, [digest_value])


def signing_time_attr(utc_time):
    # Time is a Choice; a timezone-aware datetime is wrapped as UTCTime.
    time_value = cms.Time({'utc_time': core.UTCTime(utc_time)})
    return attr(OID_SIGNING_TIME, [time_value])


def counter_signature_attr(signer_infos):
    """
    Build a countersignature unsigned attribute. Its value SET is defined by
    RFC 5652 as SignerInfos (a SET OF SignerInfo), which is also the spec
    asn1crypto binds to the counter_signature OID.
    """
    return attr(OID_COUNTER_SIGNATURE, list(signer_infos))


def digest(digest_oid, data):
    return hashlib.new(_digest_name(digest_oid), data).digest()


def signed_attrs_der_for_signing(signed_attrs):
    """
    Return the DER bytes that are actually signed for SignedAttributes.

    RFC 5652 5.4: SignedAttributes are encoded as an implicit [0] SET inside
    SignerInfo, but the signature is computed over the DER encoding of the
    SET using its universal tag (SET, 0x31). Only the leading tag byte
    changes; the length and contents stay identical.

    A standalone CMSAttributes object carries the universal SET tag, whereas
    the signed_attrs field of a SignerInfo is implicitly tagged [0]. Both
    shapes are accepted here and normalized to the universal-tag form.
    """
    encoded = signed_attrs.dump()
    if not encoded or encoded[0] not in (0x31, 0xA0):
        raise ValueError('expected a SET encoding (universal or implicit [0]) for signedAttrs')
    return b'\x31' + encoded[1:]


def rsa_pkcs1v15_sign(private_key, digest_oid, message):
    """Test-only RSASSA-PKCS1-v1_5 signature using only the standard library."""
    digest_value = hashlib.new(_digest_name(digest_oid), message).digest()
    encoded = _pkcs1_v1_5_encode(digest_oid, digest_value, private_key['modulus'].bit_length())
    message_int = _int_from_bytes(encoded)
    signature_int = pow(message_int, private_key['private_exponent'], private_key['modulus'])
    return _int_to_bytes(signature_int, private_key['modulus'].bit_length())


def rsa_pkcs1v15_verify(public_key, digest_oid, message, signature):
    """Test-only PKCS#1 v1.5 verification; returns True only on a full match."""
    modulus = public_key['modulus'].native
    exponent = public_key['public_exponent'].native
    if len(signature) != _byte_size(modulus.bit_length()):
        return False
    signature_int = _int_from_bytes(signature)
    if signature_int >= modulus:
        return False
    message_int = pow(signature_int, exponent, modulus)
    encoded = _int_to_bytes(message_int, modulus.bit_length())
    digest_value = hashlib.new(_digest_name(digest_oid), message).digest()
    expected = _pkcs1_v1_5_encode(digest_oid, digest_value, modulus.bit_length())
    return _constant_time_eq(encoded, expected)


def rsa_pkcs1v15_recover_digest(public_key, signature):
    """
    Test-only helper: run the RSA public operation and parse the recovered
    EMSA-PKCS1-v1_5 DigestInfo, returning (digest_algorithm_oid, digest_bytes).

    This lets the adapter check *which data the signer actually digested*
    without a message-digest attribute, which is exactly the situation for a
    RFC 5652 countersignature (no message-digest attribute is permitted).
    """
    modulus = public_key['modulus'].native
    exponent = public_key['public_exponent'].native
    if len(signature) != _byte_size(modulus.bit_length()):
        raise BadSignatureError('signature length does not match modulus size')
    signature_int = _int_from_bytes(signature)
    if signature_int >= modulus:
        raise BadSignatureError('signature integer is not smaller than the modulus')
    message_int = pow(signature_int, exponent, modulus)
    encoded = _int_to_bytes(message_int, modulus.bit_length())
    if encoded[0:2] != b'\x00\x01':
        raise BadSignatureError('recovered EMSA is not a PKCS#1 v1.5 type 01 block')
    separator = encoded.find(b'\x00', 2)
    if separator < 0:
        raise BadSignatureError('malformed PKCS#1 padding: no DigestInfo separator')
    try:
        digest_info = algos.DigestInfo.load(encoded[separator + 1:])
    except ValueError as exc:
        raise BadSignatureError('recovered block does not contain a DigestInfo: %s' % exc)
    return (
        digest_info['digest_algorithm']['algorithm'].native,
        digest_info['digest'].native,
    )


def _pkcs1_v1_5_encode(digest_oid, digest_value, modulus_bits):
    # RFC 8017 9.2: EM = 0x00 || 0x01 || PS (0xFF) || 0x00 || T
    digest_info = algos.DigestInfo({
        'digest_algorithm': {'algorithm': digest_oid},
        'digest': digest_value,
    }).dump()
    key_size = _byte_size(modulus_bits)
    if key_size < len(digest_info) + 11:
        raise ValueError('RSA key too small for PKCS#1 v1.5 encoding')
    padding = b'\xff' * (key_size - len(digest_info) - 3)
    return b'\x00\x01' + padding + b'\x00' + digest_info


def _byte_size(modulus_bits):
    return (modulus_bits + 7) // 8


def _int_from_bytes(data):
    return int.from_bytes(data, 'big', signed=False)


def _int_to_bytes(value, modulus_bits):
    return value.to_bytes(_byte_size(modulus_bits), 'big', signed=False)


def _constant_time_eq(left, right):
    if len(left) != len(right):
        return False
    result = 0
    for left_byte, right_byte in zip(left, right):
        result |= left_byte ^ right_byte
    return result == 0


def build_signer_info(cert, digest_oid, signed_attrs, private_key, unsigned_attrs=None):
    """
    Assemble a SignerInfo and compute a real PKCS#1 v1.5 signature over the
    DER SignedAttributes (universal SET tag). The caller decides which
    attributes go in, including deliberately non-conformant ones.
    """
    signed_input = signed_attrs_der_for_signing(signed_attrs)
    signature = rsa_pkcs1v15_sign(private_key, digest_oid, signed_input)
    return cms.SignerInfo({
        'version': 'v1',
        'sid': cert_sid(cert),
        'digest_algorithm': {'algorithm': digest_oid},
        'signed_attrs': signed_attrs,
        'signature_algorithm': {'algorithm': 'rsassa_pkcs1v15'},
        'signature': signature,
        'unsigned_attrs': unsigned_attrs,
    })


def build_unsigned_only_signer_info(cert, digest_oid, econtent, private_key, unsigned_attrs=None):
    """SignerInfo without SignedAttributes: the signature covers eContent directly."""
    signature = rsa_pkcs1v15_sign(private_key, digest_oid, econtent)
    return cms.SignerInfo({
        'version': 'v1',
        'sid': cert_sid(cert),
        'digest_algorithm': {'algorithm': digest_oid},
        'signature_algorithm': {'algorithm': 'rsassa_pkcs1v15'},
        'signature': signature,
        'unsigned_attrs': unsigned_attrs,
    })


def build_signed_data(econtent, econtent_type, signer_infos, certs, digest_oids):
    """Wrap SignerInfos into a SignedData with an attached eContent octet string."""
    signed_data = cms.SignedData({
        'version': 'v1',
        'digest_algorithms': [{'algorithm': oid} for oid in digest_oids],
        'encap_content_info': {
            'content_type': econtent_type,
            'content': core.OctetString(econtent),
        },
        'certificates': [cms.CertificateChoices(('certificate', cert)) for cert in certs],
        'crls': None,
        'signer_infos': signer_infos,
    })
    return cms.ContentInfo({
        'content_type': 'signed_data',
        'content': signed_data,
    })


def standard_signed_attrs(digest_oid, econtent, econtent_type, signing_time=None):
    """The RFC 5652 conformant SignedAttributes for an ordinary SignerInfo."""
    values = [
        content_type_attr(econtent_type),
        message_digest_attr(digest(digest_oid, econtent)),
    ]
    if signing_time is not None:
        values.append(signing_time_attr(signing_time))
    return cms.CMSAttributes(values)
