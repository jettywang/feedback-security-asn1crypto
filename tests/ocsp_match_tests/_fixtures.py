# coding: utf-8

"""
Builds a fully controlled OCSP test world without any third-party signing
library: OpenSSL CLI produces RSA keys and PKCS#1 v1.5 signatures, while
asn1crypto assembles the certificates and OCSP DER structures.

The cast of issuers is deliberately designed to defeat naive matching:

* ca_a and ca_b share the same distinguished name but hold different keys
  ("same name, different public key");
* ca_a_prime re-uses ca_a's public key under a brand new certificate
  ("same public key, re-issued issuer"), with a different issuer serial;
* every end-entity CertId is recomputed by the production code, and the test
  vectors below re-derive the same hashes with a separate, independent
  hashlib implementation.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import hashlib
import os
import shutil
import subprocess
import tempfile

from asn1crypto.algos import DigestAlgorithm, SignedDigestAlgorithm
from asn1crypto.core import (
    GeneralizedTime,
    Integer,
    Null,
    ObjectIdentifier,
    OctetBitString,
    OctetString,
    ParsableOctetString,
    Sequence,
)
from asn1crypto.keys import PublicKeyInfo
from asn1crypto.ocsp import (
    BasicOCSPResponse,
    CertId,
    CertStatus,
    OCSPRequest,
    OCSPResponse,
    OCSPResponseStatus,
    Request,
    Requests,
    ResponderId,
    ResponseBytes,
    ResponseData,
    ResponseType,
    Responses,
    SingleResponse,
    StatusGood,
    StatusUnknown,
    TBSRequest,
)
from asn1crypto.pem import unarmor
from asn1crypto.x509 import Certificate, Name, TbsCertificate, Time, Validity

SHA1_OID = '1.3.14.3.2.26'
SHA256_OID = '2.16.840.1.101.3.4.2.1'
SHA512_OID = '2.16.840.1.101.3.4.2.3'
SHA256_RSA_OID = '1.2.840.113549.1.1.11'
BASIC_OCSP_OID = '1.3.6.1.5.5.7.48.1.1'

_OPENSSL = shutil.which('openssl')


def openssl_available():
    return _OPENSSL is not None


class _RawDigestAlgorithm(Sequence):
    """DigestAlgorithm whose parameters are never coerced to NULL."""

    _fields = [
        ('algorithm', ObjectIdentifier),
        ('parameters', ObjectIdentifier),
    ]


class _NullDigestAlgorithm(Sequence):
    _fields = [
        ('algorithm', ObjectIdentifier),
        ('parameters', Null, {'optional': True}),
    ]


class _NullRawCertId(Sequence):
    _fields = [
        ('hash_algorithm', _NullDigestAlgorithm),
        ('issuer_name_hash', OctetString),
        ('issuer_key_hash', OctetString),
        ('serial_number', Integer),
    ]


class _RawCertId(Sequence):
    _fields = [
        ('hash_algorithm', _RawDigestAlgorithm),
        ('issuer_name_hash', OctetString),
        ('issuer_key_hash', OctetString),
        ('serial_number', Integer),
    ]


def _run(args, working_dir, input_bytes=None):
    proc = subprocess.run(
        [_OPENSSL] + args,
        cwd=working_dir,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return proc.stdout


def _generate_rsa_key(working_dir, label):
    key_pem = _run(
        ['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048'],
        working_dir,
    )
    key_path = os.path.join(working_dir, '%s.key' % label)
    with open(key_path, 'wb') as handle:
        handle.write(key_pem)
    return key_pem, key_path


class CertificateAuthority(object):
    def __init__(self, working_dir, common_name, serial, key_pem=None, label=None):
        self.working_dir = working_dir
        self.common_name = common_name
        self.serial = serial
        self.label = label or common_name
        self.key_path = os.path.join(working_dir, '%s.key' % self.label)
        if key_pem is None:
            self.key_pem = _generate_rsa_key(working_dir, self.label)[0]
        else:
            self.key_pem = key_pem
            with open(self.key_path, 'wb') as handle:
                handle.write(key_pem)
        public_pem = _run(['pkey', '-in', self.key_path, '-pubout'], working_dir)
        _, _, public_der = unarmor(public_pem)
        self.public_key_info = PublicKeyInfo.load(public_der)
        self.certificate = self._self_signed_certificate()

    def _self_signed_certificate(self):
        name = Name.build({
            'country_name': 'US',
            'organization_name': 'OCSP Match Test',
            'common_name': self.common_name,
        })
        tbs = TbsCertificate({
            'version': 'v3',
            'serial_number': self.serial,
            'signature': {'algorithm': 'sha256_rsa'},
            'issuer': name,
            'validity': Validity({
                'not_before': Time(name='general_time', value=_gt('2025-01-01T00:00:00')),
                'not_after': Time(name='general_time', value=_gt('2030-01-01T00:00:00')),
            }),
            'subject': name,
            'subject_public_key_info': self.public_key_info,
        })
        signature = self.sign_der(tbs.dump(), 'sha256')
        return Certificate({
            'tbs_certificate': tbs,
            'signature_algorithm': {'algorithm': 'sha256_rsa'},
            'signature_value': OctetBitString(signature),
        })

    def sign_der(self, der_bytes, digest='sha256'):
        """Return a raw PKCS#1 v1.5 signature over arbitrary DER."""

        in_path = os.path.join(self.working_dir, '%s.to_sign' % self.label)
        out_path = os.path.join(self.working_dir, '%s.signature' % self.label)
        with open(in_path, 'wb') as handle:
            handle.write(der_bytes)
        _run(
            [
                'dgst',
                '-%s' % digest,
                '-sign',
                self.key_path,
                '-out',
                out_path,
                in_path,
            ],
            self.working_dir,
        )
        with open(out_path, 'rb') as handle:
            return handle.read()


def independent_issuer_hashes(certificate, algorithm):
    """
    Independent reference implementation of the RFC 6960 hashes.

    This deliberately does not reuse any helper from the package under test:
    it walks the asn1crypto structures itself and feeds hashlib the exact
    boundaries (Name DER for the name hash, BIT STRING payload minus its
    unused-bits octet for the key hash).  Display-name and whole-SPKI hashes
    are computed too, so tests can prove they differ from the correct values.
    """

    tbs = certificate['tbs_certificate']
    name_der = tbs['subject'].dump()
    bit_string = tbs['subject_public_key_info']['public_key']
    unused_octet = bit_string.contents[0]
    key_payload = bit_string.contents[1:]
    assert bytes(bit_string) == key_payload
    assert unused_octet == 0
    return {
        'name_der': name_der,
        'key_payload': key_payload,
        'name_hash': hashlib.new(algorithm, name_der).digest(),
        'key_hash': hashlib.new(algorithm, key_payload).digest(),
        'whole_spki_hash': hashlib.new(algorithm, tbs['subject_public_key_info'].dump()).digest(),
        'display_name_hash': hashlib.new(
            algorithm, certificate.subject.human_friendly.encode('utf-8')
        ).digest(),
    }


def make_cert_id(issuer, serial, algorithm_oid=SHA256_OID, algorithm='sha256'):
    vectors = independent_issuer_hashes(issuer.certificate, algorithm)
    return CertId({
        'hash_algorithm': DigestAlgorithm({'algorithm': algorithm_oid}),
        'issuer_name_hash': vectors['name_hash'],
        'issuer_key_hash': vectors['key_hash'],
        'serial_number': serial,
    })


def make_raw_cert_id(algorithm_oid, parameters_oid, name_hash, key_hash, serial):
    """CertId with an illegal non-NULL algorithm parameter, raw DER only."""

    return _RawCertId({
        'hash_algorithm': {
            'algorithm': ObjectIdentifier(algorithm_oid),
            'parameters': ObjectIdentifier(parameters_oid),
        },
        'issuer_name_hash': name_hash,
        'issuer_key_hash': key_hash,
        'serial_number': serial,
    }).dump()


def make_raw_cert_id_with_null_parameters(algorithm_oid, name_hash, key_hash, serial):
    """CertId with legal NULL parameters but an arbitrary digest OID."""

    return _NullRawCertId({
        'hash_algorithm': {
            'algorithm': ObjectIdentifier(algorithm_oid),
            'parameters': Null(),
        },
        'issuer_name_hash': name_hash,
        'issuer_key_hash': key_hash,
        'serial_number': serial,
    }).dump()


def make_request(cert_id):
    request = Request({'req_cert': cert_id})
    return OCSPRequest({
        'tbs_request': TBSRequest({'request_list': Requests([request])}),
    })


def _gt(iso_value):
    return GeneralizedTime(iso_value.replace('-', '').replace(':', '').replace('T', '') + 'Z')


def make_single_response(cert_id, status, this_update, next_update=None,
                         revocation_time=None):
    if status == 'good':
        cert_status = CertStatus(('good', StatusGood()))
    elif status == 'unknown':
        cert_status = CertStatus(('unknown', StatusUnknown()))
    else:
        cert_status = CertStatus((
            'revoked',
            {'revocation_time': _gt(revocation_time)},
        ))
    fields = {
        'cert_id': cert_id,
        'cert_status': cert_status,
        'this_update': _gt(this_update),
    }
    if next_update is not None:
        fields['next_update'] = _gt(next_update)
    return SingleResponse(fields)


def make_ocsp_response(responder, single_responses, produced_at='2026-11-13T10:00:00'):
    response_data = ResponseData({
        'version': 'v1',
        'responder_id': ResponderId(('by_name', responder.certificate.subject)),
        'produced_at': _gt(produced_at),
        'responses': Responses(single_responses),
    })
    signature = responder.sign_der(response_data.dump(), 'sha256')
    basic = BasicOCSPResponse({
        'tbs_response_data': response_data,
        'signature_algorithm': SignedDigestAlgorithm({'algorithm': 'sha256_rsa'}),
        'signature': OctetBitString(signature),
        'certs': [responder.certificate],
    })
    return OCSPResponse({
        'response_status': OCSPResponseStatus('successful'),
        'response_bytes': ResponseBytes({
            'response_type': ResponseType(BASIC_OCSP_OID),
            'response': ParsableOctetString(basic.dump()),
        }),
    })


def make_error_response(status_name):
    return OCSPResponse({
        'response_status': OCSPResponseStatus(status_name),
    })


def build_world():
    """Create all CAs and return a dict of handles plus the temp directory."""

    working_dir = tempfile.mkdtemp(prefix='ocsp-match-fixtures-')
    try:
        ca_a = CertificateAuthority(working_dir, 'Shared Issuer CN', 1001, label='ca_a')
        ca_b = CertificateAuthority(working_dir, 'Shared Issuer CN', 2002, label='ca_b')
        ca_a_prime = CertificateAuthority(
            working_dir,
            'Shared Issuer CN',
            3003,
            key_pem=ca_a.key_pem,
            label='ca_a_prime',
        )
        ca_c = CertificateAuthority(working_dir, 'Other Issuer CN', 4004, label='ca_c')
    except Exception:
        shutil.rmtree(working_dir, ignore_errors=True)
        raise
    return {
        'working_dir': working_dir,
        'ca_a': ca_a,
        'ca_b': ca_b,
        'ca_a_prime': ca_a_prime,
        'ca_c': ca_c,
    }


def teardown_world(world):
    shutil.rmtree(world['working_dir'], ignore_errors=True)
