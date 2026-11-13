# coding: utf-8
"""In-memory DER CRL builder on asn1crypto types.

No real CA and no network: the outer signatureAlgorithm is set to a placeholder
and signature bytes are empty. Trust is injected into the engine through a
verifier callable, which lets the demo exercise both acceptance and rejection
paths without any private-key crypto (the composition logic is signature
algorithm agnostic).
"""

from __future__ import unicode_literals

from asn1crypto.algos import SignedDigestAlgorithm
from asn1crypto.core import OctetBitString, ParsableOctetString
from asn1crypto.crl import (
    CRLReason,
    CRLEntryExtension,
    CRLEntryExtensions,
    IssuingDistributionPoint,
    RevokedCertificate,
    RevokedCertificates,
    TBSCertListExtension,
    TBSCertListExtensions,
    TbsCertList,
    CertificateList,
)
from asn1crypto.x509 import (
    DistributionPointName,
    GeneralName,
    GeneralNames,
    Name,
    ReasonFlags,
    Time,
)

# Placeholder OID (1.3.6.1.4.1.0 = private arc) marking our unsigned test CRLs.
PLACEHOLDER_ALGO = '1.3.6.1.4.1.99999.1'


def _gt(text):
    # Accept 'YYYY-MM-DD HH:MM:SS' and emit ASN.1 GeneralizedTime 'YYYYMMDDHHMMSSZ'.
    if text.endswith('Z'):
        return text
    date_part, time_part = text.split(' ')
    return date_part.replace('-', '') + time_part.replace(':', '') + 'Z'


def dn(cn, o=None, ou=None):
    parts = {'common_name': cn}
    if o:
        parts['organization_name'] = o
    if ou:
        parts['organizational_unit_name'] = ou
    return Name.build(parts)


def directory_general_name(name_obj):
    return GeneralName(name='directory_name', value=name_obj)


def _entry_extension(ext_id, value, critical=False):
    return CRLEntryExtension({
        'extn_id': ext_id,
        'critical': critical,
        'extn_value': ParsableOctetString(value.dump()),
    })


def make_entry(serial, revocation_date, reason=None, cert_issuer=None):
    """revocation_date: 'YYYY-MM-DD HH:MM:00' string (GeneralizedTime).
    cert_issuer: an optional x509.Name; present -> certificateIssuer ext."""
    exts = []
    if reason is not None:
        exts.append(_entry_extension('crl_reason', CRLReason(reason)))
    if cert_issuer is not None:
        gn = GeneralNames([directory_general_name(cert_issuer)])
        exts.append(_entry_extension('certificate_issuer', gn))
    return RevokedCertificate({
        'user_certificate': serial,
        'revocation_date': Time(name='general_time', value=_gt(revocation_date)),
        'crl_entry_extensions': CRLEntryExtensions(exts),
    })


def _crl_ext(ext_id, value_bytes, critical=False):
    return TBSCertListExtension({
        'extn_id': ext_id,
        'critical': critical,
        'extn_value': ParsableOctetString(value_bytes),
    })


def build_idp(full_name_uri=None, indirect=False, only_user=False, only_ca=False,
              only_attr=False, only_some_reasons=None):
    kwargs = {
        'only_contains_user_certs': only_user,
        'only_contains_ca_certs': only_ca,
        'indirect_crl': indirect,
        'only_contains_attribute_certs': only_attr,
    }
    if full_name_uri is not None:
        gns = GeneralNames([
            GeneralName(name='uniform_resource_identifier', value=full_name_uri)
        ])
        kwargs['distribution_point'] = DistributionPointName(
            name='full_name', value=gns)
    if only_some_reasons is not None:
        kwargs['only_some_reasons'] = ReasonFlags(only_some_reasons)
    return IssuingDistributionPoint(kwargs)


def build_crl(issuer_name, this_update, next_update, entries, crl_number,
              base_crl_number=None, idp=None):
    crl_exts = []
    crl_exts.append(_crl_ext('crl_number',
                             _integer_der(crl_number)))
    if base_crl_number is not None:
        crl_exts.append(_crl_ext('delta_crl_indicator',
                                 _integer_der(base_crl_number), critical=True))
    if idp is not None:
        crl_exts.append(_crl_ext('issuing_distribution_point',
                                 idp.dump(), critical=True))

    tbs = TbsCertList({
        'version': 'v2',
        'signature': SignedDigestAlgorithm({'algorithm': PLACEHOLDER_ALGO}),
        'issuer': issuer_name,
        'this_update': Time(name='general_time', value=_gt(this_update)),
        'next_update': Time(name='general_time', value=_gt(next_update)),
        'revoked_certificates': RevokedCertificates(entries),
        'crl_extensions': TBSCertListExtensions(crl_exts),
    })
    return CertificateList({
        'tbs_cert_list': tbs,
        'signature_algorithm': SignedDigestAlgorithm({'algorithm': PLACEHOLDER_ALGO}),
        'signature': OctetBitString(b''),
    }).dump()


def _integer_der(value):
    from asn1crypto.core import Integer
    return Integer(value).dump()
