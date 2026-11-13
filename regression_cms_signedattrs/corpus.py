# coding: utf-8
"""
The regression corpus: valid baselines plus one-mutation counterexamples.

Each counterexample mutates exactly one structural element of a valid control
and is then re-signed so that the cryptographic signature over SignedAttributes
remains verifiable. This is important: the point of the material is that the
adapter rejects the structure BEFORE signature verification, proving the
rejection does not depend on a broken signature. Every negative case records
the expected rejection code and the id of its single-change legal control.
"""
from __future__ import unicode_literals, division, absolute_import, print_function

import datetime
import json
import os

import os as _os
import sys as _sys

_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))

from asn1crypto import cms

import builder

SHA256 = '2.16.840.1.101.3.4.2.1'
PAYLOAD = b'regression payload: CMS signedAttrs confusion (RFC 5652)'
SIGNING_TIME = datetime.datetime(2026, 11, 13, 8, 0, 0, tzinfo=datetime.timezone.utc)

GENERATED_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'generated')


def _valid_attrs():
    return builder.standard_signed_attrs(SHA256, PAYLOAD, builder.OID_DATA, SIGNING_TIME)


def _counter_signer_info_no_attrs(target_octets):
    """
    RFC 5652 11.4 countersignature without SignedAttributes: the signature is
    computed directly over the parent signature value octets.
    """
    countersigner_cert = builder.load_cert('countersigner')
    countersigner_key = builder.load_private_key('countersigner')
    return builder.build_unsigned_only_signer_info(
        countersigner_cert, SHA256, target_octets, countersigner_key,
    )


def _counter_signer_info_with_attrs(attrs):
    countersigner_cert = builder.load_cert('countersigner')
    countersigner_key = builder.load_private_key('countersigner')
    return builder.build_signer_info(
        countersigner_cert, SHA256, attrs, countersigner_key,
    )


def _valid_outer_signer(unsigned_attrs=None):
    cert = builder.load_cert('signer')
    private_key = builder.load_private_key('signer')
    return builder.build_signer_info(cert, SHA256, _valid_attrs(), private_key, unsigned_attrs)


def _wrap(signer_info, extra_certs=()):
    signer_cert = builder.load_cert('signer')
    certs = [signer_cert] + list(extra_certs)
    return builder.build_signed_data(PAYLOAD, builder.OID_DATA, [signer_info], certs, [SHA256])


def _wrap_with_counter(outer, counter_signer_info):
    unsigned = cms.CMSAttributes([builder.counter_signature_attr([counter_signer_info])])
    outer['unsigned_attrs'] = unsigned
    countersigner_cert = builder.load_cert('countersigner')
    return _wrap(outer, extra_certs=[countersigner_cert])


# ---------------------------------------------------------------------------
# Corpus definitions. Each builder returns (content_info, metadata dict).
# ---------------------------------------------------------------------------

def case_valid_baseline():
    signer_info = _valid_outer_signer()
    return _wrap(signer_info), {
        'id': 'valid_baseline',
        'kind': 'valid',
        'control_for': None,
        'description': 'Ordinary SignedData with content-type, message-digest and signing-time.',
        'expected_status': 'accepted',
        'expected_codes': [],
        'basis': 'RFC 5652 5.3/11.1: required attributes present once, single valued, bound to data.',
    }


def case_dup_content_type():
    attrs = _valid_attrs()
    attrs.append(builder.content_type_attr(builder.OID_DATA))  # one mutation: duplicate
    signer_info = _valid_outer_signer()
    signer_info['signed_attrs'] = attrs
    signer_info = _resign(signer_info)
    return _wrap(signer_info), {
        'id': 'dup_content_type',
        'kind': 'negative',
        'control_for': None,
        'legal_control': 'valid_baseline',
        'description': 'Two content-type attribute occurrences in signedAttrs.',
        'expected_status': 'rejected_structure',
        'expected_codes': ['duplicate_attr_type'],
        'basis': 'RFC 5652 11.3: SignedAttributes MUST NOT include duplicate attrType instances.',
        'single_change': 'append a second, identical content-type attribute to valid_baseline.',
    }


def case_dup_message_digest():
    attrs = _valid_attrs()
    attrs.append(builder.message_digest_attr(builder.digest(SHA256, PAYLOAD)))
    signer_info = _resign(_with_attrs(_valid_outer_signer(), attrs))
    return _wrap(signer_info), {
        'id': 'dup_message_digest',
        'kind': 'negative',
        'legal_control': 'valid_baseline',
        'description': 'Two message-digest attribute occurrences in signedAttrs.',
        'expected_status': 'rejected_structure',
        'expected_codes': ['duplicate_attr_type'],
        'basis': 'RFC 5652 11.3: duplicate attrType is forbidden; ambiguity over which digest binds.',
        'single_change': 'append a second, identical message-digest attribute to valid_baseline.',
    }


def case_multi_value_content_type():
    attrs = cms.CMSAttributes([
        builder.attr(builder.OID_CONTENT_TYPE, [builder.OID_DATA, builder.OID_DATA]),
        builder.message_digest_attr(builder.digest(SHA256, PAYLOAD)),
        builder.signing_time_attr(SIGNING_TIME),
    ])
    signer_info = _resign(_with_attrs(_valid_outer_signer(), attrs))
    return _wrap(signer_info), {
        'id': 'multi_value_content_type',
        'kind': 'negative',
        'legal_control': 'valid_baseline',
        'description': 'One content-type attribute carrying two values in its SET.',
        'expected_status': 'rejected_structure',
        'expected_codes': ['multi_value_attribute'],
        'basis': 'RFC 5652 11.2: content-type attribute has a single content-type value.',
        'single_change': 'put two OID values in the content-type value SET instead of one.',
    }


def case_multi_value_message_digest():
    attrs = cms.CMSAttributes([
        builder.content_type_attr(builder.OID_DATA),
        builder.attr(builder.OID_MESSAGE_DIGEST,
                     [builder.digest(SHA256, PAYLOAD), builder.digest(SHA256, PAYLOAD)]),
        builder.signing_time_attr(SIGNING_TIME),
    ])
    signer_info = _resign(_with_attrs(_valid_outer_signer(), attrs))
    return _wrap(signer_info), {
        'id': 'multi_value_message_digest',
        'kind': 'negative',
        'legal_control': 'valid_baseline',
        'description': 'One message-digest attribute carrying two octet-string values.',
        'expected_status': 'rejected_structure',
        'expected_codes': ['multi_value_attribute'],
        'basis': 'RFC 5652 11.2: message-digest attribute has a single Digest value.',
        'single_change': 'put two digest octet strings in the message-digest value SET.',
    }


def case_missing_content_type():
    attrs = cms.CMSAttributes([
        attribute for attribute in _valid_attrs()
        if attribute['type'].native not in ('content_type', builder.OID_CONTENT_TYPE)
    ])
    signer_info = _resign(_with_attrs(_valid_outer_signer(), attrs))
    return _wrap(signer_info), {
        'id': 'missing_content_type',
        'kind': 'negative',
        'legal_control': 'valid_baseline',
        'description': 'SignedAttributes present but the mandatory content-type attribute is removed.',
        'expected_status': 'rejected_structure',
        'expected_codes': ['missing_required_attribute'],
        'basis': 'RFC 5652 5.3: content-type is required when SignedAttributes is present.',
        'single_change': 'delete the single content-type attribute from valid_baseline.',
    }


def case_missing_message_digest():
    attrs = cms.CMSAttributes([
        attribute for attribute in _valid_attrs()
        if attribute['type'].native not in ('message_digest', builder.OID_MESSAGE_DIGEST)
    ])
    signer_info = _resign(_with_attrs(_valid_outer_signer(), attrs))
    return _wrap(signer_info), {
        'id': 'missing_message_digest',
        'kind': 'negative',
        'legal_control': 'valid_baseline',
        'description': 'SignedAttributes present but the mandatory message-digest attribute is removed.',
        'expected_status': 'rejected_structure',
        'expected_codes': ['missing_required_attribute'],
        'basis': 'RFC 5652 5.3: message-digest is required when SignedAttributes is present.',
        'single_change': 'delete the single message-digest attribute from valid_baseline.',
    }


def case_content_type_mismatch():
    attrs = builder.standard_signed_attrs(SHA256, PAYLOAD, builder.OID_TST_INFO, SIGNING_TIME)
    signer_info = _resign(_with_attrs(_valid_outer_signer(), attrs))
    # Outer encapContentInfo stays id-data; only the signed attribute lies.
    return _wrap(signer_info), {
        'id': 'content_type_mismatch',
        'kind': 'negative',
        'legal_control': 'valid_baseline',
        'description': 'signed content-type claims TSTInfo while eContentType is id-data.',
        'expected_status': 'rejected_structure',
        'expected_codes': ['content_type_econtent_type_mismatch'],
        'basis': 'RFC 5652 5.3: signed content-type MUST equal encapContentInfo eContentType.',
        'single_change': 'change only the signed content-type OID, leave encapContentInfo as data.',
    }


def case_digest_mismatch():
    attrs = builder.standard_signed_attrs(SHA256, PAYLOAD, builder.OID_DATA, SIGNING_TIME)
    # Flip one byte of the message-digest value; the signature over attrs stays intact.
    digest_attr = attrs[1]
    original = digest_attr['values'][0].native
    digest_attr['values'] = [original[:-1] + bytes([original[-1] ^ 0x01])]
    signer_info = _resign(_with_attrs(_valid_outer_signer(), attrs))
    return _wrap(signer_info), {
        'id': 'digest_mismatch',
        'kind': 'negative',
        'legal_control': 'valid_baseline',
        'description': 'message-digest does not match the digest of eContent.',
        'expected_status': 'rejected_structure',
        'expected_codes': ['message_digest_payload_mismatch'],
        'basis': 'RFC 5652 5.4: message-digest must be the digest of the encapsulated content.',
        'single_change': 'flip one byte of the message-digest value; payload is untouched.',
    }


def case_countersignature_in_signed_attrs():
    outer = _valid_outer_signer()
    counter = _counter_signer_info_no_attrs(outer['signature'].native)
    # One mutation: move the countersignature attribute into SignedAttributes.
    attrs = _valid_attrs()
    attrs.append(builder.counter_signature_attr([counter]))
    signer_info = _resign(_with_attrs(outer, attrs))
    return _wrap(signer_info, extra_certs=[builder.load_cert('countersigner')]), {
        'id': 'countersignature_in_signed_attrs',
        'kind': 'negative',
        'legal_control': 'valid_countersignature',
        'description': 'Countersignature attribute placed inside signedAttrs.',
        'expected_status': 'rejected_structure',
        'expected_codes': ['countersignature_must_be_unsigned'],
        'basis': 'RFC 5652 11.4: countersignature is an unsigned attribute of the SignerInfo.',
        'single_change': 'relocate the same countersignature attribute from unsigned to signed.',
    }


def case_dup_countersignature_attr():
    outer = _valid_outer_signer()
    parent_octets = outer['signature'].native
    counter_one = _counter_signer_info_no_attrs(parent_octets)
    counter_two = _counter_signer_info_no_attrs(parent_octets)
    # Two countersignature *attributes*: RFC 5652 11.4 explicitly permits more
    # than one, so this is a legal control that must NOT be rejected.
    unsigned = cms.CMSAttributes([
        builder.counter_signature_attr([counter_one]),
        builder.counter_signature_attr([counter_two]),
    ])
    outer['unsigned_attrs'] = unsigned
    return _wrap(outer, extra_certs=[builder.load_cert('countersigner')]), {
        'id': 'dup_countersignature_attr',
        'kind': 'valid',
        'description': 'Two countersignature unsigned attributes (allowed by RFC 5652 11.4).',
        'expected_status': 'accepted',
        'expected_codes': [],
        'basis': 'RFC 5652 11.4: multiple countersignature attributes are the exception to 11.3.',
        'control_purpose': 'guards against over-broad duplicate-attr rejection on countersignatures.',
    }


def case_countersigner_has_content_type():
    outer = _valid_outer_signer()
    bad_attrs = cms.CMSAttributes([
        builder.signing_time_attr(SIGNING_TIME),
        builder.content_type_attr(builder.OID_DATA),  # forbidden for countersigners
    ])
    counter = _counter_signer_info_with_attrs(bad_attrs)
    return _wrap_with_counter(outer, counter), {
        'id': 'countersigner_has_content_type',
        'kind': 'negative',
        'legal_control': 'valid_countersignature',
        'description': 'Countersigner SignedAttributes include a content-type attribute.',
        'expected_status': 'rejected_structure',
        'expected_codes': ['countersigner_forbidden_signed_attr'],
        'basis': 'RFC 5652 11.4: countersigner SignedAttributes exclude content-type.',
        'single_change': 'add a content-type attribute to the countersigner signedAttrs.',
    }


def case_countersigner_has_message_digest():
    outer = _valid_outer_signer()
    parent_digest = builder.digest(SHA256, outer['signature'].native)
    bad_attrs = cms.CMSAttributes([
        builder.signing_time_attr(SIGNING_TIME),
        builder.message_digest_attr(parent_digest),  # forbidden even if the value is right
    ])
    counter = _counter_signer_info_with_attrs(bad_attrs)
    return _wrap_with_counter(outer, counter), {
        'id': 'countersigner_has_message_digest',
        'kind': 'negative',
        'legal_control': 'valid_countersignature',
        'description': 'Countersigner SignedAttributes include a message-digest attribute.',
        'expected_status': 'rejected_structure',
        'expected_codes': ['countersigner_forbidden_signed_attr'],
        'basis': 'RFC 5652 11.4: countersigner SignedAttributes exclude message-digest.',
        'single_change': 'add a (correct) message-digest attribute to the countersigner signedAttrs.',
    }


def case_countersigner_binds_econtent():
    outer = _valid_outer_signer()
    # One mutation: the countersignature signature is over eContent instead of
    # the parent signature octets. There is no message-digest attribute, so the
    # only way to catch this is local digest binding via the recovered DigestInfo.
    counter = _counter_signer_info_no_attrs(PAYLOAD)
    return _wrap_with_counter(outer, counter), {
        'id': 'countersigner_binds_econtent',
        'kind': 'negative',
        'legal_control': 'valid_countersignature',
        'description': 'Countersignature signature digests eContent, not the parent signature.',
        'expected_status': 'rejected_signature',
        'expected_codes': ['message_digest_payload_mismatch'],
        'basis': ('RFC 5652 11.4: countersignature is computed over the parent '
                  'signature value; local digest binding rejects an otherwise '
                  'structurally valid SignerInfo.'),
        'single_change': 'sign the payload bytes instead of the parent signature octets.',
    }


def case_valid_countersignature():
    outer = _valid_outer_signer()
    counter = _counter_signer_info_no_attrs(outer['signature'].native)
    return _wrap_with_counter(outer, counter), {
        'id': 'valid_countersignature',
        'kind': 'valid',
        'description': 'Legal countersignature: unsigned, no content-type/message-digest, binds parent signature.',
        'expected_status': 'accepted',
        'expected_codes': [],
        'basis': 'RFC 5652 11.4: signature over the parent signature octets; digest recovered for binding.',
    }


def _with_attrs(signer_info, attrs):
    signer_info['signed_attrs'] = attrs
    return signer_info


def _resign(signer_info):
    """Recompute the signature after swapping SignedAttributes (same signer key)."""
    cert = builder.load_cert('signer')
    private_key = builder.load_private_key('signer')
    signed_input = builder.signed_attrs_der_for_signing(signer_info['signed_attrs'])
    signer_info['signature'] = builder.rsa_pkcs1v15_sign(
        private_key, SHA256, signed_input)
    return signer_info


CASE_BUILDERS = [
    case_valid_baseline,
    case_dup_content_type,
    case_dup_message_digest,
    case_multi_value_content_type,
    case_multi_value_message_digest,
    case_missing_content_type,
    case_missing_message_digest,
    case_content_type_mismatch,
    case_digest_mismatch,
    case_countersignature_in_signed_attrs,
    case_dup_countersignature_attr,
    case_countersigner_has_content_type,
    case_countersigner_has_message_digest,
    case_countersigner_binds_econtent,
    case_valid_countersignature,
]


def build_corpus():
    corpus = []
    for case_builder in CASE_BUILDERS:
        content_info, metadata = case_builder()
        metadata = dict(metadata)
        metadata['sha256_der'] = _hash_der(content_info)
        metadata['der_size'] = len(content_info.dump())
        corpus.append((content_info, metadata))
    return corpus


def _hash_der(content_info):
    import hashlib
    return hashlib.sha256(content_info.dump()).hexdigest()


def write_generated():
    if not os.path.exists(GENERATED_DIR):
        os.makedirs(GENERATED_DIR)
    manifest = []
    for content_info, metadata in build_corpus():
        der_path = os.path.join(GENERATED_DIR, metadata['id'] + '.der')
        with open(der_path, 'wb') as handle:
            handle.write(content_info.dump())
        entry = dict(metadata)
        entry['der_file'] = metadata['id'] + '.der'
        manifest.append(entry)
    with open(os.path.join(GENERATED_DIR, 'manifest.json'), 'w', encoding='utf-8') as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
    return manifest


if __name__ == '__main__':
    for entry in write_generated():
        print('%-42s %-18s %s' % (entry['id'], entry['kind'], entry['expected_status']))
