# coding: utf-8
"""
Contract tests for the strict CSR extension extractor against the generated
ambiguous samples and the repository's own real-world fixtures.

Run from the repository root:
    pytest samples/csr_extension_audit/test_extraction_contract.py -v
or:
    python -m pytest samples/csr_extension_audit -v
"""
from __future__ import unicode_literals

import os

import pytest

from asn1crypto import csr

from strict_extraction import AmbiguousRequest, extract_csr_extensions

HERE = os.path.dirname(os.path.abspath(__file__))
GENERATED = os.path.join(HERE, 'generated')
REPO_FIXTURES = os.path.join(HERE, '..', '..', 'tests', 'fixtures')

SAMPLES = [
    ('01_baseline_wellformed', 'accept'),
    ('02_dup_attribute', 'reject'),
    ('03_multi_value', 'reject'),
    ('04_dup_extnid', 'reject'),
    ('05_ms_and_standard', 'accept'),
    ('06_unknown_critical', 'accept'),
]


def _load_der(name):
    with open(os.path.join(GENERATED, name + '.der'), 'rb') as f:
        return csr.CertificationRequest.load(f.read())


@pytest.mark.parametrize('name,outcome', SAMPLES)
def test_ambiguity_outcomes(name, outcome):
    request = _load_der(name)
    if outcome == 'reject':
        with pytest.raises(AmbiguousRequest):
            extract_csr_extensions(request)
    else:
        result = extract_csr_extensions(request)
        assert result['extension_request_count'] == 1
        assert result['value_count'] == 1
        oids = [ext['extn_id'] for ext in result['extensions']]
        assert len(oids) == len(set(oids))


def test_baseline_provenance_fields():
    result = extract_csr_extensions(_load_der('01_baseline_wellformed'))
    by_name = {ext['extn_name']: ext for ext in result['extensions']}
    bc = by_name['basic_constraints']
    assert bc['critical'] is True
    assert bc['parsed']['ca'].native is False
    san = by_name['subject_alt_name']
    assert san['critical'] is False
    assert san['parsed'][0].native == 'baseline.example'
    assert isinstance(bc['raw_extn_value'], bytes) and bc['raw_extn_value']


def test_microsoft_attributes_are_separate_from_extensions():
    result = extract_csr_extensions(_load_der('05_ms_and_standard'))
    other_oids = {item['attr_oid'] for item in result['other_attributes']}
    assert other_oids == {
        '1.3.6.1.4.1.311.13.2.3',
        '1.3.6.1.4.1.311.21.20',
        '1.3.6.1.4.1.311.13.2.2',
    }
    ext_oids = {ext['extn_id'] for ext in result['extensions']}
    assert '1.3.6.1.4.1.311.20.2' in ext_oids
    # Applicant claims CA=true and a critical SAN; the extractor reports the
    # claim, it must never itself authorize either one.
    bc = next(e for e in result['extensions'] if e['extn_name'] == 'basic_constraints')
    assert bc['parsed']['ca'].native is True
    san = next(e for e in result['extensions'] if e['extn_name'] == 'subject_alt_name')
    assert san['critical'] is True


def test_unknown_critical_extension_kept_without_semantics():
    result = extract_csr_extensions(_load_der('06_unknown_critical'))
    unknown = next(e for e in result['extensions'] if e['extn_id'] == '1.3.6.1.4.1.99999.7.1')
    assert unknown['extn_name'] is None
    assert unknown['critical'] is True
    assert unknown['parsed'] is None
    assert unknown['raw_extn_value'] == b'\x30\x03\x02\x01\x2a'


def test_accepts_pem_and_der_bytes():
    pem_path = os.path.join(GENERATED, '01_baseline_wellformed.pem')
    with open(pem_path, 'rb') as f:
        pem_bytes = f.read()
    assert extract_csr_extensions(pem_bytes)['extension_request_count'] == 1
    with open(os.path.join(GENERATED, '01_baseline_wellformed.der'), 'rb') as f:
        der_bytes = f.read()
    assert extract_csr_extensions(der_bytes)['extension_request_count'] == 1


def test_repo_fixture_without_attributes():
    path = os.path.join(REPO_FIXTURES, 'test-inter-der.csr')
    with open(path, 'rb') as f:
        request = csr.CertificationRequest.load(f.read())
    result = extract_csr_extensions(request)
    assert result == {
        'extension_request_count': 0,
        'value_count': 0,
        'other_attributes': [],
        'extensions': [],
    }


def test_repo_fixture_windows_host_shape():
    path = os.path.join(REPO_FIXTURES, 'test-windows-host.csr')
    with open(path, 'rb') as f:
        request = csr.CertificationRequest.load(f.read())
    result = extract_csr_extensions(request)
    assert result['extension_request_count'] == 1
    assert len(result['other_attributes']) == 3
    assert len(result['extensions']) == 4
    assert {e['extn_id'] for e in result['extensions']} == {
        '1.3.6.1.4.1.311.20.2',
        '2.5.29.37',
        '2.5.29.15',
        '2.5.29.14',
    }


def test_duplicate_attributes_message_names_count():
    with pytest.raises(AmbiguousRequest, match='2 extensionRequest attributes'):
        extract_csr_extensions(_load_der('02_dup_attribute'))


from issuing_policy_skeleton import LeafCertificatePolicy, PolicyDenial  # noqa: E402


@pytest.mark.parametrize('name', [
    '02_dup_attribute',
    '03_multi_value',
    '04_dup_extnid',
    '05_ms_and_standard',
    '06_unknown_critical',
])
def test_policy_denies_conflict_and_privilege_claims(name):
    policy = LeafCertificatePolicy()
    with pytest.raises(PolicyDenial):
        policy.review(_load_der(name))


def test_policy_issues_only_for_baseline_and_overrides_san_criticality():
    policy = LeafCertificatePolicy()
    decision = policy.review(_load_der('01_baseline_wellformed'))
    issued = {item['oid']: item for item in decision['issued_extensions']}
    assert issued['2.5.29.19']['value'] == {'ca': False}
    assert issued['2.5.29.17']['critical'] is False
    assert decision['ignored_metadata_attributes'] == []
