# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import json
import os
import unittest

from asn1crypto import algos, cms, core, keys, pem, pkcs12, x509

from analysis import evidence
from analysis import sample_builder

_FIXTURES = os.path.join(os.path.dirname(__file__), 'fixtures', 'keys')
_SAMPLES = os.path.join(os.path.dirname(__file__), 'fixtures', 'pkcs12-evidence')


def _report(data):
    return evidence.analyze_pfx_bytes(data)


def _bag(report, path):
    for bag in report['bags']:
        if bag['path'] == path:
            return bag
    raise AssertionError('bag not found at %s' % path)


def _load_fixture_key(name):
    path = os.path.join(_FIXTURES, name)
    with open(path, 'rb') as handle:
        data = handle.read()
    if pem.detect(data):
        type_name, _, der_bytes = pem.unarmor(data)
        if type_name == 'RSA PRIVATE KEY':
            return keys.PrivateKeyInfo.wrap(keys.RSAPrivateKey.load(der_bytes), 'rsa')
        if type_name == 'EC PRIVATE KEY':
            return keys.PrivateKeyInfo.wrap(keys.ECPrivateKey.load(der_bytes), 'ec')
        return keys.PrivateKeyInfo.load(der_bytes)
    return keys.PrivateKeyInfo.load(data)


def _load_fixture_certificate(name):
    path = os.path.join(_FIXTURES, name)
    with open(path, 'rb') as handle:
        data = handle.read()
    der_bytes = pem.unarmor(data)[2] if pem.detect(data) else data
    return x509.Certificate.load(der_bytes)


def _candidate(report, key_id, certificate_id):
    for candidate in report['candidates']:
        if candidate['key_id'] == key_id and candidate['certificate_id'] == certificate_id:
            return candidate
    raise AssertionError('candidate not found')


class PKCS12EvidenceTests(unittest.TestCase):

    def test_committed_samples_match_generator(self):
        with open(os.path.join(_SAMPLES, 'name-collision.p12'), 'rb') as handle:
            self.assertEqual(sample_builder.build_name_collision(), handle.read())
        with open(os.path.join(_SAMPLES, 'missing-local-key-id.p12'), 'rb') as handle:
            self.assertEqual(sample_builder.build_missing_local_key_id(), handle.read())

    def test_name_collision_never_proves_pairing(self):
        with open(os.path.join(_SAMPLES, 'name-collision.p12'), 'rb') as handle:
            report = _report(handle.read())

        self.assertEqual(1, report['summary']['proof_pairs'])
        self.assertEqual(1, report['summary']['candidate_links'])
        self.assertEqual(1, report['summary']['metadata_conflicts'])

        key = _bag(report, 'auth_safe[0]/bag[0]')
        collision_cert = _bag(report, 'auth_safe[0]/bag[1]')
        matching_cert = _bag(report, 'auth_safe[0]/bag[2]')

        self.assertEqual(key['public_key_fingerprint'], matching_cert['public_key_fingerprint'])
        self.assertNotEqual(key['public_key_fingerprint'], collision_cert['public_key_fingerprint'])

        pair = report['pairs'][0]
        self.assertEqual([key['id']], pair['key_ids'])
        self.assertEqual([matching_cert['id']], pair['certificate_ids'])
        self.assertNotIn(collision_cert['id'], pair['certificate_ids'])
        self.assertEqual('match', pair['metadata']['local_key_id']['agreement'])

        candidate = _candidate(report, key['id'], collision_cert['id'])
        self.assertTrue(candidate['ambiguous'])
        self.assertTrue(candidate['fingerprint_conflict'])
        self.assertEqual('metadata-only', candidate['strength'])
        candidate_codes = set(warning['code'] for warning in candidate['warnings'])
        self.assertIn('fingerprints_differ', candidate_codes)

        conflict_codes = set(conflict['code'] for conflict in report['conflicts'])
        self.assertIn('friendly_name_collision', conflict_codes)

        orphan_paths = [orphan['path'] for orphan in report['orphans']]
        self.assertIn('auth_safe[0]/bag[1]', orphan_paths)
        self.assertEqual(1, len(orphan_paths))

    def test_missing_local_key_id_pairs_on_public_key(self):
        with open(os.path.join(_SAMPLES, 'missing-local-key-id.p12'), 'rb') as handle:
            report = _report(handle.read())

        self.assertEqual(1, report['summary']['proof_pairs'])
        self.assertEqual(1, report['summary']['pairs_missing_local_key_id'])
        self.assertEqual(0, report['summary']['candidate_links'])

        key = _bag(report, 'auth_safe[0]/bag[0]')
        cert = _bag(report, 'auth_safe[0]/bag[1]')
        self.assertEqual([], key['metadata']['local_key_ids'])
        self.assertEqual([], cert['metadata']['local_key_ids'])
        self.assertEqual(key['public_key_fingerprint'], cert['public_key_fingerprint'])

        pair = report['pairs'][0]
        self.assertEqual([key['id']], pair['key_ids'])
        self.assertEqual([cert['id']], pair['certificate_ids'])
        self.assertEqual('both_missing', pair['metadata']['local_key_id']['agreement'])
        warnings = set(warning['code'] for warning in pair['warnings'])
        self.assertIn('missing_local_key_id', warnings)
        self.assertTrue(pair['evidence']['spki_der_equal'])

    def test_nested_safe_contents_paths_are_preserved(self):
        outer = pkcs12.SafeContents([
            pkcs12.SafeBag({
                'bag_id': 'safe_contents',
                'bag_value': pkcs12.SafeContents([
                    sample_builder._certificate_bag('alpha', b'\xAA' * 20, 'Nested Name'),
                ]),
            }),
            sample_builder._key_bag('alpha', b'\xAA' * 20, 'Nested Name'),
        ])
        report = _report(sample_builder._pfx_from_contents(outer))

        self.assertEqual(1, report['summary']['containers'])
        self.assertEqual(3, report['summary']['bags'])
        self.assertEqual(2, report['summary']['leaf_bags'])
        container = _bag(report, 'auth_safe[0]/bag[0]')
        nested_cert = _bag(report, 'auth_safe[0]/bag[0]/contents/bag[0]')
        key = _bag(report, 'auth_safe[0]/bag[1]')
        self.assertEqual('safe_contents', container['kind'])
        self.assertEqual(0, container['depth'])
        self.assertEqual(1, nested_cert['depth'])
        self.assertEqual(container['id'], nested_cert['parent_id'])
        self.assertIsNone(key['parent_id'])
        self.assertEqual(1, container['child_count'])
        self.assertEqual(1, report['summary']['proof_pairs'])
        self.assertEqual(key['id'], report['pairs'][0]['key_ids'][0])
        self.assertEqual(nested_cert['id'], report['pairs'][0]['certificate_ids'][0])

    def test_duplicate_bags_are_reported(self):
        bag = sample_builder._key_bag('alpha', b'\xAA' * 20, 'Duplicate')
        report = _report(sample_builder._pfx_from_contents(
            pkcs12.SafeContents([bag, sample_builder._key_bag('alpha', b'\xAA' * 20, 'Duplicate')])
        ))
        self.assertEqual(1, report['summary']['duplicate_bag_groups'])
        conflict = [item for item in report['conflicts'] if item['code'] == 'duplicate_bag'][0]
        self.assertEqual(2, len(conflict['bag_ids']))
        for bag_report in report['bags']:
            codes = [warning['code'] for warning in bag_report['warnings']]
            self.assertIn('duplicate_bag', codes)

    def test_local_key_id_collision_marks_candidate_ambiguous(self):
        key = sample_builder._key_bag('alpha', b'\xAA' * 20, 'Collision')
        other_key = sample_builder._key_bag('beta', b'\xAA' * 20, 'Collision')
        cert = sample_builder._certificate_bag('beta', b'\xAA' * 20, 'Collision')
        report = _report(sample_builder._pfx_from_contents(
            pkcs12.SafeContents([key, other_key, cert])
        ))
        self.assertGreaterEqual(report['summary']['ambiguous_candidate_links'], 1)
        self.assertIn('local_key_id_collision', set(
            conflict['code'] for conflict in report['conflicts']
        ))
        for candidate in report['candidates']:
            if candidate['fingerprint_conflict']:
                self.assertTrue(candidate['ambiguous'])
                self.assertEqual('metadata-only', candidate['strength'])

    def test_encrypted_content_is_opaque(self):
        encrypted_info = cms.EncryptedData({
            'version': 'v0',
            'encrypted_content_info': cms.EncryptedContentInfo({
                'content_type': 'data',
                'content_encryption_algorithm': algos.EncryptionAlgorithm({
                    'algorithm': 'pkcs12_sha1_rc2_40',
                    'parameters': algos.Pbes1Params({'salt': b'01234567', 'iterations': 1024}),
                }),
                'encrypted_content': core.OctetString(b'\x00' * 16),
            }),
        })
        authenticated_safe = pkcs12.AuthenticatedSafe([
            cms.ContentInfo({'content_type': 'encrypted_data', 'content': encrypted_info}),
        ])
        pfx = pkcs12.Pfx({
            'version': 'v3',
            'auth_safe': cms.ContentInfo({
                'content_type': 'data',
                'content': core.OctetString(authenticated_safe.dump()),
            }),
        })
        report = _report(pfx.dump())
        self.assertEqual(0, report['summary']['proof_pairs'])
        self.assertFalse(report['summary']['decryption_attempted'])
        source = report['sources'][0]
        self.assertEqual('opaque', source['status'])
        self.assertEqual('encrypted_data', source['content_type'])

    def test_report_never_contains_private_components(self):
        report = _report(sample_builder.build_name_collision())
        text = json.dumps(report, sort_keys=True)
        for token in [
            '"private_exponent"',
            '"prime1"',
            '"prime2"',
            '"coefficient"',
            '"modulus"',
            '"exponent1"',
            '"exponent2"',
        ]:
            self.assertNotIn(token, text)
        self.assertFalse(report['summary']['private_key_bytes_exposed'])
        self.assertFalse(report['policy']['private_key_bytes_serialized'])

    def test_tampered_metadata_does_not_create_pair(self):
        report = _report(sample_builder.build_missing_local_key_id())
        pair = report['pairs'][0]
        self.assertEqual([], pair['metadata']['local_key_id']['key_values'])
        self.assertEqual([], pair['metadata']['local_key_id']['certificate_values'])
        self.assertTrue(pair['evidence']['spki_der_equal'])
        self.assertEqual('public_key_material_match', pair['evidence']['kind'])

    def test_mismatched_local_key_id_still_pairs_by_public_key(self):
        key = sample_builder._key_bag('alpha', b'\xAA' * 20, 'Mismatch')
        cert = sample_builder._certificate_bag('alpha', b'\xBB' * 20, 'Mismatch')
        report = _report(sample_builder._pfx_from_contents(pkcs12.SafeContents([key, cert])))
        self.assertEqual(1, report['summary']['proof_pairs'])
        pair = report['pairs'][0]
        self.assertEqual('mismatch', pair['metadata']['local_key_id']['agreement'])
        self.assertIn('local_key_id_mismatch', set(item['code'] for item in pair['warnings']))

    def test_repeated_attribute_is_reported_as_metadata_conflict(self):
        attr_one = pkcs12.Attribute({'type': 'local_key_id', 'values': [core.OctetString(b'\xAA' * 20)]})
        attr_two = pkcs12.Attribute({'type': 'local_key_id', 'values': [core.OctetString(b'\xBB' * 20)]})
        bag = pkcs12.SafeBag({
            'bag_id': 'key_bag',
            'bag_value': sample_builder._toy_private_key('alpha'),
            'bag_attributes': pkcs12.Attributes([attr_one, attr_two]),
        })
        report = _report(sample_builder._pfx_from_contents(pkcs12.SafeContents([bag])))
        codes = set(item['code'] for item in report['conflicts'])
        self.assertIn('repeated_local_key_id_attribute', codes)
        self.assertEqual(2, len(report['bags'][0]['metadata']['local_key_ids']))

    def test_real_fixture_key_types_pair_with_their_certificates(self):
        cases = [
            ('test-pkcs8.key', 'test.crt'),
            ('test-ec-named.key', 'test-ec-named.crt'),
            ('test-pkcs8-dsa.key', 'test-dsa.crt'),
        ]
        for key_path, cert_path in cases:
            private_key = _load_fixture_key(key_path)
            certificate = _load_fixture_certificate(cert_path)
            contents = pkcs12.SafeContents([
                sample_builder._key_bag_from_value(private_key, b'\x11' * 20),
                sample_builder._certificate_bag_from_value(certificate, b'\x11' * 20),
            ])
            report = _report(sample_builder._pfx_from_contents(contents))
            self.assertEqual(1, report['summary']['proof_pairs'], key_path)
            self.assertTrue(report['pairs'][0]['evidence']['spki_der_equal'], key_path)

    def test_analysis_is_deterministic(self):
        first = _report(sample_builder.build_name_collision())
        second = _report(sample_builder.build_name_collision())
        self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True))
