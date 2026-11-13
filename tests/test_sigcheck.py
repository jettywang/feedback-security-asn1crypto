# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import sys
import os

from asn1crypto import algos, keys, sigcheck, x509

from ._unittest_compat import patch

patch()

if sys.version_info < (3,):
    byte_cls = str
else:
    byte_cls = bytes


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


def _load_signed_algo(hex_string):
    if sys.version_info < (3,):
        der = hex_string.decode('hex')
    else:
        der = byte_cls.fromhex(hex_string)
    return algos.SignedDigestAlgorithm.load(der)


def _pss_signed_algo(hash_name='sha1', mgf_hash_name='sha1', salt_length=20,
                     trailer_field=1, include_params=True):
    if not include_params:
        return algos.SignedDigestAlgorithm({'algorithm': 'rsassa_pss'})
    return algos.SignedDigestAlgorithm({
        'algorithm': 'rsassa_pss',
        'parameters': {
            'hash_algorithm': {'algorithm': hash_name},
            'mask_gen_algorithm': {
                'algorithm': 'mgf1',
                'parameters': {'algorithm': mgf_hash_name},
            },
            'salt_length': salt_length,
            'trailer_field': trailer_field,
        },
    })


def _pss_public_key_algo(hash_name='sha256', salt_length=32,
                         include_params=True):
    if not include_params:
        return keys.PublicKeyAlgorithm({'algorithm': 'rsassa_pss'})
    return keys.PublicKeyAlgorithm({
        'algorithm': 'rsassa_pss',
        'parameters': {
            'hash_algorithm': {'algorithm': hash_name},
            'mask_gen_algorithm': {
                'algorithm': 'mgf1',
                'parameters': {'algorithm': hash_name},
            },
            'salt_length': salt_length,
        },
    })


def _build_certificate(inner_signature, outer_signature, public_key_algorithm):
    return x509.Certificate({
        'tbs_certificate': {
            'serial_number': 1,
            'signature': inner_signature,
            'issuer': x509.Name.build({'common_name': 'Test CA'}),
            'validity': {
                'not_before': {'utc_time': '260101000000Z'},
                'not_after': {'utc_time': '270101000000Z'},
            },
            'subject': x509.Name.build({'common_name': 'Test Subject'}),
            'subject_public_key_info': {
                'algorithm': public_key_algorithm,
                'public_key': {
                    'modulus': 0xC34F,
                    'public_exponent': 65537,
                },
            },
        },
        'signature_algorithm': outer_signature,
        'signature_value': b'\x01\x02\x03\x04',
    })


class SigcheckTests(unittest.TestCase):

    def test_equivalent_null_and_absent_parameters_bytes_differ(self):
        # sha256WithRSAEncryption with NULL parameters
        null_form = _load_signed_algo('300d06092a864886f70d01010b0500')
        # sha256WithRSAEncryption with absent parameters
        absent_form = _load_signed_algo('300b06092a864886f70d01010b')

        self.assertNotEqual(null_form.dump(), absent_form.dump())

        result = sigcheck.compare_algorithm_identifiers(null_form, absent_form)

        self.assertEqual(sigcheck.Verdict.CONSISTENT, result.verdict)
        self.assertTrue(result.consistent)
        self.assertTrue(result.bytes_differ)

    def test_equivalent_pss_explicit_defaults_bytes_differ(self):
        # rsassa_pss with explicitly encoded default parameters:
        # hash sha1 [0], salt_length 20 [2]
        explicit_form = _load_signed_algo(
            '301d06092a864886f70d01010a'
            '3010a009300706052b0e03021aa203020114'
        )
        # rsassa_pss with absent parameters (all defaults implied)
        absent_form = _pss_signed_algo(include_params=False)

        self.assertNotEqual(explicit_form.dump(), absent_form.dump())

        result = sigcheck.compare_algorithm_identifiers(
            explicit_form, absent_form,
            'tbs_certificate.signature', 'signature_algorithm'
        )

        self.assertEqual(sigcheck.Verdict.CONSISTENT, result.verdict)
        self.assertTrue(result.bytes_differ)

        paths = [field.field for field in result.fields]
        self.assertIn('parameters.hash_algorithm', paths)
        self.assertIn('parameters.mask_gen_algorithm', paths)
        self.assertIn('parameters.mask_gen_algorithm.parameters', paths)
        self.assertIn('parameters.salt_length', paths)
        self.assertIn('parameters.trailer_field', paths)
        for field in result.fields:
            self.assertEqual(sigcheck.Verdict.CONSISTENT, field.verdict)

    def test_same_oid_conflicting_pss_hash(self):
        left = _pss_signed_algo(hash_name='sha256', mgf_hash_name='sha256',
                                salt_length=32)
        right = _pss_signed_algo(hash_name='sha384', mgf_hash_name='sha384',
                                 salt_length=48)

        result = sigcheck.compare_algorithm_identifiers(left, right)

        self.assertEqual(sigcheck.Verdict.CONFLICT, result.verdict)
        self.assertFalse(result.consistent)

        by_field = {field.field: field for field in result.fields}
        self.assertEqual(
            sigcheck.Verdict.CONSISTENT, by_field['algorithm'].verdict
        )
        self.assertEqual(
            sigcheck.Verdict.CONFLICT,
            by_field['parameters.hash_algorithm'].verdict
        )
        self.assertEqual('sha256', by_field['parameters.hash_algorithm'].left)
        self.assertEqual('sha384', by_field['parameters.hash_algorithm'].right)
        self.assertEqual(
            sigcheck.Verdict.CONFLICT,
            by_field['parameters.mask_gen_algorithm.parameters'].verdict
        )
        self.assertEqual(
            sigcheck.Verdict.CONFLICT,
            by_field['parameters.salt_length'].verdict
        )
        self.assertEqual(32, by_field['parameters.salt_length'].left)
        self.assertEqual(48, by_field['parameters.salt_length'].right)

    def test_same_oid_conflicting_pss_salt_length_only(self):
        left = _pss_signed_algo(salt_length=20)
        right = _pss_signed_algo(salt_length=32)

        result = sigcheck.compare_algorithm_identifiers(left, right)

        self.assertEqual(sigcheck.Verdict.CONFLICT, result.verdict)
        by_field = {field.field: field for field in result.fields}
        self.assertEqual(
            sigcheck.Verdict.CONSISTENT,
            by_field['parameters.hash_algorithm'].verdict
        )
        self.assertEqual(
            sigcheck.Verdict.CONFLICT,
            by_field['parameters.salt_length'].verdict
        )

    def test_unknown_signature_algorithm_is_undecidable(self):
        unknown = _load_signed_algo('300706032a03040500')
        known = _load_signed_algo('300d06092a864886f70d01010b0500')

        result = sigcheck.compare_algorithm_identifiers(unknown, known)

        self.assertEqual(sigcheck.Verdict.UNDECIDABLE, result.verdict)
        self.assertFalse(result.consistent)
        self.assertEqual('algorithm', result.fields[0].field)
        self.assertEqual('1.2.3.4', result.fields[0].left)

    def test_unknown_pss_digest_is_undecidable(self):
        # rsassa_pss with hash_algorithm OID 1.2.3.4 (unknown digest)
        unknown_hash = _load_signed_algo(
            '301406092a864886f70d01010a'
            '3007a005300306012a'
        )
        known = _pss_signed_algo(include_params=False)

        result = sigcheck.compare_algorithm_identifiers(unknown_hash, known)

        self.assertEqual(sigcheck.Verdict.UNDECIDABLE, result.verdict)
        by_field = {field.field: field for field in result.fields}
        self.assertEqual(
            sigcheck.Verdict.UNDECIDABLE,
            by_field['parameters.hash_algorithm'].verdict
        )

    def test_key_constraints_stricter_conflict(self):
        # Key restricted to sha256/32, signature uses the defaults (sha1/20)
        signature = _pss_signed_algo(include_params=False)
        public_key = _pss_public_key_algo(hash_name='sha256', salt_length=32)

        result = sigcheck.check_pss_key_constraints(signature, public_key)

        self.assertEqual(sigcheck.Verdict.CONFLICT, result.verdict)
        by_field = {field.field: field for field in result.fields}
        hash_field = by_field['parameters.hash_algorithm']
        self.assertEqual(sigcheck.Verdict.CONFLICT, hash_field.verdict)
        self.assertEqual('sha1', hash_field.left)
        self.assertEqual('sha256', hash_field.right)
        self.assertIn('stricter', hash_field.reason)
        salt_field = by_field['parameters.salt_length']
        self.assertEqual(sigcheck.Verdict.CONFLICT, salt_field.verdict)
        self.assertIn('stricter', salt_field.reason)

    def test_key_constraints_satisfied(self):
        signature = _pss_signed_algo(hash_name='sha256',
                                     mgf_hash_name='sha256', salt_length=32)
        public_key = _pss_public_key_algo(hash_name='sha256', salt_length=32)

        result = sigcheck.check_pss_key_constraints(signature, public_key)

        self.assertEqual(sigcheck.Verdict.CONSISTENT, result.verdict)

    def test_key_constraints_absent_key_params(self):
        signature = _pss_signed_algo(hash_name='sha512',
                                     mgf_hash_name='sha512', salt_length=64)
        public_key = _pss_public_key_algo(include_params=False)

        result = sigcheck.check_pss_key_constraints(signature, public_key)

        self.assertEqual(sigcheck.Verdict.CONSISTENT, result.verdict)

    def test_key_constraints_plain_rsa_key(self):
        signature = _pss_signed_algo(include_params=False)
        public_key = keys.PublicKeyAlgorithm({'algorithm': 'rsa'})

        result = sigcheck.check_pss_key_constraints(signature, public_key)

        self.assertEqual(sigcheck.Verdict.CONSISTENT, result.verdict)

    def test_key_constraints_non_pss_signature_conflict(self):
        signature = algos.SignedDigestAlgorithm({'algorithm': 'sha256_rsa'})
        public_key = _pss_public_key_algo(include_params=False)

        result = sigcheck.check_pss_key_constraints(signature, public_key)

        self.assertEqual(sigcheck.Verdict.CONFLICT, result.verdict)
        self.assertEqual('algorithm', result.fields[0].field)

    def test_key_constraints_not_applicable_key(self):
        signature = _pss_signed_algo(include_params=False)
        public_key = keys.PublicKeyAlgorithm({'algorithm': 'ed25519'})

        result = sigcheck.check_pss_key_constraints(signature, public_key)

        self.assertEqual(sigcheck.Verdict.UNDECIDABLE, result.verdict)

    def test_certificate_inner_outer_equivalent_bytes_differ(self):
        inner = {
            'algorithm': 'rsassa_pss',
            'parameters': {
                'hash_algorithm': {'algorithm': 'sha1'},
                'mask_gen_algorithm': {
                    'algorithm': 'mgf1',
                    'parameters': {'algorithm': 'sha1'},
                },
                'salt_length': 20,
                'trailer_field': 1,
            },
        }
        outer = {'algorithm': 'rsassa_pss'}
        public_key = {
            'algorithm': 'rsassa_pss',
            'parameters': {
                'hash_algorithm': {'algorithm': 'sha1'},
                'mask_gen_algorithm': {
                    'algorithm': 'mgf1',
                    'parameters': {'algorithm': 'sha1'},
                },
                'salt_length': 20,
            },
        }
        cert = _build_certificate(inner, outer, public_key)

        check = sigcheck.check_certificate_signature_consistency(cert)

        self.assertEqual(sigcheck.Verdict.CONSISTENT, check.verdict)
        self.assertTrue(check.consistent)
        self.assertEqual(
            sigcheck.Verdict.CONSISTENT, check.inner_outer.verdict
        )
        self.assertEqual(
            sigcheck.Verdict.CONSISTENT, check.key_constraints.verdict
        )
        self.assertTrue(check.inner_outer.bytes_differ)

        explanation = check.explain()
        self.assertIn('tbs_certificate.signature', explanation)
        self.assertIn('parameters.hash_algorithm', explanation)
        self.assertIn('parameters.salt_length', explanation)
        self.assertIn('parameters.trailer_field', explanation)

    def test_certificate_inner_outer_conflict(self):
        inner = {
            'algorithm': 'rsassa_pss',
            'parameters': {
                'hash_algorithm': {'algorithm': 'sha256'},
                'mask_gen_algorithm': {
                    'algorithm': 'mgf1',
                    'parameters': {'algorithm': 'sha256'},
                },
                'salt_length': 32,
            },
        }
        outer = {
            'algorithm': 'rsassa_pss',
            'parameters': {
                'hash_algorithm': {'algorithm': 'sha384'},
                'mask_gen_algorithm': {
                    'algorithm': 'mgf1',
                    'parameters': {'algorithm': 'sha384'},
                },
                'salt_length': 48,
            },
        }
        public_key = {'algorithm': 'rsa'}
        cert = _build_certificate(inner, outer, public_key)

        check = sigcheck.check_certificate_signature_consistency(cert)

        self.assertEqual(sigcheck.Verdict.CONFLICT, check.verdict)
        self.assertFalse(check.consistent)
        self.assertEqual(
            sigcheck.Verdict.CONFLICT, check.inner_outer.verdict
        )
        self.assertEqual(
            sigcheck.Verdict.CONSISTENT, check.key_constraints.verdict
        )

    def test_certificate_key_constraints_stricter(self):
        signature = {'algorithm': 'rsassa_pss'}
        public_key = {
            'algorithm': 'rsassa_pss',
            'parameters': {
                'hash_algorithm': {'algorithm': 'sha256'},
                'mask_gen_algorithm': {
                    'algorithm': 'mgf1',
                    'parameters': {'algorithm': 'sha256'},
                },
                'salt_length': 32,
            },
        }
        cert = _build_certificate(signature, signature, public_key)

        check = sigcheck.check_certificate_signature_consistency(cert)

        self.assertEqual(sigcheck.Verdict.CONFLICT, check.verdict)
        self.assertEqual(
            sigcheck.Verdict.CONSISTENT, check.inner_outer.verdict
        )
        self.assertEqual(
            sigcheck.Verdict.CONFLICT, check.key_constraints.verdict
        )
        self.assertIn('stricter', check.key_constraints.explain())
