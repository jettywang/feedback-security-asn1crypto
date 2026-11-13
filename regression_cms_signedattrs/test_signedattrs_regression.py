# coding: utf-8
"""
Offline regression tests for CMS SignedAttributes confusion.

These tests deliberately work on the raw asn1crypto SET OF objects and their
DER encoding. They never convert SignedAttributes into a dict keyed by
attrType, because such a conversion silently drops the duplicate attribute
occurrences that a verifier is expected to reject.

Run with:
    python -m pytest regression_cms_signedattrs -q
or:
    python -m unittest regression_cms_signedattrs.test_signedattrs_regression -v
"""
from __future__ import unicode_literals, division, absolute_import, print_function

import os
import sys
import unittest

# Allow `python -m pytest regression_cms_signedattrs` and direct unittest runs
# to import the sibling builder/corpus/verifier modules without installation.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from asn1crypto import cms

import builder
import corpus
import verifier

HERE = os.path.dirname(os.path.abspath(__file__))
GENERATED_DIR = os.path.join(HERE, 'generated')

# Raw structural expectations per case id:
# (outer signedAttr occurrence multimap, explicit value-set size assertions)
# These describe what must remain visible WITHOUT any dict flattening.
RAW_EXPECTATIONS = {
    'dup_content_type': {'total': 4, 'counts': {'content_type': 2, 'message_digest': 1, 'signing_time': 1}},
    'dup_message_digest': {'total': 4, 'counts': {'content_type': 1, 'message_digest': 2, 'signing_time': 1}},
    'multi_value_content_type': {'total': 3, 'value_sizes': {'content_type': 2}},
    'multi_value_message_digest': {'total': 3, 'value_sizes': {'message_digest': 2}},
    'valid_baseline': {'total': 3, 'counts': {'content_type': 1, 'message_digest': 1, 'signing_time': 1}},
}


def _signed_attrs(content_info):
    return content_info['content']['signer_infos'][0]['signed_attrs']


def _type_counts(attributes):
    counts = {}
    for index in range(len(attributes)):
        oid = attributes[index]['type'].native
        counts[oid] = counts.get(oid, 0) + 1
    return counts


def _value_sizes(attributes):
    sizes = {}
    for index in range(len(attributes)):
        attribute = attributes[index]
        sizes.setdefault(attribute['type'].native, []).append(len(attribute['values']))
    return sizes


class RawAttributeViewTests(unittest.TestCase):
    """The raw SET OF, lazy access and DER must all preserve the confusion."""

    @classmethod
    def setUpClass(cls):
        cls.cases = {metadata['id']: (content_info, metadata)
                     for content_info, metadata in corpus.build_corpus()}

    def test_duplicates_survive_in_raw_setof(self):
        content_info, _ = self.cases['dup_content_type']
        signed_attrs = _signed_attrs(content_info)
        # Raw collection keeps both occurrences instead of collapsing to a key.
        self.assertEqual(4, len(signed_attrs))
        counts = _type_counts(signed_attrs)
        self.assertEqual(2, counts['content_type'])

    def test_native_view_is_list_and_keeps_duplicates(self):
        content_info, _ = self.cases['dup_message_digest']
        signed_attrs = _signed_attrs(content_info)
        native = signed_attrs.native
        # Guard: asn1crypto hands back a list of per-attribute OrderedDicts.
        self.assertIsInstance(native, list)
        oids = [entry['type'] for entry in native]
        self.assertEqual(2, oids.count('message_digest'))
        # Demonstrate what a dict keyed by attrType would destroy.
        flattened = dict((entry['type'], entry) for entry in native)
        self.assertEqual(3, len(flattened))
        self.assertNotEqual(len(native), len(flattened))

    def test_lazy_access_does_not_change_occurrences(self):
        for case_id, expectation in RAW_EXPECTATIONS.items():
            content_info, _ = self.cases[case_id]
            signed_attrs = _signed_attrs(content_info)
            # Touch every attribute and value lazily, then recount.
            for index in range(len(signed_attrs)):
                attribute = signed_attrs[index]
                _ = attribute['type'].native
                for value_index in range(len(attribute['values'])):
                    _ = attribute['values'][value_index].native
            self.assertEqual(expectation['total'], len(signed_attrs), case_id)
            if 'counts' in expectation:
                self.assertEqual(expectation['counts'], _type_counts(signed_attrs), case_id)
            if 'value_sizes' in expectation:
                sizes = _value_sizes(signed_attrs)
                for oid, expected_size in expectation['value_sizes'].items():
                    self.assertIn(expected_size, sizes[oid], case_id)

    def test_der_round_trip_preserves_duplicates_and_multivalues(self):
        for case_id in ('dup_content_type', 'dup_message_digest',
                        'multi_value_content_type', 'multi_value_message_digest'):
            content_info, _ = self.cases[case_id]
            der_bytes = content_info.dump()
            reparsed = cms.ContentInfo.load(der_bytes)
            reparsed_attrs = _signed_attrs(reparsed)
            original_attrs = _signed_attrs(content_info)
            self.assertEqual(len(original_attrs), len(reparsed_attrs), case_id)
            self.assertEqual(_type_counts(original_attrs), _type_counts(reparsed_attrs), case_id)
            # DER is stable on a second dump.
            self.assertEqual(der_bytes, reparsed.dump(), case_id)

    def test_signed_attrs_use_implicit_tag_but_signing_input_uses_universal_set(self):
        content_info, _ = self.cases['valid_baseline']
        signed_attrs = _signed_attrs(content_info)
        field_der = signed_attrs.dump()
        self.assertEqual(0xA0, field_der[0])
        signing_input = builder.signed_attrs_der_for_signing(signed_attrs)
        self.assertEqual(0x31, signing_input[0])
        self.assertEqual(field_der[1:], signing_input[1:])

    def test_generated_der_files_match_in_memory_objects(self):
        for case_id, (content_info, metadata) in self.cases.items():
            der_path = os.path.join(GENERATED_DIR, case_id + '.der')
            with open(der_path, 'rb') as handle:
                on_disk = handle.read()
            self.assertEqual(content_info.dump(), on_disk, case_id)
            self.assertEqual(cms.ContentInfo.load(on_disk).dump(), on_disk, case_id)


class AdapterRejectionTests(unittest.TestCase):
    """Every counterexample is rejected structurally, before signature checks."""

    @classmethod
    def setUpClass(cls):
        cls.cases = {metadata['id']: (content_info, metadata)
                     for content_info, metadata in corpus.build_corpus()}
        cls.results = {}
        for case_id, (content_info, _) in cls.cases.items():
            cls.results[case_id] = verifier.verify_content_info(content_info)

    def _outer_result(self, case_id):
        return self.results[case_id][0]

    def test_negative_cases_rejected_before_signature_verification(self):
        for case_id, (_, metadata) in self.cases.items():
            if metadata['kind'] != 'negative':
                continue
            result = self._outer_result(case_id)
            if metadata['expected_status'] == 'rejected_structure' and not result.countersignature_results:
                self.assertEqual('rejected_structure', result.status, case_id)
                self.assertEqual('not_attempted', result.signature_status, case_id)
            codes = [finding.code for finding in result.findings]
            for counter in result.countersignature_results:
                codes.extend(finding.code for finding in counter.findings)
            for expected_code in metadata['expected_codes']:
                self.assertIn(expected_code, codes, case_id)

    def test_valid_controls_are_accepted(self):
        for case_id in ('valid_baseline', 'valid_countersignature', 'dup_countersignature_attr'):
            result = self._outer_result(case_id)
            self.assertEqual('accepted', result.status, case_id)
            self.assertEqual([], result.findings, case_id)
            self.assertEqual('valid', result.signature_status, case_id)
            self.assertTrue(result.digest_ok, case_id)

    def test_legal_countersignature_binds_parent_signature(self):
        result = self._outer_result('valid_countersignature')
        self.assertEqual(1, len(result.countersignature_results))
        counter = result.countersignature_results[0]
        self.assertEqual('accepted', counter.status)
        self.assertTrue(counter.digest_ok)
        self.assertEqual('valid', counter.signature_status)

    def test_multiple_countersignature_attributes_not_rejected(self):
        # The exception to the duplicate-attribute rule must keep both counters.
        result = self._outer_result('dup_countersignature_attr')
        self.assertEqual(2, len(result.countersignature_results))
        for counter in result.countersignature_results:
            self.assertEqual('accepted', counter.status)
            self.assertTrue(counter.digest_ok)

    def test_countersigner_forbidden_attributes_rejected(self):
        for case_id in ('countersigner_has_content_type', 'countersigner_has_message_digest'):
            result = self._outer_result(case_id)
            counter = result.countersignature_results[0]
            self.assertEqual('rejected_structure', counter.status)
            self.assertEqual('not_attempted', counter.signature_status)
            self.assertIn(verifier.COUNTER_FORBIDDEN_SIGNED_ATTR,
                          [finding.code for finding in counter.findings])

    def test_countersigner_binding_econtent_rejected_by_local_digest(self):
        result = self._outer_result('countersigner_binds_econtent')
        counter = result.countersignature_results[0]
        # The signature is a real, well-formed PKCS#1 signature, but it was
        # computed over eContent; verifying it against the parent signature
        # input fails and the recovered digest does not bind the parent.
        self.assertEqual('rejected_signature', counter.status)
        self.assertEqual('invalid', counter.signature_status)
        self.assertFalse(counter.digest_ok)
        self.assertEqual([verifier.DIGEST_MISMATCH], [f.code for f in counter.findings])

    def test_local_payload_digest_binding(self):
        # Accepted outer signature carries a message-digest matching eContent.
        baseline = self._outer_result('valid_baseline')
        self.assertTrue(baseline.digest_ok)
        # One-byte digest tampering is caught without relying on the signature.
        tampered, _ = self.cases['digest_mismatch']
        tampered_result = verifier.verify_content_info(tampered)[0]
        self.assertIn(verifier.DIGEST_MISMATCH,
                      [finding.code for finding in tampered_result.findings])


class ParseIsNotValidationTests(unittest.TestCase):
    """Well-formed ASN.1 parsing must never be equated with a valid signature."""

    def test_all_negative_fixtures_parse_cleanly(self):
        for case_id, metadata in ((m['id'], m) for _, m in corpus.build_corpus()):
            der_path = os.path.join(GENERATED_DIR, case_id + '.der')
            with open(der_path, 'rb') as handle:
                # If this raised, the fixture would fail to parse; it does not.
                content_info = cms.ContentInfo.load(handle.read())
            self.assertEqual('signed_data', content_info['content_type'].native)

    def test_rejected_structure_still_has_cryptographically_valid_signature(self):
        # Re-signing after each single mutation keeps the signature verifiable,
        # proving structural rejection does not lean on a broken signature.
        for content_info, metadata in corpus.build_corpus():
            if metadata['kind'] != 'negative':
                continue
            signer_info = content_info['content']['signer_infos'][0]
            signed_attrs = signer_info['signed_attrs']
            if signed_attrs is None or len(signed_attrs) == 0:
                continue
            cert = verifier._certs_by_serial(content_info)[
                signer_info['sid'].chosen['serial_number'].native]
            public_key = cert['tbs_certificate']['subject_public_key_info']['public_key'].parsed
            signed_input = builder.signed_attrs_der_for_signing(signed_attrs)
            self.assertTrue(
                builder.rsa_pkcs1v15_verify(
                    public_key, signer_info['digest_algorithm']['algorithm'].native,
                    signed_input, signer_info['signature'].native),
                metadata['id'],
            )

    def test_tampered_signature_is_rejected_even_when_structure_is_valid(self):
        content_info, _ = self.cases_baseline()
        signer_info = content_info['content']['signer_infos'][0]
        signature = bytearray(signer_info['signature'].native)
        signature[0] ^= 0x01
        signer_info['signature'] = bytes(signature)
        result = verifier.verify_content_info(content_info)[0]
        self.assertEqual('rejected_signature', result.status)
        self.assertEqual('invalid', result.signature_status)
        # Structure and payload binding remain fine; only the crypto layer fails.
        self.assertEqual([], result.findings)
        self.assertTrue(result.digest_ok)

    @staticmethod
    def cases_baseline():
        for content_info, metadata in corpus.build_corpus():
            if metadata['id'] == 'valid_baseline':
                return content_info, metadata
        raise RuntimeError('valid_baseline fixture missing')


if __name__ == '__main__':
    unittest.main(verbosity=2)
