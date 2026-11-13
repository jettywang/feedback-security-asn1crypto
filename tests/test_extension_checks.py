# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os
import unittest

from asn1crypto import crl, ocsp, pem, x509
from asn1crypto._extension_checks import (
    CONFLICT_CRITICAL,
    CONFLICT_DUPLICATE,
    CONFLICT_VALUE,
    SCOPE_CERTIFICATE,
    SCOPE_CRL_ENTRY,
    SCOPE_TBS_CRL,
    SCOPE_OCSP_REQUEST,
    SCOPE_OCSP_RESPONSE,
    SCOPE_OCSP_SINGLE_REQUEST,
    SCOPE_OCSP_SINGLE_RESPONSE,
)
from asn1crypto.core import ParsableOctetString

from ._unittest_compat import patch

patch()


fixtures_dir = os.path.join(os.path.dirname(__file__), 'fixtures')


def _load_cert(relative_path):
    with open(os.path.join(fixtures_dir, relative_path), 'rb') as f:
        data = f.read()
    if pem.detect(data):
        _, _, data = pem.unarmor(data)
    return x509.Certificate.load(data)


def _extension(spec, oid, critical, parsed):
    return spec({
        'extn_id': oid,
        'critical': critical,
        'extn_value': ParsableOctetString(parsed=parsed),
    })


class ExtensionCheckReportTests(unittest.TestCase):

    def setUp(self):
        self.cert = _load_cert('geotrust_certs/codex.crt')
        self.exts = self.cert['tbs_certificate']['extensions']

    def test_normal_certificate_has_no_duplicates(self):
        checks = self.cert.extension_checks
        self.assertFalse(checks.has_duplicates)
        self.assertEqual(SCOPE_CERTIFICATE, checks.scope)
        self.assertEqual([], checks.duplicate_oids)
        self.assertEqual(
            len(self.exts),
            len(checks.entries),
        )
        # Entries preserve the original order and objects.
        for index, entry in enumerate(checks.entries):
            self.assertEqual(index, entry.index)
            self.assertIs(self.exts[index], entry.extension)
            self.assertTrue(entry.known)

    def test_original_extensions_and_order_are_preserved(self):
        original_count = len(self.exts)
        bc = [e for e in self.exts if e['extn_id'].native == 'basic_constraints'][0]
        self.exts.append(_extension(
            x509.Extension,
            'basic_constraints',
            not bc['critical'].native,
            bc['extn_value'].parsed.copy(),
        ))
        # The raw sequence keeps every extension; nothing is collapsed.
        self.assertEqual(original_count + 1, len(self.exts))
        checks = self.cert.extension_checks
        self.assertEqual(original_count + 1, len(checks.entries))
        self.assertIs(self.exts, checks.extensions)

    def test_critical_flag_conflict_is_distinguished(self):
        bc = [e for e in self.exts if e['extn_id'].native == 'basic_constraints'][0]
        self.exts.append(_extension(
            x509.Extension,
            'basic_constraints',
            not bc['critical'].native,
            bc['extn_value'].parsed.copy(),
        ))
        dup = self.cert.extension_checks.get_duplicate('basic_constraints')
        self.assertEqual(CONFLICT_CRITICAL, dup.conflict_type)
        self.assertTrue(dup.critical_conflict)
        self.assertFalse(dup.value_different)
        self.assertEqual(
            [bc_index for bc_index, e in enumerate(self.exts)
             if e['extn_id'].native == 'basic_constraints'],
            dup.indices,
        )

    def test_value_conflict_is_distinguished(self):
        original = [e for e in self.exts if e['extn_id'].native == 'key_usage'][0]
        self.exts.append(_extension(
            x509.Extension,
            'key_usage',
            original['critical'].native,
            x509.KeyUsage({'key_encipherment'}),
        ))
        dup = self.cert.extension_checks.get_duplicate('key_usage')
        self.assertEqual(CONFLICT_VALUE, dup.conflict_type)
        self.assertTrue(dup.value_different)
        self.assertFalse(dup.critical_conflict)
        self.assertEqual(original['critical'].native, dup.entries[-1].critical)

    def test_identical_duplicate_is_not_value_conflict(self):
        ku = [e for e in self.exts if e['extn_id'].native == 'key_usage'][0]
        self.exts.append(_extension(
            x509.Extension,
            'key_usage',
            ku['critical'].native,
            ku['extn_value'].parsed.copy(),
        ))
        dup = self.cert.extension_checks.get_duplicate('key_usage')
        self.assertEqual(CONFLICT_DUPLICATE, dup.conflict_type)
        self.assertFalse(dup.value_different)
        self.assertFalse(dup.critical_conflict)

    def test_unknown_oid_duplicate_is_reported(self):
        oid = '1.2.3.4.5.6'
        self.exts.append(_extension(x509.Extension, oid, False, x509.OctetString(b'aa')))
        self.exts.append(_extension(x509.Extension, oid, False, x509.OctetString(b'bb')))
        dup = self.cert.extension_checks.get_duplicate(oid)
        self.assertFalse(dup.known)
        self.assertEqual(oid, dup.oid)
        self.assertEqual(oid, dup.name)
        # Unknown values cannot be parsed with an OID spec but raw bytes still
        # drive the value-conflict classification.
        self.assertEqual(CONFLICT_VALUE, dup.conflict_type)
        self.assertIsNone(dup.entries[0].parse_error)

    def test_last_item_wins_matches_effective_entry(self):
        bc = [e for e in self.exts if e['extn_id'].native == 'basic_constraints'][0]
        replacement = _extension(
            x509.Extension,
            'basic_constraints',
            bc['critical'].native,
            x509.BasicConstraints({'ca': False, 'path_len_constraint': 3}),
        )
        self.exts.append(replacement)
        checks = self.cert.extension_checks
        effective = checks.get_duplicate('basic_constraints').effective_entry
        self.assertIs(replacement, effective.extension)
        self.assertIs(
            self.cert.basic_constraints_value,
            effective.parsed,
        )
        self.assertEqual(3, self.cert.basic_constraints_value['path_len_constraint'].native)

    def test_entries_for_returns_every_occurrence(self):
        self.exts.append(_extension(
            x509.Extension,
            'key_usage',
            False,
            x509.KeyUsage({'key_encipherment'}),
        ))
        occurrences = self.cert.extension_checks.entries_for('key_usage')
        self.assertEqual(2, len(occurrences))
        self.assertEqual([2, len(self.exts) - 1], [e.index for e in occurrences])

    def test_get_duplicate_raises_for_singleton_oid(self):
        with self.assertRaises(KeyError):
            self.cert.extension_checks.get_duplicate('basic_constraints')


class ExtensionCacheLifecycleTests(unittest.TestCase):

    def setUp(self):
        self.cert = _load_cert('geotrust_certs/codex.crt')
        exts = self.cert['tbs_certificate']['extensions']
        bc = [e for e in exts if e['extn_id'].native == 'basic_constraints'][0]
        exts.append(_extension(
            x509.Extension,
            'basic_constraints',
            not bc['critical'].native,
            x509.BasicConstraints({'ca': False, 'path_len_constraint': 1}),
        ))
        # Populate every cache before the mutations under test.
        self.assertIsNotNone(self.cert.basic_constraints_value)
        self.assertTrue(self.cert.extension_checks.has_duplicates)
        self.der_before = self.cert.dump()

    def test_replacing_extn_value_invalidates_cache(self):
        exts = self.cert['tbs_certificate']['extensions']
        replacement = _extension(
            x509.Extension,
            'basic_constraints',
            False,
            x509.BasicConstraints({'ca': True, 'path_len_constraint': 7}),
        )
        # Interleave a raw-list read with a convenience-property read.
        self.assertIsNotNone(self.cert.basic_constraints_value)
        exts[-1]['extn_value'] = replacement['extn_value']
        self.assertIsNotNone(exts[-1]['extn_value'].parsed)
        der_after = self.cert.dump()
        self.assertNotEqual(self.der_before, der_after)
        self.assertEqual(7, self.cert.basic_constraints_value['path_len_constraint'].native)
        effective = self.cert.extension_checks.get_duplicate('basic_constraints').effective_entry
        self.assertEqual(7, effective.parsed['path_len_constraint'].native)

    def test_mutating_parsed_child_invalidates_cache(self):
        pos = self.cert['tbs_certificate']['extensions'][-1]['extn_value']
        # A convenience read followed by a raw-list read must share one view.
        self.assertIsNotNone(self.cert.basic_constraints_value)
        pos.parsed['path_len_constraint'] = 9
        self.assertEqual(9, pos.parsed['path_len_constraint'].native)
        der_after = self.cert.dump()
        self.assertNotEqual(self.der_before, der_after)
        self.assertEqual(9, self.cert.basic_constraints_value['path_len_constraint'].native)
        # A second dump is stable rather than drifting.
        self.assertEqual(der_after, self.cert.dump())

    def test_deleting_duplicate_invalidates_cache(self):
        exts = self.cert['tbs_certificate']['extensions']
        del exts[-1]
        # Removing the duplicate changes the encoding, and the post-change DER
        # must be reproducible rather than drifting between reads.
        der_after = self.cert.dump()
        self.assertNotEqual(self.der_before, der_after)
        self.assertEqual(der_after, self.cert.dump())
        self.assertFalse(self.cert.extension_checks.has_duplicates)
        self.assertEqual(
            len(exts),
            len(self.cert.extension_checks.entries),
        )
        with self.assertRaises(KeyError):
            self.cert.extension_checks.get_duplicate('basic_constraints')

    def test_copy_then_mutate_only_the_copy(self):
        original_der = self.cert.dump()
        clone = self.cert.copy()
        clone['tbs_certificate']['extensions'][-1]['extn_value'].parsed['path_len_constraint'] = 42
        # The copy reflects its own edit through both access styles.
        self.assertEqual(42, clone.basic_constraints_value['path_len_constraint'].native)
        self.assertNotEqual(original_der, clone.dump())
        # The original is untouched and still encodes identically.
        self.assertEqual(1, self.cert.basic_constraints_value['path_len_constraint'].native)
        self.assertEqual(original_der, self.cert.dump())

    def test_unmodified_copy_remains_identical(self):
        clone = self.cert.copy()
        self.assertEqual(self.cert.dump(), clone.dump())
        self.assertEqual(
            self.cert.basic_constraints_value.native,
            clone.basic_constraints_value.native,
        )


class ExtensionScopeTests(unittest.TestCase):

    def test_crl_scopes(self):
        with open(os.path.join(fixtures_dir, 'eid2011.crl'), 'rb') as f:
            cert_list = crl.CertificateList.load(f.read())
        self.assertEqual(SCOPE_TBS_CRL, cert_list.extension_checks.scope)

        tbs_exts = cert_list['tbs_cert_list']['crl_extensions']
        tbs_exts.append(_extension(crl.TBSCertListExtension, 'crl_number', False, crl.Integer(999)))
        dup = cert_list.extension_checks.get_duplicate('crl_number')
        self.assertEqual(CONFLICT_VALUE, dup.conflict_type)
        self.assertEqual(999, cert_list.crl_number_value.native)

        revoked = cert_list['tbs_cert_list']['revoked_certificates'][0]
        self.assertEqual(SCOPE_CRL_ENTRY, revoked.extension_checks.scope)
        entry_exts = revoked['crl_entry_extensions']
        entry_exts.append(_extension(
            crl.CRLEntryExtension, 'crl_reason', True,
            crl.CRLReason('key_compromise'),
        ))
        entry_exts.append(_extension(
            crl.CRLEntryExtension, 'crl_reason', False,
            crl.CRLReason('key_compromise'),
        ))
        self.assertTrue(revoked.extension_checks.get_duplicate('crl_reason').critical_conflict)

    def test_ocsp_scopes(self):
        with open(os.path.join(fixtures_dir, 'ocsp_response'), 'rb') as f:
            response = ocsp.OCSPResponse.load(f.read())
        self.assertEqual(SCOPE_OCSP_RESPONSE, response.extension_checks.scope)
        single = response.basic_ocsp_response['tbs_response_data']['responses'][0]
        self.assertEqual(SCOPE_OCSP_SINGLE_RESPONSE, single.extension_checks.scope)

        with open(os.path.join(fixtures_dir, 'ocsp_request'), 'rb') as f:
            request = ocsp.OCSPRequest.load(f.read())
        self.assertEqual(SCOPE_OCSP_REQUEST, request.extension_checks.scope)
        single_request = request['tbs_request']['request_list'][0]
        self.assertEqual(
            SCOPE_OCSP_SINGLE_REQUEST,
            single_request.extension_checks.scope,
        )

    def test_absent_extension_layer_is_reported_as_empty(self):
        # A response with no response_bytes has no response extension layer.
        response = ocsp.OCSPResponse({'response_status': 'try_later'})
        checks = response.extension_checks
        self.assertEqual(SCOPE_OCSP_RESPONSE, checks.scope)
        self.assertIsNone(checks.extensions)
        self.assertEqual([], checks.entries)
        self.assertFalse(checks.has_duplicates)
        self.assertEqual(set(), response.critical_extensions)
        self.assertIsNone(response.nonce_value)

    def test_ocsp_response_duplicate_through_parsed_octet_string(self):
        with open(os.path.join(fixtures_dir, 'ocsp_response'), 'rb') as f:
            response = ocsp.OCSPResponse.load(f.read())
        response_data = response.basic_ocsp_response['tbs_response_data']
        response_data['response_extensions'] = ocsp.ResponseDataExtensions([
            _extension(ocsp.ResponseDataExtension, 'nonce', False, ocsp.OctetString(b'one')),
            _extension(ocsp.ResponseDataExtension, 'nonce', False, ocsp.OctetString(b'two')),
        ])
        checks = response.extension_checks
        self.assertEqual(SCOPE_OCSP_RESPONSE, checks.scope)
        dup = checks.get_duplicate('nonce')
        self.assertEqual(CONFLICT_VALUE, dup.conflict_type)
        self.assertEqual(b'two', response.nonce_value.native)
        # In-place parsed edit through the raw structure is seen by the
        # convenience property after the cache is rebuilt.
        response_data['response_extensions'][-1]['extn_value'].parsed.set(b'three')
        self.assertEqual(b'three', response.nonce_value.native)


class ExtensionDerRoundTripTests(unittest.TestCase):

    def test_duplicate_survives_der_round_trip(self):
        cert = _load_cert('geotrust_certs/codex.crt')
        exts = cert['tbs_certificate']['extensions']
        exts.append(_extension(
            x509.Extension,
            'key_usage',
            False,
            x509.KeyUsage({'key_encipherment'}),
        ))
        encoded = cert.dump()
        reloaded = x509.Certificate.load(encoded)
        self.assertTrue(reloaded.extension_checks.has_duplicates)
        dup = reloaded.extension_checks.get_duplicate('key_usage')
        self.assertEqual(2, len(dup.entries))
        self.assertEqual(
            [e.extension.dump() for e in cert.extension_checks.get_duplicate('key_usage').entries],
            [e.extension.dump() for e in dup.entries],
        )
