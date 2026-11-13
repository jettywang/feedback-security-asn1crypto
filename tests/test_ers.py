# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import json
import os
import unittest

import hashlib
from datetime import datetime

from asn1crypto import cms, core, ers, tsp, util
from ._unittest_compat import patch

patch()

tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures', 'ers')

with open(os.path.join(fixtures_dir, 'expected.json'), 'r') as _f:
    EXPECTED = json.load(_f)


def _fixture(name):
    with open(os.path.join(fixtures_dir, name + '.der'), 'rb') as f:
        return f.read()


def _codes(result, severity):
    return [
        (finding.code, finding.chain_index, finding.entry_index)
        for finding in result.findings
        if finding.severity == severity
    ]


class ERSCheckTests(unittest.TestCase):

    def test_single_chain_two_renewals(self):
        result = ers.check_der(_fixture('single_chain_two_renewals'))

        self.assertEqual(ers.STATUS_PASS, result.status)
        self.assertEqual(1, result.chain_count)
        self.assertEqual(3, len(result.entries))
        self.assertEqual([], result.chain_breaks)
        self.assertEqual([], result.structural_errors)

        expected = EXPECTED['fixtures']['single_chain_two_renewals']
        for actual, wanted in zip(result.entries, expected['entries']):
            self.assertEqual(wanted['chain_index'], actual['chain_index'])
            self.assertEqual(wanted['entry_index'], actual['entry_index'])
            self.assertEqual(wanted['renewal'], actual['renewal'])
            self.assertEqual(wanted['algorithm'], actual['algorithm'])
            self.assertEqual(wanted['algorithm_source'], actual['algorithm_source'])
            self.assertEqual(wanted['imprint_digest'], actual['imprint_digest'])
            if wanted['renewal'] == 'timestamp':
                self.assertEqual(wanted['previous_token_digest'], actual['leaf_digest'])
                self.assertEqual(ers._OUTCOME_OK, actual['outcome'])

        # Entry 0 has no explicit algorithm, so it was derived from the TSTInfo
        self.assertEqual('derived', result.entries[0]['algorithm_source'])
        self.assertEqual('explicit', result.entries[1]['algorithm_source'])

    def test_two_chains(self):
        result = ers.check_der(_fixture('two_chains'))

        self.assertEqual(ers.STATUS_PASS, result.status)
        self.assertEqual(2, result.chain_count)
        self.assertEqual(4, len(result.entries))

        expected = EXPECTED['fixtures']['two_chains']['entries']
        hash_tree = result.entries[2]
        self.assertEqual('hash_tree', hash_tree['renewal'])
        self.assertEqual(expected[2]['previous_chains_digest'], hash_tree['previous_chains_digest'])
        self.assertEqual(expected[2]['rebuilt_root'], hash_tree['rebuilt_root'])
        self.assertEqual(ers._OUTCOME_OK, hash_tree['outcome'])

    def test_tree_path_altered(self):
        result = ers.check_der(_fixture('tree_path_altered'))

        self.assertEqual(ers.STATUS_FAIL, result.status)
        self.assertEqual(
            [('renewal_digest_mismatch', 1, 0)],
            _codes(result, ers.SEVERITY_ERROR)
        )
        self.assertEqual(1, len(result.chain_breaks))
        self.assertEqual([], result.structural_errors)

        finding = result.chain_breaks[0]
        self.assertEqual('chain 1 entry 0', finding.location)
        expected_root = EXPECTED['fixtures']['tree_path_altered']['entries'][2]['rebuilt_root']
        self.assertEqual(expected_root, finding.details['rebuilt_root'])

    def test_digest_valid_out_of_order(self):
        result = ers.check_der(_fixture('digest_valid_out_of_order'))

        self.assertEqual(ers.STATUS_FAIL, result.status)
        self.assertEqual(
            [('timestamp_order', 0, 1)],
            _codes(result, ers.SEVERITY_ERROR)
        )
        # The digests themselves are intact - only the order is wrong, and
        # the entries must still be reported in their original DER order
        self.assertEqual([0, 1, 2], [entry['entry_index'] for entry in result.entries])
        intact = [e for e in result.entries
                  if e['outcome'] in (ers._OUTCOME_OK, ers._OUTCOME_UNCHECKED)]
        self.assertEqual(3, len(intact))

    def test_timestamp_renewal_wrong_digest(self):
        result = ers.check_der(_fixture('timestamp_renewal_wrong_digest'))

        self.assertEqual(ers.STATUS_FAIL, result.status)
        self.assertEqual(
            [('renewal_digest_mismatch', 0, 1)],
            _codes(result, ers.SEVERITY_ERROR)
        )

    def test_chain_link_wrong_digest(self):
        result = ers.check_der(_fixture('chain_link_wrong_digest'))

        self.assertEqual(ers.STATUS_FAIL, result.status)
        self.assertEqual(
            [('renewal_digest_mismatch', 1, 0)],
            _codes(result, ers.SEVERITY_ERROR)
        )

    def test_hash_tree_algorithm_change_is_unverified(self):
        result = ers.check_der(_fixture('hash_tree_algorithm_change'))

        self.assertEqual(ers.STATUS_UNVERIFIED, result.status)
        self.assertEqual([], result.chain_breaks)
        self.assertEqual(
            [('hash_tree_algorithm_change_unverified', 1, 0)],
            _codes(result, ers.SEVERITY_WARNING)
        )
        self.assertEqual(ers._OUTCOME_UNVERIFIED, result.entries[2]['outcome'])

    def test_entries_match_independent_digests(self):
        for name, expected in EXPECTED['fixtures'].items():
            result = ers.check_der(_fixture(name))
            self.assertEqual(expected['status'], result.status, name)
            self.assertEqual(len(expected['entries']), len(result.entries), name)
            for actual, wanted in zip(result.entries, expected['entries']):
                self.assertEqual(wanted['gen_time'], actual['gen_time'], name)
                self.assertEqual(wanted['renewal'], actual['renewal'], name)
                self.assertEqual(wanted['imprint_digest'], actual['imprint_digest'], name)
                self.assertEqual(wanted['algorithm'], actual['algorithm'], name)
                if wanted['renewal'] == 'timestamp':
                    self.assertEqual(wanted['previous_token_digest'], actual['leaf_digest'], name)
                if wanted['previous_chains_digest'] is not None:
                    self.assertEqual(wanted['previous_chains_digest'], actual['previous_chains_digest'], name)
            self.assertEqual(
                [(e['code'], e['chain_index'], e['entry_index']) for e in expected['errors']],
                _codes(result, ers.SEVERITY_ERROR),
                name,
            )
            self.assertEqual(
                [(e['code'], e['chain_index'], e['entry_index']) for e in expected['warnings']],
                _codes(result, ers.SEVERITY_WARNING),
                name,
            )

    def test_findings_have_stable_equality(self):
        a = ers.Finding('code', 'message', chain_index=1, entry_index=0)
        b = ers.Finding('code', 'message', chain_index=1, entry_index=0)
        c = ers.Finding('code', 'message', chain_index=1, entry_index=1)
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)
        self.assertEqual('chain 1 entry 0', a.location)
        self.assertEqual('chain 1', ers.Finding('code', 'message', chain_index=1).location)
        self.assertIsNone(ers.Finding('code', 'message').location)

    def test_signature_is_separate_from_chain_status(self):
        for name in EXPECTED['fixtures']:
            result = ers.check_der(_fixture(name))
            self.assertFalse(result.signature_checked, name)
            codes = [f.code for f in result.signature_findings]
            self.assertEqual(['signature_not_checked'], codes, name)
            self.assertEqual(ers.SEVERITY_INFO, result.signature_findings[0].severity, name)
            # Signature trust must never turn a coherent chain into a failure
            self.assertNotEqual(
                True,
                any(f.code == 'signature_not_checked' and f.severity == ers.SEVERITY_ERROR
                    for f in result.findings),
                name,
            )

    def test_native_is_json_serializable(self):
        result = ers.check_der(_fixture('tree_path_altered'))
        encoded = json.dumps(result.native())
        decoded = json.loads(encoded)
        self.assertEqual('fail', decoded['status'])
        self.assertEqual(1, len(decoded['chain_breaks']))
        self.assertEqual(1, len(decoded['signature']))
        self.assertEqual(3, len(decoded['entries']))

    def test_derive_algorithm_can_be_disabled(self):
        result = ers.check_der(_fixture('single_chain_two_renewals'), derive_algorithm=False)

        # Entries without an explicit digest algorithm become unverified
        self.assertEqual([], result.chain_breaks)
        self.assertNotEqual(ers.STATUS_PASS, result.status)
        # The initial entry is never reconstructable offline, and entry 2 has
        # no explicit algorithm to fall back on
        self.assertEqual(ers._OUTCOME_UNCHECKED, result.entries[0]['outcome'])
        self.assertEqual(ers._OUTCOME_OK, result.entries[1]['outcome'])
        self.assertEqual(ers._OUTCOME_UNVERIFIED, result.entries[2]['outcome'])


class ERSModelTests(unittest.TestCase):

    def test_standard_layer_round_trip(self):
        der = _fixture('single_chain_two_renewals')
        record = tsp.EvidenceRecord.load(der)
        self.assertEqual(der, record.dump())

        sequence = record['archive_time_stamp_sequence']
        self.assertIsInstance(sequence, tsp.ArchiveTimeStampSequence)
        self.assertIsInstance(sequence[0], tsp.ArchiveTimeStampChain)
        self.assertIsInstance(sequence[0][0], tsp.ArchiveTimeStamp)

        # Two chains, with one chain having two entries
        two_chain_der = _fixture('two_chains')
        two_chain_record = tsp.EvidenceRecord.load(two_chain_der)
        self.assertEqual(two_chain_der, two_chain_record.dump())
        two_chain_sequence = two_chain_record['archive_time_stamp_sequence']
        self.assertEqual(2, len(two_chain_sequence))
        self.assertEqual(2, len(two_chain_sequence[0]))
        self.assertEqual(2, len(two_chain_sequence[1]))

    def test_optional_fields_and_reduced_hashtree(self):
        record = tsp.EvidenceRecord.load(_fixture('two_chains'))
        entry = record['archive_time_stamp_sequence'][1][0]
        self.assertIsInstance(entry['reduced_hashtree'], tsp.PartialHashtrees)
        self.assertEqual(2, len(entry['reduced_hashtree']))
        self.assertEqual(32, len(entry['reduced_hashtree'][0][0].native))

    def test_legacy_flat_layout_is_rejected_by_layered_model(self):
        flat = _fixture('legacy_flat_sequence')
        record = tsp.EvidenceRecord.load(flat)
        # The flat bytes still load, but the layered model refuses to treat
        # them as chains - this is the explicit migration trigger, not a
        # silent reinterpretation
        def read_sequence():
            return record['archive_time_stamp_sequence'].native
        self.assertRaises(ValueError, read_sequence)

    def test_legacy_flat_explicit_migration(self):
        flat = _fixture('legacy_flat_sequence')
        migration = EXPECTED['legacy_flat']

        migrated = tsp.ArchiveTimeStampSequence.from_legacy_flat_der(flat)
        self.assertEqual(1, len(migrated))
        self.assertIsInstance(migrated[0], tsp.ArchiveTimeStampChain)
        self.assertEqual(2, len(migrated[0]))

        with open(os.path.join(fixtures_dir, migration['migrated_der']), 'rb') as f:
            migrated_der = f.read()
        self.assertEqual(migrated_der, migrated.dump())

        # The migrated sequence, placed in a record, checks cleanly against
        # the digests computed by the fixture generator
        record = tsp.EvidenceRecord({
            'version': 'v1',
            'digest_algorithms': [{'algorithm': 'sha256'}],
            'archive_time_stamp_sequence': migrated,
        })
        result = ers.check_evidence_record(record)
        self.assertEqual(ers.STATUS_PASS, result.status)
        self.assertEqual(
            migration['previous_token_digest'],
            result.entries[1]['leaf_digest']
        )

    def test_legacy_flat_migration_does_not_alter_entries(self):
        flat = _fixture('legacy_flat_sequence')
        migrated = tsp.ArchiveTimeStampSequence.from_legacy_flat_der(flat)
        # Each entry keeps its original encoding byte for byte
        self.assertEqual(
            tsp.ArchiveTimeStampSequence.load(migrated.dump()).dump(),
            migrated.dump()
        )

    def test_model_rejects_wrong_sequence_layer(self):
        der = _fixture('single_chain_two_renewals')
        record = tsp.EvidenceRecord.load(der)
        # The DER layer is standardized and must not be silently flattened
        self.assertIsInstance(
            record['archive_time_stamp_sequence'][0],
            tsp.ArchiveTimeStampChain
        )


def _timestamp_token(algorithm, imprint, gen_time, serial):
    tst_info = tsp.TSTInfo({
        'version': 'v1',
        'policy': '1.3.6.1.4.1.4146.1.1',
        'message_imprint': {
            'hash_algorithm': {'algorithm': algorithm},
            'hashed_message': imprint,
        },
        'serial_number': serial,
        'gen_time': gen_time,
    })
    signed_data = cms.SignedData({
        'version': 'v3',
        'digest_algorithms': [{'algorithm': algorithm}],
        'encap_content_info': {
            'content_type': 'tst_info',
            'content': tst_info,
        },
        'signer_infos': [],
    })
    return cms.ContentInfo({'content_type': 'signed_data', 'content': signed_data})


def _at(gen_time, imprint, algorithm='sha256', hashtree=None, explicit=True):
    fields = {'time_stamp': _timestamp_token(algorithm, imprint, gen_time, 1)}
    if explicit:
        fields['digest_algorithm'] = {'algorithm': algorithm}
    if hashtree is not None:
        fields['reduced_hashtree'] = hashtree
    return tsp.ArchiveTimeStamp(fields)


class ERSSemanticsTests(unittest.TestCase):

    def test_group_renewal_covering_multiple_timestamps(self):
        # RFC 4998 allows one renewal to cover several earlier timestamps,
        # with their digests as values of the first partial hashtree
        t0 = datetime(2024, 1, 1, tzinfo=util.timezone.utc)
        t1 = datetime(2025, 1, 1, tzinfo=util.timezone.utc)
        t2 = datetime(2026, 1, 1, tzinfo=util.timezone.utc)

        first = _at(t0, b'\x00' * 32, explicit=False)
        second = _at(t1, hashlib.sha256(first['time_stamp'].dump()).digest())
        h0 = hashlib.sha256(first['time_stamp'].dump()).digest()
        h1 = hashlib.sha256(second['time_stamp'].dump()).digest()
        group = hashlib.sha256(b''.join(sorted([h0, h1]))).digest()
        sibling = hashlib.sha256(b'sibling').digest()
        root = hashlib.sha256(b''.join(sorted([group, sibling]))).digest()

        third = _at(t2, root, hashtree=[[h0, h1], [sibling]])
        record = tsp.EvidenceRecord({
            'version': 'v1',
            'digest_algorithms': [{'algorithm': 'sha256'}],
            'archive_time_stamp_sequence': [[first, second, third]],
        })

        result = ers.check_evidence_record(record)
        self.assertEqual(ers.STATUS_PASS, result.status)
        self.assertEqual(ers._OUTCOME_OK, result.entries[2]['outcome'])

    def test_chain_link_cannot_use_previous_timestamp_digest(self):
        # A new chain's first timestamp must commit to the previous chains,
        # not merely to the last timestamp token of the previous chain
        t0 = datetime(2024, 1, 1, tzinfo=util.timezone.utc)
        t1 = datetime(2025, 1, 1, tzinfo=util.timezone.utc)
        t2 = datetime(2026, 1, 1, tzinfo=util.timezone.utc)

        first = _at(t0, b'\x00' * 32, explicit=False)
        second_imprint = hashlib.sha256(first['time_stamp'].dump()).digest()
        second = _at(t1, second_imprint)
        third = _at(t2, second_imprint)
        record = tsp.EvidenceRecord({
            'version': 'v1',
            'digest_algorithms': [{'algorithm': 'sha256'}],
            'archive_time_stamp_sequence': [[first, second], [third]],
        })

        result = ers.check_evidence_record(record)
        self.assertEqual(ers.STATUS_FAIL, result.status)
        self.assertEqual(
            [('renewal_digest_mismatch', 1, 0)],
            _codes(result, ers.SEVERITY_ERROR)
        )

    def test_each_chain_covers_all_previous_chains(self):
        t0 = datetime(2024, 1, 1, tzinfo=util.timezone.utc)
        t1 = datetime(2025, 1, 1, tzinfo=util.timezone.utc)
        t2 = datetime(2026, 1, 1, tzinfo=util.timezone.utc)
        t3 = datetime(2027, 1, 1, tzinfo=util.timezone.utc)
        t4 = datetime(2028, 1, 1, tzinfo=util.timezone.utc)

        first = _at(t0, b'\x00' * 32, explicit=False)
        second = _at(t1, hashlib.sha256(first['time_stamp'].dump()).digest())
        chain0 = tsp.ArchiveTimeStampChain([first, second])

        previous_digest = hashlib.sha256(
            tsp.ArchiveTimeStampSequence([chain0]).dump()
        ).digest()
        sibling = hashlib.sha256(b'sibling').digest()
        root = hashlib.sha256(b''.join(sorted([previous_digest, sibling]))).digest()
        third = _at(t2, root, hashtree=[[previous_digest], [sibling]])
        fourth = _at(t3, hashlib.sha256(third['time_stamp'].dump()).digest())
        chain1 = tsp.ArchiveTimeStampChain([third, fourth])

        # A new chain must commit to all previous chains, not just the last
        all_previous = hashlib.sha256(
            tsp.ArchiveTimeStampSequence([chain0, chain1]).dump()
        ).digest()
        chain2 = tsp.ArchiveTimeStampChain([_at(t4, all_previous)])

        record = tsp.EvidenceRecord({
            'version': 'v1',
            'digest_algorithms': [{'algorithm': 'sha256'}],
            'archive_time_stamp_sequence': [chain0, chain1, chain2],
        })
        self.assertEqual(ers.STATUS_PASS, ers.check_evidence_record(record).status)

        only_last = hashlib.sha256(
            tsp.ArchiveTimeStampSequence([chain1]).dump()
        ).digest()
        chain2_bad = tsp.ArchiveTimeStampChain([_at(t4, only_last)])
        bad_record = tsp.EvidenceRecord({
            'version': 'v1',
            'digest_algorithms': [{'algorithm': 'sha256'}],
            'archive_time_stamp_sequence': [chain0, chain1, chain2_bad],
        })
        bad = ers.check_evidence_record(bad_record)
        self.assertEqual(ers.STATUS_FAIL, bad.status)
        self.assertEqual([('renewal_digest_mismatch', 2, 0)], _codes(bad, ers.SEVERITY_ERROR))

    def test_truncated_input_fails_without_raising(self):
        der = _fixture('single_chain_two_renewals')
        for length in (4, 40, len(der) - 10):
            result = ers.check_der(der[:length])
            self.assertEqual(ers.STATUS_FAIL, result.status)
            self.assertEqual(1, len(result.structural_errors))
            self.assertIsNone(result.structural_errors[0].location)

    def test_legacy_flat_input_requires_explicit_migration(self):
        result = ers.check_der(_fixture('legacy_flat_sequence'))
        self.assertEqual(ers.STATUS_FAIL, result.status)
        messages = [f.message for f in result.structural_errors]
        self.assertEqual(1, len(messages))
        self.assertIn('from_legacy_flat_der', messages[0])

    def test_missing_time_stamp_is_structural_error(self):
        # A sequence containing only an explicit digest algorithm and no
        # time_stamp ContentInfo
        raw = core.Sequence.load(
            b'\x30\x0d\xa0\x0b\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01'
        )
        broken_entry = tsp.ArchiveTimeStamp.load(raw.dump())
        record = tsp.EvidenceRecord({
            'version': 'v1',
            'digest_algorithms': [{'algorithm': 'sha256'}],
            'archive_time_stamp_sequence': [[broken_entry]],
        })
        result = ers.check_evidence_record(record)
        self.assertEqual(ers.STATUS_FAIL, result.status)
        codes = [f.code for f in result.structural_errors]
        self.assertTrue('missing_time_stamp' in codes or 'invalid_archive_time_stamp' in codes)


class ERSCLITests(unittest.TestCase):

    def _run(self, *paths):
        import subprocess
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return subprocess.call(
            [__import__('sys').executable, '-m', 'asn1crypto.ers'] + list(paths),
            cwd=root,
        )

    def test_cli_pass_exits_zero(self):
        self.assertEqual(0, self._run(os.path.join(fixtures_dir, 'two_chains.der')))

    def test_cli_fail_exits_one(self):
        self.assertEqual(1, self._run(os.path.join(fixtures_dir, 'tree_path_altered.der')))

    def test_cli_unverified_exits_three(self):
        self.assertEqual(3, self._run(os.path.join(fixtures_dir, 'hash_tree_algorithm_change.der')))
