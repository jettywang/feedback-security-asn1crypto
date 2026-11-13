# coding: utf-8

"""
Generates the RFC 4998 archive time stamp chain fixtures and the expected
digest values used by the tests.

This script deliberately does not import asn1crypto.ers. Every expected digest
below is computed here, directly with hashlib, from the DER bytes this script
constructs. The checker under test only consumes the generated .der files, so
it can never be the source of its own expected values.

Run from the repository root:

    python tests/fixtures/ers/generate.py
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import hashlib
import json
import os
from datetime import datetime

from asn1crypto import cms, core, tsp, util


OUT_DIR = os.path.dirname(os.path.abspath(__file__))


def _hash(algorithm, data):
    return hashlib.new(algorithm, data).digest()


def _fold(algorithm, values):
    """
    Folds digest values pairwise, each pair sorted, as the RFC 4998 binary
    tree definition requires.
    """

    node = values[0]
    for value in values[1:]:
        left, right = node, value
        if right < left:
            left, right = right, left
        node = _hash(algorithm, left + right)
    return node


def _timestamp(algorithm, imprint, gen_time, serial):
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
    return cms.ContentInfo({
        'content_type': 'signed_data',
        'content': signed_data,
    }).dump()


def _archive_time_stamp(time_stamp_der, explicit_algorithm=None, reduced_hashtree=None):
    fields = {
        'time_stamp': cms.ContentInfo.load(time_stamp_der),
    }
    if explicit_algorithm is not None:
        fields['digest_algorithm'] = {'algorithm': explicit_algorithm}
    if reduced_hashtree is not None:
        fields['reduced_hashtree'] = [[value] for value in reduced_hashtree]
    return tsp.ArchiveTimeStamp(fields)


def _evidence_record(digest_algorithms, chains, path):
    evidence = tsp.EvidenceRecord({
        'version': 'v1',
        'digest_algorithms': [{'algorithm': alg} for alg in digest_algorithms],
        'archive_time_stamp_sequence': list(chains),
    })
    der = evidence.dump()
    with open(os.path.join(OUT_DIR, path), 'wb') as f:
        f.write(der)
    return der


def _entry(chain_index, entry_index, gen_time, imprint, algorithm, source,
           renewal, previous_token_digest=None, previous_chains_digest=None,
           rebuilt_root=None):
    return {
        'chain_index': chain_index,
        'entry_index': entry_index,
        'gen_time': gen_time.isoformat(),
        'algorithm': algorithm,
        'algorithm_source': source,
        'renewal': renewal,
        'imprint_digest': imprint.hex(),
        'previous_token_digest': None if previous_token_digest is None else previous_token_digest.hex(),
        'previous_chains_digest': None if previous_chains_digest is None else previous_chains_digest.hex(),
        'rebuilt_root': None if rebuilt_root is None else rebuilt_root.hex(),
    }


def build_single_chain_two_renewals():
    data = b'archived payload for the single-chain sample'
    t0 = datetime(2024, 1, 1, 0, 0, 0, tzinfo=util.timezone.utc)
    t1 = datetime(2025, 1, 1, 0, 0, 0, tzinfo=util.timezone.utc)
    t2 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=util.timezone.utc)

    initial = _hash('sha256', data)
    ts0_der = _timestamp('sha256', initial, t0, 1)
    ats0 = _archive_time_stamp(ts0_der)  # no explicit algorithm: derive from TSTInfo

    renewal1_leaf = _hash('sha256', ts0_der)
    ts1_der = _timestamp('sha256', renewal1_leaf, t1, 2)
    ats1 = _archive_time_stamp(ts1_der, explicit_algorithm='sha256')

    renewal2_leaf = _hash('sha256', ts1_der)
    ts2_der = _timestamp('sha256', renewal2_leaf, t2, 3)
    ats2 = _archive_time_stamp(ts2_der)  # no explicit algorithm: derive from TSTInfo

    _evidence_record(['sha256'], [_chain(ats0, ats1, ats2)], 'single_chain_two_renewals.der')

    return {
        'description': 'single chain, initial timestamp plus two timestamp renewals',
        'status': 'pass',
        'chains': 1,
        'entries': [
            _entry(0, 0, t0, initial, 'sha256', 'derived', 'initial'),
            _entry(0, 1, t1, renewal1_leaf, 'sha256', 'explicit', 'timestamp',
                   previous_token_digest=renewal1_leaf),
            _entry(0, 2, t2, renewal2_leaf, 'sha256', 'derived', 'timestamp',
                   previous_token_digest=renewal2_leaf),
        ],
        'errors': [],
        'warnings': [],
    }


def _chain(*archive_time_stamps):
    return tsp.ArchiveTimeStampChain(list(archive_time_stamps))


def build_two_chains():
    data = b'archived payload for the two-chain sample'
    t0 = datetime(2024, 1, 1, 0, 0, 0, tzinfo=util.timezone.utc)
    t1 = datetime(2025, 1, 1, 0, 0, 0, tzinfo=util.timezone.utc)
    t2 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=util.timezone.utc)
    t3 = datetime(2027, 1, 1, 0, 0, 0, tzinfo=util.timezone.utc)

    initial = _hash('sha256', data)
    ts0_der = _timestamp('sha256', initial, t0, 11)
    ats0 = _archive_time_stamp(ts0_der)

    renewal_leaf = _hash('sha256', ts0_der)
    ts1_der = _timestamp('sha256', renewal_leaf, t1, 12)
    ats1 = _archive_time_stamp(ts1_der, explicit_algorithm='sha256')
    chain0 = _chain(ats0, ats1)

    previous_chains_digest = _hash('sha256', tsp.ArchiveTimeStampSequence([chain0]).dump())
    sibling = _hash('sha256', b'sibling node in the archive hash tree')
    root = _fold('sha256', [previous_chains_digest, sibling])
    ts2_der = _timestamp('sha256', root, t2, 13)
    ats2 = _archive_time_stamp(
        ts2_der, explicit_algorithm='sha256',
        reduced_hashtree=[previous_chains_digest, sibling],
    )

    renewal2_leaf = _hash('sha256', ts2_der)
    ts3_der = _timestamp('sha256', renewal2_leaf, t3, 14)
    ats3 = _archive_time_stamp(ts3_der)
    chain1 = _chain(ats2, ats3)

    _evidence_record(['sha256'], [chain0, chain1], 'two_chains.der')

    return {
        'description': 'two chains: timestamp renewal, then hash tree renewal with a reduced hash tree',
        'status': 'pass',
        'chains': 2,
        'entries': [
            _entry(0, 0, t0, initial, 'sha256', 'derived', 'initial'),
            _entry(0, 1, t1, renewal_leaf, 'sha256', 'explicit', 'timestamp',
                   previous_token_digest=renewal_leaf),
            _entry(1, 0, t2, root, 'sha256', 'explicit', 'hash_tree',
                   previous_chains_digest=previous_chains_digest,
                   rebuilt_root=root),
            _entry(1, 1, t3, renewal2_leaf, 'sha256', 'derived', 'timestamp',
                   previous_token_digest=renewal2_leaf),
        ],
        'errors': [],
        'warnings': [],
    }


def build_tree_path_altered():
    data = b'archived payload for the altered hash tree path sample'
    t0 = datetime(2024, 1, 1, 0, 0, 0, tzinfo=util.timezone.utc)
    t1 = datetime(2025, 1, 1, 0, 0, 0, tzinfo=util.timezone.utc)
    t2 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=util.timezone.utc)

    initial = _hash('sha256', data)
    ts0_der = _timestamp('sha256', initial, t0, 21)
    ats0 = _archive_time_stamp(ts0_der)

    renewal_leaf = _hash('sha256', ts0_der)
    ts1_der = _timestamp('sha256', renewal_leaf, t1, 22)
    ats1 = _archive_time_stamp(ts1_der, explicit_algorithm='sha256')
    chain0 = _chain(ats0, ats1)

    previous_chains_digest = _hash('sha256', tsp.ArchiveTimeStampSequence([chain0]).dump())
    correct_sibling = _hash('sha256', b'expected sibling in the archive hash tree')
    altered_sibling = _hash('sha256', b'altered sibling in the archive hash tree')
    expected_root = _fold('sha256', [previous_chains_digest, correct_sibling])
    altered_root = _fold('sha256', [previous_chains_digest, altered_sibling])

    # The timestamp signs the correct root, but the reduced path carried in
    # the evidence record was altered after issuance.
    ts2_der = _timestamp('sha256', expected_root, t2, 23)
    ats2 = _archive_time_stamp(
        ts2_der, explicit_algorithm='sha256',
        reduced_hashtree=[previous_chains_digest, altered_sibling],
    )

    _evidence_record(['sha256'], [chain0, _chain(ats2)], 'tree_path_altered.der')

    return {
        'description': 'hash tree renewal whose reduced path sibling was altered after the timestamp was issued',
        'status': 'fail',
        'chains': 2,
        'entries': [
            _entry(0, 0, t0, initial, 'sha256', 'derived', 'initial'),
            _entry(0, 1, t1, renewal_leaf, 'sha256', 'explicit', 'timestamp',
                   previous_token_digest=renewal_leaf),
            _entry(1, 0, t2, expected_root, 'sha256', 'explicit', 'hash_tree',
                   previous_chains_digest=previous_chains_digest,
                   rebuilt_root=altered_root),
        ],
        'errors': [
            {'code': 'renewal_digest_mismatch', 'chain_index': 1, 'entry_index': 0},
        ],
        'warnings': [],
    }


def build_digest_valid_out_of_order():
    data = b'archived payload for the out-of-order sample'
    t0 = datetime(2024, 5, 1, 0, 0, 0, tzinfo=util.timezone.utc)
    t1 = datetime(2024, 3, 1, 0, 0, 0, tzinfo=util.timezone.utc)
    t2 = datetime(2024, 4, 1, 0, 0, 0, tzinfo=util.timezone.utc)

    initial = _hash('sha256', data)
    ts0_der = _timestamp('sha256', initial, t0, 31)
    ats0 = _archive_time_stamp(ts0_der)

    renewal1_leaf = _hash('sha256', ts0_der)
    ts1_der = _timestamp('sha256', renewal1_leaf, t1, 32)
    ats1 = _archive_time_stamp(ts1_der, explicit_algorithm='sha256')

    renewal2_leaf = _hash('sha256', ts1_der)
    ts2_der = _timestamp('sha256', renewal2_leaf, t2, 33)
    ats2 = _archive_time_stamp(ts2_der)

    _evidence_record(['sha256'], [_chain(ats0, ats1, ats2)], 'digest_valid_out_of_order.der')

    return {
        'description': 'digest chain is valid, but the generation times decrease within the chain',
        'status': 'fail',
        'chains': 1,
        'entries': [
            _entry(0, 0, t0, initial, 'sha256', 'derived', 'initial'),
            _entry(0, 1, t1, renewal1_leaf, 'sha256', 'explicit', 'timestamp',
                   previous_token_digest=renewal1_leaf),
            _entry(0, 2, t2, renewal2_leaf, 'sha256', 'derived', 'timestamp',
                   previous_token_digest=renewal2_leaf),
        ],
        'errors': [
            {'code': 'timestamp_order', 'chain_index': 0, 'entry_index': 1},
        ],
        'warnings': [],
    }


def build_hash_tree_algorithm_change():
    data = b'archived payload for the hash tree algorithm change sample'
    t0 = datetime(2024, 1, 1, 0, 0, 0, tzinfo=util.timezone.utc)
    t1 = datetime(2025, 1, 1, 0, 0, 0, tzinfo=util.timezone.utc)
    t2 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=util.timezone.utc)

    initial = _hash('sha256', data)
    ts0_der = _timestamp('sha256', initial, t0, 41)
    ats0 = _archive_time_stamp(ts0_der)

    renewal_leaf = _hash('sha256', ts0_der)
    ts1_der = _timestamp('sha256', renewal_leaf, t1, 42)
    ats1 = _archive_time_stamp(ts1_der, explicit_algorithm='sha256')
    chain0 = _chain(ats0, ats1)

    previous_chains_digest = _hash('sha384', tsp.ArchiveTimeStampSequence([chain0]).dump())
    ts2_der = _timestamp('sha384', previous_chains_digest, t2, 43)
    ats2 = _archive_time_stamp(ts2_der, explicit_algorithm='sha384')
    chain1 = _chain(ats2)

    _evidence_record(['sha256', 'sha384'], [chain0, chain1], 'hash_tree_algorithm_change.der')

    return {
        'description': 'hash tree renewal that switches the digest algorithm from sha256 to sha384',
        'status': 'unverified',
        'chains': 2,
        'entries': [
            _entry(0, 0, t0, initial, 'sha256', 'derived', 'initial'),
            _entry(0, 1, t1, renewal_leaf, 'sha256', 'explicit', 'timestamp',
                   previous_token_digest=renewal_leaf),
            # The timestamp imprint below is what a full re-hash of the
            # previous chains with the new algorithm would produce, but the
            # checker must report this entry as unverified because
            # algorithm-change renewal is not implemented.
            _entry(1, 0, t2, previous_chains_digest, 'sha384', 'explicit', 'hash_tree'),
        ],
        'errors': [],
        'warnings': [
            {'code': 'hash_tree_algorithm_change_unverified', 'chain_index': 1, 'entry_index': 0},
        ],
    }


def build_timestamp_renewal_wrong_digest():
    data = b'archived payload for the wrong renewal digest sample'
    t0 = datetime(2024, 1, 1, 0, 0, 0, tzinfo=util.timezone.utc)
    t1 = datetime(2025, 1, 1, 0, 0, 0, tzinfo=util.timezone.utc)

    initial = _hash('sha256', data)
    ts0_der = _timestamp('sha256', initial, t0, 61)
    ats0 = _archive_time_stamp(ts0_der)

    wrong_imprint = _hash('sha256', ts0_der + b'!')
    ts1_der = _timestamp('sha256', wrong_imprint, t1, 62)
    ats1 = _archive_time_stamp(ts1_der, explicit_algorithm='sha256')

    _evidence_record(['sha256'], [_chain(ats0, ats1)], 'timestamp_renewal_wrong_digest.der')

    return {
        'description': 'second timestamp renews a digest that does not cover the first timestamp token',
        'status': 'fail',
        'chains': 1,
        'entries': [
            _entry(0, 0, t0, initial, 'sha256', 'derived', 'initial'),
            _entry(0, 1, t1, wrong_imprint, 'sha256', 'explicit', 'timestamp',
                   previous_token_digest=_hash('sha256', ts0_der)),
        ],
        'errors': [
            {'code': 'renewal_digest_mismatch', 'chain_index': 0, 'entry_index': 1},
        ],
        'warnings': [],
    }


def build_chain_link_wrong_digest():
    data = b'archived payload for the wrong chain link sample'
    t0 = datetime(2024, 1, 1, 0, 0, 0, tzinfo=util.timezone.utc)
    t1 = datetime(2025, 1, 1, 0, 0, 0, tzinfo=util.timezone.utc)
    t2 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=util.timezone.utc)

    initial = _hash('sha256', data)
    ts0_der = _timestamp('sha256', initial, t0, 71)
    ats0 = _archive_time_stamp(ts0_der)

    renewal_leaf = _hash('sha256', ts0_der)
    ts1_der = _timestamp('sha256', renewal_leaf, t1, 72)
    ats1 = _archive_time_stamp(ts1_der, explicit_algorithm='sha256')
    chain0 = _chain(ats0, ats1)

    unrelated = _hash('sha256', b'unrelated hash tree root')
    ts2_der = _timestamp('sha256', unrelated, t2, 73)
    ats2 = _archive_time_stamp(ts2_der, explicit_algorithm='sha256')

    _evidence_record(['sha256'], [chain0, _chain(ats2)], 'chain_link_wrong_digest.der')

    previous_chains_digest = _hash('sha256', tsp.ArchiveTimeStampSequence([chain0]).dump())

    return {
        'description': 'hash tree renewal does not cover the previous chains',
        'status': 'fail',
        'chains': 2,
        'entries': [
            _entry(0, 0, t0, initial, 'sha256', 'derived', 'initial'),
            _entry(0, 1, t1, renewal_leaf, 'sha256', 'explicit', 'timestamp',
                   previous_token_digest=renewal_leaf),
            _entry(1, 0, t2, unrelated, 'sha256', 'explicit', 'hash_tree',
                   previous_chains_digest=previous_chains_digest,
                   rebuilt_root=unrelated),
        ],
        'errors': [
            {'code': 'renewal_digest_mismatch', 'chain_index': 1, 'entry_index': 0},
        ],
        'warnings': [],
    }


def build_legacy_flat():
    """
    The flat SEQUENCE OF ArchiveTimeStamp layout used before ArchiveTimeStampChain
    was modeled. It is retained only to exercise the explicit migration helper.
    """

    data = b'archived payload for the legacy flat sample'
    t0 = datetime(2024, 1, 1, 0, 0, 0, tzinfo=util.timezone.utc)
    t1 = datetime(2025, 1, 1, 0, 0, 0, tzinfo=util.timezone.utc)

    initial = _hash('sha256', data)
    ts0_der = _timestamp('sha256', initial, t0, 51)
    ats0 = _archive_time_stamp(ts0_der)

    renewal_leaf = _hash('sha256', ts0_der)
    ts1_der = _timestamp('sha256', renewal_leaf, t1, 52)
    ats1 = _archive_time_stamp(ts1_der, explicit_algorithm='sha256')

    flat = core.SequenceOf(spec=tsp.ArchiveTimeStamp)
    flat.append(ats0)
    flat.append(ats1)
    flat_der = flat.dump()
    with open(os.path.join(OUT_DIR, 'legacy_flat_sequence.der'), 'wb') as f:
        f.write(flat_der)

    migrated = tsp.ArchiveTimeStampSequence.from_legacy_flat_der(flat_der)
    with open(os.path.join(OUT_DIR, 'legacy_flat_migrated.der'), 'wb') as f:
        f.write(migrated.dump())

    return {
        'description': 'flat SEQUENCE OF ArchiveTimeStamp and its explicit single-chain migration',
        'flat_der': 'legacy_flat_sequence.der',
        'migrated_der': 'legacy_flat_migrated.der',
        'chains': 1,
        'entries': 2,
        'previous_token_digest': renewal_leaf.hex(),
        'status': 'pass',
    }


def main():
    fixtures = {
        'single_chain_two_renewals': build_single_chain_two_renewals(),
        'two_chains': build_two_chains(),
        'tree_path_altered': build_tree_path_altered(),
        'digest_valid_out_of_order': build_digest_valid_out_of_order(),
        'hash_tree_algorithm_change': build_hash_tree_algorithm_change(),
        'timestamp_renewal_wrong_digest': build_timestamp_renewal_wrong_digest(),
        'chain_link_wrong_digest': build_chain_link_wrong_digest(),
    }
    legacy = build_legacy_flat()

    manifest = {
        'note': 'All digest expectations were computed by generate.py with hashlib, '
                'independently of asn1crypto.ers.',
        'fixtures': fixtures,
        'legacy_flat': legacy,
    }
    with open(os.path.join(OUT_DIR, 'expected.json'), 'w') as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write('\n')


if __name__ == '__main__':
    main()
