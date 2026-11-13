# coding: utf-8

"""
End-to-end checks for ocsp_match.matcher.

The test vectors deliberately cross every failure mode the matcher must keep
distinct: two digest algorithms, same-name/different-key issuers, same-key
re-issued issuers, shuffled and duplicated responses, unsupported digests,
illegal algorithm parameters, missing answers, duplicate conflicts and a
correctly-signed response whose SingleResponse names the wrong certificate.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest

from asn1crypto.ocsp import CertId, OCSPRequest, OCSPResponse

from ocsp_match import (
    MatchStatus,
    OcspMatchError,
    ResponseDisposition,
    issuer_fingerprint,
    match_ocsp,
    parse_cert_id,
)
from ocsp_match_tests import _fixtures as fx


def _verify_signature(ca, basic_response):
    """Independent OpenSSL verification of a BasicOCSPResponse signature."""

    working_dir = tempfile.mkdtemp(prefix='ocsp-verify-')
    try:
        tbs_path = os.path.join(working_dir, 'tbs.der')
        sig_path = os.path.join(working_dir, 'sig.bin')
        pub_path = os.path.join(working_dir, 'pub.pem')
        with open(tbs_path, 'wb') as handle:
            handle.write(basic_response['tbs_response_data'].dump())
        with open(sig_path, 'wb') as handle:
            handle.write(basic_response['signature'].native)
        public_pem = subprocess.run(
            [fx._OPENSSL, 'pkey', '-in', ca.key_path, '-pubout'],
            capture_output=True,
            check=True,
        ).stdout
        with open(pub_path, 'wb') as handle:
            handle.write(public_pem)
        result = subprocess.run(
            [
                fx._OPENSSL, 'dgst', '-sha256', '-verify', pub_path,
                '-signature', sig_path, tbs_path,
            ],
            capture_output=True,
        )
        return result.stdout.decode().strip() == 'Verified OK'
    finally:
        shutil.rmtree(working_dir, ignore_errors=True)


@unittest.skipUnless(fx.openssl_available(), 'openssl CLI required for fixtures')
class OcspMatcherTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.world = fx.build_world()
        cls.ca_a = cls.world['ca_a']
        cls.ca_b = cls.world['ca_b']
        cls.ca_a_prime = cls.world['ca_a_prime']
        cls.ca_c = cls.world['ca_c']
        cls.issuers = [
            ('A', cls.ca_a.certificate),
            ('B', cls.ca_b.certificate),
            ('A_prime', cls.ca_a_prime.certificate),
            ('C', cls.ca_c.certificate),
        ]

    @classmethod
    def tearDownClass(cls):
        fx.teardown_world(cls.world)

    def _report_for_source(self, report, source):
        reports = [item for item in report.requests if item.source == source]
        self.assertEqual(len(reports), 1)
        return reports[0]

    def test_hash_boundaries_match_independent_hashlib_vectors(self):
        for algorithm, oid in (('sha1', fx.SHA1_OID), ('sha256', fx.SHA256_OID)):
            for ca in (self.ca_a, self.ca_b, self.ca_a_prime, self.ca_c):
                reference = fx.independent_issuer_hashes(ca.certificate, algorithm)
                fingerprint = issuer_fingerprint(ca.certificate, algorithms=(algorithm,))
                evidence = fingerprint.fingerprints[0]

                self.assertEqual(evidence.algorithm, algorithm)
                self.assertEqual(evidence.algorithm_oid, oid)
                self.assertEqual(evidence.name_der, reference['name_der'])
                self.assertEqual(evidence.key_bit_string_payload, reference['key_payload'])
                self.assertEqual(evidence.name_hash, reference['name_hash'])
                self.assertEqual(evidence.key_hash, reference['key_hash'])

                # The two forbidden shortcuts must produce different digests.
                self.assertNotEqual(evidence.key_hash, reference['whole_spki_hash'])
                self.assertNotEqual(evidence.name_hash, reference['display_name_hash'])

                # Recompute once more directly with hashlib, no production helper.
                self.assertEqual(
                    evidence.name_hash,
                    hashlib.new(algorithm, ca.certificate.subject.dump()).digest(),
                )
                bit_string = ca.certificate['tbs_certificate'][
                    'subject_public_key_info'
                ]['public_key']
                self.assertEqual(
                    evidence.key_hash,
                    hashlib.new(algorithm, bit_string.contents[1:]).digest(),
                )

    def test_same_name_different_key_keeps_candidates_distinct(self):
        self.assertEqual(
            self.ca_a.certificate.subject.dump(),
            self.ca_b.certificate.subject.dump(),
        )
        fp_a = issuer_fingerprint(self.ca_a.certificate, algorithms=('sha256',))
        fp_b = issuer_fingerprint(self.ca_b.certificate, algorithms=('sha256',))
        self.assertEqual(
            fp_a.fingerprints[0].name_hash,
            fp_b.fingerprints[0].name_hash,
        )
        self.assertNotEqual(
            fp_a.fingerprints[0].key_hash,
            fp_b.fingerprints[0].key_hash,
        )

    def test_reissued_same_key_issuer_is_ambiguous_not_first_wins(self):
        fp_a = issuer_fingerprint(self.ca_a.certificate, algorithms=('sha256',))
        fp_prime = issuer_fingerprint(self.ca_a_prime.certificate, algorithms=('sha256',))
        self.assertEqual(
            fp_a.fingerprints[0].key_hash,
            fp_prime.fingerprints[0].key_hash,
        )
        self.assertEqual(
            fp_a.fingerprints[0].name_hash,
            fp_prime.fingerprints[0].name_hash,
        )
        self.assertNotEqual(
            self.ca_a.certificate.serial_number,
            self.ca_a_prime.certificate.serial_number,
        )

        cert_id = fx.make_cert_id(self.ca_a, 5101)
        request = fx.make_request(cert_id)
        single = fx.make_single_response(
            cert_id, 'good', '2026-11-13T09:00:00', '2026-11-20T09:00:00'
        )
        response = fx.make_ocsp_response(self.ca_a, [single])

        report = match_ocsp([request], [response.dump()], self.issuers)
        result = report.requests[0]
        self.assertIs(result.status, MatchStatus.AMBIGUOUS)
        self.assertEqual(
            sorted(item.label for item in result.issuers),
            ['A', 'A_prime'],
        )
        self.assertEqual(len(report.ambiguous), 1)
        self.assertEqual(report.matched, ())

    def test_unique_issuer_matches_and_preserves_evidence(self):
        cert_id = fx.make_cert_id(self.ca_c, 5201)
        request = fx.make_request(cert_id)
        single = fx.make_single_response(
            cert_id,
            'revoked',
            '2026-11-13T09:00:00',
            '2026-11-20T09:00:00',
            revocation_time='2026-11-10T12:00:00',
        )
        response = fx.make_ocsp_response(self.ca_c, [single])

        report = match_ocsp(
            [('batch-line-7', request)], [response.dump()], self.issuers
        )
        result = self._report_for_source(report, 'batch-line-7')
        self.assertIs(result.status, MatchStatus.MATCHED)
        self.assertEqual([item.label for item in result.issuers], ['C'])

        evidence = result.responses[0]
        self.assertEqual(evidence.status_name, 'revoked')
        self.assertEqual(
            evidence.revocation_time.isoformat(), '2026-11-10T12:00:00+00:00'
        )
        self.assertEqual(
            evidence.this_update.isoformat(), '2026-11-13T09:00:00+00:00'
        )
        self.assertEqual(
            evidence.next_update.isoformat(), '2026-11-20T09:00:00+00:00'
        )
        self.assertEqual(evidence.cert_id.serial_number, 5201)
        self.assertEqual(len(report.matched), 1)

    def test_cross_algorithm_requests_both_resolve(self):
        sha256_id = fx.make_cert_id(self.ca_c, 5301, fx.SHA256_OID, 'sha256')
        sha1_id = fx.make_cert_id(self.ca_c, 5301, fx.SHA1_OID, 'sha1')
        request_256 = fx.make_request(sha256_id)
        request_1 = fx.make_request(sha1_id)

        response = fx.make_ocsp_response(self.ca_c, [
            fx.make_single_response(sha256_id, 'good', '2026-11-13T09:00:00'),
            fx.make_single_response(sha1_id, 'good', '2026-11-13T09:00:00'),
        ])

        report = match_ocsp(
            [('sha256-req', request_256), ('sha1-req', request_1)],
            [response.dump()],
            self.issuers,
            digest_algorithms=('sha1', 'sha256'),
        )
        by_source = {item.source: item for item in report.requests}
        self.assertIs(by_source['sha256-req'].status, MatchStatus.MATCHED)
        self.assertIs(by_source['sha1-req'].status, MatchStatus.MATCHED)
        self.assertEqual(
            by_source['sha256-req'].cert_id.algorithm_oid, fx.SHA256_OID
        )
        self.assertEqual(
            by_source['sha1-req'].cert_id.algorithm_oid, fx.SHA1_OID
        )

    def test_same_serial_different_issuer_is_distinguished_by_hashes(self):
        # Two unrelated issuers each issue a certificate with the same serial.
        shared_serial = 9901
        ca_a_cert_id = fx.make_cert_id(self.ca_a, shared_serial)
        ca_c_cert_id = fx.make_cert_id(self.ca_c, shared_serial)
        self.assertEqual(
            ca_a_cert_id['serial_number'].native,
            ca_c_cert_id['serial_number'].native,
        )
        self.assertNotEqual(
            ca_a_cert_id['issuer_name_hash'].native,
            ca_c_cert_id['issuer_name_hash'].native,
        )
        # Responses arrive shuffled relative to request order.
        response = fx.make_ocsp_response(self.ca_c, [
            fx.make_single_response(
                ca_c_cert_id, 'good', '2026-11-13T09:00:00'
            ),
            fx.make_single_response(
                ca_a_cert_id, 'unknown', '2026-11-13T09:00:00'
            ),
        ])
        report = match_ocsp(
            [
                ('a-serial', fx.make_request(ca_a_cert_id)),
                ('c-serial', fx.make_request(ca_c_cert_id)),
            ],
            [response.dump()],
            self.issuers,
        )
        by_source = {item.source: item for item in report.requests}
        a_result = by_source['a-serial']
        c_result = by_source['c-serial']
        self.assertEqual(
            sorted(item.label for item in a_result.issuers),
            ['A', 'A_prime'],
        )
        self.assertEqual(
            [item.label for item in c_result.issuers], ['C']
        )
        self.assertEqual(
            a_result.responses[0].status_name, 'unknown'
        )
        self.assertEqual(
            c_result.responses[0].status_name, 'good'
        )

    def test_shuffled_cross_algorithm_responses_resolve_independently(self):
        # Same issuer/serial requested under both digests; response order is
        # reversed and mixed inside one BasicOCSPResponse.
        serial = 9902
        sha256_id = fx.make_cert_id(self.ca_c, serial, fx.SHA256_OID, 'sha256')
        sha1_id = fx.make_cert_id(self.ca_c, serial, fx.SHA1_OID, 'sha1')
        response = fx.make_ocsp_response(self.ca_c, [
            fx.make_single_response(sha1_id, 'good', '2026-11-13T08:00:00'),
            fx.make_single_response(sha256_id, 'good', '2026-11-13T09:00:00'),
        ])
        report = match_ocsp(
            [
                ('sha256-first', fx.make_request(sha256_id)),
                ('sha1-first', fx.make_request(sha1_id)),
            ],
            [response.dump()],
            self.issuers,
            digest_algorithms=('sha1', 'sha256'),
        )
        by_source = {item.source: item for item in report.requests}
        self.assertEqual(
            by_source['sha256-first'].responses[0].cert_id.algorithm_oid,
            fx.SHA256_OID,
        )
        self.assertEqual(
            by_source['sha1-first'].responses[0].cert_id.algorithm_oid,
            fx.SHA1_OID,
        )
        self.assertEqual(
            by_source['sha256-first'].responses[0].this_update.hour, 9
        )
        self.assertEqual(
            by_source['sha1-first'].responses[0].this_update.hour, 8
        )
        for result in by_source.values():
            self.assertIs(result.status, MatchStatus.MATCHED)

    def test_equivalent_requests_share_response_without_losing_sources(self):
        cert_id = fx.make_cert_id(self.ca_c, 5401)
        request_one = fx.make_request(cert_id)
        request_two = fx.make_request(cert_id)
        single = fx.make_single_response(
            cert_id, 'good', '2026-11-13T09:00:00', '2026-11-20T09:00:00'
        )
        response = fx.make_ocsp_response(self.ca_c, [single])

        report = match_ocsp(
            [('source-A', request_one), ('source-B', request_two)],
            [response.dump()],
            self.issuers,
        )
        self.assertEqual(len(report.requests), 2)
        self.assertEqual(
            sorted(item.source for item in report.requests),
            ['source-A', 'source-B'],
        )
        for item in report.requests:
            self.assertIs(item.status, MatchStatus.MATCHED)
            self.assertEqual(len(item.responses), 1)
            self.assertEqual(
                item.responses[0].this_update.isoformat(),
                '2026-11-13T09:00:00+00:00',
            )
        groups = report.groups
        self.assertEqual(len(groups), 1)
        self.assertEqual(len(next(iter(groups.values()))), 2)

    def test_shuffled_duplicate_consistent_responses_are_flagged(self):
        cert_id = fx.make_cert_id(self.ca_c, 5501)
        request = fx.make_request(cert_id)
        first = fx.make_single_response(
            cert_id, 'good', '2026-11-13T09:00:00', '2026-11-20T09:00:00'
        )
        second = fx.make_single_response(
            cert_id, 'good', '2026-11-13T09:00:00', '2026-11-20T09:00:00'
        )
        # Deliberately reversed message order.
        response = fx.make_ocsp_response(self.ca_c, [second, first])

        report = match_ocsp([request], [response.dump()], self.issuers)
        self.assertIs(report.requests[0].status, MatchStatus.MATCHED)
        self.assertEqual(len(report.duplicate_responses), 1)
        duplicate = report.duplicate_responses[0]
        self.assertIs(
            duplicate.disposition, ResponseDisposition.DUPLICATE_CONSISTENT
        )
        self.assertEqual(len(duplicate.evidence), 2)
        self.assertEqual(report.unmatched_responses, ())

    def test_duplicate_conflicting_responses_are_mismatch(self):
        cert_id = fx.make_cert_id(self.ca_c, 5601)
        request = fx.make_request(cert_id)
        good = fx.make_single_response(
            cert_id, 'good', '2026-11-13T09:00:00'
        )
        revoked = fx.make_single_response(
            cert_id,
            'revoked',
            '2026-11-13T09:00:00',
            revocation_time='2026-11-01T00:00:00',
        )
        response = fx.make_ocsp_response(self.ca_c, [good, revoked])

        report = match_ocsp([request], [response.dump()], self.issuers)
        result = report.requests[0]
        self.assertIs(result.status, MatchStatus.MISMATCH)
        self.assertIn('disagree on status', result.reason)
        self.assertIsNotNone(result.conflict)
        self.assertEqual(len(result.responses), 2)
        self.assertEqual(len(report.duplicate_responses), 1)
        self.assertIs(
            report.duplicate_responses[0].disposition,
            ResponseDisposition.DUPLICATE_CONFLICT,
        )
        self.assertEqual(report.unmatched_responses, ())

    def test_duplicates_across_messages_keep_message_index(self):
        cert_id = fx.make_cert_id(self.ca_c, 8001)
        request = fx.make_request(cert_id)
        first_message = fx.make_ocsp_response(
            self.ca_c,
            [fx.make_single_response(
                cert_id, 'good', '2026-11-13T09:00:00'
            )],
            produced_at='2026-11-13T10:00:00',
        )
        second_message = fx.make_ocsp_response(
            self.ca_c,
            [fx.make_single_response(
                cert_id, 'good', '2026-11-13T11:00:00'
            )],
            produced_at='2026-11-13T12:00:00',
        )

        report = match_ocsp(
            [request],
            [first_message.dump(), second_message.dump()],
            self.issuers,
        )
        result = report.requests[0]
        self.assertIs(result.status, MatchStatus.MATCHED)
        self.assertEqual(len(result.responses), 2)
        self.assertEqual(
            sorted(item.message_index for item in result.responses), [0, 1]
        )
        self.assertEqual(len(report.duplicate_responses), 1)
        self.assertIs(
            report.duplicate_responses[0].disposition,
            ResponseDisposition.DUPLICATE_CONSISTENT,
        )
        self.assertEqual(
            sorted(item.this_update.hour for item in result.responses),
            [9, 11],
        )

    def test_missing_response_is_distinct_from_mismatch(self):
        cert_id = fx.make_cert_id(self.ca_c, 5701)
        request = fx.make_request(cert_id)
        empty_response = fx.make_ocsp_response(self.ca_c, [])

        report = match_ocsp([request], [empty_response.dump()], self.issuers)
        self.assertIs(report.requests[0].status, MatchStatus.MISSING_RESPONSE)
        self.assertEqual(len(report.missing), 1)
        self.assertEqual(report.mismatched, ())

    def test_non_successful_response_counts_as_missing_with_notice(self):
        cert_id = fx.make_cert_id(self.ca_c, 5702)
        request = fx.make_request(cert_id)
        error_response = fx.make_error_response('try_later')

        report = match_ocsp([request], [error_response.dump()], self.issuers)
        self.assertIs(report.requests[0].status, MatchStatus.MISSING_RESPONSE)
        self.assertEqual(
            report.non_successful_responses[0]['response_status'], 'try_later'
        )

    def test_unsupported_digest_is_reported_not_hashed(self):
        vectors = fx.independent_issuer_hashes(self.ca_c.certificate, 'sha256')
        # Whirlpool digest OID (1.0.10118.3.0.55): a real digest OID that the
        # recomputation table does not support.  Parameters stay NULL so that
        # "unsupported" and "illegal parameters" remain distinct outcomes.
        whirlpool_oid = '1.0.10118.3.0.55'
        raw_der = fx.make_raw_cert_id_with_null_parameters(
            whirlpool_oid,
            vectors['name_hash'],
            vectors['key_hash'],
            5801,
        )
        cert_id = CertId.load(raw_der)
        request = fx.make_request(cert_id)

        report = match_ocsp([request], [], self.issuers)
        result = report.requests[0]
        self.assertIs(result.status, MatchStatus.UNSUPPORTED_DIGEST)
        self.assertEqual(len(report.unsupported), 1)
        self.assertEqual(result.cert_id.algorithm_oid, whirlpool_oid)
        self.assertEqual(result.cert_id.parameters_kind, 'null')

    def test_illegal_algorithm_parameters_are_rejected(self):
        vectors = fx.independent_issuer_hashes(self.ca_c.certificate, 'sha256')
        # parameters must be NULL; here an OID sits in the parameters slot.
        raw_der = fx.make_raw_cert_id(
            fx.SHA256_OID,
            fx.SHA256_RSA_OID,
            vectors['name_hash'],
            vectors['key_hash'],
            5901,
        )
        cert_id = CertId.load(raw_der)
        parsed = parse_cert_id(cert_id)
        self.assertFalse(parsed.valid_parameters)
        self.assertEqual(parsed.parameters_kind, 'ObjectIdentifier')

        request = fx.make_request(cert_id)
        report = match_ocsp(
            [request],
            [fx.make_ocsp_response(
                self.ca_c,
                [fx.make_single_response(cert_id, 'good', '2026-11-13T09:00:00')],
            ).dump()],
            self.issuers,
        )
        result = report.requests[0]
        self.assertIs(result.status, MatchStatus.INVALID_ALGORITHM_PARAMETERS)
        self.assertEqual(len(report.invalid_parameters), 1)

    def test_wrong_certificate_signed_response_is_near_miss_or_mismatch(self):
        # The response is structurally complete and validly signed by ca_b,
        # yet its SingleResponse identifies ca_c's certificate material.
        target_id = fx.make_cert_id(self.ca_c, 6001)
        single = fx.make_single_response(
            target_id, 'good', '2026-11-13T09:00:00', '2026-11-20T09:00:00'
        )
        response = fx.make_ocsp_response(self.ca_b, [single])
        parsed_response = OCSPResponse.load(response.dump())
        basic = parsed_response.basic_ocsp_response

        # The signature itself is valid: the structural counterexample is a
        # well-formed, verifiable OCSP response, not corrupted DER.
        self.assertTrue(_verify_signature(self.ca_b, basic))
        embedded = basic['certs'][0]
        self.assertEqual(
            embedded['tbs_certificate']['subject_public_key_info'].dump(),
            self.ca_b.public_key_info.dump(),
        )
        self.assertNotEqual(
            embedded['tbs_certificate']['subject_public_key_info'].dump(),
            self.ca_c.public_key_info.dump(),
        )
        # ...while the CertId carried inside points at ca_c's material.
        carried = basic['tbs_response_data']['responses'][0]['cert_id']
        self.assertEqual(carried['issuer_key_hash'].native, target_id['issuer_key_hash'].native)

        # Request names ca_c material; response answers it but the only
        # signing issuer embedded is ca_b - matching itself is still exact on
        # CertId, while a request for a serial nobody answers becomes orphan.
        report = match_ocsp(
            [fx.make_request(target_id)],
            [response.dump()],
            self.issuers,
        )
        self.assertIs(report.requests[0].status, MatchStatus.MATCHED)
        self.assertEqual(
            [item.label for item in report.requests[0].issuers], ['C']
        )
        # The matcher never asserts the embedded signer is the right trust
        # anchor; it only records which issuer the CertId hashes reproduce.
        self.assertFalse(hasattr(report.requests[0], 'trusted'))

        # Now flip the request to a different serial: the signed response no
        # longer answers any request and becomes an orphan/near-miss.
        other_id = fx.make_cert_id(self.ca_c, 6002)
        orphan_report = match_ocsp(
            [fx.make_request(other_id)],
            [response.dump()],
            self.issuers,
        )
        self.assertIs(
            orphan_report.requests[0].status, MatchStatus.MISSING_RESPONSE
        )
        self.assertTrue(orphan_report.unmatched_responses)
        dispositions = {
            item.disposition for item in orphan_report.unmatched_responses
        }
        self.assertTrue(dispositions & {
            ResponseDisposition.ORPHAN,
            ResponseDisposition.NEAR_MISS,
        })

        # With ca_c excluded from the candidate set, no issuer reproduces even
        # one hash component, so the same signed response is a pure orphan.
        pure_orphan_report = match_ocsp(
            [fx.make_request(other_id)],
            [response.dump()],
            [('A', self.ca_a.certificate), ('B', self.ca_b.certificate)],
        )
        orphan_entry = pure_orphan_report.unmatched_responses[0]
        self.assertIs(orphan_entry.disposition, ResponseDisposition.ORPHAN)
        self.assertEqual(orphan_entry.near_misses, ())

    def test_name_only_match_is_mismatch_with_near_miss_evidence(self):
        # Same DN as ca_a/ca_b but a CertId built from ca_b's key, while the
        # candidate list deliberately omits ca_b.
        cert_id = fx.make_cert_id(self.ca_b, 6101)
        request = fx.make_request(cert_id)

        # The response answers a different serial: it cannot attach to the
        # request and becomes an orphan.  ca_a's identical DN still makes the
        # issuerNameHash collide, producing a name-only near-miss hint.
        foreign_id = fx.make_cert_id(self.ca_b, 6199)
        foreign_single = fx.make_single_response(
            foreign_id, 'good', '2026-11-13T09:00:00'
        )
        response = fx.make_ocsp_response(self.ca_b, [foreign_single])

        report = match_ocsp(
            [request],
            [response.dump()],
            [('A', self.ca_a.certificate), ('C', self.ca_c.certificate)],
        )
        result = report.requests[0]
        self.assertIs(result.status, MatchStatus.MISSING_RESPONSE)
        self.assertEqual(result.issuers, ())

        orphan = report.unmatched_responses[0]
        self.assertIs(orphan.disposition, ResponseDisposition.NEAR_MISS)
        self.assertTrue(any(
            hint['name_hash_equal'] and not hint['key_hash_equal']
            for hint in orphan.near_misses
        ))

    def test_issuer_fingerprint_rejects_non_octet_key_boundary_input(self):
        cert_id = fx.make_cert_id(self.ca_c, 6201)
        with self.assertRaises(OcspMatchError):
            issuer_fingerprint(cert_id)

    def test_shuffled_full_batch_classifies_every_outcome(self):
        matched_id = fx.make_cert_id(self.ca_c, 7001)
        ambiguous_id = fx.make_cert_id(self.ca_a, 7002)
        missing_id = fx.make_cert_id(self.ca_c, 7003)
        conflict_id = fx.make_cert_id(self.ca_c, 7004)

        requests = [
            ('matched', fx.make_request(matched_id)),
            ('ambiguous', fx.make_request(ambiguous_id)),
            ('missing', fx.make_request(missing_id)),
            ('conflict', fx.make_request(conflict_id)),
        ]

        singles = [
            fx.make_single_response(
                conflict_id, 'good', '2026-11-13T09:00:00'
            ),
            fx.make_single_response(
                ambiguous_id, 'good', '2026-11-13T09:00:00'
            ),
            fx.make_single_response(
                conflict_id,
                'revoked',
                '2026-11-13T09:00:00',
                revocation_time='2026-11-05T00:00:00',
            ),
            fx.make_single_response(
                matched_id, 'good', '2026-11-13T09:00:00',
                '2026-11-20T09:00:00',
            ),
        ]
        response = fx.make_ocsp_response(self.ca_c, singles)

        report = match_ocsp(
            requests, [response.dump()], self.issuers
        )
        statuses = {item.source: item.status for item in report.requests}
        self.assertIs(statuses['matched'], MatchStatus.MATCHED)
        self.assertIs(statuses['ambiguous'], MatchStatus.AMBIGUOUS)
        self.assertIs(statuses['missing'], MatchStatus.MISSING_RESPONSE)
        self.assertIs(statuses['conflict'], MatchStatus.MISMATCH)
        ambiguous_report = next(
            item for item in report.requests if item.source == 'ambiguous'
        )
        self.assertEqual(
            sorted(item.label for item in ambiguous_report.issuers),
            ['A', 'A_prime'],
        )

    def test_missing_precomputed_algorithm_raises_instead_of_false_mismatch(self):
        cert_id = fx.make_cert_id(self.ca_c, 9101, fx.SHA1_OID, 'sha1')
        request = fx.make_request(cert_id)
        response = fx.make_ocsp_response(
            self.ca_c,
            [fx.make_single_response(cert_id, 'good', '2026-11-13T09:00:00')],
        )
        with self.assertRaises(OcspMatchError) as context:
            match_ocsp(
                [request],
                [response.dump()],
                self.issuers,
                digest_algorithms=('sha256',),
            )
        self.assertIn('sha1', str(context.exception))

    def test_malformed_der_raises_typed_error(self):
        with self.assertRaises(OcspMatchError):
            match_ocsp([b'\x30\x03\x02\x01'], [], self.issuers)
        with self.assertRaises(OcspMatchError):
            match_ocsp([], [b'\x30\x03\x02\x01'], self.issuers)
        with self.assertRaises(OcspMatchError):
            issuer_fingerprint(b'\x30\x03\x02\x01')

    def test_matcher_does_not_claim_trust(self):
        # The report exposes raw structures and timestamps but contains no
        # field asserting signature validity or freshness.
        cert_id = fx.make_cert_id(self.ca_c, 7101)
        response = fx.make_ocsp_response(
            self.ca_c,
            [fx.make_single_response(
                cert_id, 'good', '2026-11-13T09:00:00',
                '2026-11-20T09:00:00',
            )],
        )
        report = match_ocsp(
            [fx.make_request(cert_id)], [response.dump()], self.issuers
        )
        result = report.requests[0]
        self.assertFalse(hasattr(result, 'trusted'))
        self.assertFalse(hasattr(result, 'signature_valid'))
        self.assertIsNotNone(result.responses[0].single_response)


if __name__ == '__main__':
    unittest.main()
