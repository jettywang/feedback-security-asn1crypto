# coding: utf-8
"""
Print a human-readable verification report for every corpus case.

This is the offline entry point a backend team can run without pytest:
    python regression_cms_signedattrs/run_report.py

It rebuilds each ContentInfo in memory, loads the on-disk DER copy, runs the
minimal adapter and prints status, structural findings, digest binding and
signature status. Parse success is reported separately from acceptance.
"""
from __future__ import unicode_literals, division, absolute_import, print_function

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from asn1crypto import cms

import corpus
import verifier

GENERATED_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'generated')


def _print_result(result, indent='  '):
    print('%sstatus=%s digest_binding=%s signature=%s'
          % (indent, result.status, result.digest_ok, result.signature_status))
    for finding in result.findings:
        print('%s  - %s: %s' % (indent, finding.code, finding.detail))
    for nested in result.countersignature_results:
        print('%s[%s]' % (indent, nested.location))
        _print_result(nested, indent + '  ')


def main():
    failures = 0
    for content_info, metadata in corpus.build_corpus():
        der_path = os.path.join(GENERATED_DIR, metadata['id'] + '.der')
        with open(der_path, 'rb') as handle:
            parsed = cms.ContentInfo.load(handle.read())  # must parse cleanly
        parse_ok = parsed.dump() == content_info.dump()

        print('=' * 78)
        print('%-42s kind=%-8s parse_ok=%s' % (metadata['id'], metadata['kind'], parse_ok))
        print('  %s' % metadata['description'])
        print('  basis: %s' % metadata['basis'])
        if 'single_change' in metadata:
            print('  single change vs %s: %s' % (metadata['legal_control'], metadata['single_change']))

        results = verifier.verify_content_info(parsed)
        accepted = all(
            result.accepted and all(nested.accepted for nested in result.countersignature_results)
            for result in results
        )
        for result in results:
            _print_result(result)

        want_accepted = metadata['expected_status'] == 'accepted'
        if accepted != want_accepted:
            failures += 1
            print('  !! UNEXPECTED: wanted accepted=%s' % want_accepted)

    print('=' * 78)
    print('report complete: %d unexpected outcome(s)' % failures)
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
