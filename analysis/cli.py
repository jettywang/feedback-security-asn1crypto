# coding: utf-8
"""
Command line entry point for rendering PKCS#12 SafeBag evidence reports.

The CLI only reads already-decrypted PKCS#12 files. It never prompts for a
password and never emits private key components.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import argparse
import json
import os
import sys

from .evidence import analyze_pfx


def build_parser():
    parser = argparse.ArgumentParser(
        prog='python -m analysis.cli',
        description='Report SafeBag evidence relationships in decrypted PKCS#12 files.'
    )
    parser.add_argument(
        'paths',
        nargs='+',
        metavar='PKCS12',
        help='one or more already-decrypted PKCS#12 (PFX) files'
    )
    parser.add_argument(
        '--json',
        action='store_true',
        dest='as_json',
        help='emit the full evidence report as JSON'
    )
    parser.add_argument(
        '--indent',
        type=int,
        default=2,
        help='JSON indentation width (default: 2)'
    )
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    reports = []
    exit_code = 0
    for path in args.paths:
        if not os.path.exists(path):
            sys.stderr.write('missing input: %s\n' % path)
            exit_code = 1
            continue
        try:
            report = analyze_pfx(path)
        except (ValueError, TypeError) as exc:
            sys.stderr.write('cannot analyze %s: %s\n' % (path, exc))
            exit_code = 1
            continue
        reports.append(report)

    if args.as_json:
        payload = reports[0] if len(reports) == 1 else reports
        json.dump(payload, sys.stdout, indent=args.indent, sort_keys=True)
        sys.stdout.write('\n')
    else:
        for report in reports:
            _print_summary(report)
    return exit_code


def _print_summary(report):
    summary = report['summary']
    print('input: %s' % report['input']['source'])
    print('  container: %s  sha256: %s' % (report['input']['container'], report['input']['sha256']))
    print('  bags: %d (keys %d, shrouded %d, certificates %d, containers %d)' % (
        summary['bags'], summary['key_bags'], summary['shrouded_key_bags'],
        summary['certificate_bags'], summary['containers']
    ))
    print('  proof-backed pairs: %d  metadata candidates: %d  conflicts: %d  orphans: %d' % (
        summary['proof_pairs'], summary['candidate_links'], summary['metadata_conflicts'],
        summary['orphan_keys'] + summary['orphan_certificates']
    ))
    for pair in report['pairs']:
        print('  pair %s <-> %s  fingerprint %s' % (
            ', '.join(pair['key_ids']), ', '.join(pair['certificate_ids']), pair['fingerprint']
        ))
        for warning in pair['warnings']:
            print('    warning: %s' % warning['message'])
    for candidate in report['candidates']:
        print('  candidate %s <-> %s (%s%s)' % (
            candidate['key_id'], candidate['certificate_id'],
            'metadata only', ', conflicting public keys' if candidate['fingerprint_conflict'] else ''
        ))
    for orphan in report['orphans']:
        print('  orphan %s %s: %s' % (orphan['type'], orphan['path'], orphan['reason']))
    for conflict in report['conflicts']:
        print('  conflict %s: %s' % (conflict['code'], conflict['message']))
    print('  private key bytes exposed: %s' % summary['private_key_bytes_exposed'])


if __name__ == '__main__':
    sys.exit(main())
