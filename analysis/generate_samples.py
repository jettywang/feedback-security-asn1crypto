# coding: utf-8
"""
Writes the synthetic PKCS#12 evidence samples used by the tests and demos.

Usage::

    python -m analysis.generate_samples OUTPUT_DIR

The generated files are fully decrypted PKCS#12 structures. They contain only
toy RSA values and are intended for evidence-model demonstrations, not for
production use.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import argparse
import json
import os
import sys

from .evidence import analyze_pfx
from .sample_builder import build_samples


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='python -m analysis.generate_samples',
        description='Generate synthetic PKCS#12 SafeBag evidence samples.'
    )
    parser.add_argument('directory', metavar='OUTPUT_DIR')
    parser.add_argument(
        '--report',
        action='store_true',
        help='also write an evidence JSON report beside each sample'
    )
    args = parser.parse_args(argv)

    paths = build_samples(args.directory)
    for name, path in sorted(paths.items()):
        print('%s: %s' % (name, path))
        if args.report:
            report_path = os.path.splitext(path)[0] + '.evidence.json'
            with open(report_path, 'w') as handle:
                json.dump(analyze_pfx(path), handle, indent=2, sort_keys=True)
                handle.write('\n')
            print('  evidence: %s' % report_path)
    return 0


if __name__ == '__main__':
    sys.exit(main())
