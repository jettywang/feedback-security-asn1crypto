# coding: utf-8
"""
Drive the six generated CSRs through:
  1. raw structural inspection (attribute count, SET values, duplicate extnIDs)
  2. re-encoding / round-trip checks (DER SET OF sorting, mutation stability)
  3. the strict extractor (reject-or-describe contract)
  4. three naive anti-patterns, exposing which applicant claim silently wins

Run:
    python analyze_samples.py [generated_dir]
Exit code is always zero; this is an audit report, not a test gate.
"""
from __future__ import unicode_literals, print_function

import json
import os
import sys

from asn1crypto import core, csr, pem, x509

from naive_antipatterns import (
    first_attribute_only,
    flatten_last_wins,
    load,
    native_dict_squash,
)
from strict_extraction import AmbiguousRequest, extract_csr_extensions

EXTENSION_REQUEST_OID = '1.2.840.113549.1.9.14'
BC_OID = '2.5.29.19'
SAN_OID = '2.5.29.17'


def _extension_values(attr):
    values_field = attr['values']
    if isinstance(values_field, core.Any):
        values_field = values_field.parsed
    return values_field


def inspect_structure(request):
    """Describe the raw layout without collapsing anything into a dict."""
    cri = request['certification_request_info']
    lines = []
    attr_oids = []
    er_count = 0
    dup_detail = []

    for attr_pos, attr in enumerate(cri['attributes']):
        oid = attr['type'].dotted
        attr_oids.append('%s (%s)' % (oid, attr['type'].native))
        if oid != EXTENSION_REQUEST_OID:
            continue
        er_count += 1
        values = list(_extension_values(attr))
        lines.append('  extensionRequest #%d: %d Extensions value(s) in SET'
                     % (er_count, len(values)))
        for value_pos, extensions_seq in enumerate(values):
            ids = [ext['extn_id'].dotted for ext in extensions_seq]
            lines.append('    value[%d] extnIDs = %s' % (value_pos, ids))
            seen = {}
            for idx, ext in enumerate(extensions_seq):
                o = ext['extn_id'].dotted
                seen.setdefault(o, []).append(idx)
            for o, positions in seen.items():
                if len(positions) > 1:
                    dup_detail.append((o, positions))
                    lines.append('    !! duplicate OID %s at positions %s'
                                 % (o, positions))
    return {
        'attribute_order': attr_oids,
        'extension_request_count': er_count,
        'duplicates': dup_detail,
        'lines': lines,
    }


def check_reencoding(der_bytes, request):
    reparsed = csr.CertificationRequest.load(der_bytes)
    re_encoded = reparsed.dump(force=True)
    return {
        'byte_identical_roundtrip': re_encoded == der_bytes,
        'force_der_length': len(re_encoded),
        'original_length': len(der_bytes),
        'attribute_order_after_force': [
            '%s' % a['type'].dotted for a in reparsed['certification_request_info']['attributes']
        ],
    }


def summarize_bc(ext_map):
    """Decode whichever basicConstraints entry survives a naive merge."""
    entry = ext_map.get(BC_OID)
    if entry is None:
        return None
    bc = x509.BasicConstraints.load(entry['raw_extn_value'])
    out = {'ca': bool(bc['ca'].native), 'critical': entry['critical']}
    if bc['path_len_constraint'].native is not None:
        out['path_len'] = bc['path_len_constraint'].native
    return out


def summarize_san(ext_map):
    entry = ext_map.get(SAN_OID)
    if entry is None:
        return None
    names = x509.GeneralNames.load(entry['raw_extn_value'])
    return {
        'critical': entry['critical'],
        'names': [gn.native for gn in names],
    }


def report(base_dir):
    with open(os.path.join(base_dir, 'manifest.json')) as f:
        manifest = json.load(f)

    summaries = []
    for entry in manifest:
        der_path = os.path.join(base_dir, entry['der_file'])
        with open(der_path, 'rb') as f:
            der_bytes = f.read()
        request = load(der_bytes)

        print('=' * 78)
        print('SAMPLE %s' % entry['name'])
        print('  %s' % entry['description'])
        print('  self-signature valid: %s (signature only proves key possession)'
              % entry['self_signature_valid'])

        structure = inspect_structure(request)
        print('  CRI attributes in encoded order:')
        for oid_desc in structure['attribute_order']:
            print('    - %s' % oid_desc)
        for line in structure['lines']:
            print(line)

        enc = check_reencoding(der_bytes, request)
        print('  re-encoding: identical=%s; SET OF order after force-dump: %s'
              % (enc['byte_identical_roundtrip'],
                 enc['attribute_order_after_force']))

        try:
            strict = extract_csr_extensions(request)
            print('  STRICT EXTRACTOR: accepted, %d extension(s) with provenance:'
                  % len(strict['extensions']))
            for ext in strict['extensions']:
                print('    [%d] oid=%s name=%s critical=%s known_semantics=%s'
                      % (ext['index'], ext['extn_id'], ext['extn_name'],
                         ext['critical'], ext['parsed'] is not None))
            if strict['other_attributes']:
                print('  non-extensionRequest attributes (applicant metadata only):')
                for other in strict['other_attributes']:
                    print('    - %s (%s)' % (other['attr_oid'], other['attr_name']))
            verdict = 'ACCEPT-STRUCTURE'
        except AmbiguousRequest as e:
            print('  STRICT EXTRACTOR: REJECT -> %s' % e)
            verdict = 'REJECT-AMBIGUOUS'

        last_wins = flatten_last_wins(request)
        first_only = first_attribute_only(request)
        squash = native_dict_squash(request)
        print('  ANTI-PATTERN flatten_last_wins -> bc=%r san=%r'
              % (summarize_bc(last_wins), summarize_san(last_wins)))
        print('  ANTI-PATTERN first_attribute_only -> %d extension(s), bc present=%s'
              % (len(first_only), any(e['extn_id'] == BC_OID for e in first_only)))
        print('  ANTI-PATTERN native_dict_squash -> %d surviving OID key(s): %s'
              % (len(squash), sorted(squash)))

        summaries.append({
            'sample': entry['name'],
            'verdict': verdict,
            'extension_request_count': structure['extension_request_count'],
            'duplicates': structure['duplicates'],
            'naive_last_wins_bc': summarize_bc(last_wins),
            'naive_last_wins_san': summarize_san(last_wins),
        })

    print('=' * 78)
    print('SUMMARY (strict contract vs. silent merge)')
    for s in summaries:
        print('  %-26s %-18s naive_bc=%r'
              % (s['sample'], s['verdict'], s['naive_last_wins_bc']))
    return summaries


if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'generated'
    )
    report(target)
