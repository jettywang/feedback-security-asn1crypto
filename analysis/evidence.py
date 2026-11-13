# coding: utf-8
"""
Extract and relate SafeBag evidence from already-decrypted PKCS#12 containers.

The analysis keeps three notions separate:

 - inventory: which bags exist in the nested SafeContents tree
 - metadata: friendlyName and localKeyId values, retained with their paths
 - proof: byte-identical public key material shared by a private key and a
   certificate's SubjectPublicKeyInfo

Only proof produces a key/certificate pair. Metadata is retained as evidence
with its source path so collisions, mismatches and missing attributes remain
visible instead of being silently resolved. Encrypted content is never
decrypted and private key bytes are never serialized.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import base64
import binascii
import hashlib

from asn1crypto import core, keys, pem, pkcs12
from asn1crypto.util import int_to_bytes


_FORMAT = 'pkcs12-safe-bag-evidence'
_FORMAT_VERSION = 1
_KEY_KINDS = ('key_bag', 'pkcs8_shrouded_key_bag')


def analyze_pfx_bytes(data, source_name=None):
    """
    Analyzes a fully-decrypted PKCS#12 byte string.

    PEM-wrapped PKCS#12 input is accepted when a PKCS12/PFX armor is present.

    :param data:
        A byte string of the PKCS#12 (PFX) structure

    :param source_name:
        An optional unicode string used only to label the input in the report

    :return:
        A dict containing the evidence report
    """

    authenticated_safe, input_note = _load_authenticated_safe(data)
    report = _Analyzer(authenticated_safe).report()
    report['input'] = {
        'source': source_name,
        'sha256': hashlib.sha256(data).hexdigest(),
        'container': input_note,
    }
    return report


def analyze_pfx(path):
    """
    Reads and analyzes a fully-decrypted PKCS#12 file.

    :param path:
        A filesystem path to the PKCS#12 (PFX) file

    :return:
        A dict containing the evidence report
    """

    with open(path, 'rb') as handle:
        return analyze_pfx_bytes(handle.read(), source_name=path)


def load_pfx(path):
    """
    Loads a PKCS#12 file and returns the parsed Pfx object.

    Encrypted content is not decrypted; callers can inspect the
    AuthenticatedSafe entries themselves.
    """

    with open(path, 'rb') as handle:
        data = handle.read()
    if pem.detect(data):
        for type_name, _, der_bytes in pem.unarmor(data, multiple=True):
            if type_name in ('PKCS12', 'PFX'):
                data = der_bytes
                break
    return pkcs12.Pfx.load(data)


def _load_authenticated_safe(data):
    """
    Loads PKCS#12 and returns the AuthenticatedSafe sequence plus a note about
    how the input was encoded.
    """

    input_note = 'der'
    if pem.detect(data):
        for type_name, _, der_bytes in pem.unarmor(data, multiple=True):
            if type_name in ('PKCS12', 'PFX'):
                data = der_bytes
                input_note = 'pem:%s' % type_name
                break
    pfx = pkcs12.Pfx.load(data)
    return pfx.authenticated_safe, input_note


class _Analyzer(object):
    """
    Walks nested SafeContents and produces an evidence report.
    """

    def __init__(self, authenticated_safe):
        self._authenticated_safe = authenticated_safe
        self._sources = []
        self._entries = []
        self._next_id = 0
        self._walked = False

    def report(self):
        self._collect()
        key_entries = [entry for entry in self._entries if entry['kind'] in _KEY_KINDS]
        cert_entries = [entry for entry in self._entries if entry['kind'] == 'cert_bag']

        duplicate_groups = self._duplicate_bag_groups()
        metadata_conflicts = self._metadata_conflicts()
        candidates = self._candidates(key_entries, cert_entries)
        pairs, paired_keys, paired_certs = self._pairs(key_entries, cert_entries)
        orphans = self._orphans(key_entries, cert_entries, pairs, paired_keys, paired_certs, candidates)
        missing_lkid_pairs = [
            pair for pair in pairs
            if pair['metadata']['local_key_id']['agreement'] in ('both_missing', 'missing_key', 'missing_certificate')
        ]

        bag_warnings = {}
        for group in duplicate_groups:
            for bag_id in group['bag_ids']:
                warning = {
                    'code': group['code'],
                    'message': group['message'],
                    'evidence': group['paths'],
                }
                if 'digest_sha256' in group:
                    warning['digest_sha256'] = group['digest_sha256']
                bag_warnings.setdefault(bag_id, []).append(warning)

        for entry in self._entries:
            entry['warnings'] = bag_warnings.get(entry['id'], [])

        summary = {
            'bags': len(self._entries),
            'leaf_bags': len([entry for entry in self._entries if entry['kind'] != 'safe_contents']),
            'containers': len([entry for entry in self._entries if entry['kind'] == 'safe_contents']),
            'key_bags': len([entry for entry in self._entries if entry['kind'] == 'key_bag']),
            'shrouded_key_bags': len([entry for entry in self._entries if entry['kind'] == 'pkcs8_shrouded_key_bag']),
            'certificate_bags': len(cert_entries),
            'proof_pairs': len(pairs),
            'paired_keys': len(paired_keys),
            'paired_certificates': len(paired_certs),
            'orphan_keys': len([item for item in orphans if item['type'] == 'key']),
            'orphan_certificates': len([item for item in orphans if item['type'] == 'certificate']),
            'candidate_links': len(candidates),
            'ambiguous_candidate_links': len([item for item in candidates if item['ambiguous']]),
            'metadata_conflicts': len(metadata_conflicts),
            'duplicate_bag_groups': len(duplicate_groups),
            'pairs_missing_local_key_id': len(missing_lkid_pairs),
            'private_key_bytes_exposed': False,
            'decryption_attempted': False,
        }

        return {
            'format': _FORMAT,
            'version': _FORMAT_VERSION,
            'policy': {
                'pairing_proof': 'equal public key material fingerprint',
                'friendly_name_is_proof': False,
                'subject_name_is_proof': False,
                'chain_order_is_proof': False,
                'local_key_id_is_proof': False,
                'encrypted_content_decrypted': False,
                'private_key_bytes_serialized': False,
            },
            'input': {'source': None, 'sha256': None, 'container': None},
            'sources': self._source_report(),
            'summary': summary,
            'bags': [self._entry_report(entry) for entry in self._entries],
            'pairs': pairs,
            'candidates': candidates,
            'orphans': orphans,
            'conflicts': metadata_conflicts + duplicate_groups,
        }

    def _collect(self):
        if self._walked:
            return
        self._walked = True
        for index, content_info in enumerate(self._authenticated_safe):
            source = 'auth_safe[%d]' % index
            content_type = content_info['content_type'].native
            if content_type == 'data':
                try:
                    contents = _safe_contents_from_content_info(content_info)
                except (ValueError, TypeError) as exc:
                    self._sources.append({
                        'source': source,
                        'content_type': content_type,
                        'status': 'unreadable',
                        'reason': _error_text(exc),
                        'bag_count': 0,
                    })
                    continue
                self._sources.append({
                    'source': source,
                    'content_type': content_type,
                    'status': 'walked',
                    'bag_count': len(contents),
                })
                self._walk(contents, source, None, source, (), 0)
            else:
                reason = 'encrypted content is not decrypted by this analysis'
                if content_type != 'encrypted_data':
                    reason = 'unsupported AuthenticatedSafe content type: %s' % content_type
                self._sources.append({
                    'source': source,
                    'content_type': content_type,
                    'status': 'opaque',
                    'reason': reason,
                    'bag_count': 0,
                })

    def _walk(self, contents, source, parent_id, prefix, indices, depth):
        for index, bag in enumerate(contents):
            self._walk_bag(bag, source, parent_id, prefix, indices + (index,), depth)

    def _walk_bag(self, bag, source, parent_id, prefix, indices, depth):
        kind = bag['bag_id'].native
        path = '%s/bag[%d]' % (prefix, indices[0])

        entry = {
            'id': None,
            'path': path,
            'indices': list(indices),
            'source': source,
            'kind': kind,
            'parent_id': parent_id,
            'depth': depth,
            'bag': bag,
            'warnings': [],
        }

        if kind == 'safe_contents':
            entry['id'] = self._allocate_id('container')
            entry['children'] = []
            try:
                children = bag['bag_value']
                if hasattr(children, 'parsed') and not isinstance(children, pkcs12.SafeContents):
                    children = children.parsed
                entry['child_count'] = len(children)
                self._walk(children, source, entry['id'], path + '/contents', (), depth + 1)
            except (ValueError, TypeError) as exc:
                entry['child_count'] = 0
                entry['warnings'].append({
                    'code': 'unreadable_safe_contents',
                    'message': 'nested SafeContents could not be parsed',
                    'reason': _error_text(exc),
                })
            self._entries.append(entry)
            return

        entry['id'] = self._allocate_id('bag')
        try:
            entry['attributes'] = _read_attributes(bag, path)
        except (ValueError, TypeError) as exc:
            entry['attributes'] = []
            entry['warnings'].append({
                'code': 'unreadable_attributes',
                'message': 'bag attributes could not be parsed',
                'reason': _error_text(exc),
            })
        self._entries.append(entry)

        if kind == 'key_bag':
            self._inspect_key(entry)
        elif kind == 'pkcs8_shrouded_key_bag':
            self._inspect_shrouded_key(entry)
        elif kind == 'cert_bag':
            self._inspect_certificate(entry)
        else:
            entry['detail'] = {'type': kind}
            entry['public_key_fingerprint'] = None
            entry['public_key_algorithm'] = None
            entry['public_key_source'] = None

    def _allocate_id(self, prefix):
        self._next_id += 1
        return '%s-%d' % (prefix, self._next_id)

    def _inspect_key(self, entry):
        private_key_info = entry['bag']['bag_value']
        entry['detail'] = _describe_key(private_key_info)
        derived = _derive_public_key(private_key_info)
        derived['source'] = (
            'public components derived from key bag %s; private key bytes are not serialized'
            % entry['path']
        )
        entry['public_key_fingerprint'] = derived.get('fingerprint')
        entry['public_key_algorithm'] = derived.get('algorithm')
        entry['public_key_source'] = derived.get('source')
        entry['public_key_detail'] = derived

    def _inspect_shrouded_key(self, entry):
        shrouded = entry['bag']['bag_value']
        try:
            algorithm = shrouded['encryption_algorithm']['algorithm'].native
        except (ValueError, TypeError, KeyError):
            algorithm = None
        entry['detail'] = {
            'type': 'pkcs8_shrouded_key_bag',
            'encryption_algorithm': algorithm,
            'opaque_private_key_material': True,
            'private_bytes_exposed': False,
        }
        entry['public_key_fingerprint'] = None
        entry['public_key_algorithm'] = None
        entry['public_key_source'] = 'shrouded key bag was not decrypted; no public key was derived'
        entry['public_key_detail'] = {'available': False, 'reason': 'pkcs8_shrouded_key_bag'}

    def _inspect_certificate(self, entry):
        cert_bag = entry['bag']['bag_value']
        try:
            cert_id = cert_bag['cert_id'].native
        except (ValueError, TypeError) as exc:
            entry['detail'] = {'type': 'cert_bag', 'certificate_id': None, 'parsed': False}
            entry['public_key_fingerprint'] = None
            entry['public_key_algorithm'] = None
            entry['public_key_source'] = None
            entry['public_key_detail'] = {
                'available': False,
                'reason': 'certificate bag id is unreadable: %s' % _error_text(exc),
            }
            entry['warnings'].append({
                'code': 'unreadable_certificate_bag',
                'message': 'certificate bag id could not be parsed',
                'reason': _error_text(exc),
            })
            return
        if cert_id != 'x509':
            entry['detail'] = {'type': 'cert_bag', 'certificate_id': cert_id, 'parsed': False}
            entry['public_key_fingerprint'] = None
            entry['public_key_algorithm'] = None
            entry['public_key_source'] = None
            entry['public_key_detail'] = {'available': False, 'reason': 'unsupported certificate bag id'}
            return
        try:
            certificate = cert_bag['cert_value'].parsed
            spki = certificate.public_key
            material = _spki_canonical_material(spki)
            entry['detail'] = _describe_certificate(certificate)
            entry['public_key_fingerprint'] = _sha256_prefixed(material)
            entry['public_key_algorithm'] = spki['algorithm']['algorithm'].native
            entry['public_key_source'] = 'certificate SPKI at %s' % entry['path']
            entry['public_key_detail'] = {
                'available': True,
                'kind': 'certificate_spki',
                'canonical_fingerprint': entry['public_key_fingerprint'],
                'spki_sha256': hashlib.sha256(spki.dump()).hexdigest(),
                'spki_der_bytes': len(spki.dump()),
            }
        except (ValueError, TypeError) as exc:
            entry['detail'] = {'type': 'cert_bag', 'certificate_id': 'x509', 'parsed': False}
            entry['public_key_fingerprint'] = None
            entry['public_key_algorithm'] = None
            entry['public_key_source'] = None
            entry['public_key_detail'] = {
                'available': False,
                'reason': 'certificate could not be parsed: %s' % _error_text(exc),
            }
            entry['warnings'].append({
                'code': 'unreadable_certificate_bag',
                'message': 'certificate bag value could not be parsed',
                'reason': _error_text(exc),
            })

    def _entry_report(self, entry):
        if entry['kind'] == 'safe_contents':
            return {
                'id': entry['id'],
                'path': entry['path'],
                'indices': entry['indices'],
                'source': entry['source'],
                'kind': entry['kind'],
                'parent_id': entry['parent_id'],
                'depth': entry['depth'],
                'child_count': entry['child_count'],
                'warnings': entry['warnings'],
            }
        metadata = _metadata_report(entry['attributes'])
        return {
            'id': entry['id'],
            'path': entry['path'],
            'indices': entry['indices'],
            'source': entry['source'],
            'kind': entry['kind'],
            'parent_id': entry['parent_id'],
            'depth': entry['depth'],
            'detail': entry['detail'],
            'metadata': metadata,
            'public_key_fingerprint': entry['public_key_fingerprint'],
            'public_key_algorithm': entry['public_key_algorithm'],
            'public_key_source': entry['public_key_source'],
            'public_key_detail': entry['public_key_detail'],
            'warnings': entry['warnings'],
        }

    def _source_report(self):
        output = []
        for source in self._sources:
            item = dict(source)
            output.append(item)
        for entry in self._entries:
            if entry['kind'] == 'safe_contents':
                output.append({
                    'source': 'nested SafeContents at %s' % entry['path'],
                    'content_type': 'safe_contents',
                    'status': 'walked',
                    'bag_count': entry['child_count'],
                })
        return output

    def _duplicate_bag_groups(self):
        exact_groups = {}
        content_groups = {}
        for entry in self._entries:
            if entry['kind'] == 'safe_contents':
                continue
            exact_groups.setdefault(hashlib.sha256(entry['bag'].dump()).hexdigest(), []).append(entry)
            key = (entry['kind'], _bag_value_digest(entry))
            content_groups.setdefault(key, []).append(entry)

        output = []
        for digest, entries in exact_groups.items():
            if len(entries) < 2:
                continue
            output.append({
                'code': 'duplicate_bag',
                'digest_sha256': digest,
                'bag_ids': [entry['id'] for entry in entries],
                'paths': [entry['path'] for entry in entries],
                'kinds': [entry['kind'] for entry in entries],
                'message': 'byte-identical SafeBag values were found at multiple paths',
            })

        for key, entries in content_groups.items():
            if len(entries) < 2:
                continue
            if len(set(hashlib.sha256(entry['bag'].dump()).hexdigest() for entry in entries)) == 1:
                continue
            output.append({
                'code': 'duplicate_bag_content',
                'bag_ids': [entry['id'] for entry in entries],
                'paths': [entry['path'] for entry in entries],
                'kinds': [entry['kind'] for entry in entries],
                'message': 'the same bag value appears with different attributes',
            })

        output.sort(key=lambda item: item['paths'][0])
        return output

    def _metadata_conflicts(self):
        output = []
        lkid_groups = {}
        name_groups = {}
        for entry in self._entries:
            if entry['kind'] == 'safe_contents':
                continue
            for record in entry['attributes']:
                if record['type'] == 'local_key_id':
                    for value in record['values']:
                        lkid_groups.setdefault(value['hex'], []).append((entry, record, value))
                elif record['type'] == 'friendly_name':
                    for value in record['values']:
                        name_groups.setdefault(value['value'], []).append((entry, record, value))

        for value, occurrences in sorted(lkid_groups.items()):
            fingerprints = sorted(set(
                entry['public_key_fingerprint'] for entry, record, item in occurrences
                if entry['public_key_fingerprint'] is not None
            ))
            if len(fingerprints) > 1:
                output.append({
                    'code': 'local_key_id_collision',
                    'local_key_id': value,
                    'bag_ids': sorted(set(entry['id'] for entry, record, item in occurrences)),
                    'fingerprints': fingerprints,
                    'sources': [item['path'] for entry, record, item in occurrences],
                    'message': 'one localKeyId value appears on bags with different public key material',
                })

        for value, occurrences in sorted(name_groups.items()):
            fingerprints = sorted(set(
                entry['public_key_fingerprint'] for entry, record, item in occurrences
                if entry['public_key_fingerprint'] is not None
            ))
            if len(fingerprints) > 1:
                output.append({
                    'code': 'friendly_name_collision',
                    'friendly_name': value,
                    'bag_ids': sorted(set(entry['id'] for entry, record, item in occurrences)),
                    'fingerprints': fingerprints,
                    'sources': [item['path'] for entry, record, item in occurrences],
                    'message': 'one friendlyName value appears on bags with different public key material',
                })

        for entry in self._entries:
            if entry['kind'] == 'safe_contents':
                continue
            lkids = [record for record in entry['attributes'] if record['type'] == 'local_key_id']
            names = [record for record in entry['attributes'] if record['type'] == 'friendly_name']
            if len(lkids) > 1:
                output.append({
                    'code': 'repeated_local_key_id_attribute',
                    'bag_id': entry['id'],
                    'path': entry['path'],
                    'sources': [record['path'] for record in lkids],
                    'message': 'bag carries more than one localKeyId attribute',
                })
            if len(names) > 1:
                output.append({
                    'code': 'repeated_friendly_name_attribute',
                    'bag_id': entry['id'],
                    'path': entry['path'],
                    'sources': [record['path'] for record in names],
                    'message': 'bag carries more than one friendlyName attribute',
                })
        output.sort(key=lambda item: (
            item['code'],
            item.get('local_key_id') or item.get('friendly_name') or item.get('path'),
        ))
        return output

    def _pairs(self, key_entries, cert_entries):
        by_fingerprint = {}
        for entry in key_entries:
            if entry['public_key_fingerprint'] is not None:
                by_fingerprint.setdefault(entry['public_key_fingerprint'], []).append(entry)
        cert_by_fingerprint = {}
        for entry in cert_entries:
            if entry['public_key_fingerprint'] is not None:
                cert_by_fingerprint.setdefault(entry['public_key_fingerprint'], []).append(entry)

        pairs = []
        paired_keys = set()
        paired_certs = set()
        for fingerprint in sorted(set(by_fingerprint.keys()) & set(cert_by_fingerprint.keys())):
            key_group = by_fingerprint[fingerprint]
            cert_group = cert_by_fingerprint[fingerprint]
            paired_keys.update([entry['id'] for entry in key_group])
            paired_certs.update([entry['id'] for entry in cert_group])

            key_lkids = _collected_values(key_group, 'local_key_id')
            cert_lkids = _collected_values(cert_group, 'local_key_id')
            key_names = _collected_values(key_group, 'friendly_name')
            cert_names = _collected_values(cert_group, 'friendly_name')

            lkid_agreement = _agreement(key_lkids, cert_lkids)
            name_agreement = _agreement(key_names, cert_names)
            warnings = []
            if lkid_agreement in ('both_missing', 'missing_key', 'missing_certificate'):
                warnings.append({
                    'code': 'missing_local_key_id',
                    'message': 'localKeyId is absent on at least one side; pairing rests on public key material only',
                })
            elif lkid_agreement == 'mismatch':
                warnings.append({
                    'code': 'local_key_id_mismatch',
                    'message': 'localKeyId values differ although public key material matches',
                })
            if name_agreement == 'mismatch':
                warnings.append({
                    'code': 'friendly_name_mismatch',
                    'message': 'friendlyName values differ; names were not used as pairing proof',
                })
            if len(key_group) > 1:
                warnings.append({
                    'code': 'duplicate_public_key_material',
                    'message': 'more than one key bag contains the same public key material',
                })
            if len(cert_group) > 1:
                warnings.append({
                    'code': 'multiple_equivalent_certificates',
                    'message': 'more than one certificate bag contains the same public key material',
                })

            spki_sources = []
            for entry in key_group + cert_group:
                detail = entry['public_key_detail']
                spki_sources.append({
                    'bag_id': entry['id'],
                    'source': entry['public_key_source'],
                    'spki_sha256': detail.get('spki_sha256'),
                    'spki_der_bytes': detail.get('spki_der_bytes'),
                })
            key_spkis = [entry['public_key_detail'].get('spki_sha256') for entry in key_group]
            cert_spkis = [entry['public_key_detail'].get('spki_sha256') for entry in cert_group]
            pairs.append({
                'fingerprint': fingerprint,
                'key_ids': [entry['id'] for entry in key_group],
                'certificate_ids': [entry['id'] for entry in cert_group],
                'key_count': len(key_group),
                'certificate_count': len(cert_group),
                'evidence': {
                    'kind': 'public_key_material_match',
                    'fingerprint_scope': 'algorithm-specific canonical public key components',
                    'spki_sources': spki_sources,
                    'spki_der_equal': len(set(key_spkis) | set(cert_spkis)) == 1,
                    'spki_der_note': (
                        'exact SPKI encodings match'
                        if len(set(key_spkis) | set(cert_spkis)) == 1
                        else 'canonical public key components match; exact SPKI encodings differ'
                    ),
                },
                'metadata': {
                    'local_key_id': {
                        'key_values': key_lkids,
                        'certificate_values': cert_lkids,
                        'agreement': lkid_agreement,
                    },
                    'friendly_name': {
                        'key_values': key_names,
                        'certificate_values': cert_names,
                        'agreement': name_agreement,
                    },
                    'subject_name': {
                        'used_for_pairing': False,
                        'note': 'certificate subject names are descriptive and are not a pairing proof',
                    },
                },
                'warnings': warnings,
            })
        return pairs, paired_keys, paired_certs

    def _candidates(self, key_entries, cert_entries):
        candidates = []
        for key_entry in key_entries:
            for cert_entry in cert_entries:
                if key_entry['public_key_fingerprint'] is not None and \
                        key_entry['public_key_fingerprint'] == cert_entry['public_key_fingerprint']:
                    continue
                basis = []
                key_lkids = _entry_values(key_entry, 'local_key_id')
                cert_lkids = _entry_values(cert_entry, 'local_key_id')
                common_lkids = set(item['value'] for item in key_lkids) & \
                    set(item['value'] for item in cert_lkids)
                for value in sorted(common_lkids):
                    basis.append({
                        'type': 'local_key_id',
                        'value': value,
                        'key_sources': [item['path'] for item in key_lkids if item['value'] == value],
                        'certificate_sources': [item['path'] for item in cert_lkids if item['value'] == value],
                    })
                key_names = _entry_values(key_entry, 'friendly_name')
                cert_names = _entry_values(cert_entry, 'friendly_name')
                common_names = set(item['value'] for item in key_names) & \
                    set(item['value'] for item in cert_names)
                for value in sorted(common_names):
                    basis.append({
                        'type': 'friendly_name',
                        'value': value,
                        'key_sources': [item['path'] for item in key_names if item['value'] == value],
                        'certificate_sources': [item['path'] for item in cert_names if item['value'] == value],
                    })
                if not basis:
                    continue

                key_fp = key_entry['public_key_fingerprint']
                cert_fp = cert_entry['public_key_fingerprint']
                contradictory = key_fp is not None and cert_fp is not None and key_fp != cert_fp
                candidate = {
                    'key_id': key_entry['id'],
                    'certificate_id': cert_entry['id'],
                    'key_path': key_entry['path'],
                    'certificate_path': cert_entry['path'],
                    'basis': basis,
                    'strength': 'metadata-only',
                    'public_key_fingerprints': {
                        'key': key_fp,
                        'certificate': cert_fp,
                    },
                    'fingerprint_conflict': contradictory,
                    'unverified_public_key': key_fp is None or cert_fp is None,
                    'ambiguous': self._candidate_is_ambiguous(basis, key_entry, cert_entry, key_entries, cert_entries),
                    'evidence_sources': _candidate_sources(basis, key_entry, cert_entry),
                    'warnings': [],
                }
                if contradictory:
                    candidate['warnings'].append({
                        'code': 'fingerprints_differ',
                        'message': 'metadata suggests a relationship, but public key material differs',
                    })
                if candidate['unverified_public_key']:
                    candidate['warnings'].append({
                        'code': 'public_key_unavailable',
                        'message': 'public key material is unavailable or opaque, so the candidate cannot be verified',
                    })
                candidates.append(candidate)
        candidates.sort(key=lambda item: (item['key_id'], item['certificate_id']))
        return candidates

    def _candidate_is_ambiguous(self, basis, key_entry, cert_entry, key_entries, cert_entries):
        for item in basis:
            if item['type'] == 'local_key_id':
                value = item['value']
                matching_keys = [
                    entry for entry in key_entries
                    if any(value == record['value'] for record in _entry_values(entry, 'local_key_id'))
                ]
                matching_certs = [
                    entry for entry in cert_entries
                    if any(value == record['value'] for record in _entry_values(entry, 'local_key_id'))
                ]
                if len(matching_keys) > 1 or len(matching_certs) > 1:
                    return True
            elif item['type'] == 'friendly_name':
                value = item['value']
                matching_keys = [
                    entry for entry in key_entries
                    if any(value == record['value'] for record in _entry_values(entry, 'friendly_name'))
                ]
                matching_certs = [
                    entry for entry in cert_entries
                    if any(value == record['value'] for record in _entry_values(entry, 'friendly_name'))
                ]
                if len(matching_keys) > 1 or len(matching_certs) > 1:
                    return True
        return False

    def _orphans(self, key_entries, cert_entries, pairs, paired_keys, paired_certs, candidates):
        output = []
        for entry in key_entries:
            if entry['id'] in paired_keys:
                continue
            related = [item for item in candidates if item['key_id'] == entry['id']]
            item = self._orphan_report(entry, 'key', related)
            output.append(item)
        for entry in cert_entries:
            if entry['id'] in paired_certs:
                continue
            related = [item for item in candidates if item['certificate_id'] == entry['id']]
            item = self._orphan_report(entry, 'certificate', related)
            output.append(item)
        output.sort(key=lambda item: item['id'])
        return output

    def _orphan_report(self, entry, type_name, related):
        opaque = entry['public_key_fingerprint'] is None
        if opaque:
            reason = 'public key material is unavailable; the bag is opaque or uses an unsupported key encoding'
        elif type_name == 'key':
            reason = 'no certificate bag has matching public key material'
        else:
            reason = 'no key bag has matching public key material'
        if related:
            reason += '; metadata-only candidates exist'
        return {
            'id': entry['id'],
            'type': type_name,
            'path': entry['path'],
            'kind': entry['kind'],
            'reason': reason,
            'isolated': len(related) == 0,
            'opaque_public_key': opaque,
            'public_key_fingerprint': entry['public_key_fingerprint'],
            'public_key_source': entry['public_key_source'],
            'candidate_ids': [item['certificate_id'] if type_name == 'key' else item['key_id'] for item in related],
            'metadata_sources': [source['path'] for source in _metadata_sources(entry)],
            'evidence_sources': [entry['public_key_source']] + [source['path'] for source in _metadata_sources(entry)],
        }


def _bag_value_digest(entry):
    value = entry['bag']['bag_value']
    if hasattr(value, 'dump'):
        return hashlib.sha256(value.dump()).hexdigest()
    return hashlib.sha256(repr(value).encode('utf-8')).hexdigest()


def _safe_contents_from_content_info(content_info):
    content_type = content_info['content_type'].native
    content = content_info['content']
    if content_type == 'data':
        if isinstance(content, core.OctetString):
            return pkcs12.SafeContents.load(content.native)
        if isinstance(content, pkcs12.SafeContents):
            return content
        return pkcs12.SafeContents.load(content.native)
    if content_type == 'signed_data':
        signed_data = content
        encap = signed_data['encap_content_info']
        return pkcs12.SafeContents.load(encap['content'].native)
    raise ValueError('unsupported content type: %s' % content_type)


def _read_attributes(bag, bag_path):
    attributes = bag['bag_attributes']
    if isinstance(attributes, core.Void) or attributes is None:
        return []
    output = []
    for index, attribute in enumerate(attributes):
        type_name = attribute['type'].native
        values = attribute['values']
        records = []
        if isinstance(values, core.Void) or values is None:
            values = []
        for value_index, value in enumerate(values):
            raw = value.native
            record = {
                'type': type_name,
                'path': '%s/attributes[%d]/values[%d]' % (bag_path, index, value_index),
                'attribute_path': '%s/attributes[%d]' % (bag_path, index),
                'attribute_index': index,
                'value_index': value_index,
            }
            if type_name == 'local_key_id':
                if isinstance(raw, bytes):
                    record['hex'] = _hex(raw)
                    record['base64'] = base64.b64encode(raw).decode('ascii')
                    record['value'] = _hex(raw)
                else:
                    record['hex'] = _hex(raw)
                    record['base64'] = None
                    record['value'] = _hex(raw)
            elif type_name == 'friendly_name':
                record['value'] = _text(raw)
            else:
                record['value'] = _json_safe(raw)
            records.append(record)
        output.append({
            'type': type_name,
            'path': '%s/attributes[%d]' % (bag_path, index),
            'attribute_index': index,
            'value_count': len(records),
            'values': records,
        })
    return output


def _metadata_report(attributes):
    return {
        'friendly_names': [
            item for record in attributes if record['type'] == 'friendly_name' for item in record['values']
        ],
        'local_key_ids': [
            item for record in attributes if record['type'] == 'local_key_id' for item in record['values']
        ],
        'attributes': [
            {
                'type': record['type'],
                'path': record['path'],
                'values': [item['value'] for item in record['values']],
                'value_paths': [item['path'] for item in record['values']],
            }
            for record in attributes
        ],
        'sources': [record['path'] for record in attributes],
    }


def _metadata_sources(entry):
    return [{'type': record['type'], 'path': record['path']} for record in entry['attributes']]


def _entry_values(entry, type_name):
    return [
        item
        for record in entry['attributes']
        if record['type'] == type_name
        for item in record['values']
    ]


def _collected_values(entries, type_name):
    values = {}
    for entry in entries:
        for item in _entry_values(entry, type_name):
            value = item.get('hex') if type_name == 'local_key_id' else item.get('value')
            values.setdefault(value, []).append({'bag_id': entry['id'], 'source': item['path']})
    return [
        {'value': value, 'sources': occurrences}
        for value, occurrences in sorted(values.items(), key=lambda pair: str(pair[0]))
    ]


def _agreement(key_values, cert_values):
    key_set = set(item['value'] for item in key_values)
    cert_set = set(item['value'] for item in cert_values)
    if not key_set and not cert_set:
        return 'both_missing'
    if not key_set:
        return 'missing_key'
    if not cert_set:
        return 'missing_certificate'
    if key_set & cert_set:
        return 'match'
    return 'mismatch'


def _candidate_sources(basis, key_entry, cert_entry):
    sources = [key_entry['public_key_source'], cert_entry['public_key_source']]
    for item in basis:
        sources.extend(item['key_sources'])
        sources.extend(item['certificate_sources'])
    return sources


def _describe_key(private_key_info):
    algorithm = private_key_info['private_key_algorithm']['algorithm']
    return {
        'type': 'key_bag',
        'private_key_algorithm': algorithm.native,
        'private_key_algorithm_oid': algorithm.dotted,
        'encrypted': False,
        'private_bytes_exposed': False,
    }


def _describe_certificate(certificate):
    return {
        'type': 'cert_bag',
        'certificate_id': 'x509',
        'subject': _subject_report(certificate.subject),
        'subject_source': 'certificate subject',
        'issuer': _subject_report(certificate.issuer),
        'issuer_source': 'certificate issuer',
        'serial_hex': '%x' % certificate.serial_number,
        'serial_source': 'certificate serial number',
        'certificate_sha256': hashlib.sha256(certificate.dump()).hexdigest(),
        'certificate_der_bytes': len(certificate.dump()),
        'chain_order_used': False,
        'private_bytes_exposed': False,
    }


def _subject_report(name):
    native = name.native
    output = []
    for key in native:
        value = native[key]
        if isinstance(value, list):
            for item in value:
                output.append({'type': key, 'value': _json_safe(item)})
        else:
            output.append({'type': key, 'value': _json_safe(value)})
    return output


def _derive_public_key(private_key_info):
    algorithm = private_key_info['private_key_algorithm']['algorithm'].native
    source = 'public components derived from key bag %s' % ('private_key_algorithm=%s' % algorithm)
    try:
        private_payload = private_key_info['private_key'].parsed
    except (ValueError, TypeError, KeyError) as exc:
        return {'available': False, 'reason': _error_text(exc), 'source': source, 'fingerprint': None}

    if algorithm in ('rsa', 'rsassa_pss'):
        try:
            modulus = private_payload['modulus'].native
            exponent = private_payload['public_exponent'].native
            public_key = keys.RSAPublicKey({
                'modulus': core.Integer(modulus),
                'public_exponent': core.Integer(exponent),
            })
            public_algorithm = keys.PublicKeyAlgorithm({'algorithm': algorithm})
            if algorithm == 'rsa':
                public_algorithm['parameters'] = core.Null()
            elif private_key_info['private_key_algorithm']['parameters'] and \
                    not isinstance(private_key_info['private_key_algorithm']['parameters'], core.Void):
                public_algorithm['parameters'] = private_key_info['private_key_algorithm']['parameters']
            spki = keys.PublicKeyInfo({
                'algorithm': public_algorithm,
                'public_key': public_key,
            })
            return _derived_report(spki, 'rsa', source)
        except (ValueError, TypeError, KeyError) as exc:
            return {'available': False, 'reason': _error_text(exc), 'source': source, 'fingerprint': None}

    if algorithm == 'ec':
        try:
            point = private_payload['public_key']
            if isinstance(point, core.Void) or point is None:
                return {
                    'available': False,
                    'reason': 'EC private key does not embed a public point',
                    'source': source,
                    'fingerprint': None,
                }
            parameters = private_key_info['private_key_algorithm']['parameters']
            public_algorithm = keys.PublicKeyAlgorithm({'algorithm': 'ec'})
            if parameters and not isinstance(parameters, core.Void):
                public_algorithm['parameters'] = parameters
            spki = keys.PublicKeyInfo({
                'algorithm': public_algorithm,
                'public_key': keys.ECPointBitString(point.native),
            })
            return _derived_report(spki, 'ec', source)
        except (ValueError, TypeError, KeyError) as exc:
            return {'available': False, 'reason': _error_text(exc), 'source': source, 'fingerprint': None}

    if algorithm == 'dsa':
        try:
            parameters = private_key_info['private_key_algorithm']['parameters']
            private_value = private_payload.native
            public_value = pow(parameters['g'].native, private_value, parameters['p'].native)
            public_algorithm = keys.PublicKeyAlgorithm({'algorithm': 'dsa'})
            public_algorithm['parameters'] = parameters
            spki = keys.PublicKeyInfo({
                'algorithm': public_algorithm,
                'public_key': core.Integer(public_value),
            })
            return _derived_report(spki, 'dsa', source)
        except (ValueError, TypeError, KeyError) as exc:
            return {'available': False, 'reason': _error_text(exc), 'source': source, 'fingerprint': None}

    return {
        'available': False,
        'reason': 'deriving a public key for algorithm %s is not supported' % algorithm,
        'source': source,
        'fingerprint': None,
    }


def _derived_report(spki, family, source):
    material = _spki_canonical_material(spki)
    fingerprint = _sha256_prefixed(material)
    return {
        'available': True,
        'kind': 'derived_from_private_key',
        'algorithm': spki['algorithm']['algorithm'].native,
        'family': family,
        'canonical_fingerprint': fingerprint,
        'spki_sha256': hashlib.sha256(spki.dump()).hexdigest(),
        'spki_der_bytes': len(spki.dump()),
        'fingerprint': fingerprint,
        'source': source,
    }


def _spki_canonical_material(spki):
    algorithm = spki['algorithm']['algorithm'].native
    if algorithm in ('rsa', 'rsassa_pss', 'rsaes_oaep'):
        public_key = spki['public_key'].parsed
        return b'rsa' + b'\x00' + _int_bytes(public_key['modulus'].native) + \
            b'\x00' + _int_bytes(public_key['public_exponent'].native)
    if algorithm == 'ec':
        parameters = spki['algorithm']['parameters']
        if isinstance(parameters, core.Void) or parameters is None:
            curve = b'implicit'
        elif parameters.name == 'named':
            curve = b'named:' + parameters.chosen.dotted.encode('ascii')
        elif parameters.name == 'specified':
            curve = b'specified:' + hashlib.sha256(parameters.dump()).digest()
        else:
            curve = b'other:' + hashlib.sha256(parameters.dump()).digest()
        return b'ec' + b'\x00' + curve + b'\x00' + spki['public_key'].native
    if algorithm == 'dsa':
        parameters = spki['algorithm']['parameters']
        public_value = spki['public_key'].parsed.native
        return b'dsa' + b'\x00' + _int_bytes(parameters['p'].native) + b'\x00' + \
            _int_bytes(parameters['q'].native) + b'\x00' + _int_bytes(parameters['g'].native) + \
            b'\x00' + _int_bytes(public_value)
    if algorithm in ('ed25519', 'ed448', 'x25519', 'x448'):
        return algorithm.encode('ascii') + b'\x00' + spki['public_key'].native
    return b'spki:' + hashlib.sha256(spki.dump()).digest()


def _sha256_prefixed(material):
    return 'sha256:' + hashlib.sha256(material).hexdigest()


def _int_bytes(value):
    return int_to_bytes(value)


def _hex(value):
    if isinstance(value, bytes):
        return binascii.hexlify(value).decode('ascii')
    return str(value)


def _text(value):
    if isinstance(value, bytes):
        return base64.b64encode(value).decode('ascii')
    if not isinstance(value, str):
        return str(value)
    return value


def _json_safe(value):
    if isinstance(value, bytes):
        return {'base64': base64.b64encode(value).decode('ascii')}
    if isinstance(value, dict):
        return dict((str(key), _json_safe(item)) for key, item in value.items())
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)


def _error_text(exc):
    text = str(exc)
    if len(text) > 240:
        text = text[:237] + '...'
    return text
