# coding: utf-8
"""
Anti-patterns that turn ambiguous CSRs into one "legal looking" config.

Each function mirrors real-world backend code. They never raise on ambiguity;
instead they silently pick a winner. Run analyze_samples.py to see which
applicant claim ends up winning for every conflicting sample.
"""
from __future__ import unicode_literals

from asn1crypto import core, csr

EXTENSION_REQUEST_OID = '1.2.840.113549.1.9.14'


def _extension_values(attr):
    values_field = attr['values']
    if isinstance(values_field, core.Any):
        values_field = values_field.parsed
    return values_field


def flatten_last_wins(request):
    """
    Walk every extensionRequest attribute and every Extensions value, dumping
    each extension into a dict keyed by OID. Later occurrences overwrite earlier
    ones; ordering also changes when asn1crypto re-sorts SET OF on re-encoding.
    """
    cri = request['certification_request_info']
    merged = {}
    for attr in cri['attributes']:
        if attr['type'].dotted != EXTENSION_REQUEST_OID:
            continue
        for extensions_seq in _extension_values(attr):
            for ext in extensions_seq:
                merged[ext['extn_id'].dotted] = {
                    'critical': ext['critical'].native,
                    'raw_extn_value': bytes(ext['extn_value']),
                }
    return merged


def first_attribute_only(request):
    """Only read the first extensionRequest attribute; discard later ones."""
    cri = request['certification_request_info']
    for attr in cri['attributes']:
        if attr['type'].dotted == EXTENSION_REQUEST_OID:
            return [
                dict(extn_id=ext['extn_id'].dotted,
                     critical=ext['critical'].native,
                     raw_extn_value=bytes(ext['extn_value']))
                for ext in _extension_values(attr)[0]
            ]
    return []


def native_dict_squash(request):
    """
    Rely on .native conversions. Sequence.native returns an OrderedDict keyed by
    field *name*, so repeated Extension entries inside a SequenceOf survive as
    list items - but code that then builds {extn_id: ...} by hand loses them the
    same way flatten_last_wins does. Included to show where the data disappears.
    """
    cri = request['certification_request_info']
    result = {}
    for attr_native in cri['attributes'].native:
        if attr_native['type'] != 'extension_request':
            continue
        for extensions_native in attr_native['values']:
            for ext_native in extensions_native:
                result[ext_native['extn_id']] = ext_native['critical']
    return result


def load(path_or_bytes):
    if isinstance(path_or_bytes, (bytes, bytearray)):
        data = bytes(path_or_bytes)
    else:
        with open(path_or_bytes, 'rb') as f:
            data = f.read()
    if data.lstrip().startswith(b'-----BEGIN'):
        from asn1crypto import pem
        _, _, data = pem.unarmor(data)
    return csr.CertificationRequest.load(data)
