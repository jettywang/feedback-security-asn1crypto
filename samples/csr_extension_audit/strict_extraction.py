# coding: utf-8
"""
Strict, provenance-preserving extraction of CSR extensionRequest attributes.

This module is the recommended integration contract for a certificate-issuing
backend. It is deliberately *not* a CA: it never decides which extensions end up
in a certificate. It only turns the raw CSR structure into an unambiguous,
fully-attributed request description - or raises AmbiguousRequest so the caller
can reject the CSR.

Contract
--------
extract_csr_extensions(request) returns a dict with:

  extension_request_count : int   number of extensionRequest attributes (must be 1)
  value_count             : int   Extensions values inside that attribute (must be 1)
  other_attributes        : list  non-extensionRequest attribute OIDs, with values
  extensions              : list  of dicts, each with provenance fields:
        index          - position within the single Extensions SEQUENCE
        extn_id        - dotted OID string, always present even if unmapped
        extn_name      - mapped name, or None when the OID is unknown
        critical       - bool, exactly as the applicant encoded it
        raw_extn_value - bytes of extnValue, before any semantic parsing
        parsed         - asn1crypto object if the OID has a spec, else None

Raises AmbiguousRequest when the CSR does not meet the single-attribute /
single-value / unique-extnID shape. Callers must treat that as a rejection, not
something to merge away.
"""
from __future__ import unicode_literals

from asn1crypto import core, csr

EXTENSION_REQUEST_OID = '1.2.840.113549.1.9.14'


class AmbiguousRequest(ValueError):
    """Raised when a CSR's extensionRequest layout cannot be treated as one claim."""


def extract_csr_extensions(request):
    """
    :param request:
        An asn1crypto.csr.CertificationRequest, or raw DER bytes / PEM bytes.

    :raises:
        AmbiguousRequest - on any structural ambiguity in extensionRequest.

    :return:
        dict described in the module docstring.
    """
    request = _coerce_request(request)
    cri = request['certification_request_info']
    attributes = cri['attributes']

    extension_requests = []
    other_attributes = []
    if attributes is not None and not _is_void(attributes):
        for attr in attributes:
            attr_oid = attr['type'].dotted
            if attr_oid == EXTENSION_REQUEST_OID:
                extension_requests.append(attr)
            else:
                other_attributes.append({
                    'attr_oid': attr_oid,
                    'attr_name': attr['type'].native,
                    'values': _native_any(attr['values']),
                })

    if len(extension_requests) == 0:
        return {
            'extension_request_count': 0,
            'value_count': 0,
            'other_attributes': other_attributes,
            'extensions': [],
        }

    if len(extension_requests) > 1:
        raise AmbiguousRequest(
            'CSR contains %d extensionRequest attributes; RFC 5272-style '
            'processing needs exactly one. Reject instead of merging.'
            % len(extension_requests)
        )

    attr = extension_requests[0]
    # attr['values'] is declared Any and, through CRIAttribute._oid_specs, is
    # parsed into SetOfExtensions. On freshly parsed input it is already the
    # SetOfExtensions; on some construct paths it may still be an Any wrapper.
    values = list(_extension_values(attr))
    if len(values) != 1:
        raise AmbiguousRequest(
            'extensionRequest attribute contains %d Extensions values in its '
            'SET; exactly one is permitted.' % len(values)
        )

    extensions_seq = values[0]
    seen_oids = set()
    extracted = []
    for index, ext in enumerate(extensions_seq):
        extn_id_field = ext['extn_id']
        oid = extn_id_field.dotted
        if oid in seen_oids:
            raise AmbiguousRequest(
                'extension OID %s appears more than once within the '
                'Extensions SEQUENCE (first duplicate at index %d).'
                % (oid, index)
            )
        seen_oids.add(oid)

        name = extn_id_field.native
        is_mapped = name != oid
        extracted.append({
            'index': index,
            'extn_id': oid,
            'extn_name': name if is_mapped else None,
            'critical': ext['critical'].native,
            'raw_extn_value': bytes(ext['extn_value']),
            'parsed': _try_parse_extn_value(ext),
        })

    return {
        'extension_request_count': 1,
        'value_count': 1,
        'other_attributes': other_attributes,
        'extensions': extracted,
    }


def _extension_values(attr):
    values_field = attr['values']
    if isinstance(values_field, core.Any):
        values_field = values_field.parsed
    return values_field


def _try_parse_extn_value(ext):
    """Return the semantic object only when asn1crypto has a spec for the OID."""
    oid = ext['extn_id'].dotted
    if oid not in type(ext['extn_id'])._map:
        return None
    try:
        return ext['extn_value'].parsed
    except (ValueError, TypeError):
        return None


def _native_any(any_field):
    try:
        return any_field.native
    except (ValueError, TypeError):
        return None


def _is_void(value):
    return value is core.VOID


def _coerce_request(request):
    if isinstance(request, csr.CertificationRequest):
        return request
    if isinstance(request, (bytes, bytearray)):
        data = bytes(request)
        if data.lstrip().startswith(b'-----BEGIN'):
            from asn1crypto import pem
            _, _, data = pem.unarmor(data)
        return csr.CertificationRequest.load(data)
    raise TypeError('expected CertificationRequest or DER/PEM bytes')
