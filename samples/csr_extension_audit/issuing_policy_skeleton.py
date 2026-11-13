# coding: utf-8
"""
Minimal issuing-policy skeleton showing where parser work ends and CA policy
begins. It intentionally contains no ASN.1 parsing logic of its own: all
structure handling comes from strict_extraction.extract_csr_extensions(), and
every decision is expressed as an explicit allow/deny rule on the attested
claims.

This is deliberately not a full CA - there is no signing, profile engine, or
storage. It demonstrates the boundary a maintainer should preserve.
"""
from __future__ import unicode_literals

from asn1crypto import x509

from strict_extraction import AmbiguousRequest, extract_csr_extensions

BC_OID = '2.5.29.19'
SAN_OID = '2.5.29.17'
EKU_OID = '2.5.29.37'


class PolicyDenial(Exception):
    """Raised when policy refuses to issue for the requested shape/content."""


class LeafCertificatePolicy(object):
    """Example policy: only constrained leaf certificates may be issued."""

    # Domains this CA is actually willing to assert in a SAN.
    allowed_san_suffixes = ('.example', 'example')
    allowed_eku = {'server_auth', 'client_auth'}

    def review(self, request):
        try:
            claims = extract_csr_extensions(request)
        except AmbiguousRequest as e:
            raise PolicyDenial('ambiguous CSR structure: %s' % e)

        decisions = []
        for ext in claims['extensions']:
            decisions.append(self._decide(ext))

        # Metadata attributes (e.g. Microsoft enrollment info) never become
        # certificate extensions through this path; log them out of band.
        metadata = [o['attr_name'] for o in claims['other_attributes']]
        return {'issued_extensions': [d for d in decisions if d is not None],
                'ignored_metadata_attributes': metadata}

    def _decide(self, ext):
        oid = ext['extn_id']

        if oid == BC_OID:
            bc = ext['parsed']
            # CA=true is an applicant request, never an entitlement. A leaf
            # profile denies it regardless of the critical flag.
            if bool(bc['ca'].native):
                raise PolicyDenial('basicConstraints CA=true not allowed for leaf profile')
            return {'oid': oid, 'action': 'issue',
                    'critical': True, 'value': {'ca': False}}

        if oid == SAN_OID:
            names = ext['parsed']
            for general_name in names:
                if general_name.name != 'dns_name':
                    raise PolicyDenial('only DNS SAN names are supported')
                host = general_name.native
                if not self._suffix_allowed(host):
                    raise PolicyDenial('SAN name %r outside allowed suffixes' % host)
            # The CA, not the applicant, chooses the criticality of a leaf SAN.
            return {'oid': oid, 'action': 'issue', 'critical': False,
                    'value': [g.native for g in names]}

        if oid == EKU_OID:
            requested = set(ext['parsed'].native)
            if not requested <= self.allowed_eku:
                raise PolicyDenial('EKU %r exceeds profile' % requested)
            return {'oid': oid, 'action': 'issue', 'critical': False,
                    'value': sorted(requested)}

        # Unknown critical extension: the parser preserved the bytes and the
        # critical flag, but policy cannot interpret it, so it must refuse.
        if ext['critical']:
            raise PolicyDenial(
                'unknown critical extension %s cannot be honored' % oid
            )
        # Unknown non-critical extension: omit it from the certificate rather
        # than copying opaque bytes blindly.
        return None

    def _suffix_allowed(self, host):
        host = host.lower().rstrip('.')
        return any(host == s.lstrip('.') or host.endswith(s)
                   for s in self.allowed_san_suffixes)
