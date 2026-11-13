# coding: utf-8
"""Data model that keeps two layers strictly separate:

1. Parsed layer — what asn1crypto decoded from the DER. Nothing here has been
   validated; a signature failure or out-of-order update means these objects
   must never drive a security decision.
2. Trusted layer — facts/verdicts derived only from CRLs whose signature and
   temporal/context checks have passed inside an established scope.

The split mirrors RFC 5280 5.2: parsing (5.2.1..5.2.5) versus path
validation (6.3), where CRL processing only produces a revocation conclusion
for an already validated certificate.
"""

from __future__ import unicode_literals

import enum
from dataclasses import dataclass, field
from typing import Optional

from asn1crypto.crl import CertificateList


class TrustLevel(enum.Enum):
    PARSED = 'parsed'          # DER decoded, signature/context NOT verified
    TRUSTED = 'trusted'        # signature + scope + ordering checks passed


class RevocationStatus(enum.Enum):
    """Per-(issuer, serial) state inside ONE trusted CRL scope."""

    NOT_LISTED = 'not_listed'            # no entry in the composed CRL view
    REVOKED = 'revoked'                  # on-hold or definitively revoked
    REMOVED = 'removed'                  # removeFromCRL applied in this view
    UNKNOWN = 'unknown'                  # cannot decide; caller must not allow


class EntryKey:
    """The identity of a revoked certificate is (certificateIssuer, serial),
    never the serial alone. Two different issuers reusing the same serial
    number are different certificates and must never collide.

    The issuer is normalized to the DER of its RDNSequence (RFC 5280 7.1
    comparison), so encoding differences (PrintableString vs UTF8String with
    the same abstract value, whitespace) compare correctly.
    """

    __slots__ = ('issuer_der', 'serial')

    def __init__(self, issuer_der, serial):
        self.issuer_der = bytes(issuer_der)
        self.serial = int(serial)

    @classmethod
    def from_name(cls, name, serial):
        return cls(name.chosen.dump() if name.name == '' else name.dump(), serial)

    def __eq__(self, other):
        return (isinstance(other, EntryKey)
                and self.serial == other.serial
                and self.issuer_der == other.issuer_der)

    def __hash__(self):
        return hash((self.issuer_der, self.serial))

    def __repr__(self):
        return 'EntryKey(serial=%d, issuer_der=%s...)' % (
            self.serial, self.issuer_der[:6].hex())


@dataclass
class RevocationFact:
    """A trusted revocation fact (a composed entry in one scope)."""

    key: EntryKey
    reason: str                       # CRLReason native name, 'unspecified' default
    revocation_date: object           # asn1crypto Time
    source_crl_number: int            # CRL number of the CRL that last set it
    source_kind: str                  # 'base' | 'delta'
    status: RevocationStatus

    def clone(self, **changes):
        data = {
            'key': self.key,
            'reason': self.reason,
            'revocation_date': self.revocation_date,
            'source_crl_number': self.source_crl_number,
            'source_kind': self.source_kind,
            'status': self.status,
        }
        data.update(changes)
        return RevocationFact(**data)


@dataclass
class CRLScope:
    """The identity of a CRL stream. Base and delta can only merge when every
    field matches. Serial-number merging across different scopes is invalid.
    """

    crl_issuer_der: bytes
    idp_der: Optional[bytes]                  # DER of IDP extnValue, or None
    indirect: bool
    only_user_certs: bool
    only_ca_certs: bool
    only_attribute_certs: bool
    only_some_reasons_der: Optional[bytes]    # DER of ReasonFlags, or None
    dp_full_name_der: Optional[bytes]         # DER of full GeneralNames, or None

    def is_compatible_with(self, other):
        """RFC 5280 5.2.4 (b): same issuer and same issuing distribution point
        / scope. We compare the structural scope fields rather than relying on
        a single DER blob so the reason-set and cert-type flags participate.
        """
        return (
            self.crl_issuer_der == other.crl_issuer_der
            and self.idp_der == other.idp_der
            and self.indirect == other.indirect
            and self.only_user_certs == other.only_user_certs
            and self.only_ca_certs == other.only_ca_certs
            and self.only_attribute_certs == other.only_attribute_certs
            and self.only_some_reasons_der == other.only_some_reasons_der
            and self.dp_full_name_der == other.dp_full_name_der
        )

    def reason_in_scope(self, reason):
        """only_some_reasons limits which reason codes this CRL is
        authoritative for. A None reason set means the CRL covers all reasons.
        ReasonFlags bit mapping: RFC 5280 5.2.5 / asn1crypto ReasonFlags._map.
        """
        if self.only_some_reasons_der is None:
            return True
        return reason in self._reason_bits()

    def _reason_bits(self):
        from asn1crypto.x509 import ReasonFlags
        flags = ReasonFlags()
        flags.contents = self.only_some_reasons_der
        return set(flags.native)


@dataclass
class ParsedCRL:
    """Everything asn1crypto decoded from one CertificateList, plus a
    trace of certificateIssuer inheritance. Still UNTRUSTED at this stage.
    """

    cert_list: CertificateList
    kind: str                                  # 'base' | 'delta'
    crl_number: Optional[int]
    base_crl_number: Optional[int]             # only for deltas
    this_update: object
    next_update: object
    scope: CRLScope
    entries: list = field(default_factory=list)   # list[ParsedEntry]
    trust: TrustLevel = TrustLevel.PARSED
    parse_warnings: list = field(default_factory=list)


@dataclass
class ParsedEntry:
    """One revokedCertificates item after inheritance resolution."""

    key: EntryKey
    reason: str
    revocation_date: object
    had_certificate_issuer_ext: bool
    inherited_from_previous: bool


@dataclass
class Verdict:
    """Final answer for one (issuer, serial) lookup in one scope."""

    key: EntryKey
    status: RevocationStatus
    reason: Optional[str]
    source_crl_number: Optional[int]
    scope: CRLScope
    notes: list = field(default_factory=list)
