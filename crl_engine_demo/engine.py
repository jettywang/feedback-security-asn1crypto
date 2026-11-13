# coding: utf-8
"""Composition engine for indirect CRLs and delta CRLs.

Design invariants (RFC 5280 5.2):

* Parsed != trusted. A CRL starts life as TrustLevel.PARSED. Only after an
  injected signature verifier accepts it, and the engine's own freshness and
  ordering checks pass, does it become TRUSTED and enter a scope's state.
* Identity of a revoked cert is (certificateIssuer, serial). Serial-only
  matching is forbidden.
* A delta merges only into a base with byte-identical scope (same CRL issuer,
  same issuingDistributionPoint semantics) and a valid baseCRLNumber linkage.
* Every stop condition raises TrustBoundaryError: the caller must treat the
  affected scope as UNKNOWN rather than fall back to "not revoked".
"""

from __future__ import unicode_literals

from asn1crypto.crl import CertificateList

from .model import (
    EntryKey,
    ParsedCRL,
    ParsedEntry,
    RevocationFact,
    RevocationStatus,
    TrustLevel,
    Verdict,
    CRLScope,
)

# CRLReason code -> ReasonFlags bit position (RFC 5280 5.2.5, note bit 7 is
# unused because removeFromCRL(8) is a delta instruction, not a scope reason).
REASON_BIT = {
    'key_compromise': 1,
    'ca_compromise': 2,
    'affiliation_changed': 3,
    'superseded': 4,
    'cessation_of_operation': 5,
    'certificate_hold': 6,
    'privilege_withdrawn': 7,
    'aa_compromise': 9,
    'unspecified': None,
    'remove_from_crl': None,
}


class TrustBoundaryError(Exception):
    """Raised when a revocation conclusion cannot be established. The safe
    response is RevocationStatus.UNKNOWN / fail-closed, never 'good'."""


class CRLEngine:
    def __init__(self, signature_verifier, now_provider, strict_base=True):
        """
        :param signature_verifier: callable(CertificateList) -> bool. Encapsulates
            the PKI trust decision (issuer cert lookup, AKI chaining, signature
            check). The engine never invents trust.
        :param now_provider: callable() -> datetime for freshness checks.
        :param strict_base: True = delta requires an exact baseCRLNumber match
            (RFC 5280 literal). False = tolerate newer bases per common
            implementations, still with full scope/ordering validation.
        """
        self._verify = signature_verifier
        self._now = now_provider
        self.strict_base = strict_base
        # scope identity key -> ScopeState
        self._scopes = {}
        self.trace = []

    # ------------------------------------------------------------------ parse

    def parse(self, der_bytes):
        """Stage 1: DER -> ParsedCRL. Pure decoding + certificateIssuer
        inheritance. No trust is conferred here."""
        cert_list = CertificateList.load(der_bytes)
        tbs = cert_list['tbs_cert_list']
        crl_issuer = tbs['issuer']

        delta_ind = cert_list.delta_crl_indicator_value
        kind = 'delta' if delta_ind is not None else 'base'
        crl_number = self._int(cert_list.crl_number_value)
        base_crl_number = self._int(delta_ind) if delta_ind is not None else None

        idp = cert_list.issuing_distribution_point_value
        scope = self._build_scope(crl_issuer, idp)

        entries, warnings = self._resolve_entries(
            tbs, crl_issuer, scope, bool(idp and idp['indirect_crl'].native))

        parsed = ParsedCRL(
            cert_list=cert_list,
            kind=kind,
            crl_number=crl_number,
            base_crl_number=base_crl_number,
            this_update=tbs['this_update'].native,
            next_update=tbs['next_update'].native if tbs['next_update'].chosen else None,
            scope=scope,
            entries=entries,
            parse_warnings=warnings,
        )
        self.trace.append(('parse', kind, crl_number,
                           [(e.key.serial, e.reason, e.inherited_from_previous)
                            for e in entries]))
        return parsed

    def _resolve_entries(self, tbs, crl_issuer, scope, indirect_flag):
        """RFC 5280 5.2.5: process revokedCertificates in order; a
        certificateIssuer extension applies to its own entry and remains the
        'last seen issuer' for every following entry until replaced. Entries
        without the extension inherit the running issuer (which starts as the
        CRL issuer)."""
        entries = []
        warnings = []
        running_issuer = crl_issuer          # default before any extension
        revoked = tbs['revoked_certificates']
        if len(revoked) == 0:
            return entries, warnings

        for rc in revoked:
            serial = rc['user_certificate'].native
            ext_issuer = rc.issuer_name      # None when extension absent
            inherited = False
            if ext_issuer is not None:
                running_issuer = ext_issuer
            else:
                inherited = True             # took the running/default issuer
            key = EntryKey.from_name(running_issuer, serial)

            reason_obj = rc.crl_reason_value
            reason = reason_obj.native if reason_obj is not None else 'unspecified'

            if reason == 'remove_from_crl' and not indirect_flag:
                warnings.append(
                    'removeFromCRL present but IDP indirect_crl is not asserted')
            if ext_issuer is not None and not indirect_flag:
                warnings.append(
                    'certificateIssuer present but IDP indirect_crl is not asserted')

            entries.append(ParsedEntry(
                key=key,
                reason=reason,
                revocation_date=rc['revocation_date'].native,
                had_certificate_issuer_ext=ext_issuer is not None,
                inherited_from_previous=inherited,
            ))
        return entries, warnings

    def _build_scope(self, crl_issuer, idp):
        if idp is None:
            return CRLScope(
                crl_issuer_der=crl_issuer.dump(),
                idp_der=None, indirect=False,
                only_user_certs=False, only_ca_certs=False,
                only_attribute_certs=False,
                only_some_reasons_der=None, dp_full_name_der=None)

        dp = idp['distribution_point']
        dp_der = None
        if dp.chosen is not None and dp.name == 'full_name':
            dp_der = dp.chosen.dump()
        reasons = idp['only_some_reasons']
        # IMPLICIT [3] wrapper means .dump() carries a context tag; keep only
        # the BitString content bytes so scope comparison and rebuild work.
        reasons_der = bytes(reasons.contents) if reasons.native is not None else None
        return CRLScope(
            crl_issuer_der=crl_issuer.dump(),
            idp_der=idp.dump(),
            indirect=bool(idp['indirect_crl'].native),
            only_user_certs=bool(idp['only_contains_user_certs'].native),
            only_ca_certs=bool(idp['only_contains_ca_certs'].native),
            only_attribute_certs=bool(idp['only_contains_attribute_certs'].native),
            only_some_reasons_der=reasons_der,
            dp_full_name_der=dp_der)

    @staticmethod
    def _int(value):
        return None if value is None else int(value.native)

    @staticmethod
    def _naive_utc(value):
        if value is None:
            return None
        if value.tzinfo is not None:
            import datetime
            return value.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        return value

    # ------------------------------------------------------------------ trust

    def establish_trust(self, parsed):
        """Stage 2: cross the parsed -> trusted boundary. Runs the injected
        signature verifier and all context checks. Failure raises
        TrustBoundaryError and leaves scope state untouched."""
        if not self._verify(parsed.cert_list):
            raise TrustBoundaryError(
                'signature/issuer trust rejected for CRL number %r'
                % parsed.crl_number)

        now = self._now()
        this_update = self._naive_utc(parsed.this_update)
        next_update = self._naive_utc(parsed.next_update)
        if next_update is not None and now > next_update:
            raise TrustBoundaryError(
                'CRL number %r is stale: now %s > nextUpdate %s'
                % (parsed.crl_number, now, next_update))
        if now < this_update:
            raise TrustBoundaryError(
                'CRL number %r is not yet valid (thisUpdate %s in future)'
                % (parsed.crl_number, this_update))
        if parsed.crl_number is None:
            raise TrustBoundaryError('CRL number extension is required for merge')

        parsed.trust = TrustLevel.TRUSTED
        self.trace.append(('trust', parsed.kind, parsed.crl_number, 'accepted'))
        return parsed

    # ------------------------------------------------------------------ ingest

    def ingest(self, der_bytes):
        """Parse + trust + merge in one call, returning the ParsedCRL. Any
        TrustBoundaryError aborts before state is mutated."""
        parsed = self.parse(der_bytes)
        self.establish_trust(parsed)
        state = self._select_scope(parsed)
        if parsed.kind == 'base':
            state.apply_base(parsed, self.trace)
        else:
            state.apply_delta(parsed, self.trace, self.strict_base)
        return parsed

    def _select_scope(self, parsed):
        """Locate the stream this CRL belongs to. A delta may never open a new
        scope silently: if any existing scope shares the CRL issuer but has a
        different IDP/cert-type/reason set, that is an incompatibility, not a
        second valid stream."""
        key = parsed.scope.idp_der or parsed.scope.crl_issuer_der
        existing = self._scopes.get(key)
        if existing is not None:
            if not existing.scope.is_compatible_with(parsed.scope):
                raise TrustBoundaryError(
                    'scope collision on key: non-identical IDP/issuer fields')
            return existing
        if parsed.kind == 'delta':
            for state in self._scopes.values():
                if state.scope.crl_issuer_der == parsed.scope.crl_issuer_der:
                    raise TrustBoundaryError(
                        'delta scope (IDP/cert-type/reason-set) is incompatible '
                        'with the base scope for the same CRL issuer; merge refused')
        state = ScopeState(parsed.scope)
        self._scopes[key] = state
        return state

    # ------------------------------------------------------------------ query

    def lookup(self, issuer_name, serial, scope_key=None):
        """Return a Verdict. Missing/out-of-order inputs yield UNKNOWN, never
        an implicit 'good'. scope_key may pin the IDP DER; otherwise all
        scopes whose stream could contain the cert are considered."""
        key = EntryKey.from_name(issuer_name, serial)
        if not self._scopes:
            return Verdict(key, RevocationStatus.UNKNOWN, None, None,
                           CRLScope(b'', None, False, False, False, False, None, None),
                           ['no CRL ingested'])
        notes = []
        for sk, state in self._scopes.items():
            if scope_key is not None and sk != scope_key:
                continue
            fact = state.facts.get(key)
            if fact is None:
                notes.append('scope %s: not listed' % sk[:8].hex())
                continue
            notes.append('scope %s: %s via CRL #%d (%s)'
                         % (sk[:8].hex(), fact.status.value,
                            fact.source_crl_number, fact.source_kind))
            if fact.status == RevocationStatus.REVOKED:
                return Verdict(key, fact.status, fact.reason,
                               fact.source_crl_number, state.scope, notes)
        # Listed as REMOVED everywhere it appears, or never listed.
        for state in self._scopes.values():
            fact = state.facts.get(key)
            if fact is not None and fact.status == RevocationStatus.REMOVED:
                return Verdict(key, RevocationStatus.REMOVED, fact.reason,
                               fact.source_crl_number, state.scope, notes)
        return Verdict(key, RevocationStatus.NOT_LISTED, None, None,
                       next(iter(self._scopes.values())).scope, notes)


class ScopeState:
    """Mutable trusted state for one CRL stream (one issuer + one IDP)."""

    def __init__(self, scope):
        self.scope = scope
        self.facts = {}                       # EntryKey -> RevocationFact
        self.bases = {}                       # crl_number -> ParsedCRL
        self.deltas = []                      # ParsedCRL in arrival order
        self.base_number = None

    def apply_base(self, parsed, trace):
        # A newer complete CRL is a full replacement of the stream's view.
        if self.base_number is not None and parsed.crl_number <= self.base_number:
            raise TrustBoundaryError(
                'out-of-order base #%r: current base is #%r'
                % (parsed.crl_number, self.base_number))
        self.facts = {}
        for entry in parsed.entries:
            self._ingest_entry(entry, parsed, trace)
        self.bases[parsed.crl_number] = parsed
        self.base_number = parsed.crl_number
        # Re-apply any deltas that still chain from this base (handles base
        # refresh between delta arrivals).
        chained = [d for d in self.deltas
                   if d.base_crl_number <= parsed.crl_number < d.crl_number]
        for delta in sorted(chained, key=lambda d: d.crl_number):
            self._merge_delta(delta, trace)
        trace.append(('base', parsed.crl_number, 'snapshot replaced',
                      sorted(k.serial for k in self.facts)))

    def apply_delta(self, parsed, trace, strict_base):
        if self.base_number is None:
            raise TrustBoundaryError(
                'delta #%r arrived before any base CRL; cannot interpret '
                'removeFromCRL without a base' % parsed.crl_number)
        if not self.scope.is_compatible_with(parsed.scope):
            raise TrustBoundaryError('delta scope differs from base scope')
        if parsed.base_crl_number > self.base_number:
            raise TrustBoundaryError(
                'delta #%r references base #%r but only #%r is available; '
                'stop and fetch the referenced base'
                % (parsed.crl_number, parsed.base_crl_number, self.base_number))
        if strict_base and parsed.base_crl_number != self.base_number:
            raise TrustBoundaryError(
                'strict mode: delta baseCRLNumber #%r != current base #%r'
                % (parsed.base_crl_number, self.base_number))
        if parsed.crl_number <= self.base_number:
            raise TrustBoundaryError(
                'delta CRL number #%r must exceed base #%r'
                % (parsed.crl_number, self.base_number))
        for prior in self.deltas:
            if prior.crl_number == parsed.crl_number:
                raise TrustBoundaryError('duplicate delta #%r' % parsed.crl_number)
            if prior.crl_number > parsed.crl_number:
                raise TrustBoundaryError(
                    'out-of-order delta #%r after #%r; rebuild from base'
                    % (parsed.crl_number, prior.crl_number))
        self.deltas.append(parsed)
        self._merge_delta(parsed, trace)

    def _merge_delta(self, delta, trace):
        for entry in delta.entries:
            if entry.reason == 'remove_from_crl':
                self._apply_removal(entry, delta, trace)
            else:
                # A new/changed revocation. Replaces reason for a known key,
                # otherwise adds it. certificate_hold -> definitive reason is
                # the normal hold-release-by-revocation transition.
                self._ingest_entry(entry, delta, trace)

    def _apply_removal(self, entry, delta, trace):
        existing = self.facts.get(entry.key)
        if existing is None:
            trace.append(('delta', delta.crl_number,
                          'removeFromCRL for unknown key serial=%d -> no-op (still not listed)'
                          % entry.key.serial))
            return
        if existing.reason != 'certificate_hold':
            # RFC 5280 5.2.4: removeFromCRL is only meaningful for holds; a
            # definitive revocation cannot be undone by a delta.
            trace.append(('delta', delta.crl_number,
                          'removeFromCRL rejected for serial=%d: reason %s is definitive'
                          % (entry.key.serial, existing.reason)))
            return
        self.facts[entry.key] = existing.clone(
            status=RevocationStatus.REMOVED,
            reason='remove_from_crl',
            source_crl_number=delta.crl_number,
            source_kind='delta')
        trace.append(('delta', delta.crl_number,
                      'serial=%d hold REMOVED' % entry.key.serial))

    def _ingest_entry(self, entry, source, trace):
        if not self.scope.reason_in_scope(entry.reason):
            trace.append(('scope', source.crl_number,
                          'serial=%d reason %s outside onlySomeReasons -> ignored in this scope'
                          % (entry.key.serial, entry.reason)))
            return
        fact = RevocationFact(
            key=entry.key,
            reason=entry.reason,
            revocation_date=entry.revocation_date,
            source_crl_number=source.crl_number,
            source_kind=source.kind,
            status=RevocationStatus.REVOKED)
        old = self.facts.get(entry.key)
        self.facts[entry.key] = fact
        trace.append((source.kind, source.crl_number,
                      'serial=%d issuer=%s reason=%s%s'
                      % (entry.key.serial, entry.key.issuer_der[:4].hex(),
                         entry.reason,
                         '' if old is None else ' (replaced %s)' % old.reason)))
