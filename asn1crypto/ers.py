# coding: utf-8

"""
Offline consistency checking for RFC 4998 (Evidence Record Syntax) archive
time stamp renewal chains. Exports the following items:

 - check_evidence_record()
 - check_der()
 - CheckResult()
 - Finding()
 - STATUS_PASS, STATUS_FAIL, STATUS_UNVERIFIED
 - SEVERITY_INFO, SEVERITY_WARNING, SEVERITY_ERROR

The checker uses only information present in the evidence record. It never
verifies CMS signatures, so signature trust is always reported as not
checked and never contributes to a pass or fail result.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import hashlib
import sys

from ._types import byte_cls
from .cms import (
    ContentInfo,
    EncapsulatedContentInfo,
    ParsableOctetString,
)
from .core import (
    Any,
    Asn1Value,
    OctetString,
    Void,
)
from .tsp import (
    ArchiveTimeStampSequence,
    TSTInfo,
)


STATUS_PASS = 'pass'
STATUS_FAIL = 'fail'
STATUS_UNVERIFIED = 'unverified'

SEVERITY_INFO = 'info'
SEVERITY_WARNING = 'warning'
SEVERITY_ERROR = 'error'

# Finding categories, so callers can tell the three kinds of outcome apart
CATEGORY_STRUCTURE = 'structure'
CATEGORY_CHAIN = 'chain'
CATEGORY_DATA = 'data'
CATEGORY_SIGNATURE = 'signature'

# asn1crypto digest names mapped to hashlib constructor names. Anything not
# in this map is passed to hashlib as-is; when hashlib does not know it, the
# affected check is reported as unverified instead of failed.
_HASHLIB_NAMES = {
    'md2': 'md2',
    'md5': 'md5',
    'sha1': 'sha1',
    'sha224': 'sha224',
    'sha256': 'sha256',
    'sha384': 'sha384',
    'sha512': 'sha512',
    'sha512_224': 'sha512_224',
    'sha512_256': 'sha512_256',
    'sha3_224': 'sha3_224',
    'sha3_256': 'sha3_256',
    'sha3_384': 'sha3_384',
    'sha3_512': 'sha3_512',
}

_RENEWAL_INITIAL = 'initial'
_RENEWAL_TIMESTAMP = 'timestamp'
_RENEWAL_HASH_TREE = 'hash_tree'

_OUTCOME_OK = 'ok'
_OUTCOME_MISMATCH = 'mismatch'
_OUTCOME_UNVERIFIED = 'unverified'
_OUTCOME_UNCHECKED = 'unchecked'
_OUTCOME_ERROR = 'error'


class Finding(object):
    """
    A single result from checking an evidence record. Findings about one
    archive time stamp carry the zero-based chain index and the zero-based
    entry index within that chain. The indexes always refer to the original
    DER order - entries are never sorted or rewritten.
    """

    def __init__(self, code, message, severity=SEVERITY_ERROR,
                 category=CATEGORY_CHAIN, chain_index=None, entry_index=None,
                 details=None):
        self.code = code
        self.message = message
        self.severity = severity
        self.category = category
        self.chain_index = chain_index
        self.entry_index = entry_index
        self.details = details or {}

    def __repr__(self):
        return '<Finding %s at %s>' % (self.code, self.location or 'record')

    def __eq__(self, other):
        if not isinstance(other, Finding):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self.__eq__(other)

    @property
    def location(self):
        """
        :return:
            A unicode string identifying the chain and entry, or None when
            the finding is not tied to one archive time stamp
        """

        if self.chain_index is None:
            return None
        if self.entry_index is None:
            return 'chain %d' % self.chain_index
        return 'chain %d entry %d' % (self.chain_index, self.entry_index)

    def native(self):
        """
        :return:
            A dict containing only JSON-serializable values
        """

        return {
            'code': self.code,
            'message': self.message,
            'severity': self.severity,
            'category': self.category,
            'chain_index': self.chain_index,
            'entry_index': self.entry_index,
            'location': self.location,
            'details': self.details,
        }


class CheckResult(object):
    """
    The outcome of checking an evidence record.

    The overall status is one of:

     - pass: every check that applies to the record was performed and passed
     - fail: at least one error finding was produced
     - unverified: no error was found, but at least one applicable check could
       not be performed offline, for example an unsupported digest algorithm
       or an unimplemented hash-tree algorithm change

    Signature trust is deliberately outside the status. It is reported by
    signature_checked and by the signature_not_checked finding.
    """

    def __init__(self, findings=None, chain_count=0, entries=None,
                 signature_checked=False):
        self.findings = list(findings or [])
        self.chain_count = chain_count
        self.entries = list(entries or [])
        self.signature_checked = signature_checked

    def __repr__(self):
        return '<CheckResult %s chains=%d entries=%d findings=%d>' % (
            self.status, self.chain_count, len(self.entries), len(self.findings))

    @property
    def status(self):
        if any(f.severity == SEVERITY_ERROR for f in self.findings):
            return STATUS_FAIL
        if any(f.severity == SEVERITY_WARNING for f in self.findings):
            return STATUS_UNVERIFIED
        return STATUS_PASS

    @property
    def chain_breaks(self):
        """
        :return:
            A list of Finding objects where a renewal timestamp does not
            cover the previous timestamp or the previous chains, or where a
            digest algorithm or time order is inconsistent
        """

        return [f for f in self.findings
                if f.category == CATEGORY_CHAIN and f.severity == SEVERITY_ERROR]

    @property
    def structural_errors(self):
        """
        :return:
            A list of Finding objects about malformed evidence record
            structure, independent of any hash comparison
        """

        return [f for f in self.findings
                if f.category == CATEGORY_STRUCTURE and f.severity == SEVERITY_ERROR]

    @property
    def unverified_findings(self):
        """
        :return:
            A list of Finding objects about applicable checks that could not
            be performed offline
        """

        return [f for f in self.findings if f.severity == SEVERITY_WARNING]

    @property
    def signature_findings(self):
        """
        :return:
            A list of Finding objects about signature trust
        """

        return [f for f in self.findings if f.category == CATEGORY_SIGNATURE]

    def native(self):
        """
        :return:
            A dict containing only JSON-serializable values
        """

        return {
            'status': self.status,
            'chain_count': self.chain_count,
            'entry_count': len(self.entries),
            'signature_checked': self.signature_checked,
            'chain_breaks': [f.native() for f in self.chain_breaks],
            'structural_errors': [f.native() for f in self.structural_errors],
            'unverified': [f.native() for f in self.unverified_findings],
            'signature': [f.native() for f in self.signature_findings],
            'entries': self.entries,
            'findings': [f.native() for f in self.findings],
        }


def check_der(encoded_data, strict=False, **kwargs):
    """
    Parses a DER-encoded RFC 4998 EvidenceRecord and runs
    check_evidence_record()

    A byte string that is not parseable as an EvidenceRecord produces a
    CheckResult with status "fail" and a structure finding, rather than
    raising, so callers can process untrusted input uniformly.

    :param encoded_data:
        A byte string of the DER-encoded EvidenceRecord

    :param strict:
        A boolean indicating if trailing data should be forbidden

    :return:
        A CheckResult object
    """

    from .tsp import EvidenceRecord
    try:
        evidence_record = EvidenceRecord.load(encoded_data, strict=strict)
    except (ValueError, TypeError) as e:
        return CheckResult([
            Finding(
                'signature_not_checked',
                'CMS signature trust was not checked; parsing failed before '
                'any chain could be inspected',
                severity=SEVERITY_INFO,
                category=CATEGORY_SIGNATURE,
            ),
            Finding(
                'invalid_evidence_record',
                'the input is not a parseable EvidenceRecord: %s' % e,
                category=CATEGORY_STRUCTURE,
            ),
        ], 0, [])
    return check_evidence_record(evidence_record, **kwargs)


def check_evidence_record(evidence_record, derive_algorithm=True):
    """
    Checks the internal consistency of an RFC 4998 EvidenceRecord. This is
    an offline check: digests are recomputed from the data present in the
    record, but no CMS signature is verified.

    Checks performed:

     - the EvidenceRecord version is v1
     - every chain contains at least one archive time stamp
     - all entries in one chain use the same digest algorithm
     - an explicitly encoded digest algorithm agrees with the hash algorithm
       of the wrapped TSTInfo message imprint
     - generation times are non-decreasing within a chain and from one chain
       to the next
     - entry N in a chain covers the DER encoding of the timeStamp token of
       entry N-1
     - the first entry of chain N covers the DER encoding of all previous
       chains
     - a reduced hash tree is rebuilt and the resulting root is compared with
       the digest the wrapped timestamp actually signs

    Entries are never reordered, and no part of the input is rewritten.

    Renewal digests are computed over the DER encoding of the previous
    timestamp token, matching RFC 4998's instruction to hash the timestamp
    as a DER value. A token that parsed from non-DER BER is re-encoded for
    hashing only; the record itself is never modified, and the result then
    depends on the re-encoded form being the one that was timestamped.

    :param evidence_record:
        An asn1crypto.tsp.EvidenceRecord object

    :param derive_algorithm:
        If True, an ArchiveTimeStamp without an explicit digest_algorithm
        uses the hash algorithm of its wrapped TSTInfo message imprint. If
        False, only explicitly encoded digest algorithms are used, and a
        missing one makes the entry unverified.

    :return:
        A CheckResult object
    """

    findings = []
    chain_count = 0

    findings.append(Finding(
        'signature_not_checked',
        'CMS signature trust was not checked; only the archive time stamp '
        'chain was verified',
        severity=SEVERITY_INFO,
        category=CATEGORY_SIGNATURE,
    ))

    try:
        version = evidence_record['version'].native
        sequence = evidence_record['archive_time_stamp_sequence']
        chains = list(sequence)
        chain_count = len(chains)
    except (ValueError, TypeError, KeyError) as e:
        message = 'could not parse the evidence record: %s' % e
        if 'archive_time_stamp_sequence' in str(e):
            message = (
                'could not parse the layered archive time stamp sequence '
                '(%s); a flat pre-ArchiveTimeStampChain encoding must be '
                'migrated explicitly with '
                'tsp.ArchiveTimeStampSequence.from_legacy_flat_der() instead '
                'of being silently accepted' % ' '.join(str(e).split())
            )
        findings.append(Finding(
            'invalid_evidence_record',
            message,
            category=CATEGORY_STRUCTURE,
        ))
        return CheckResult(findings, chain_count, [])

    if version != 'v1':
        findings.append(Finding(
            'unsupported_version',
            'EvidenceRecord version must be v1 for RFC 4998, not "%s"' % version,
            category=CATEGORY_STRUCTURE,
        ))
        return CheckResult(findings, chain_count, [])

    if not chains:
        findings.append(Finding(
            'empty_sequence',
            'the archive time stamp sequence contains no chains',
            category=CATEGORY_STRUCTURE,
        ))
        return CheckResult(findings, chain_count, [])

    chain_entries = []
    for chain_index, chain in enumerate(chains):
        raw_entries = list(chain)
        if not raw_entries:
            findings.append(Finding(
                'empty_chain',
                'chain contains no archive time stamps',
                category=CATEGORY_STRUCTURE,
                chain_index=chain_index,
            ))
        extracted = []
        for entry_index, entry in enumerate(raw_entries):
            item = _extract_entry(entry, chain_index, entry_index, derive_algorithm)
            extracted.append(item)
            if item.error is not None:
                findings.append(Finding(
                    item.error.code,
                    item.error.message,
                    category=CATEGORY_STRUCTURE,
                    chain_index=chain_index,
                    entry_index=entry_index,
                ))
        chain_entries.append(extracted)

    for chain_index, extracted in enumerate(chain_entries):
        _check_chain_algorithms(findings, extracted, chain_index)

    _check_time_order(findings, chain_entries)

    for chain_index, extracted in enumerate(chain_entries):
        for entry_index, item in enumerate(extracted):
            if item.error is not None:
                item.outcome = _OUTCOME_ERROR
                continue

            if item.algorithm_conflict:
                item.outcome = _OUTCOME_UNVERIFIED
                continue

            if entry_index == 0:
                if chain_index == 0:
                    item.renewal = _RENEWAL_INITIAL
                    item.outcome = _OUTCOME_UNCHECKED
                    findings.append(Finding(
                        'initial_timestamp_not_checked',
                        'the initial timestamp covers the archived data, which '
                        'is not part of the evidence record; only its algorithm '
                        'and structure were checked',
                        severity=SEVERITY_INFO,
                        category=CATEGORY_DATA,
                        chain_index=chain_index,
                        entry_index=entry_index,
                    ))
                else:
                    item.renewal = _RENEWAL_HASH_TREE
                    _check_hash_tree_renewal(
                        findings, item, chain_entries, chain_index, entry_index,
                    )
                continue

            item.renewal = _RENEWAL_TIMESTAMP
            previous = extracted[entry_index - 1]
            if previous.error is not None or previous.time_stamp is None:
                item.outcome = _OUTCOME_UNVERIFIED
                continue
            if item.algorithm is None:
                item.outcome = _OUTCOME_UNVERIFIED
                continue
            algorithm_name = _hashlib_name(item.algorithm)
            if algorithm_name is None:
                item.outcome = _OUTCOME_UNVERIFIED
                findings.append(Finding(
                    'unsupported_digest_algorithm',
                    'digest algorithm "%s" is not available for offline digest '
                    'recomputation' % item.algorithm,
                    severity=SEVERITY_WARNING,
                    category=CATEGORY_CHAIN,
                    chain_index=chain_index,
                    entry_index=entry_index,
                    details={'algorithm': item.algorithm},
                ))
                continue

            # RFC 4998 renews the timestamp token bytes. A renewal may cover
            # several earlier timestamps at once, so the immediate previous
            # digest must appear as one value of the first partial hashtree;
            # the hash tree may carry other covered digests alongside it.
            item.leaf_digest = _hash(algorithm_name, previous.time_stamp.dump())
            _check_coverage(
                findings, item, chain_index, entry_index,
                leaf_digest=item.leaf_digest,
                renewal='previous timestamp',
            )

    # Any applicable check that was skipped still has to become visible, so
    # the overall status can not silently degrade to "pass"
    for chain_index, extracted in enumerate(chain_entries):
        for item in extracted:
            if item.error is not None or item.outcome != _OUTCOME_UNVERIFIED:
                continue
            if _has_unverified_finding(findings, chain_index, item.entry_index):
                continue
            findings.append(Finding(
                'renewal_unverified',
                'the renewal coverage of this archive time stamp could not be '
                'checked offline',
                severity=SEVERITY_WARNING,
                category=CATEGORY_CHAIN,
                chain_index=chain_index,
                entry_index=item.entry_index,
            ))

    entries = [item.native() for extracted in chain_entries for item in extracted]
    return CheckResult(findings, chain_count, entries)


class _StructuralError(Exception):

    def __init__(self, code, message):
        Exception.__init__(self, message)
        self.code = code
        self.message = message


class _Entry(object):
    """
    Internal extracted representation of one ArchiveTimeStamp
    """

    def __init__(self, raw, chain_index, entry_index):
        self.raw = raw
        self.chain_index = chain_index
        self.entry_index = entry_index
        self.time_stamp = None
        self.tst_info = None
        self.gen_time = None
        self.imprint_algorithm = None
        self.imprint_digest = None
        self.explicit_algorithm = None
        self.algorithm = None
        self.algorithm_source = None
        self.algorithm_conflict = False
        self.reduced_hashtree = None
        self.error = None
        self.renewal = None
        self.outcome = _OUTCOME_UNCHECKED
        self.leaf_digest = None
        self.rebuilt_root = None
        self.previous_chains_digest = None

    def native(self):
        return {
            'chain_index': self.chain_index,
            'entry_index': self.entry_index,
            'gen_time': self.gen_time.isoformat() if self.gen_time is not None else None,
            'explicit_algorithm': self.explicit_algorithm,
            'derived_algorithm': self.imprint_algorithm,
            'algorithm': self.algorithm,
            'algorithm_source': self.algorithm_source,
            'renewal': self.renewal,
            'reduced_hashtree': self.reduced_hashtree is not None,
            'leaf_digest': _hex(self.leaf_digest),
            'previous_chains_digest': _hex(self.previous_chains_digest),
            'imprint_digest': _hex(self.imprint_digest),
            'rebuilt_root': _hex(self.rebuilt_root),
            'outcome': self.outcome,
            'error': self.error.code if self.error is not None else None,
        }


def _extract_entry(raw, chain_index, entry_index, derive_algorithm):
    item = _Entry(raw, chain_index, entry_index)

    try:
        time_stamp = raw['time_stamp']
    except (ValueError, TypeError, KeyError) as e:
        item.error = _StructuralError(
            'invalid_archive_time_stamp',
            'could not parse the archive time stamp: %s' % e,
        )
        return item

    if isinstance(time_stamp, Void) or time_stamp is None:
        item.error = _StructuralError(
            'missing_time_stamp',
            'archive time stamp has no time_stamp ContentInfo',
        )
        return item
    item.time_stamp = time_stamp

    try:
        item.tst_info = _extract_tst_info(time_stamp)
    except _StructuralError as e:
        item.error = e
        return item

    try:
        item.gen_time = item.tst_info['gen_time'].native
        item.imprint_algorithm = item.tst_info['message_imprint']['hash_algorithm']['algorithm'].native
        item.imprint_digest = item.tst_info['message_imprint']['hashed_message'].native
    except (ValueError, TypeError, KeyError) as e:
        item.error = _StructuralError(
            'invalid_tst_info',
            'could not read the TSTInfo message imprint: %s' % e,
        )
        return item

    try:
        explicit = raw['digest_algorithm']
        if not isinstance(explicit, Void) and explicit is not None:
            item.explicit_algorithm = explicit['algorithm'].native
    except (ValueError, TypeError) as e:
        item.error = _StructuralError(
            'invalid_digest_algorithm',
            'could not read the archive time stamp digest algorithm: %s' % e,
        )
        return item

    try:
        hashtree = raw['reduced_hashtree']
        if not isinstance(hashtree, Void) and hashtree is not None:
            item.reduced_hashtree = [[v.native for v in partial] for partial in hashtree]
    except (ValueError, TypeError) as e:
        item.error = _StructuralError(
            'invalid_reduced_hashtree',
            'could not read the reduced hash tree: %s' % e,
        )
        return item

    if item.explicit_algorithm is not None:
        item.algorithm = item.explicit_algorithm
        item.algorithm_source = 'explicit'
    elif derive_algorithm:
        item.algorithm = item.imprint_algorithm
        item.algorithm_source = 'derived'

    return item


def _extract_tst_info(time_stamp):
    try:
        content_type = time_stamp['content_type'].native
    except (ValueError, TypeError, KeyError) as e:
        raise _StructuralError(
            'invalid_time_stamp',
            'could not read the time stamp content type: %s' % e,
        )

    if content_type != 'signed_data':
        raise _StructuralError(
            'unexpected_time_stamp_content',
            'time stamp content type must be signed_data, not "%s"' % content_type,
        )

    try:
        signed_data = time_stamp['content']
        if not isinstance(signed_data, Asn1Value):
            raise ValueError('SignedData did not parse')
        encap = signed_data['encap_content_info']
    except (ValueError, TypeError, KeyError) as e:
        raise _StructuralError(
            'invalid_time_stamp',
            'could not parse the timestamp token SignedData: %s' % e,
        )

    if isinstance(encap, (EncapsulatedContentInfo, ContentInfo)):
        inner_type = encap['content_type'].native
        content = encap['content']
    else:
        raise _StructuralError(
            'invalid_time_stamp',
            'could not identify the encapsulated content info of the timestamp token',
        )

    if inner_type != 'tst_info':
        raise _StructuralError(
            'missing_tst_info',
            'timestamp token eContentType must be tst_info, not "%s"' % inner_type,
        )

    try:
        parsed = _parse_tst_info_content(content)
    except (ValueError, TypeError, AttributeError) as e:
        raise _StructuralError(
            'invalid_tst_info',
            'could not parse the TSTInfo: %s' % e,
        )

    if not isinstance(parsed, TSTInfo):
        raise _StructuralError(
            'invalid_tst_info',
            'timestamp token content did not parse as TSTInfo',
        )

    return parsed


def _parse_tst_info_content(content):
    if isinstance(content, ParsableOctetString):
        return content.parsed
    if isinstance(content, Any):
        inner = content.parsed
        if isinstance(inner, ParsableOctetString):
            return inner.parsed
        if isinstance(inner, OctetString):
            return TSTInfo.load(inner.native)
        return inner
    if isinstance(content, OctetString):
        return TSTInfo.load(content.native)
    return content


def _check_chain_algorithms(findings, extracted, chain_index):
    expected = None
    expected_index = None
    for item in extracted:
        if item.error is not None:
            continue

        if _algorithm_differs(item.explicit_algorithm, item.imprint_algorithm):
            item.algorithm_conflict = True
            findings.append(Finding(
                'digest_algorithm_mismatch',
                'explicit digest algorithm "%s" disagrees with the TSTInfo '
                'message imprint algorithm "%s"; the effective digest '
                'algorithm is ambiguous'
                % (item.explicit_algorithm, item.imprint_algorithm),
                severity=SEVERITY_WARNING,
                category=CATEGORY_STRUCTURE,
                chain_index=chain_index,
                entry_index=item.entry_index,
                details={
                    'explicit_algorithm': item.explicit_algorithm,
                    'derived_algorithm': item.imprint_algorithm,
                },
            ))

        if item.algorithm is None:
            continue
        if expected is None:
            expected = item.algorithm
            expected_index = item.entry_index
            continue
        if item.algorithm != expected:
            findings.append(Finding(
                'digest_algorithm_changed',
                'entry uses digest algorithm "%s" but entry %d in the same '
                'chain uses "%s"' % (item.algorithm, expected_index, expected),
                category=CATEGORY_CHAIN,
                chain_index=chain_index,
                entry_index=item.entry_index,
                details={
                    'algorithm': item.algorithm,
                    'chain_algorithm': expected,
                    'chain_algorithm_entry_index': expected_index,
                },
            ))
            return


def _algorithm_name(algorithm):
    """
    Normalizes an asn1crypto digest algorithm name. Mapped names and dotted
    OIDs compare equal, and the name is what hashlib and DigestAlgorithmId
    agree on.
    """

    if algorithm is None:
        return None
    from .algos import DigestAlgorithmId
    return DigestAlgorithmId.map(algorithm)


def _algorithm_differs(left, right):
    """
    Compares two digest algorithm identifiers by their digest size, so an
    absent or NULL parameters field does not create a false mismatch
    """

    if left is None or right is None:
        return False
    left_name = _hashlib_name(left)
    right_name = _hashlib_name(right)
    if left_name is not None and right_name is not None:
        return _digest_size(left_name) != _digest_size(right_name)
    return _algorithm_name(left) != _algorithm_name(right)


def _digest_size(algorithm_name):
    return hashlib.new(algorithm_name, b'').digest_size


def _check_time_order(findings, chain_entries):
    for chain_index, extracted in enumerate(chain_entries):
        previous = None
        previous_index = None
        for item in extracted:
            if item.error is not None or item.gen_time is None:
                continue
            if previous is not None and item.gen_time < previous:
                findings.append(Finding(
                    'timestamp_order',
                    'generation time %s is earlier than entry %d in the same '
                    'chain (%s); the entries keep their original DER order and '
                    'were not reordered'
                    % (item.gen_time.isoformat(), previous_index, previous.isoformat()),
                    category=CATEGORY_CHAIN,
                    chain_index=chain_index,
                    entry_index=item.entry_index,
                    details={
                        'gen_time': item.gen_time.isoformat(),
                        'previous_gen_time': previous.isoformat(),
                        'previous_entry_index': previous_index,
                    },
                ))
            previous = item.gen_time
            previous_index = item.entry_index

    for chain_index in range(1, len(chain_entries)):
        previous_chain = chain_entries[chain_index - 1]
        current_chain = chain_entries[chain_index]
        last = None
        for item in previous_chain:
            if item.error is None and item.gen_time is not None:
                last = item
        first = None
        for item in current_chain:
            if item.error is None and item.gen_time is not None:
                first = item
                break
        if last is None or first is None:
            continue
        if first.gen_time < last.gen_time:
            findings.append(Finding(
                'chain_time_order',
                'the first timestamp of chain %d (%s) is earlier than the last '
                'timestamp of chain %d (%s)'
                % (chain_index, first.gen_time.isoformat(),
                   chain_index - 1, last.gen_time.isoformat()),
                category=CATEGORY_CHAIN,
                chain_index=chain_index,
                entry_index=first.entry_index,
                details={
                    'gen_time': first.gen_time.isoformat(),
                    'previous_chain_index': chain_index - 1,
                    'previous_gen_time': last.gen_time.isoformat(),
                    'previous_entry_index': last.entry_index,
                },
            ))


def _check_hash_tree_renewal(findings, item, chain_entries, chain_index, entry_index):
    """
    RFC 4998 hash tree renewal: the first timestamp of a new chain covers all
    previous chains. When the digest algorithm changes the previous chain
    hashes would have to be recomputed over the archived data, which is not
    implemented here - that case is reported as unverified, never as a pass.
    """

    previous_chain = chain_entries[chain_index - 1]
    previous_algorithm = _chain_algorithm(previous_chain)
    current_algorithm = _chain_algorithm(chain_entries[chain_index])

    if current_algorithm is None or previous_algorithm is None:
        item.outcome = _OUTCOME_UNVERIFIED
        return

    if current_algorithm != previous_algorithm:
        item.outcome = _OUTCOME_UNVERIFIED
        findings.append(Finding(
            'hash_tree_algorithm_change_unverified',
            'hash tree renewal changes the digest algorithm from "%s" to "%s"; '
            'recomputing the previous chains for the new algorithm is not '
            'implemented' % (previous_algorithm, current_algorithm),
            severity=SEVERITY_WARNING,
            category=CATEGORY_CHAIN,
            chain_index=chain_index,
            entry_index=entry_index,
            details={
                'previous_algorithm': previous_algorithm,
                'algorithm': current_algorithm,
            },
        ))
        return

    algorithm_name = _hashlib_name(current_algorithm)
    if algorithm_name is None:
        item.outcome = _OUTCOME_UNVERIFIED
        return

    item.previous_chains_digest = _previous_chains_digest(
        chain_entries, chain_index, algorithm_name
    )

    # Verify the digest the new chain actually commits to. With a reduced
    # hash tree the path is rebuilt from the previous chain digest and any
    # sibling values; without one the timestamp must sign that digest
    # directly. A renewal that folds re-hashed archived data into the
    # previous chain commitment can not be recomputed offline and is
    # reported through the reduced-hash-tree unverified path, never as a
    # pass.
    _check_coverage(
        findings, item, chain_index, entry_index,
        leaf_digest=item.previous_chains_digest,
        renewal='previous chains',
        allow_unverified_fallback=True,
    )


def _check_coverage(findings, item, chain_index, entry_index, leaf_digest,
                    renewal, allow_unverified_fallback=False):
    """
    Verifies that the timestamp message imprint is bound to the data it
    renews.

    Without a reduced hash tree, the imprint must equal the digest of the
    renewed data. With one, the first partial hashtree must contain that
    digest, and every partial hashtree is folded in the encoded order into a
    root that must equal the imprint. This mirrors the reference RFC 4998
    implementation, which never reorders a reduced path.

    :param allow_unverified_fallback:
        When True, a path whose root matches the imprint but which does not
        directly contain the known digest is reported as unverified instead
        of as a mismatch. Chain-boundary renewals use this because a folded
        commitment may include archived data that is not in the record.
    """

    if item.imprint_digest is None:
        item.outcome = _OUTCOME_UNVERIFIED
        return

    known_digests = [leaf_digest] if leaf_digest is not None else []

    if item.reduced_hashtree is None:
        item.rebuilt_root = item.imprint_digest
        # Without a reduced hash tree the timestamp covers exactly one
        # digest, and ordinary timestamp renewal requires it to be the
        # immediately previous timestamp token in the chain.
        if item.imprint_digest == leaf_digest:
            item.outcome = _OUTCOME_OK
            return
        item.outcome = _OUTCOME_MISMATCH
        findings.append(Finding(
            'renewal_digest_mismatch',
            'the timestamp does not cover the %s' % renewal,
            category=CATEGORY_CHAIN,
            chain_index=chain_index,
            entry_index=entry_index,
            details={
                'algorithm': item.algorithm,
                'imprint_digest': _hex(item.imprint_digest),
                'expected_digest': _hex(leaf_digest),
            },
        ))
        return

    algorithm_name = _hashlib_name(item.algorithm)
    if algorithm_name is None:
        item.outcome = _OUTCOME_UNVERIFIED
        return

    root = _fold_path(algorithm_name, item.reduced_hashtree)
    item.rebuilt_root = root
    if root is None:
        item.outcome = _OUTCOME_UNVERIFIED
        findings.append(Finding(
            'reduced_hashtree_unverified',
            'the reduced hash tree could not be folded',
            severity=SEVERITY_WARNING,
            category=CATEGORY_CHAIN,
            chain_index=chain_index,
            entry_index=entry_index,
        ))
        return

    if root != item.imprint_digest:
        item.outcome = _OUTCOME_MISMATCH
        findings.append(Finding(
            'renewal_digest_mismatch',
            'the reduced hash tree does not reconstruct to the timestamp '
            'message imprint for the %s' % renewal,
            category=CATEGORY_CHAIN,
            chain_index=chain_index,
            entry_index=entry_index,
            details={
                'algorithm': item.algorithm,
                'imprint_digest': _hex(item.imprint_digest),
                'rebuilt_root': _hex(root),
                'expected_digest': _hex(leaf_digest),
            },
        ))
        return

    contained = _leaf_covered(algorithm_name, item.reduced_hashtree, known_digests)
    if contained:
        item.outcome = _OUTCOME_OK
        return

    if allow_unverified_fallback:
        item.outcome = _OUTCOME_UNVERIFIED
        findings.append(Finding(
            'hash_tree_renewal_unverified',
            'the reduced hash tree reconstructs to the timestamp, but the '
            'known digest is only covered through a folded commitment that '
            'requires archived data not present in the record',
            severity=SEVERITY_WARNING,
            category=CATEGORY_CHAIN,
            chain_index=chain_index,
            entry_index=entry_index,
            details={
                'algorithm': item.algorithm,
                'expected_digest': _hex(leaf_digest),
            },
        ))
        return

    item.outcome = _OUTCOME_MISMATCH
    findings.append(Finding(
        'renewal_digest_mismatch',
        'the reduced hash tree reconstructs to the timestamp, but does not '
        'cover the %s' % renewal,
        category=CATEGORY_CHAIN,
        chain_index=chain_index,
        entry_index=entry_index,
        details={
            'algorithm': item.algorithm,
            'imprint_digest': _hex(item.imprint_digest),
            'rebuilt_root': _hex(root),
            'expected_digest': _hex(leaf_digest),
        },
    ))


def _leaf_covered(algorithm_name, hashtree, digest_values):
    """
    True when the first partial hashtree contains any of the known digests
    as one of its values, or when the first partial hashtree as a whole
    hashes to one of them
    """

    if not hashtree:
        return False
    first = hashtree[0]
    for value in digest_values:
        if value in first:
            return True
    if len(first) > 1:
        return _node_hash(algorithm_name, first) in digest_values
    return False


def _fold_path(algorithm_name, partials):
    """
    Folds a list of partial hashtrees into a root digest. Each partial
    hashtree becomes one node, and nodes are combined sequentially in
    sorted pair order, exactly as the reference RFC 4998 implementation
    rebuilds a reduced path. The encoded path order is never changed.
    """

    nodes = []
    for partial in partials:
        node = _node_hash(algorithm_name, partial)
        if node is None:
            return None
        nodes.append(node)
    root = nodes[0]
    for node in nodes[1:]:
        root = _branch_hash(algorithm_name, root, node)
    return root


def _node_hash(algorithm_name, values):
    if len(values) == 0:
        return None
    if len(values) == 1:
        return values[0]
    return _hash(algorithm_name, b''.join(sorted(values)))


def _branch_hash(algorithm_name, left, right):
    if right < left:
        left, right = right, left
    return _hash(algorithm_name, left + right)


def _previous_chains_digest(chain_entries, chain_index, algorithm_name):
    previous_chains = [
        [item.raw for item in extracted]
        for extracted in chain_entries[:chain_index]
    ]
    sequence = ArchiveTimeStampSequence(previous_chains)
    return _hash(algorithm_name, sequence.dump())


def _chain_algorithm(extracted):
    for item in extracted:
        if item.error is None and item.algorithm is not None:
            return item.algorithm
    return None


def _has_unverified_finding(findings, chain_index, entry_index):
    for finding in findings:
        if finding.severity != SEVERITY_WARNING:
            continue
        if finding.chain_index == chain_index and finding.entry_index == entry_index:
            return True
    return False


def _hashlib_name(algorithm):
    if algorithm is None:
        return None
    name = _HASHLIB_NAMES.get(algorithm, algorithm)
    try:
        hashlib.new(name, b'').digest()
    except (ValueError, TypeError):
        return None
    return name


def _hash(algorithm_name, data):
    return hashlib.new(algorithm_name, data).digest()


def _hex(value):
    if value is None or not isinstance(value, byte_cls):
        return None
    return value.hex()


def main(argv=None):
    """
    Command line entry point for checking EvidenceRecord files offline.
    Prints a JSON report for each file and exits non-zero when any file
    fails. A file whose status is "unverified" exits with a distinct code so
    a pipeline can tell it apart from a broken chain.

    Usage: python -m asn1crypto.ers FILE [FILE ...]
    """

    import json

    if argv is None:
        argv = sys.argv[1:]

    if not argv:
        sys.stderr.write('usage: python -m asn1crypto.ers FILE [FILE ...]\n')
        return 2

    exit_code = 0
    for path in argv:
        try:
            with open(path, 'rb') as f:
                encoded = f.read()
        except (IOError, OSError) as e:
            sys.stderr.write('%s: %s\n' % (path, e))
            exit_code = 2
            continue

        result = check_der(encoded)
        report = result.native()
        report['file'] = path
        sys.stdout.write(json.dumps(report, indent=2, sort_keys=True) + '\n')

        if result.status == STATUS_FAIL:
            exit_code = max(exit_code, 1)
        elif result.status == STATUS_UNVERIFIED:
            exit_code = max(exit_code, 3)

    return exit_code


if __name__ == '__main__':
    sys_exit = main()
    raise SystemExit(sys_exit)
