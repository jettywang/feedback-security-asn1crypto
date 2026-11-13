# coding: utf-8

"""
Unified handling of X.509-style extensions for certificates, CRLs and OCSP
messages.

RFC 5280 only permits a given extension OID to appear once, but nothing in the
ASN.1 structure enforces that. When a malformed or malicious object repeats an
OID, the convenience properties (e.g. ``Certificate.basic_constraints_value``)
and the raw ``Extensions`` sequence can disagree because the properties simply
retain the last matching value. This module keeps the original extensions and
their ordering intact and produces a single, authoritative report that callers
of certificates, CRLs and OCSP messages can use to see every duplicate and
where it was found.

The convenience accessors intentionally retain the existing "last item wins"
behavior for backwards compatibility, but they are driven by the same
conflict-aware processing as the report, so a value exposed through a property
is always the same value marked as effective in
:class:`ExtensionCheckResult`.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

from ._errors import unwrap
from ._types import type_name
from .core import VOID


# Conflict classifications, ordered from most to least specific. Only the most
# specific conflict is recorded for a group of duplicate OIDs.
CONFLICT_CRITICAL = 'critical_conflict'
CONFLICT_VALUE = 'value_conflict'
CONFLICT_DUPLICATE = 'duplicate'

# Scope labels identifying which extension layer of a signed object a result
# describes.
SCOPE_CERTIFICATE = 'certificate'
SCOPE_TBS_CRL = 'crl_tbs_extensions'
SCOPE_CRL_ENTRY = 'crl_entry_extensions'
SCOPE_OCSP_REQUEST = 'ocsp_request_extensions'
SCOPE_OCSP_SINGLE_REQUEST = 'ocsp_single_request_extensions'
SCOPE_OCSP_RESPONSE = 'ocsp_response_extensions'
SCOPE_OCSP_SINGLE_RESPONSE = 'ocsp_single_response_extensions'


class ExtensionEntry(object):
    """
    A single extension as it appears in an extensions sequence, preserving the
    original position and raw encoding.
    """

    def __init__(self, index, extension, known):
        self._index = index
        self._extension = extension
        self._known = known
        self._oid = extension['extn_id'].dotted
        self._name = extension['extn_id'].native
        self._critical = extension['critical'].native
        self._extn_value = extension['extn_value']
        self._value_bytes = bytes(extension['extn_value'])
        self._parsed = None
        self._parse_error = None

    @property
    def index(self):
        """
        :return:
            The zero-based position of the extension in the original sequence
        """

        return self._index

    @property
    def extension(self):
        """
        :return:
            The original Extension sequence object, never reordered or removed
        """

        return self._extension

    @property
    def oid(self):
        """
        :return:
            A unicode string of the dotted OID, e.g. ``"2.5.29.19"``
        """

        return self._oid

    @property
    def name(self):
        """
        :return:
            The mapped name of a known OID, otherwise the dotted OID itself
        """

        return self._name

    @property
    def known(self):
        """
        :return:
            A boolean - if the OID has a registered name and value spec
        """

        return self._known

    @property
    def critical(self):
        """
        :return:
            A boolean for the critical flag of this occurrence
        """

        return self._critical

    @property
    def extn_value(self):
        """
        :return:
            The ParsableOctetString holding the raw extension value
        """

        return self._extn_value

    @property
    def value_bytes(self):
        """
        :return:
            A byte string of the raw extnValue contents, used to detect values
            that parse differently but encode identically, and vice versa
        """

        return self._value_bytes

    @property
    def parsed(self):
        """
        The value parsed according to the OID-specific spec. For an unknown OID,
        or when the value can not be parsed, this is None and :attr:`parse_error`
        describes the failure.

        :return:
            An asn1crypto.core.Asn1Value object or None
        """

        if self._parsed is None and self._parse_error is None and self._known:
            try:
                spec = self._extension._oid_specs.get(self._name)
                if spec is None:
                    self._parsed = self._extn_value.parsed
                else:
                    self._parsed = self._extn_value.parse(spec)
            except (ValueError, TypeError) as e:
                self._parse_error = e.args[0]
        return self._parsed

    @property
    def parse_error(self):
        """
        :return:
            None, or a unicode string describing why the value could not be
            parsed with the OID-specific spec
        """

        if self._known:
            self.parsed
        return self._parse_error

    def __repr__(self):
        return '<ExtensionEntry [%d] %s critical=%s>' % (
            self._index,
            self._name,
            self._critical,
        )


class DuplicateExtensions(object):
    """
    Every occurrence of a repeated extension OID, with the reason the
    occurrences are considered to conflict.
    """

    def __init__(self, oid, name, known, entries, conflict_type, value_different):
        self._oid = oid
        self._name = name
        self._known = known
        self._entries = list(entries)
        self._conflict_type = conflict_type
        self._value_different = value_different

    @property
    def oid(self):
        """
        :return:
            A unicode string of the dotted OID that appears more than once
        """

        return self._oid

    @property
    def name(self):
        """
        :return:
            The mapped name for a known OID, otherwise the dotted OID itself
        """

        return self._name

    @property
    def known(self):
        """
        :return:
            A boolean - if the OID is registered with a name and value spec
        """

        return self._known

    @property
    def indices(self):
        """
        :return:
            A list of integers with every position holding this OID, in order
        """

        return [entry.index for entry in self._entries]

    @property
    def entries(self):
        """
        :return:
            A list of :class:`ExtensionEntry` objects, in original order
        """

        return list(self._entries)

    @property
    def effective_entry(self):
        """
        The occurrence exposed through the convenience properties. This matches
        the historical "last item wins" behavior and is never silently treated
        as an authoritative security conclusion.

        :return:
            The last :class:`ExtensionEntry` for this OID
        """

        return self._entries[-1]

    @property
    def conflict_type(self):
        """
        One of :data:`CONFLICT_CRITICAL`, :data:`CONFLICT_VALUE` or
        :data:`CONFLICT_DUPLICATE`:

         - ``CONFLICT_CRITICAL`` - the occurrences do not agree on the critical
           flag.
         - ``CONFLICT_VALUE`` - the critical flags agree, but the values are
           parseable and semantically different (different DER encodings).
         - ``CONFLICT_DUPLICATE`` - the OID is repeated with identical values
           and critical flags.

        Unknown or unparseable values are compared by their raw octet bytes.

        :return:
            A unicode string classification
        """

        return self._conflict_type

    @property
    def value_different(self):
        """
        :return:
            A boolean - if the raw extnValue octets differ between occurrences
        """

        return self._value_different

    @property
    def critical_conflict(self):
        """
        :return:
            A boolean - if the occurrences disagree on the critical flag
        """

        return self._conflict_type == CONFLICT_CRITICAL

    def __repr__(self):
        return '<DuplicateExtensions %s %s indices=%r>' % (
            self._name,
            self._conflict_type,
            self.indices,
        )


class ExtensionCheckResult(object):
    """
    The unified extension inspection result for one extension layer of a
    certificate, CRL or OCSP message. The original extensions and their order
    are always available through :attr:`entries`; any OID appearing more than
    once is additionally described in :attr:`duplicates`.
    """

    def __init__(self, scope, host, extension_path, entries, duplicates, has_duplicates):
        self._scope = scope
        self._host = host
        self._extension_path = tuple(extension_path)
        self._entries = entries
        self._duplicates = duplicates
        self._has_duplicates = has_duplicates

    @property
    def scope(self):
        """
        :return:
            A unicode string identifying the extension layer, one of the
            ``SCOPE_*`` constants
        """

        return self._scope

    @property
    def host(self):
        """
        :return:
            The certificate, CRL or OCSP object the extensions belong to
        """

        return self._host

    @property
    def extension_path(self):
        """
        :return:
            A tuple of unicode string field names leading from the host to the
            extensions sequence
        """

        return self._extension_path

    @property
    def extensions(self):
        """
        :return:
            The original Extensions SequenceOf object, unchanged and in order;
            None when the optional extension layer is absent
        """

        return _resolve_extensions(self._host, self._extension_path)

    @property
    def entries(self):
        """
        :return:
            A list of :class:`ExtensionEntry` for every extension, in order
        """

        return list(self._entries)

    @property
    def has_duplicates(self):
        """
        :return:
            A boolean - if at least one OID occurs more than once
        """

        return self._has_duplicates

    @property
    def duplicates(self):
        """
        :return:
            A dict keyed by dotted OID of :class:`DuplicateExtensions`, in the
            order each duplicated OID was first encountered
        """

        return dict(self._duplicates)

    @property
    def duplicate_oids(self):
        """
        :return:
            A list of dotted OID unicode strings that appear more than once, in
            first-seen order
        """

        return list(self._duplicates.keys())

    def get_duplicate(self, oid):
        """
        :param oid:
            A dotted OID unicode string, or the registered name of an extension

        :raises:
            KeyError - when the OID occurs only once (or not at all)

        :return:
            A :class:`DuplicateExtensions` object
        """

        if oid in self._duplicates:
            return self._duplicates[oid]
        for duplicate in self._duplicates.values():
            if duplicate.name == oid:
                return duplicate
        raise KeyError(unwrap(
            '''
            No duplicate extension with OID or name %s is present in the %s
            extensions of %s
            ''',
            repr(oid),
            self._scope,
            type_name(self._host),
        ))

    def entries_for(self, oid):
        """
        :param oid:
            A dotted OID unicode string, or the registered name of an extension

        :return:
            A list of :class:`ExtensionEntry` objects for every occurrence of
            the OID, in original order
        """

        return [
            entry for entry in self._entries
            if entry.oid == oid or entry.name == oid
        ]

    def __repr__(self):
        return '<ExtensionCheckResult scope=%s extensions=%d duplicates=%r>' % (
            self._scope,
            len(self._entries),
            self.duplicate_oids,
        )


def _resolve_extensions(host, extension_path):
    """
    Walks a field path without raising when an optional intermediate field is
    absent. The special field name ``"#parsed"`` descends into the parsed value
    of a :class:`~asn1crypto.core.ParsableOctetString`, which is used by OCSP
    responses where the basic response is carried inside an octet string.

    :param host:
        An asn1crypto Sequence object

    :param extension_path:
        A tuple of unicode string field names

    :return:
        The extensions SequenceOf, or None if any optional field is missing
    """

    current = host
    for field in extension_path:
        if field == '#parsed':
            current = current.parsed
            continue
        if field not in current._field_map:
            return None
        index = current._field_map[field]
        if current.children is not None and index < len(current.children):
            child = current.children[index]
            if child is None or (child.__class__ != tuple and child is VOID):
                return None
        value = current[field]
        if value is None:
            return None
        current = value
    return current


def _parsed_extension_value(extension):
    """
    Parses an extension's extnValue with the spec registered for its OID.

    Accessing ``extension['extn_value'].parsed`` normally triggers OID-driven
    parsing through the Extension's ``_oid_pair`` machinery; however, when the
    octet string's raw bytes were replaced through ``.set()``, its cached
    parsed object is gone and the parameterless ``.parsed`` falls back to a
    generic spec. Looking the OID spec up explicitly keeps the convenience
    values strongly typed after any mutation.

    :param extension:
        An Extension Sequence object

    :return:
        The parsed extnValue Asn1Value object
    """

    extn_value = extension['extn_value']
    name = extension['extn_id'].native
    spec = (extension._oid_specs or {}).get(name)
    if spec is None:
        return extn_value.parsed
    return extn_value.parse(spec)


def _build_extension_entries(extensions):
    """
    :param extensions:
        A SequenceOf of Extension objects

    :return:
        A list of :class:`ExtensionEntry` objects
    """

    entries = []
    for index, extension in enumerate(extensions):
        oid = extension['extn_id'].dotted
        oid_specs = extension._oid_specs or {}
        known = extension['extn_id'].native in oid_specs
        entries.append(ExtensionEntry(index, extension, known))
    return entries


def _classify_duplicate(entries):
    """
    Determines the conflict classification for a group of entries sharing an OID.

    :param entries:
        A list of :class:`ExtensionEntry` objects with the same OID

    :return:
        A two-element tuple of (conflict type unicode string, boolean indicating
        if the raw extnValue octets differ)
    """

    value_bytes = [entry.value_bytes for entry in entries]
    value_different = any(data != value_bytes[0] for data in value_bytes[1:])

    critical_flags = set(entry.critical for entry in entries)
    if len(critical_flags) > 1:
        return CONFLICT_CRITICAL, value_different

    if value_different:
        return CONFLICT_VALUE, True

    return CONFLICT_DUPLICATE, False


def build_extension_check_result(host, scope, extension_path):
    """
    Inspects one extension layer of a host object and builds the unified report.

    :param host:
        The certificate, CRL or OCSP Sequence object owning the extensions

    :param scope:
        A ``SCOPE_*`` unicode string labeling the extension layer

    :param extension_path:
        A tuple of field names from the host to its extensions SequenceOf

    :return:
        An :class:`ExtensionCheckResult`
    """

    extensions = _resolve_extensions(host, extension_path)
    if extensions is None:
        entries = []
    else:
        entries = _build_extension_entries(extensions)

    grouped = {}
    order = []
    for entry in entries:
        if entry.oid not in grouped:
            grouped[entry.oid] = []
            order.append(entry.oid)
        grouped[entry.oid].append(entry)

    duplicates = {}
    has_duplicates = False
    for oid in order:
        group = grouped[oid]
        if len(group) < 2:
            continue
        has_duplicates = True
        conflict_type, value_different = _classify_duplicate(group)
        duplicates[oid] = DuplicateExtensions(
            oid,
            group[0].name,
            group[0].known,
            group,
            conflict_type,
            value_different,
        )

    return ExtensionCheckResult(
        scope,
        host,
        extension_path,
        entries,
        duplicates,
        has_duplicates,
    )


def extension_fingerprint(host, extension_path):
    """
    Builds a state signature for an extension layer so cached convenience values
    can be invalidated when the extensions are mutated. The signature combines
    object identity (so replacements, appends and deletes are detected) with the
    raw octets of each extension (so in-place edits are detected), avoiding a
    full dump/load round-trip of the host object.

    :param host:
        The certificate, CRL or OCSP Sequence object owning the extensions

    :param extension_path:
        A tuple of field names from the host to its extensions SequenceOf

    :return:
        None when the optional extension layer is absent, otherwise a tuple
    """

    extensions = _resolve_extensions(host, extension_path)
    if extensions is None:
        return None

    signature = [id(extensions), len(extensions)]
    for extension in extensions:
        signature.append((
            id(extension),
            id(extension['extn_id']),
            id(extension['critical']),
            id(extension['extn_value']),
            bytes(extension['extn_value']),
        ))
    return tuple(signature)


class ExtensionHostMixin(object):
    """
    Shared, cache-aware extension processing for the certificate, CRL and OCSP
    host classes. A host class declares its extension layer through
    ``_extension_scope`` and ``_extension_path`` and names the convenience value
    attributes it supports in ``_extension_value_attributes``.

    The first time a convenience property or :attr:`extension_checks` is used,
    :meth:`_set_extensions` records the last occurrence of each known OID (the
    historical "last item wins" behavior) and caches a fingerprint of the
    extension layer. Any later mutation that changes the fingerprint - replacing
    an extnValue, editing a parsed child, deleting or appending an extension, or
    modifying only a deep copy - causes the cache to be rebuilt before the next
    read, without dumping and reloading the whole host object.
    """

    # Subclasses override these three class attributes.
    _extension_scope = None
    _extension_path = ()
    _extension_value_attributes = ()

    _processed_extensions = False
    _critical_extensions = None
    _extension_fingerprint = None
    _extension_check_result = None

    def _extension_layer(self):
        """
        :return:
            The extensions SequenceOf for this host, or None if the optional
            layer is absent
        """

        return _resolve_extensions(self, self._extension_path)

    def _extensions_need_processing(self):
        """
        Compares the current extension layer against the cached fingerprint.

        :return:
            A boolean - if the extensions have never been processed, or have
            changed since the last processing
        """

        if not self._processed_extensions:
            return True
        return extension_fingerprint(self, self._extension_path) != self._extension_fingerprint

    def _reset_extension_values(self):
        """
        Clears every convenience value attribute so stale parsed objects are
        never exposed after the extension layer changes.
        """

        for attribute_name in self._extension_value_attributes:
            setattr(self, attribute_name, None)
        self._critical_extensions = set()

    def _set_extensions(self):
        """
        Populates the convenience value attributes with the last occurrence of
        each supported OID and builds the set of names marked critical. The
        original extensions and their ordering are never modified; duplicates and
        conflicts are reported separately through :attr:`extension_checks`.
        """

        self._reset_extension_values()

        extensions = self._extension_layer()
        if extensions is not None:
            for extension in extensions:
                name = extension['extn_id'].native
                attribute_name = '_%s_value' % name
                if attribute_name in self._extension_value_attributes:
                    setattr(self, attribute_name, _parsed_extension_value(extension))
                if extension['critical'].native:
                    self._critical_extensions.add(name)

        self._extension_fingerprint = extension_fingerprint(self, self._extension_path)
        # The report is derived data and must be rebuilt from the live extension
        # layer on the next access after any mutation.
        self._extension_check_result = None
        self._processed_extensions = True

    def _ensure_extensions_processed(self):
        """
        Processes the extension layer lazily, rebuilding the cache whenever the
        fingerprint shows the layer was mutated.
        """

        if self._extensions_need_processing():
            self._set_extensions()

    @property
    def extension_checks(self):
        """
        The unified duplicate/conflict report for this host's extension layer.
        The result is always computed against the current extensions, so it
        stays correct after in-place mutations; it is cached only until the
        layer changes.

        :return:
            An :class:`ExtensionCheckResult`
        """

        self._ensure_extensions_processed()
        if self._extension_check_result is None:
            self._extension_check_result = build_extension_check_result(
                self,
                self._extension_scope,
                self._extension_path,
            )
        return self._extension_check_result

    @property
    def critical_extensions(self):
        """
        Returns a set of the names (or OID if not a known extension) of the
        extensions marked as critical. When an OID appears more than once with
        conflicting critical flags, every flagged name is retained here and the
        conflict is described by :attr:`extension_checks`.

        :return:
            A set of unicode strings
        """

        self._ensure_extensions_processed()
        return self._critical_extensions
