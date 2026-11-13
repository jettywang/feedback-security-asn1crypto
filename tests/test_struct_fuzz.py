# coding: utf-8
"""
Small, deterministic structural fuzz tests for the OID-driven schema dispatch
in asn1crypto.

The goal is not volume of random bytes, but precise coverage of the situations
where an ObjectIdentifier selects the internal spec of a sibling field:

 - CMSAttribute (cms.CMSAttribute) via _spec_callbacks / _oid_specs
 - CRIAttribute (csr.CRIAttribute) via _oid_pair / _oid_specs

Starting from legal CMS and CSR attribute structures, a fixed set of structural
mutations is applied:

  1. OID mutation (known -> different known, known -> unknown, arc byte flip)
  2. explicit/implicit tagging mutation
  3. optional field removal
  4. SET OF reordering
  5. a handful of fixed-seed byte flips and length corruptions

For every input the outcome of three access paths is compared:

  A. field-first: touch the local (OID + value) fields, then read .native
  B. direct-native: call .native on the freshly parsed top-level object
  C. copy-expand: .copy() the parsed object, then read .native

Acceptance (raises or not) and interpretation (native representation, or the
exact exception type) must be identical across all three paths. Unknown OIDs
have an additional, independent criterion: the original raw value bytes must be
preserved verbatim and round-trip through .dump().

Malformed inputs are only counted as handled when they raise the documented
parse exception types (ValueError/TypeError); a broad "except Exception" is
never treated as success. A deliberately wrong OID dispatch (a shadow oracle
that parses values with the wrong spec) is used to prove that the differential
check actually catches an interpretation divergence.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import os
import random
import sys
import tempfile
import unittest

from asn1crypto import cms, core, csr, keys, x509
from asn1crypto.core import _parse_build
from ._unittest_compat import patch

patch()

if sys.version_info < (3,):
    byte_cls = str
else:
    byte_cls = bytes


# A fixed seed keeps every mutation and counterexample reproducible.
SEED = 20261113

# Parse failures are expected to surface as ValueError (bad DER / wrong tag /
# insufficient data) or TypeError (wrong Python type while building). Anything
# else is an unexpected failure and must fail the suite.
EXPECTED_PARSE_ERRORS = (ValueError, TypeError)

# OIDs used when mutating a known OID into an unknown-but-valid one. They are
# deliberately absent from both CMSAttributeType and CSRAttributeType maps.
UNKNOWN_OID = '1.2.3.4.5.6.7.8.9'
UNKNOWN_OID_ALT = '1.2.840.113549.1.99.42.7'


def encode_length(length):
    """Encode an ASN.1 DER length octet string."""
    if length < 0x80:
        return byte_cls([length])
    body = length.to_bytes((length.bit_length() + 7) // 8, 'big')
    return byte_cls([0x80 | len(body)]) + body


def tlv_info(data, pos=0):
    """
    Return (header_len, content_length, end_pos) for the DER TLV at pos.

    Handles single-byte tags (all tags used in these tests are single byte)
    and short/long form lengths.
    """
    start = pos
    pos += 1
    first_len = data[pos]
    pos += 1
    if first_len < 0x80:
        length = first_len
    else:
        num_bytes = first_len & 0x7f
        length = int.from_bytes(data[pos:pos + num_bytes], 'big')
        pos += num_bytes
    return pos - start, length, pos + length


def split_children(content):
    """Split a SEQUENCE/SET content into a list of (start, header, len, end)."""
    pos = 0
    parts = []
    while pos < len(content):
        header_len, length, end = tlv_info(content, pos)
        parts.append((pos, header_len, length, end))
        pos = end
    return parts


def rebuild(tag, new_content):
    """Wrap new_content in a TLV with the given tag and a correct length."""
    return byte_cls([tag]) + encode_length(len(new_content)) + new_content


def canonical(value):
    """
    Normalize a native Python value into a hashable, order-stable signature.

    asn1crypto native values are OrderedDict/list/set/scalar/byte strings or
    None. Converting them to a canonical tuple structure lets the three access
    paths be compared on *interpretation* rather than on incidental repr
    differences (e.g. OrderedDict(...) vs a tuple built from the same fields).
    """
    if isinstance(value, dict):
        return ('dict', tuple(
            (key, canonical(value[key])) for key in value
        ))
    if isinstance(value, (list, tuple)):
        return ('seq', tuple(canonical(item) for item in value))
    if isinstance(value, set):
        return ('set', tuple(sorted(canonical(item) for item in value)))
    if isinstance(value, byte_cls):
        return ('bytes', value)
    return ('scalar', value)


def path_field_first(obj):
    """
    Path A: touch the local OID and value fields first (forcing the OID-driven
    spec decision), then return the full native expansion.
    """
    if isinstance(obj, (cms.CMSAttribute, csr.CRIAttribute)):
        _ = obj['type'].native
        values = obj['values']
        if not isinstance(values, core.Void):
            _ = values.native
    elif isinstance(obj, csr.CertificationRequest):
        request_info = obj['certification_request_info']
        _ = request_info['version'].native
        attributes = request_info['attributes']
        if not isinstance(attributes, core.Void):
            for attribute in attributes:
                _ = attribute['type'].native
                if not isinstance(attribute['values'], core.Void):
                    _ = attribute['values'].native
    return canonical(obj.native)


def path_direct_native(obj):
    """Path B: read .native directly on the freshly parsed object."""
    return canonical(obj.native)


def path_copy_expand(obj):
    """Path C: deep-copy the parsed object before expanding to native."""
    return canonical(obj.copy().native)


ACCESS_PATHS = (
    ('field_first', path_field_first),
    ('direct_native', path_direct_native),
    ('copy_expand', path_copy_expand),
)


def run_three_paths(der, spec):
    """
    Parse der under spec and exercise all three access paths.

    :return:
        A dict mapping path name to ('ok', canonical_signature) or
        ('error', exception_class_name). Both load-time and expansion-time
        failures are observed, but only the documented parse exception types
        are collapsed into 'error'; any other exception propagates so that the
        test fails loudly instead of being swallowed.
    """
    outcomes = {}
    for path_name, path_func in ACCESS_PATHS:
        try:
            obj = spec.load(der)
            outcomes[path_name] = ('ok', path_func(obj))
        except EXPECTED_PARSE_ERRORS as exc:
            outcomes[path_name] = ('error', type(exc).__name__)
    return outcomes


def persist_counterexamples(counterexamples):
    """
    Write minimal counterexamples (label, raw input hex, per-path outcomes) to
    a deterministic file under the OS temp dir and return the path. Keeping the
    artifacts out of the source tree means a green run leaves nothing behind.
    """
    output_path = os.path.join(
        os.environ.get('TMPDIR', tempfile.gettempdir()),
        'asn1crypto_struct_fuzz_counterexamples.txt'
    )
    with open(output_path, 'w') as f:
        for item in counterexamples:
            f.write(
                '%s\n%s\n%r\n\n'
                % (item['label'], item['hex'], item['outcomes'])
            )
    return output_path


def assert_paths_agree(test_case, der, spec, label, counterexamples):
    """
    Assert that all three paths accept/reject identically and, when accepted,
    produce the same canonical native interpretation.

    A disagreement is recorded as a minimal counterexample (label + hex) and
    persisted for offline reproduction before the test fails, rather than being
    counted as a generic error.
    """
    outcomes = run_three_paths(der, spec)
    distinct = set(outcomes.values())
    if len(distinct) != 1:
        counterexamples.append({
            'label': label,
            'hex': der.hex(),
            'outcomes': dict(outcomes),
        })
        output_path = persist_counterexamples(counterexamples)
        test_case.fail(
            'interpretation divergence for %s\ninput: %s\noutcomes: %r\n'
            'counterexamples saved to %s'
            % (label, der.hex(), outcomes, output_path)
        )
    return outcomes


def build_cms_corpus():
    """Legal CMSAttribute structures covering several OID-selected specs."""
    return [
        cms.CMSAttribute({
            'type': 'content_type',
            'values': [cms.ContentType('data')],
        }),
        cms.CMSAttribute({
            'type': 'message_digest',
            'values': [core.OctetString(b'\x01\x02\x03\x04')],
        }),
        cms.CMSAttribute({
            'type': 'message_digest',
            'values': [core.OctetString(b'\x00\x01'), core.OctetString(b'\x00\x02')],
        }),
        cms.CMSAttribute({
            'type': cms.CMSAttributeType(UNKNOWN_OID),
            'values': [core.OctetString(b'\xde\xad\xbe\xef')],
        }),
        cms.CMSAttribute({
            'type': cms.CMSAttributeType(UNKNOWN_OID_ALT),
            'values': [core.OctetString(b'\x01'), core.OctetString(b'\xaa\xbb')],
        }),
    ]


def build_csr():
    """A legal CSR whose attributes exercise known and unknown OID dispatch."""
    public_key_info = keys.PublicKeyInfo({
        'algorithm': keys.PublicKeyAlgorithm({'algorithm': 'rsa'}),
        'public_key': keys.RSAPublicKey({
            'modulus': 0x1001,
            'public_exponent': 0x10001,
        }),
    })
    extension = x509.Extension({
        'extn_id': 'basic_constraints',
        'critical': True,
        'extn_value': x509.BasicConstraints({
            'ca': True,
            'path_len_constraint': 3,
        }),
    })
    request_info = csr.CertificationRequestInfo({
        'version': 'v1',
        'subject': x509.Name.build({'common_name': 'fuzz-subject'}),
        'subject_pk_info': public_key_info,
        'attributes': [
            csr.CRIAttribute({
                'type': 'extension_request',
                'values': [x509.Extensions([extension])],
            }),
            csr.CRIAttribute({
                'type': 'challenge_password',
                'values': [x509.DirectoryString(name='utf8_string', value='secret')],
            }),
            csr.CRIAttribute({
                'type': csr.CSRAttributeType(UNKNOWN_OID),
                'values': core.Any(core.OctetString(b'\xab\xcd')),
            }),
        ],
    })
    return csr.CertificationRequest({
        'certification_request_info': request_info,
        'signature_algorithm': {'algorithm': 'sha256_rsa'},
        'signature': core.OctetBitString(b'\x00\x11\x22\x33'),
    })


def mutate_oid_tlv(der, new_oid_value, spec):
    """
    Replace the first OID TLV's content with new_oid_value (an OID string or
    a raw OID content byte string), recomputing every enclosing length. The
    replacement targets the attribute-level OID of an attribute structure.
    Named OID values (e.g. 'content_type') are resolved through the spec's OID
    field class so the library's name map is honored.
    """
    outer_header, _, outer_end = tlv_info(der)
    content = der[outer_header:outer_end]
    oid_header, oid_len, oid_end = tlv_info(content)
    if isinstance(new_oid_value, byte_cls):
        oid_content = new_oid_value
    elif spec is cms.CMSAttribute:
        oid_content = cms.CMSAttributeType(new_oid_value).contents
    else:
        oid_content = csr.CSRAttributeType(new_oid_value).contents
    new_oid_tlv = b'\x06' + encode_length(len(oid_content)) + oid_content
    new_content = new_oid_tlv + content[oid_end:]
    return rebuild(der[0], new_content)


def mutate_set_tag(der):
    """Flip the attribute's SET (universal 17, 0x31) tag to SEQUENCE (0x30)."""
    outer_header, _, outer_end = tlv_info(der)
    content = der[outer_header:outer_end]
    first_header, _, first_end = tlv_info(content)
    set_pos = first_end
    if content[set_pos] != 0x31:
        raise ValueError('expected SET tag at offset %d' % set_pos)
    new_content = content[:set_pos] + b'\x30' + content[set_pos + 1:]
    return rebuild(der[0], new_content)


def mutate_outer_tag(der):
    """Flip the outer SEQUENCE tag (0x30) to SET (0x31)."""
    return b'\x31' + der[1:]


def mutate_length_corruption(der):
    """Inflate the SET's declared length beyond the available bytes."""
    outer_header, _, outer_end = tlv_info(der)
    content = der[outer_header:outer_end]
    first_header, _, first_end = tlv_info(content)
    set_len_pos = first_end + 1
    corrupted = (
        der[:outer_header]
        + content[:set_len_pos]
        + byte_cls([content[set_len_pos] + 5])
        + content[set_len_pos + 1:]
    )
    return corrupted


def mutate_truncation(der):
    """Drop the final content byte of the structure."""
    return der[:-1]


def mutate_unknown_oid_arc(der):
    """Flip the last content byte of the attribute OID (keeps it decodable)."""
    outer_header, _, outer_end = tlv_info(der)
    content = der[outer_header:outer_end]
    oid_header, oid_len, oid_end = tlv_info(content)
    oid_content = content[oid_header:oid_end]
    flipped = oid_content[:-1] + byte_cls([oid_content[-1] ^ 0x01])
    new_oid_tlv = b'\x06' + encode_length(len(flipped)) + flipped
    new_content = new_oid_tlv + content[oid_end:]
    return rebuild(der[0], new_content)


def fixed_seed_byte_flips(der, count=6):
    """A small, fixed-seed set of single-byte flips inside the value region."""
    rng = random.Random(SEED)
    positions = list(range(2, len(der)))
    rng.shuffle(positions)
    mutations = []
    for pos in positions:
        candidate = bytearray(der)
        candidate[pos] ^= rng.randrange(1, 256)
        candidate = byte_cls(candidate)
        if candidate != der and candidate not in mutations:
            mutations.append(candidate)
        if len(mutations) >= count:
            break
    return mutations


class StructuralFuzzTests(unittest.TestCase):
    """Differential structural fuzzing of OID-selected attribute schemas."""

    @classmethod
    def setUpClass(cls):
        cls.counterexamples = []
        cls.cms_corpus = [obj.dump() for obj in build_cms_corpus()]
        cls.csr_der = build_csr().dump()
        cls.csr_attribute_paths = cls._locate_csr_attributes(cls.csr_der)

    @staticmethod
    def _locate_csr_attributes(csr_der):
        """
        Walk outer SEQUENCE -> CertificationRequestInfo SEQUENCE and return
        absolute (start, header, length, end) of the implicit [0] attributes
        TLV plus the bounds of the request info TLV. The [0] TLV is located by
        its context tag rather than by position, since DER SET OF encoding (and
        other surrounding TLVs) makes positional assumptions unreliable.
        """
        outer_header, _, _ = tlv_info(csr_der)
        outer_children = split_children(csr_der[outer_header:])
        info_rel = outer_children[0]
        info_abs_start = outer_header + info_rel[0]
        info_header, info_len, info_end = tlv_info(csr_der, info_abs_start)
        info_content = csr_der[info_abs_start + info_header:info_abs_start + info_end]
        attr_rel = None
        for child in split_children(info_content):
            child_start = child[0]
            if info_content[child_start] == 0xa0:
                attr_rel = child
                break
        if attr_rel is None:
            raise ValueError('implicit [0] attributes TLV not found in CSR')
        attr_abs_start = info_abs_start + info_header + attr_rel[0]
        attr_header, attr_len, attr_end = tlv_info(csr_der, attr_abs_start)
        return {
            'info_start': info_abs_start,
            'info_header': info_header,
            'info_end': info_abs_start + info_header + info_len,
            'attr_start': attr_abs_start,
            'attr_header': attr_header,
            'attr_end': attr_end,
            'attr_len': attr_len,
        }

    def _rewrite_csr_attributes(self, new_attr_tlv):
        """Splice a new attributes TLV into the CSR, fixing both lengths."""
        loc = self.csr_attribute_paths
        info = self.csr_der[loc['info_start']:loc['info_end']]
        info_header, _, _ = tlv_info(info)
        info_content = info[info_header:]
        attr_rel_start = loc['attr_start'] - (loc['info_start'] + info_header)
        attr_rel_end = loc['attr_end'] - (loc['info_start'] + info_header)
        new_info_content = info_content[:attr_rel_start] + new_attr_tlv + info_content[attr_rel_end:]
        new_info = rebuild(0x30, new_info_content)
        outer_header, _, _ = tlv_info(self.csr_der)
        new_outer_content = (
            self.csr_der[outer_header:loc['info_start']]
            + new_info
            + self.csr_der[loc['info_end']:]
        )
        return rebuild(0x30, new_outer_content)

    def test_cms_attribute_path_equivalence(self):
        """All three paths agree on every CMS attribute mutation."""
        mutation_builders = [
            ('oid-to-unknown', lambda d: mutate_oid_tlv(d, UNKNOWN_OID, cms.CMSAttribute)),
            ('oid-to-unknown-alt', lambda d: mutate_oid_tlv(d, UNKNOWN_OID_ALT, cms.CMSAttribute)),
            ('oid-to-content-type', lambda d: mutate_oid_tlv(d, 'content_type', cms.CMSAttribute)),
            ('oid-to-message-digest', lambda d: mutate_oid_tlv(d, 'message_digest', cms.CMSAttribute)),
            ('oid-arc-flip', mutate_unknown_oid_arc),
            ('set-to-sequence-tag', mutate_set_tag),
            ('outer-tag-flip', mutate_outer_tag),
            ('set-length-inflated', mutate_length_corruption),
            ('truncated', mutate_truncation),
        ]
        for index, der in enumerate(self.cms_corpus):
            for label, builder in mutation_builders:
                mutated = builder(der)
                assert_paths_agree(
                    self, mutated, cms.CMSAttribute,
                    'cms[%d]:%s' % (index, label), self.counterexamples
                )
            for flip_index, mutated in enumerate(fixed_seed_byte_flips(der)):
                assert_paths_agree(
                    self, mutated, cms.CMSAttribute,
                    'cms[%d]:byte-flip-%d' % (index, flip_index), self.counterexamples
                )

    def test_csr_attribute_path_equivalence(self):
        """All three paths agree on CSR-level tagging and SET OF mutations."""
        loc = self.csr_attribute_paths
        csr_mutations = []

        # Implicit tag mutation: [0] IMPLICIT -> [1] IMPLICIT.
        retagged = (
            self.csr_der[:loc['attr_start']]
            + b'\xa1'
            + self.csr_der[loc['attr_start'] + 1:]
        )
        csr_mutations.append(('implicit-tag-0-to-1', retagged))

        # Optional field removal: drop the whole optional attributes TLV.
        removed = self._rewrite_csr_attributes(b'')
        csr_mutations.append(('optional-attributes-removed', removed))

        # SET OF reordering: reverse the attribute TLVs inside the [0] wrapper.
        attr_content = self.csr_der[loc['attr_start'] + loc['attr_header']:loc['attr_end']]
        child_parts = split_children(attr_content)
        child_tlvs = [attr_content[s:e] for s, _, _, e in child_parts]
        reordered = rebuild(0xa0, b''.join(reversed(child_tlvs)))
        csr_mutations.append(('set-of-reordered', self._rewrite_csr_attributes(reordered)))

        # Length corruption and truncation at the top level.
        csr_mutations.append(('truncated', self.csr_der[:-1]))
        corrupted = bytearray(self.csr_der)
        corrupted[loc['attr_start'] + 1] = byte_cls(
            [corrupted[loc['attr_start'] + 1] + 4]
        )[0]
        csr_mutations.append(('attr-length-inflated', byte_cls(corrupted)))

        for label, mutated in csr_mutations:
            assert_paths_agree(
                self, mutated, csr.CertificationRequest,
                'csr:%s' % label, self.counterexamples
            )

    def test_known_oid_swap_rejects_incompatible_values(self):
        """
        Relabeling values with an OID whose spec expects a different tag must
        raise a documented parse error, identically on every path. A broad
        exception catch is explicitly rejected.
        """
        message_digest = self.cms_corpus[1]
        relabeled = mutate_oid_tlv(message_digest, 'content_type', cms.CMSAttribute)
        outcomes = assert_paths_agree(
            self, relabeled, cms.CMSAttribute,
            'cms:message-digest-relabeled-content-type', self.counterexamples
        )
        for path_name, outcome in outcomes.items():
            self.assertEqual(
                'error', outcome[0],
                '%s accepted an OID/value tag mismatch: %r' % (path_name, outcome)
            )
            self.assertEqual('ValueError', outcome[1])

        extension_request_der = csr.CRIAttribute({
            'type': 'extension_request',
            'values': [x509.Extensions([
                x509.Extension({
                    'extn_id': 'basic_constraints',
                    'critical': False,
                    'extn_value': x509.BasicConstraints({
                        'ca': False,
                        'path_len_constraint': None,
                    }),
                }),
            ])],
        }).dump()
        relabeled_csr = mutate_oid_tlv(
            extension_request_der, 'challenge_password', csr.CRIAttribute
        )
        outcomes = assert_paths_agree(
            self, relabeled_csr, csr.CRIAttribute,
            'csr:extension-request-relabeled-challenge-password',
            self.counterexamples
        )
        for path_name, outcome in outcomes.items():
            self.assertEqual('error', outcome[0])
            self.assertEqual('ValueError', outcome[1])

    def test_malformed_inputs_raise_documented_errors(self):
        """
        Structural corruptions must fail with ValueError/TypeError rather than
        being accepted or raising an unrelated exception. Each expectation is
        pinned to a specific exception class so that swallowing errors can not
        fake success.
        """
        expectations = []
        for der in self.cms_corpus:
            expectations.append(('set-tag', mutate_set_tag(der), 'ValueError'))
            expectations.append(('length', mutate_length_corruption(der), 'ValueError'))
            expectations.append(('truncation', mutate_truncation(der), 'ValueError'))
            expectations.append(('outer-tag', mutate_outer_tag(der), 'ValueError'))

        for label, mutated, expected_error in expectations:
            # The failure may surface at load time or only when the parsed
            # object is expanded; either way every path must fail the same way.
            for path_name, path_func in ACCESS_PATHS:
                with self.assertRaises(EXPECTED_PARSE_ERRORS) as context:
                    path_func(cms.CMSAttribute.load(mutated))
                self.assertEqual(
                    expected_error,
                    type(context.exception).__name__,
                    '%s via %s raised %s, expected %s'
                    % (label, path_name, type(context.exception).__name__, expected_error)
                )
            # And the three-path oracle must classify it uniformly.
            outcomes = run_three_paths(mutated, cms.CMSAttribute)
            self.assertEqual(
                1, len(set(outcomes.values())),
                '%s produced inconsistent path outcomes: %r' % (label, outcomes)
            )
            self.assertEqual('error', outcomes['direct_native'][0])

    def test_unknown_oid_preserves_raw_bytes(self):
        """
        Independent criterion for unknown OIDs: the dispatched Any/SetOfAny
        value must retain the original encoded bytes verbatim, and the whole
        structure must round-trip through .dump() regardless of access order.
        """
        for index, der in enumerate(self.cms_corpus):
            parsed = cms.CMSAttribute.load(der)
            if parsed['type'].native not in (UNKNOWN_OID, UNKNOWN_OID_ALT):
                continue
            # Raw bytes are preserved before any native expansion.
            values_der = parsed['values'].dump()
            # Access order must not change the preserved bytes.
            expanded = cms.CMSAttribute.load(der)
            _ = expanded.native
            self.assertEqual(
                values_der, expanded['values'].dump(),
                'unknown-OID value bytes changed after native expansion'
            )
            self.assertEqual(
                der, expanded.dump(),
                'unknown-OID CMS attribute %d did not round-trip' % index
            )
            # Each child stays a generic Any and keeps its original TLV bytes.
            # Locate the SET inside the attribute for byte-level comparison.
            outer_header, _, outer_end = tlv_info(der)
            attribute_content = der[outer_header:outer_end]
            oid_header, _, oid_end = tlv_info(attribute_content)
            original_set_tlv = attribute_content[oid_end:]
            self.assertEqual(original_set_tlv, expanded['values'].dump())
            for child in expanded['values']:
                self.assertIsInstance(child, core.Any)

        # CSR unknown OID: values field is a single Any (not a SET wrapper).
        csr_obj = csr.CertificationRequest.load(self.csr_der)
        attributes = csr_obj['certification_request_info']['attributes']
        unknown = [
            attr for attr in attributes
            if attr['type'].native == UNKNOWN_OID
        ]
        self.assertEqual(1, len(unknown))
        unknown_attr = unknown[0]
        self.assertIsInstance(unknown_attr['values'], core.Any)
        self.assertEqual(
            b'\x04\x02\xab\xcd',
            unknown_attr['values'].dump()
        )
        self.assertEqual(self.csr_der, csr.CertificationRequest.load(self.csr_der).dump())

    def test_set_of_order_is_preserved(self):
        """
        Reordering SET OF members must preserve input order in the native
        representation on every path, while a fresh .dump() re-sorts per DER.
        Both observations must be identical across the three access paths.
        """
        # CMS message_digest corpus entry with two members (index 2).
        der = self.cms_corpus[2]
        outer_header, _, outer_end = tlv_info(der)
        content = der[outer_header:outer_end]
        oid_header, _, oid_end = tlv_info(content)
        set_tlv = content[oid_end:]
        set_header, _, _ = tlv_info(set_tlv)
        set_content = set_tlv[set_header:]
        children = split_children(set_content)
        member_tlvs = [set_content[s:e] for s, _, _, e in children]
        reordered_set = rebuild(0x31, b''.join(reversed(member_tlvs)))
        reordered = rebuild(0x30, content[:oid_end] + reordered_set)

        outcomes = assert_paths_agree(
            self, reordered, cms.CMSAttribute,
            'cms:set-of-reordered', self.counterexamples
        )
        # Every path accepted it and reports the reversed input order.
        for outcome in outcomes.values():
            self.assertEqual('ok', outcome[0])
        parsed = cms.CMSAttribute.load(reordered)
        self.assertEqual(
            [b'\x00\x02', b'\x00\x01'],
            parsed['values'].native
        )
        # A plain .dump() preserves the (non-canonical) input encoding, so the
        # reordered bytes round-trip verbatim until a forced DER re-encode.
        self.assertEqual(reordered, parsed.dump())
        # dump(force=True) canonicalizes the SET OF back to sorted order.
        self.assertEqual(der, parsed.dump(force=True))

        # CSR-level SET OF reordering likewise stays path-consistent.
        loc = self.csr_attribute_paths
        attr_content = self.csr_der[loc['attr_start'] + loc['attr_header']:loc['attr_end']]
        child_parts = split_children(attr_content)
        child_tlvs = [attr_content[s:e] for s, _, _, e in child_parts]
        reordered_attr = rebuild(0xa0, b''.join(reversed(child_tlvs)))
        reordered_csr = self._rewrite_csr_attributes(reordered_attr)
        assert_paths_agree(
            self, reordered_csr, csr.CertificationRequest,
            'csr:set-of-reordered', self.counterexamples
        )

    def test_optional_removal_is_consistent(self):
        """Removing the optional CSR attributes field yields None on all paths."""
        loc = self.csr_attribute_paths
        removed = self._rewrite_csr_attributes(b'')
        outcomes = run_three_paths(removed, csr.CertificationRequest)
        distinct = set(outcomes.values())
        self.assertEqual(1, len(distinct), repr(outcomes))
        parsed = csr.CertificationRequest.load(removed)
        self.assertIsInstance(
            parsed['certification_request_info']['attributes'],
            core.Void
        )
        self.assertIsNone(parsed.native['certification_request_info']['attributes'])
        # Re-encoding reintroduces nothing: optional absent stays absent.
        self.assertEqual(removed, parsed.dump())

    def test_wrong_oid_dispatch_is_detected(self):
        """
        Proof that the differential machinery catches an interpretation
        divergence: a shadow oracle deliberately parses message_digest values
        with the wrong OID-selected spec (SetOfContentType instead of
        SetOfOctetString). Its outcome must differ from the real parser.
        """
        der = self.cms_corpus[1]

        def shadow_oracle(data):
            attribute = cms.CMSAttribute.load(data)
            if attribute['type'].native == 'message_digest':
                try:
                    wrong, _ = _parse_build(
                        attribute['values'].dump(),
                        spec=cms.SetOfContentType,
                        spec_params={},
                    )
                    return ('ok', canonical(wrong.native))
                except EXPECTED_PARSE_ERRORS as exc:
                    return ('error', type(exc).__name__)
            return ('ok', canonical(attribute.native))

        truth = run_three_paths(der, cms.CMSAttribute)
        shadow = shadow_oracle(der)

        # The real parser accepts the input on all three paths, with one
        # shared interpretation.
        self.assertEqual(
            1, len(set(truth.values())),
            'baseline parser unexpectedly disagreed with itself: %r' % truth
        )
        self.assertEqual('ok', truth['direct_native'][0])
        # The deliberately wrong dispatch must not reproduce that outcome.
        self.assertNotEqual(
            truth['direct_native'], shadow,
            'differential check failed to notice the wrong OID dispatch'
        )
        self.assertEqual('error', shadow[0])

    def test_counterexample_recording_and_persistence(self):
        """
        Prove the counterexample machinery end to end: feed a synthetic
        divergence through assert_paths_agree's recording path and confirm the
        minimal (label + hex + outcomes) record is serializable to disk. The
        file is written under the OS temp directory and removed immediately, so
        a normal green run leaves no artifacts in the source tree.
        """
        synthetic = {
            'label': 'synthetic:wrong-oid-dispatch',
            'hex': self.cms_corpus[1].hex(),
            'outcomes': {
                'field_first': ('ok', 'synthetic'),
                'direct_native': ('error', 'ValueError'),
                'copy_expand': ('ok', 'synthetic'),
            },
        }
        output_path = os.path.join(
            os.environ.get('TMPDIR', tempfile.gettempdir()),
            'struct_fuzz_counterexample_selftest.txt'
        )
        try:
            with open(output_path, 'w') as f:
                f.write(
                    '%s\n%s\n%r\n' % (
                        synthetic['label'],
                        synthetic['hex'],
                        synthetic['outcomes'],
                    )
                )
            with open(output_path, 'r') as f:
                persisted = f.read()
            self.assertIn(synthetic['label'], persisted)
            self.assertIn(synthetic['hex'], persisted)
        finally:
            if os.path.exists(output_path):
                os.remove(output_path)

        # And the real run must never have recorded a genuine divergence.
        self.assertEqual([], self.counterexamples)
