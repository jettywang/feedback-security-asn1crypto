# coding: utf-8

"""
Structural self-consistency checks for signature algorithm parameters.

This module provides a pre-flight structural check for certificate import
pipelines: before a certificate is handed to a cryptographic library, it
explains whether the signature algorithm parameters are self-consistent by

 - comparing the inner (tbsCertificate.signature) and outer
   (Certificate.signatureAlgorithm) AlgorithmIdentifiers of a certificate, and
 - checking the signature algorithm against RSA-PSS parameter constraints
   carried by the subject public key (RFC 4055 / RFC 5756).

Comparisons are performed on algorithm semantics: absent parameters, NULL
parameters and explicitly-encoded default values are normalized before
comparison, so structures that differ in DER bytes may still be reported as
equivalent. For RSA-PSS, the message digest, the MGF digest, the salt length
and the trailer field all participate in the comparison. Algorithms or
parameter structures this module does not understand yield an "undecidable"
verdict instead of being silently treated as consistent.

This is a structural check only. It does not replace certificate chain
building, path validation or cryptographic signature verification.

Exports the following items:

 - Verdict
 - FieldExplanation
 - AlgorithmCheckResult
 - CertificateSignatureCheck
 - compare_algorithm_identifiers()
 - check_certificate_signature_algorithms()
 - check_pss_key_constraints()
 - check_certificate_signature_consistency()
"""

from __future__ import unicode_literals, division, absolute_import, print_function

from ._types import str_cls
from .algos import (
    DigestAlgorithm,
    DigestAlgorithmId,
    MaskGenAlgorithm,
    RSASSAPSSParams,
    SignedDigestAlgorithmId,
    TrailerField,
)
from .core import Null, Void
from .keys import PublicKeyAlgorithmId


class Verdict(object):
    """
    Outcome of a structural comparison. CONFLICT indicates the two structures
    disagree, UNDECIDABLE indicates the structures contain algorithms or
    parameters this module can not interpret, and CONSISTENT indicates the
    structures are semantically equivalent.
    """

    CONSISTENT = 'consistent'
    UNDECIDABLE = 'undecidable'
    CONFLICT = 'conflict'


_VERDICT_RANK = {
    Verdict.CONSISTENT: 0,
    Verdict.UNDECIDABLE: 1,
    Verdict.CONFLICT: 2,
}


class FieldExplanation(object):
    """
    The comparison outcome for a single field of an AlgorithmIdentifier,
    allowing a verdict to be traced back to the exact field that produced it.
    """

    def __init__(self, field, verdict, reason, left=None, right=None):
        """
        :param field:
            A dotted path to the field, relative to the compared
            AlgorithmIdentifier, e.g. "parameters.mask_gen_algorithm"

        :param verdict:
            One of the Verdict constants

        :param reason:
            A human-readable explanation of the outcome

        :param left:
            The normalized semantic value from the left structure

        :param right:
            The normalized semantic value from the right structure
        """

        self.field = field
        self.verdict = verdict
        self.reason = reason
        self.left = left
        self.right = right

    def __repr__(self):
        return (
            'FieldExplanation(field=%s, verdict=%s, left=%s, right=%s)'
            % (self.field, self.verdict, self.left, self.right)
        )


class AlgorithmCheckResult(object):
    """
    The aggregated result of comparing two algorithm structures, retaining a
    FieldExplanation for every field that participated in the comparison.
    """

    def __init__(self, left_label='left', right_label='right'):
        """
        :param left_label:
            A label identifying the left structure, used in explanations

        :param right_label:
            A label identifying the right structure, used in explanations
        """

        self.left_label = left_label
        self.right_label = right_label
        self.fields = []
        self.left_bytes = None
        self.right_bytes = None

    def add_field(self, field, verdict, reason, left=None, right=None):
        explanation = FieldExplanation(field, verdict, reason, left, right)
        self.fields.append(explanation)
        return explanation

    @property
    def verdict(self):
        """
        :return:
            The worst verdict of any field, one of the Verdict constants
        """

        worst = Verdict.CONSISTENT
        for field in self.fields:
            if _VERDICT_RANK[field.verdict] > _VERDICT_RANK[worst]:
                worst = field.verdict
        return worst

    @property
    def consistent(self):
        """
        :return:
            A boolean indicating the structures are semantically consistent
        """

        return self.verdict == Verdict.CONSISTENT

    @property
    def bytes_differ(self):
        """
        :return:
            None if the DER encodings were not recorded, otherwise a boolean
            indicating the two structures encode to different bytes
        """

        if self.left_bytes is None or self.right_bytes is None:
            return None
        return self.left_bytes != self.right_bytes

    def explain(self):
        """
        :return:
            A multi-line unicode string tracing the verdict to each field
        """

        lines = [
            '%s vs %s: %s' % (self.left_label, self.right_label, self.verdict)
        ]
        for field in self.fields:
            lines.append(
                '  %s: %s (%s vs %s) - %s'
                % (field.field, field.verdict, field.left, field.right, field.reason)
            )
        return '\n'.join(lines)

    def __repr__(self):
        return (
            'AlgorithmCheckResult(%s vs %s, verdict=%s)'
            % (self.left_label, self.right_label, self.verdict)
        )


class CertificateSignatureCheck(object):
    """
    The combined structural check for a certificate: the inner/outer
    AlgorithmIdentifier comparison plus the RSA-PSS public key constraint
    check.
    """

    def __init__(self, inner_outer, key_constraints):
        """
        :param inner_outer:
            An AlgorithmCheckResult comparing tbsCertificate.signature with
            Certificate.signatureAlgorithm

        :param key_constraints:
            An AlgorithmCheckResult checking the signature algorithm against
            the subject public key RSA-PSS constraints
        """

        self.inner_outer = inner_outer
        self.key_constraints = key_constraints

    @property
    def verdict(self):
        """
        :return:
            The worst verdict of the two checks, one of the Verdict constants
        """

        if _VERDICT_RANK[self.key_constraints.verdict] > _VERDICT_RANK[self.inner_outer.verdict]:
            return self.key_constraints.verdict
        return self.inner_outer.verdict

    @property
    def consistent(self):
        """
        :return:
            A boolean indicating both checks are semantically consistent
        """

        return self.verdict == Verdict.CONSISTENT

    def explain(self):
        """
        :return:
            A multi-line unicode string tracing the verdict to each field of
            both checks
        """

        return '\n'.join([
            self.inner_outer.explain(),
            self.key_constraints.explain(),
        ])

    def __repr__(self):
        return 'CertificateSignatureCheck(verdict=%s)' % self.verdict


_KNOWN_DIGEST_NAMES = set(DigestAlgorithmId._map.values())
_KNOWN_SIGNATURE_NAMES = set(SignedDigestAlgorithmId._map.values())
_KNOWN_PUBLIC_KEY_NAMES = set(PublicKeyAlgorithmId._map.values())
_KNOWN_MGF_NAMES = set(['mgf1'])

_DEFAULT_PSS_HASH = 'sha1'
_DEFAULT_PSS_MGF_HASH = 'sha1'
_DEFAULT_PSS_SALT_LENGTH = 20
_DEFAULT_PSS_TRAILER_FIELD = 1

_TRAILER_FIELD_NAMES = {
    1: 'trailer_field_bc',
}


def _algorithm_name(algorithm_identifier, known_names):
    """
    Resolves the algorithm OID of an AlgorithmIdentifier to its registered
    name

    :param algorithm_identifier:
        An asn1crypto Sequence with an "algorithm" field

    :param known_names:
        A set of unicode strings of the names known for the structure

    :return:
        A unicode string of the algorithm name, or None if the OID is not
        registered in the relevant map
    """

    name = algorithm_identifier['algorithm'].native
    if not isinstance(name, str_cls) or name not in known_names:
        return None
    return name


def _parameters_state(parameters):
    """
    Classifies the parameters field of an AlgorithmIdentifier

    :param parameters:
        An asn1crypto value

    :return:
        One of the unicode strings "absent", "null" or "other"
    """

    if isinstance(parameters, Void):
        return 'absent'
    if isinstance(parameters, Null):
        return 'null'
    return 'other'


def _describe_digest(digest_algorithm):
    """
    :param digest_algorithm:
        An algos.DigestAlgorithm object

    :return:
        A unicode string describing the digest algorithm for explanations
    """

    name = digest_algorithm['algorithm'].native
    state = _parameters_state(digest_algorithm['parameters'])
    if state == 'other':
        return '%s (with parameters)' % name
    return name


def _compare_digest_algorithms(left, right, path, result):
    """
    Semantically compares two DigestAlgorithm structures, treating absent and
    NULL parameters as equivalent, and records the outcome

    :param left:
        An algos.DigestAlgorithm object

    :param right:
        An algos.DigestAlgorithm object

    :param path:
        A unicode string of the dotted field path for explanations

    :param result:
        An AlgorithmCheckResult to record field explanations into
    """

    left_name = _algorithm_name(left, _KNOWN_DIGEST_NAMES)
    right_name = _algorithm_name(right, _KNOWN_DIGEST_NAMES)
    left_desc = _describe_digest(left)
    right_desc = _describe_digest(right)

    if left_name is None or right_name is None:
        result.add_field(
            path,
            Verdict.UNDECIDABLE,
            'unknown digest algorithm OID can not be compared',
            left_desc,
            right_desc
        )
        return

    if left_name != right_name:
        result.add_field(
            path,
            Verdict.CONFLICT,
            'digest algorithms differ',
            left_name,
            right_name
        )
        return

    left_state = _parameters_state(left['parameters'])
    right_state = _parameters_state(right['parameters'])

    if left_state != 'other' and right_state != 'other':
        result.add_field(
            path,
            Verdict.CONSISTENT,
            'absent and NULL digest parameters are equivalent',
            left_desc,
            right_desc
        )
        return

    if left_state == 'other' and right_state == 'other' and \
            left['parameters'].dump() == right['parameters'].dump():
        result.add_field(
            path,
            Verdict.CONSISTENT,
            'digest parameters are byte-identical',
            left_desc,
            right_desc
        )
        return

    result.add_field(
        path,
        Verdict.UNDECIDABLE,
        'digest algorithm carries parameters this check can not interpret',
        left_desc,
        right_desc
    )


def _extract_pss_params(parameters):
    """
    Normalizes RSASSA-PSS parameters, filling in the RFC 4055 default values
    for absent fields and for entirely absent parameters

    :param parameters:
        An algos.RSASSAPSSParams object, or a core.Void if the parameters
        field is absent

    :return:
        A dict with the keys "hash_algorithm" and "mask_gen_algorithm" (each
        an algos structure or None if not interpretable), "mask_gen_digest"
        (an algos.DigestAlgorithm or None), "salt_length" (an integer or
        None) and "trailer_field" (an integer or None)
    """

    normalized = {
        'hash_algorithm': DigestAlgorithm({'algorithm': _DEFAULT_PSS_HASH}),
        'mask_gen_algorithm': MaskGenAlgorithm({
            'algorithm': 'mgf1',
            'parameters': {'algorithm': _DEFAULT_PSS_MGF_HASH},
        }),
        'mask_gen_digest': DigestAlgorithm({'algorithm': _DEFAULT_PSS_MGF_HASH}),
        'salt_length': _DEFAULT_PSS_SALT_LENGTH,
        'trailer_field': _DEFAULT_PSS_TRAILER_FIELD,
    }

    if isinstance(parameters, Void):
        return normalized

    if not isinstance(parameters, RSASSAPSSParams):
        return None

    hash_algorithm = parameters['hash_algorithm']
    if not isinstance(hash_algorithm, Void):
        if not isinstance(hash_algorithm, DigestAlgorithm):
            return None
        normalized['hash_algorithm'] = hash_algorithm

    mask_gen_algorithm = parameters['mask_gen_algorithm']
    if not isinstance(mask_gen_algorithm, Void):
        if not isinstance(mask_gen_algorithm, MaskGenAlgorithm):
            return None
        normalized['mask_gen_algorithm'] = mask_gen_algorithm
        mask_gen_digest = mask_gen_algorithm['parameters']
        if isinstance(mask_gen_digest, Void):
            normalized['mask_gen_digest'] = DigestAlgorithm(
                {'algorithm': _DEFAULT_PSS_MGF_HASH}
            )
        elif isinstance(mask_gen_digest, DigestAlgorithm):
            normalized['mask_gen_digest'] = mask_gen_digest
        else:
            normalized['mask_gen_digest'] = None

    salt_length = parameters['salt_length']
    if not isinstance(salt_length, Void):
        normalized['salt_length'] = salt_length.native

    trailer_field = parameters['trailer_field']
    if not isinstance(trailer_field, Void):
        normalized['trailer_field'] = _trailer_field_value(trailer_field)

    return normalized


def _trailer_field_value(trailer_field):
    """
    Normalizes a TrailerField value to its integer form, since the native
    value may be the mapped name instead of the integer

    :param trailer_field:
        An algos.TrailerField object

    :return:
        An integer, or None if the value can not be interpreted
    """

    native = trailer_field.native
    if isinstance(native, int):
        return native
    for number, name in TrailerField._map.items():
        if name == native:
            return number
    return None


def _describe_trailer_field(value):
    """
    :param value:
        An integer trailer field value

    :return:
        A unicode string describing the trailer field for explanations
    """

    name = _TRAILER_FIELD_NAMES.get(value)
    if name is None:
        return str_cls(value)
    return '%s (%d)' % (name, value)


def _compare_pss_params(left_params, right_params, path, result):
    """
    Semantically compares two sets of RSASSA-PSS parameters field by field:
    message digest, MGF digest, salt length and trailer field

    :param left_params:
        An algos.RSASSAPSSParams object or core.Void

    :param right_params:
        An algos.RSASSAPSSParams object or core.Void

    :param path:
        A unicode string of the dotted field path for explanations

    :param result:
        An AlgorithmCheckResult to record field explanations into
    """

    left = _extract_pss_params(left_params)
    right = _extract_pss_params(right_params)

    if left is None or right is None:
        result.add_field(
            path,
            Verdict.UNDECIDABLE,
            'RSA-PSS parameters are not interpretable as RSASSA-PSS-params'
        )
        return

    _compare_digest_algorithms(
        left['hash_algorithm'],
        right['hash_algorithm'],
        path + '.hash_algorithm',
        result
    )

    left_mgf = left['mask_gen_algorithm']['algorithm'].native
    right_mgf = right['mask_gen_algorithm']['algorithm'].native
    if left_mgf not in _KNOWN_MGF_NAMES or right_mgf not in _KNOWN_MGF_NAMES:
        result.add_field(
            path + '.mask_gen_algorithm',
            Verdict.UNDECIDABLE,
            'unknown mask generation function can not be compared',
            left_mgf,
            right_mgf
        )
    elif left_mgf != right_mgf:
        result.add_field(
            path + '.mask_gen_algorithm',
            Verdict.CONFLICT,
            'mask generation functions differ',
            left_mgf,
            right_mgf
        )
    else:
        result.add_field(
            path + '.mask_gen_algorithm',
            Verdict.CONSISTENT,
            'mask generation functions match',
            left_mgf,
            right_mgf
        )

    if left['mask_gen_digest'] is None or right['mask_gen_digest'] is None:
        result.add_field(
            path + '.mask_gen_algorithm.parameters',
            Verdict.UNDECIDABLE,
            'MGF parameters are not interpretable as a DigestAlgorithm'
        )
    else:
        _compare_digest_algorithms(
            left['mask_gen_digest'],
            right['mask_gen_digest'],
            path + '.mask_gen_algorithm.parameters',
            result
        )

    if left['salt_length'] == right['salt_length']:
        result.add_field(
            path + '.salt_length',
            Verdict.CONSISTENT,
            'salt lengths match',
            left['salt_length'],
            right['salt_length']
        )
    else:
        result.add_field(
            path + '.salt_length',
            Verdict.CONFLICT,
            'salt lengths differ',
            left['salt_length'],
            right['salt_length']
        )

    if left['trailer_field'] is None or right['trailer_field'] is None:
        result.add_field(
            path + '.trailer_field',
            Verdict.UNDECIDABLE,
            'trailer field value can not be interpreted',
            left['trailer_field'],
            right['trailer_field']
        )
    elif left['trailer_field'] == right['trailer_field']:
        result.add_field(
            path + '.trailer_field',
            Verdict.CONSISTENT,
            'trailer fields match',
            _describe_trailer_field(left['trailer_field']),
            _describe_trailer_field(right['trailer_field'])
        )
    else:
        result.add_field(
            path + '.trailer_field',
            Verdict.CONFLICT,
            'trailer fields differ',
            _describe_trailer_field(left['trailer_field']),
            _describe_trailer_field(right['trailer_field'])
        )


def _compare_simple_parameters(left, right, path, result):
    """
    Compares the parameters of algorithms without a registered parameter
    structure, treating absent and NULL parameters as equivalent

    :param left:
        An AlgorithmIdentifier-style asn1crypto Sequence

    :param right:
        An AlgorithmIdentifier-style asn1crypto Sequence

    :param path:
        A unicode string of the dotted field path for explanations

    :param result:
        An AlgorithmCheckResult to record field explanations into
    """

    left_params = left['parameters']
    right_params = right['parameters']
    left_state = _parameters_state(left_params)
    right_state = _parameters_state(right_params)

    if left_state != 'other' and right_state != 'other':
        result.add_field(
            path,
            Verdict.CONSISTENT,
            'absent and NULL parameters are equivalent for this algorithm',
            left_state,
            right_state
        )
        return

    if left_state == 'other' and right_state == 'other' and \
            left_params.dump() == right_params.dump():
        result.add_field(
            path,
            Verdict.CONSISTENT,
            'parameters are byte-identical',
            'present',
            'present'
        )
        return

    result.add_field(
        path,
        Verdict.UNDECIDABLE,
        'algorithm parameters are present and this check can not interpret '
        'their semantics',
        left_state,
        right_state
    )


def compare_algorithm_identifiers(left, right, left_label='left',
                                  right_label='right'):
    """
    Semantically compares two AlgorithmIdentifier structures (for example
    algos.SignedDigestAlgorithm or keys.PublicKeyAlgorithm), normalizing
    absent parameters, NULL parameters and explicitly-encoded default values
    before comparison

    :param left:
        An AlgorithmIdentifier-style asn1crypto Sequence

    :param right:
        An AlgorithmIdentifier-style asn1crypto Sequence

    :param left_label:
        A unicode string identifying the left structure in explanations

    :param right_label:
        A unicode string identifying the right structure in explanations

    :return:
        An AlgorithmCheckResult
    """

    result = AlgorithmCheckResult(left_label, right_label)
    result.left_bytes = left.dump()
    result.right_bytes = right.dump()

    known_names = _KNOWN_SIGNATURE_NAMES | _KNOWN_PUBLIC_KEY_NAMES
    left_name = _algorithm_name(left, known_names)
    right_name = _algorithm_name(right, known_names)
    left_dotted = left['algorithm'].dotted
    right_dotted = right['algorithm'].dotted

    if left_name is None or right_name is None:
        result.add_field(
            'algorithm',
            Verdict.UNDECIDABLE,
            'unknown algorithm OID can not be compared',
            left_dotted,
            right_dotted
        )
        return result

    if left_name != right_name:
        result.add_field(
            'algorithm',
            Verdict.CONFLICT,
            'algorithm OIDs differ',
            '%s (%s)' % (left_name, left_dotted),
            '%s (%s)' % (right_name, right_dotted)
        )
        return result

    result.add_field(
        'algorithm',
        Verdict.CONSISTENT,
        'algorithm OIDs match',
        '%s (%s)' % (left_name, left_dotted),
        '%s (%s)' % (right_name, right_dotted)
    )

    if left_name == 'rsassa_pss':
        _compare_pss_params(
            left['parameters'],
            right['parameters'],
            'parameters',
            result
        )
    else:
        _compare_simple_parameters(left, right, 'parameters', result)

    return result


def check_certificate_signature_algorithms(cert):
    """
    Compares the inner (tbsCertificate.signature) and outer
    (Certificate.signatureAlgorithm) AlgorithmIdentifiers of a certificate

    :param cert:
        An x509.Certificate object

    :return:
        An AlgorithmCheckResult
    """

    return compare_algorithm_identifiers(
        cert['tbs_certificate']['signature'],
        cert['signature_algorithm'],
        'tbs_certificate.signature',
        'signature_algorithm'
    )


def check_pss_key_constraints(signature_algorithm, public_key_algorithm):
    """
    Checks a signature algorithm against the RSA-PSS parameter constraints
    carried by a public key. When the public key algorithm is rsassa_pss and
    its parameters are present, RFC 4055 restricts the key to signatures
    using exactly those parameters; when the parameters are absent, or the
    key is a plain rsaEncryption key, no constraint applies.

    :param signature_algorithm:
        An algos.SignedDigestAlgorithm object

    :param public_key_algorithm:
        A keys.PublicKeyAlgorithm object

    :return:
        An AlgorithmCheckResult
    """

    result = AlgorithmCheckResult('signature_algorithm', 'public_key_algorithm')
    result.left_bytes = signature_algorithm.dump()
    result.right_bytes = public_key_algorithm.dump()

    key_name = _algorithm_name(public_key_algorithm, _KNOWN_PUBLIC_KEY_NAMES)
    key_dotted = public_key_algorithm['algorithm'].dotted

    if key_name is None:
        result.add_field(
            'algorithm',
            Verdict.UNDECIDABLE,
            'unknown public key algorithm OID can not be checked',
            None,
            key_dotted
        )
        return result

    if key_name == 'rsa':
        result.add_field(
            'algorithm',
            Verdict.CONSISTENT,
            'rsaEncryption public key carries no RSA-PSS parameter '
            'constraints',
            None,
            'rsa (%s)' % key_dotted
        )
        return result

    if key_name != 'rsassa_pss':
        result.add_field(
            'algorithm',
            Verdict.UNDECIDABLE,
            'public key algorithm does not carry RSA-PSS constraints; this '
            'check is not applicable',
            None,
            '%s (%s)' % (key_name, key_dotted)
        )
        return result

    signature_name = _algorithm_name(signature_algorithm, _KNOWN_SIGNATURE_NAMES)
    signature_dotted = signature_algorithm['algorithm'].dotted

    if signature_name is None:
        result.add_field(
            'algorithm',
            Verdict.UNDECIDABLE,
            'unknown signature algorithm OID can not be checked against '
            'RSA-PSS key constraints',
            signature_dotted,
            'rsassa_pss (%s)' % key_dotted
        )
        return result

    if signature_name != 'rsassa_pss':
        result.add_field(
            'algorithm',
            Verdict.CONFLICT,
            'public key is restricted to rsassa_pss signatures but the '
            'signature algorithm is %s' % signature_name,
            '%s (%s)' % (signature_name, signature_dotted),
            'rsassa_pss (%s)' % key_dotted
        )
        return result

    result.add_field(
        'algorithm',
        Verdict.CONSISTENT,
        'signature algorithm matches the rsassa_pss public key',
        'rsassa_pss (%s)' % signature_dotted,
        'rsassa_pss (%s)' % key_dotted
    )

    key_params = public_key_algorithm['parameters']
    if isinstance(key_params, Void):
        result.add_field(
            'parameters',
            Verdict.CONSISTENT,
            'public key carries no RSA-PSS parameter constraints',
            None,
            'absent'
        )
        return result

    field_count = len(result.fields)
    _compare_pss_params(
        signature_algorithm['parameters'],
        key_params,
        'parameters',
        result
    )

    for field in result.fields[field_count:]:
        if field.verdict == Verdict.CONFLICT:
            field.reason += (
                '; the public key constraint is stricter than the signature '
                'parameters'
            )

    return result


def check_certificate_signature_consistency(cert):
    """
    Runs the full structural self-consistency check for a certificate: the
    inner/outer AlgorithmIdentifier comparison and the RSA-PSS public key
    constraint check. This does not replace certificate chain building, path
    validation or cryptographic signature verification.

    :param cert:
        An x509.Certificate object

    :return:
        A CertificateSignatureCheck
    """

    inner_outer = check_certificate_signature_algorithms(cert)
    key_constraints = check_pss_key_constraints(
        cert['signature_algorithm'],
        cert['tbs_certificate']['subject_public_key_info']['algorithm']
    )
    return CertificateSignatureCheck(inner_outer, key_constraints)
