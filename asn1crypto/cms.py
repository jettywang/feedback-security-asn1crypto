# coding: utf-8

"""
ASN.1 type classes for cryptographic message syntax (CMS). Structures are also
compatible with PKCS#7. Exports the following items:

 - AuthenticatedData()
 - AuthEnvelopedData()
 - CompressedData()
 - ContentInfo()
 - DigestedData()
 - EncryptedData()
 - EnvelopedData()
 - RecipientInfoCandidate()
 - RecipientMatch()
 - RecipientSelection()
 - SignedAndEnvelopedData()
 - SignedData()

Other type classes are defined that help compose the types listed above.

Most CMS structures in the wild are formatted as ContentInfo encapsulating one of the other types.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

try:
    import zlib
except (ImportError):
    zlib = None

from ._errors import unwrap
from .algos import (
    _ForceNullParameters,
    DigestAlgorithm,
    EncryptionAlgorithm,
    EncryptionAlgorithmId,
    HmacAlgorithm,
    KdfAlgorithm,
    RSAESOAEPParams,
    SignedDigestAlgorithm,
)
from .core import (
    Any,
    BitString,
    Choice,
    Enumerated,
    GeneralizedTime,
    Integer,
    Null,
    ObjectIdentifier,
    OctetBitString,
    OctetString,
    ParsableOctetString,
    Sequence,
    SequenceOf,
    SetOf,
    UTCTime,
    UTF8String,
    Void,
)
from .crl import CertificateList
from .keys import PublicKeyInfo
from .ocsp import OCSPResponse
from .x509 import Attributes, Certificate, Extensions, GeneralName, GeneralNames, Name


# These structures are taken from
# ftp://ftp.rsasecurity.com/pub/pkcs/ascii/pkcs-6.asc

class ExtendedCertificateInfo(Sequence):
    _fields = [
        ('version', Integer),
        ('certificate', Certificate),
        ('attributes', Attributes),
    ]


class ExtendedCertificate(Sequence):
    _fields = [
        ('extended_certificate_info', ExtendedCertificateInfo),
        ('signature_algorithm', SignedDigestAlgorithm),
        ('signature', OctetBitString),
    ]


# These structures are taken from https://tools.ietf.org/html/rfc5652,
# https://tools.ietf.org/html/rfc5083, http://tools.ietf.org/html/rfc2315,
# https://tools.ietf.org/html/rfc5940, https://tools.ietf.org/html/rfc3274,
# https://tools.ietf.org/html/rfc3281


class CMSVersion(Integer):
    _map = {
        0: 'v0',
        1: 'v1',
        2: 'v2',
        3: 'v3',
        4: 'v4',
        5: 'v5',
    }


class CMSAttributeType(ObjectIdentifier):
    _map = {
        '1.2.840.113549.1.9.3': 'content_type',
        '1.2.840.113549.1.9.4': 'message_digest',
        '1.2.840.113549.1.9.5': 'signing_time',
        '1.2.840.113549.1.9.6': 'counter_signature',
        # https://datatracker.ietf.org/doc/html/rfc2633#section-2.5.2
        '1.2.840.113549.1.9.15': 'smime_capabilities',
        # https://tools.ietf.org/html/rfc2633#page-26
        '1.2.840.113549.1.9.16.2.11': 'encrypt_key_pref',
        # https://tools.ietf.org/html/rfc3161#page-20
        '1.2.840.113549.1.9.16.2.14': 'signature_time_stamp_token',
        # https://tools.ietf.org/html/rfc6211#page-5
        '1.2.840.113549.1.9.52': 'cms_algorithm_protection',
        # https://docs.microsoft.com/en-us/previous-versions/hh968145(v%3Dvs.85)
        '1.3.6.1.4.1.311.2.4.1': 'microsoft_nested_signature',
        # Some places refer to this as SPC_RFC3161_OBJID, others szOID_RFC3161_counterSign.
        # https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_algorithm_identifier
        # refers to szOID_RFC3161_counterSign as "1.2.840.113549.1.9.16.1.4",
        # but that OID is also called szOID_TIMESTAMP_TOKEN. Because of there being
        # no canonical source for this OID, we give it our own name
        '1.3.6.1.4.1.311.3.3.1': 'microsoft_time_stamp_token',
    }


class Time(Choice):
    _alternatives = [
        ('utc_time', UTCTime),
        ('generalized_time', GeneralizedTime),
    ]


class ContentType(ObjectIdentifier):
    _map = {
        '1.2.840.113549.1.7.1': 'data',
        '1.2.840.113549.1.7.2': 'signed_data',
        '1.2.840.113549.1.7.3': 'enveloped_data',
        '1.2.840.113549.1.7.4': 'signed_and_enveloped_data',
        '1.2.840.113549.1.7.5': 'digested_data',
        '1.2.840.113549.1.7.6': 'encrypted_data',
        '1.2.840.113549.1.9.16.1.2': 'authenticated_data',
        '1.2.840.113549.1.9.16.1.9': 'compressed_data',
        '1.2.840.113549.1.9.16.1.23': 'authenticated_enveloped_data',
    }


class CMSAlgorithmProtection(Sequence):
    _fields = [
        ('digest_algorithm', DigestAlgorithm),
        ('signature_algorithm', SignedDigestAlgorithm, {'implicit': 1, 'optional': True}),
        ('mac_algorithm', HmacAlgorithm, {'implicit': 2, 'optional': True}),
    ]


class SetOfContentType(SetOf):
    _child_spec = ContentType


class SetOfOctetString(SetOf):
    _child_spec = OctetString


class SetOfTime(SetOf):
    _child_spec = Time


class SetOfAny(SetOf):
    _child_spec = Any


class SetOfCMSAlgorithmProtection(SetOf):
    _child_spec = CMSAlgorithmProtection


class CMSAttribute(Sequence):
    _fields = [
        ('type', CMSAttributeType),
        ('values', None),
    ]

    _oid_specs = {}

    def _values_spec(self):
        return self._oid_specs.get(self['type'].native, SetOfAny)

    _spec_callbacks = {
        'values': _values_spec
    }


class CMSAttributes(SetOf):
    _child_spec = CMSAttribute


class IssuerSerial(Sequence):
    _fields = [
        ('issuer', GeneralNames),
        ('serial', Integer),
        ('issuer_uid', OctetBitString, {'optional': True}),
    ]


class AttCertVersion(Integer):
    _map = {
        0: 'v1',
        1: 'v2',
    }


class AttCertSubject(Choice):
    _alternatives = [
        ('base_certificate_id', IssuerSerial, {'explicit': 0}),
        ('subject_name', GeneralNames, {'explicit': 1}),
    ]


class AttCertValidityPeriod(Sequence):
    _fields = [
        ('not_before_time', GeneralizedTime),
        ('not_after_time', GeneralizedTime),
    ]


class AttributeCertificateInfoV1(Sequence):
    _fields = [
        ('version', AttCertVersion, {'default': 'v1'}),
        ('subject', AttCertSubject),
        ('issuer', GeneralNames),
        ('signature', SignedDigestAlgorithm),
        ('serial_number', Integer),
        ('att_cert_validity_period', AttCertValidityPeriod),
        ('attributes', Attributes),
        ('issuer_unique_id', OctetBitString, {'optional': True}),
        ('extensions', Extensions, {'optional': True}),
    ]


class AttributeCertificateV1(Sequence):
    _fields = [
        ('ac_info', AttributeCertificateInfoV1),
        ('signature_algorithm', SignedDigestAlgorithm),
        ('signature', OctetBitString),
    ]


class DigestedObjectType(Enumerated):
    _map = {
        0: 'public_key',
        1: 'public_key_cert',
        2: 'other_objy_types',
    }


class ObjectDigestInfo(Sequence):
    _fields = [
        ('digested_object_type', DigestedObjectType),
        ('other_object_type_id', ObjectIdentifier, {'optional': True}),
        ('digest_algorithm', DigestAlgorithm),
        ('object_digest', OctetBitString),
    ]


class Holder(Sequence):
    _fields = [
        ('base_certificate_id', IssuerSerial, {'implicit': 0, 'optional': True}),
        ('entity_name', GeneralNames, {'implicit': 1, 'optional': True}),
        ('object_digest_info', ObjectDigestInfo, {'implicit': 2, 'optional': True}),
    ]


class V2Form(Sequence):
    _fields = [
        ('issuer_name', GeneralNames, {'optional': True}),
        ('base_certificate_id', IssuerSerial, {'explicit': 0, 'optional': True}),
        ('object_digest_info', ObjectDigestInfo, {'explicit': 1, 'optional': True}),
    ]


class AttCertIssuer(Choice):
    _alternatives = [
        ('v1_form', GeneralNames),
        ('v2_form', V2Form, {'implicit': 0}),
    ]


class IetfAttrValue(Choice):
    _alternatives = [
        ('octets', OctetString),
        ('oid', ObjectIdentifier),
        ('string', UTF8String),
    ]


class IetfAttrValues(SequenceOf):
    _child_spec = IetfAttrValue


class IetfAttrSyntax(Sequence):
    _fields = [
        ('policy_authority', GeneralNames, {'implicit': 0, 'optional': True}),
        ('values', IetfAttrValues),
    ]


class SetOfIetfAttrSyntax(SetOf):
    _child_spec = IetfAttrSyntax


class SvceAuthInfo(Sequence):
    _fields = [
        ('service', GeneralName),
        ('ident', GeneralName),
        ('auth_info', OctetString, {'optional': True}),
    ]


class SetOfSvceAuthInfo(SetOf):
    _child_spec = SvceAuthInfo


class RoleSyntax(Sequence):
    _fields = [
        ('role_authority', GeneralNames, {'implicit': 0, 'optional': True}),
        ('role_name', GeneralName, {'explicit': 1}),
    ]


class SetOfRoleSyntax(SetOf):
    _child_spec = RoleSyntax


class ClassList(BitString):
    _map = {
        0: 'unmarked',
        1: 'unclassified',
        2: 'restricted',
        3: 'confidential',
        4: 'secret',
        5: 'top_secret',
    }


class SecurityCategory(Sequence):
    _fields = [
        ('type', ObjectIdentifier, {'implicit': 0}),
        ('value', Any, {'explicit': 1}),
    ]


class SetOfSecurityCategory(SetOf):
    _child_spec = SecurityCategory


class Clearance(Sequence):
    _fields = [
        ('policy_id', ObjectIdentifier),
        ('class_list', ClassList, {'default': set(['unclassified'])}),
        ('security_categories', SetOfSecurityCategory, {'optional': True}),
    ]


class SetOfClearance(SetOf):
    _child_spec = Clearance


class BigTime(Sequence):
    _fields = [
        ('major', Integer),
        ('fractional_seconds', Integer),
        ('sign', Integer, {'optional': True}),
    ]


class LeapData(Sequence):
    _fields = [
        ('leap_time', BigTime),
        ('action', Integer),
    ]


class SetOfLeapData(SetOf):
    _child_spec = LeapData


class TimingMetrics(Sequence):
    _fields = [
        ('ntp_time', BigTime),
        ('offset', BigTime),
        ('delay', BigTime),
        ('expiration', BigTime),
        ('leap_event', SetOfLeapData, {'optional': True}),
    ]


class SetOfTimingMetrics(SetOf):
    _child_spec = TimingMetrics


class TimingPolicy(Sequence):
    _fields = [
        ('policy_id', SequenceOf, {'spec': ObjectIdentifier}),
        ('max_offset', BigTime, {'explicit': 0, 'optional': True}),
        ('max_delay', BigTime, {'explicit': 1, 'optional': True}),
    ]


class SetOfTimingPolicy(SetOf):
    _child_spec = TimingPolicy


class AttCertAttributeType(ObjectIdentifier):
    _map = {
        '1.3.6.1.5.5.7.10.1': 'authentication_info',
        '1.3.6.1.5.5.7.10.2': 'access_identity',
        '1.3.6.1.5.5.7.10.3': 'charging_identity',
        '1.3.6.1.5.5.7.10.4': 'group',
        '2.5.4.72': 'role',
        '2.5.4.55': 'clearance',
        '1.3.6.1.4.1.601.10.4.1': 'timing_metrics',
        '1.3.6.1.4.1.601.10.4.2': 'timing_policy',
    }


class AttCertAttribute(Sequence):
    _fields = [
        ('type', AttCertAttributeType),
        ('values', None),
    ]

    _oid_specs = {
        'authentication_info': SetOfSvceAuthInfo,
        'access_identity': SetOfSvceAuthInfo,
        'charging_identity': SetOfIetfAttrSyntax,
        'group': SetOfIetfAttrSyntax,
        'role': SetOfRoleSyntax,
        'clearance': SetOfClearance,
        'timing_metrics': SetOfTimingMetrics,
        'timing_policy': SetOfTimingPolicy,
    }

    def _values_spec(self):
        return self._oid_specs.get(self['type'].native, SetOfAny)

    _spec_callbacks = {
        'values': _values_spec
    }


class AttCertAttributes(SequenceOf):
    _child_spec = AttCertAttribute


class AttributeCertificateInfoV2(Sequence):
    _fields = [
        ('version', AttCertVersion),
        ('holder', Holder),
        ('issuer', AttCertIssuer),
        ('signature', SignedDigestAlgorithm),
        ('serial_number', Integer),
        ('att_cert_validity_period', AttCertValidityPeriod),
        ('attributes', AttCertAttributes),
        ('issuer_unique_id', OctetBitString, {'optional': True}),
        ('extensions', Extensions, {'optional': True}),
    ]


class AttributeCertificateV2(Sequence):
    # Handle the situation where a V2 cert is encoded as V1
    _bad_tag = 1

    _fields = [
        ('ac_info', AttributeCertificateInfoV2),
        ('signature_algorithm', SignedDigestAlgorithm),
        ('signature', OctetBitString),
    ]


class OtherCertificateFormat(Sequence):
    _fields = [
        ('other_cert_format', ObjectIdentifier),
        ('other_cert', Any),
    ]


class CertificateChoices(Choice):
    _alternatives = [
        ('certificate', Certificate),
        ('extended_certificate', ExtendedCertificate, {'implicit': 0}),
        ('v1_attr_cert', AttributeCertificateV1, {'implicit': 1}),
        ('v2_attr_cert', AttributeCertificateV2, {'implicit': 2}),
        ('other', OtherCertificateFormat, {'implicit': 3}),
    ]

    def validate(self, class_, tag, contents):
        """
        Ensures that the class and tag specified exist as an alternative. This
        custom version fixes parsing broken encodings there a V2 attribute
        # certificate is encoded as a V1

        :param class_:
            The integer class_ from the encoded value header

        :param tag:
            The integer tag from the encoded value header

        :param contents:
            A byte string of the contents of the value - used when the object
            is explicitly tagged

        :raises:
            ValueError - when value is not a valid alternative
        """

        super(CertificateChoices, self).validate(class_, tag, contents)
        if self._choice == 2:
            if AttCertVersion.load(Sequence.load(contents)[0].dump()).native == 'v2':
                self._choice = 3


class CertificateSet(SetOf):
    _child_spec = CertificateChoices


class ContentInfo(Sequence):
    _fields = [
        ('content_type', ContentType),
        ('content', Any, {'explicit': 0, 'optional': True}),
    ]

    _oid_pair = ('content_type', 'content')
    _oid_specs = {}

    def recipient_selection(self, certificates):
        """
        Convenience wrapper around
        :meth:`EnvelopedData.recipient_selection` for a ContentInfo
        encapsulating enveloped data.

        :param certificates:
            An x509.Certificate object, or a list of them

        :return:
            A RecipientSelection object

        :raises:
            ValueError - when the encapsulated content is not enveloped data
        """

        content = self['content']
        if self['content_type'].native != 'enveloped_data' or \
                not isinstance(content, EnvelopedData):
            raise ValueError(unwrap(
                '''
                ContentInfo.recipient_selection() is only valid for content of
                type enveloped_data, not %s
                ''',
                self['content_type'].native
            ))

        return content.recipient_selection(certificates)


class SetOfContentInfo(SetOf):
    _child_spec = ContentInfo


class EncapsulatedContentInfo(Sequence):
    _fields = [
        ('content_type', ContentType),
        ('content', ParsableOctetString, {'explicit': 0, 'optional': True}),
    ]

    _oid_pair = ('content_type', 'content')
    _oid_specs = {}


class IssuerAndSerialNumber(Sequence):
    _fields = [
        ('issuer', Name),
        ('serial_number', Integer),
    ]


class SignerIdentifier(Choice):
    _alternatives = [
        ('issuer_and_serial_number', IssuerAndSerialNumber),
        ('subject_key_identifier', OctetString, {'implicit': 0}),
    ]


class DigestAlgorithms(SetOf):
    _child_spec = DigestAlgorithm


class CertificateRevocationLists(SetOf):
    _child_spec = CertificateList


class SCVPReqRes(Sequence):
    _fields = [
        ('request', ContentInfo, {'explicit': 0, 'optional': True}),
        ('response', ContentInfo),
    ]


class OtherRevInfoFormatId(ObjectIdentifier):
    _map = {
        '1.3.6.1.5.5.7.16.2': 'ocsp_response',
        '1.3.6.1.5.5.7.16.4': 'scvp',
    }


class OtherRevocationInfoFormat(Sequence):
    _fields = [
        ('other_rev_info_format', OtherRevInfoFormatId),
        ('other_rev_info', Any),
    ]

    _oid_pair = ('other_rev_info_format', 'other_rev_info')
    _oid_specs = {
        'ocsp_response': OCSPResponse,
        'scvp': SCVPReqRes,
    }


class RevocationInfoChoice(Choice):
    _alternatives = [
        ('crl', CertificateList),
        ('other', OtherRevocationInfoFormat, {'implicit': 1}),
    ]


class RevocationInfoChoices(SetOf):
    _child_spec = RevocationInfoChoice


class SignerInfo(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('sid', SignerIdentifier),
        ('digest_algorithm', DigestAlgorithm),
        ('signed_attrs', CMSAttributes, {'implicit': 0, 'optional': True}),
        ('signature_algorithm', SignedDigestAlgorithm),
        ('signature', OctetString),
        ('unsigned_attrs', CMSAttributes, {'implicit': 1, 'optional': True}),
    ]


class SignerInfos(SetOf):
    _child_spec = SignerInfo


class SignedData(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('digest_algorithms', DigestAlgorithms),
        ('encap_content_info', None),
        ('certificates', CertificateSet, {'implicit': 0, 'optional': True}),
        ('crls', RevocationInfoChoices, {'implicit': 1, 'optional': True}),
        ('signer_infos', SignerInfos),
    ]

    def _encap_content_info_spec(self):
        # If the encap_content_info is version v1, then this could be a PKCS#7
        # structure, or a CMS structure. CMS wraps the encoded value in an
        # Octet String tag.

        # If the version is greater than 1, it is definite CMS
        if self['version'].native != 'v1':
            return EncapsulatedContentInfo

        # Otherwise, the ContentInfo spec from PKCS#7 will be compatible with
        # CMS v1 (which only allows Data, an Octet String) and PKCS#7, which
        # allows Any
        return ContentInfo

    _spec_callbacks = {
        'encap_content_info': _encap_content_info_spec
    }


class OriginatorInfo(Sequence):
    _fields = [
        ('certs', CertificateSet, {'implicit': 0, 'optional': True}),
        ('crls', RevocationInfoChoices, {'implicit': 1, 'optional': True}),
    ]


class RecipientIdentifier(Choice):
    _alternatives = [
        ('issuer_and_serial_number', IssuerAndSerialNumber),
        ('subject_key_identifier', OctetString, {'implicit': 0}),
    ]


class KeyEncryptionAlgorithmId(ObjectIdentifier):
    _map = {
        '1.2.840.113549.1.1.1': 'rsaes_pkcs1v15',
        '1.2.840.113549.1.1.7': 'rsaes_oaep',
        '2.16.840.1.101.3.4.1.5': 'aes128_wrap',
        '2.16.840.1.101.3.4.1.8': 'aes128_wrap_pad',
        '2.16.840.1.101.3.4.1.25': 'aes192_wrap',
        '2.16.840.1.101.3.4.1.28': 'aes192_wrap_pad',
        '2.16.840.1.101.3.4.1.45': 'aes256_wrap',
        '2.16.840.1.101.3.4.1.48': 'aes256_wrap_pad',
    }

    _reverse_map = {
        'rsa': '1.2.840.113549.1.1.1',
        'rsaes_pkcs1v15': '1.2.840.113549.1.1.1',
        'rsaes_oaep': '1.2.840.113549.1.1.7',
        'aes128_wrap': '2.16.840.1.101.3.4.1.5',
        'aes128_wrap_pad': '2.16.840.1.101.3.4.1.8',
        'aes192_wrap': '2.16.840.1.101.3.4.1.25',
        'aes192_wrap_pad': '2.16.840.1.101.3.4.1.28',
        'aes256_wrap': '2.16.840.1.101.3.4.1.45',
        'aes256_wrap_pad': '2.16.840.1.101.3.4.1.48',
    }


class KeyEncryptionAlgorithm(_ForceNullParameters, Sequence):
    _fields = [
        ('algorithm', KeyEncryptionAlgorithmId),
        ('parameters', Any, {'optional': True}),
    ]

    _oid_pair = ('algorithm', 'parameters')
    _oid_specs = {
        'rsaes_oaep': RSAESOAEPParams,
    }


class KeyTransRecipientInfo(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('rid', RecipientIdentifier),
        ('key_encryption_algorithm', KeyEncryptionAlgorithm),
        ('encrypted_key', OctetString),
    ]


class OriginatorIdentifierOrKey(Choice):
    _alternatives = [
        ('issuer_and_serial_number', IssuerAndSerialNumber),
        ('subject_key_identifier', OctetString, {'implicit': 0}),
        ('originator_key', PublicKeyInfo, {'implicit': 1}),
    ]


class OtherKeyAttribute(Sequence):
    _fields = [
        ('key_attr_id', ObjectIdentifier),
        ('key_attr', Any),
    ]


class RecipientKeyIdentifier(Sequence):
    _fields = [
        ('subject_key_identifier', OctetString),
        ('date', GeneralizedTime, {'optional': True}),
        ('other', OtherKeyAttribute, {'optional': True}),
    ]

    def _setup(self):
        super(RecipientKeyIdentifier, self)._setup()
        # This creates a backwards compatible shim for an
        # incorrect format field name that was in old versions
        self._field_map['subjectKeyIdentifier'] = self._field_map['subject_key_identifier']


class KeyAgreementRecipientIdentifier(Choice):
    _alternatives = [
        ('issuer_and_serial_number', IssuerAndSerialNumber),
        ('r_key_id', RecipientKeyIdentifier, {'implicit': 0}),
    ]


class RecipientEncryptedKey(Sequence):
    _fields = [
        ('rid', KeyAgreementRecipientIdentifier),
        ('encrypted_key', OctetString),
    ]


class RecipientEncryptedKeys(SequenceOf):
    _child_spec = RecipientEncryptedKey


class KeyAgreeRecipientInfo(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('originator', OriginatorIdentifierOrKey, {'explicit': 0}),
        ('ukm', OctetString, {'explicit': 1, 'optional': True}),
        ('key_encryption_algorithm', KeyEncryptionAlgorithm),
        ('recipient_encrypted_keys', RecipientEncryptedKeys),
    ]


class KEKIdentifier(Sequence):
    _fields = [
        ('key_identifier', OctetString),
        ('date', GeneralizedTime, {'optional': True}),
        ('other', OtherKeyAttribute, {'optional': True}),
    ]


class KEKRecipientInfo(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('kekid', KEKIdentifier),
        ('key_encryption_algorithm', KeyEncryptionAlgorithm),
        ('encrypted_key', OctetString),
    ]


class PasswordRecipientInfo(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('key_derivation_algorithm', KdfAlgorithm, {'implicit': 0, 'optional': True}),
        ('key_encryption_algorithm', KeyEncryptionAlgorithm),
        ('encrypted_key', OctetString),
    ]


class OtherRecipientInfo(Sequence):
    _fields = [
        ('ori_type', ObjectIdentifier),
        ('ori_value', Any),
    ]


class RecipientInfo(Choice):
    _alternatives = [
        ('ktri', KeyTransRecipientInfo),
        ('kari', KeyAgreeRecipientInfo, {'implicit': 1}),
        ('kekri', KEKRecipientInfo, {'implicit': 2}),
        ('pwri', PasswordRecipientInfo, {'implicit': 3}),
        ('ori', OtherRecipientInfo, {'implicit': 4}),
    ]


class RecipientInfos(SetOf):
    _child_spec = RecipientInfo


class RecipientMatch(object):
    """
    A single recipient encrypted key that was matched to one of the local
    certificates while enumerating the RecipientInfo structures of a CMS
    EnvelopedData or AuthEnvelopedData value.

    A match only records *why* a recipient entry was selected - no private key
    material is ever referenced, and no decryption is attempted. The encrypted
    key bytes are retained so that a caller can perform the actual unwrap after
    inspecting :attr:`.status`.
    """

    #: The recipient entry used an IssuerAndSerialNumber identifier
    MATCH_ISSUER_AND_SERIAL = 'issuer_and_serial_number'
    #: The recipient entry used a SubjectKeyIdentifier identifier
    MATCH_SUBJECT_KEY_IDENTIFIER = 'subject_key_identifier'

    #: The entry can be acted upon with the matched certificate's private key
    STATUS_USABLE = 'usable'
    #: The key encryption algorithm OID is not known to asn1crypto
    STATUS_UNKNOWN_ALGORITHM = 'unknown_algorithm'
    #: The algorithm is known, but its parameters could not be parsed
    STATUS_UNSUPPORTED_PARAMETERS = 'unsupported_parameters'
    #: The certificate's key usage extension forbids the required operation
    STATUS_INVALID_KEY_USAGE = 'invalid_key_usage'

    def __init__(self, recipient_info_type, match_basis, certificate,
                 key_encryption_algorithm, encrypted_key, status,
                 reason=None, recipient_encrypted_key_index=None):
        self.recipient_info_type = recipient_info_type
        self.match_basis = match_basis
        self.certificate = certificate
        self.key_encryption_algorithm = key_encryption_algorithm
        self.encrypted_key = encrypted_key
        self.status = status
        self.reason = reason
        self.recipient_encrypted_key_index = recipient_encrypted_key_index

    def __repr__(self):
        return 'RecipientMatch(%s, %s, %s, %s)' % (
            self.recipient_info_type,
            self.match_basis,
            self.status,
            self.reason,
        )

    @property
    def usable(self):
        """
        :return:
            A boolean - if the match has status ``"usable"``
        """

        return self.status == self.STATUS_USABLE

    @property
    def identity_key(self):
        """
        A stable identifier of the certificate that matched, used to detect the
        same identity appearing in multiple recipient entries regardless of
        which identifier form selected it.

        :return:
            A byte string
        """

        return self.certificate.issuer_serial


class RecipientInfoCandidate(object):
    """
    The matches found inside a single top-level RecipientInfo. For a
    KeyTransRecipientInfo there is at most one :class:`RecipientMatch`; for a
    KeyAgreeRecipientInfo there is one match per relevant member of the
    RecipientEncryptedKeys sequence, preserving the layered ownership.
    """

    def __init__(self, recipient_info_type, recipient_info, matches):
        self.recipient_info_type = recipient_info_type
        self.recipient_info = recipient_info
        self.matches = matches

    def __repr__(self):
        return 'RecipientInfoCandidate(%s, %d match(es))' % (
            self.recipient_info_type,
            len(self.matches),
        )

    @property
    def statuses(self):
        """
        :return:
            A set of the distinct ``status`` values of the contained matches
        """

        return set([match.status for match in self.matches])

    @property
    def usable(self):
        """
        :return:
            A boolean - if every contained match is usable
        """

        return all(match.usable for match in self.matches)


class RecipientSelection(object):
    """
    The order-independent result of enumerating the recipient entries of an
    enveloped CMS structure against a set of local certificates. Only entries
    that refer to one of the local certificates produce
    :class:`RecipientInfoCandidate` objects, so an empty :attr:`.candidates`
    list means no recipient was addressed to this holder, which is a distinct
    outcome from an unsupported algorithm or invalid key usage.
    """

    #: No recipient entry referred to any local certificate
    STATUS_NO_MATCH = 'no_match'
    #: A single certificate is referenced by two or more different ciphertexts
    STATUS_AMBIGUOUS = 'ambiguous'
    #: At least one matching entry is usable and no ambiguity was detected
    STATUS_USABLE = 'usable'
    #: All matching entries are blocked by algorithm or key usage problems
    STATUS_UNSUPPORTED = 'unsupported'

    _problem_statuses = (
        RecipientMatch.STATUS_UNKNOWN_ALGORITHM,
        RecipientMatch.STATUS_UNSUPPORTED_PARAMETERS,
        RecipientMatch.STATUS_INVALID_KEY_USAGE,
    )

    def __init__(self, candidates, recipient_info_count, other_recipient_info_count):
        self.candidates = candidates
        self.recipient_info_count = recipient_info_count
        self.other_recipient_info_count = other_recipient_info_count

        ciphertexts_by_identity = {}
        for candidate in candidates:
            for match in candidate.matches:
                ciphertexts = ciphertexts_by_identity.setdefault(match.identity_key, set())
                ciphertexts.add(match.encrypted_key)

        self.ambiguous_identities = sorted([
            identity for identity, ciphertexts in ciphertexts_by_identity.items()
            if len(ciphertexts) > 1
        ])

        all_statuses = set()
        for candidate in candidates:
            all_statuses.update(candidate.statuses)

        if not candidates:
            self.status = self.STATUS_NO_MATCH
        elif self.ambiguous_identities:
            self.status = self.STATUS_AMBIGUOUS
        elif RecipientMatch.STATUS_USABLE in all_statuses:
            self.status = self.STATUS_USABLE
        else:
            self.status = self.STATUS_UNSUPPORTED

        self.reasons = sorted(all_statuses.intersection(self._problem_statuses))

    def __repr__(self):
        return 'RecipientSelection(%s, %d candidate(s))' % (
            self.status,
            len(self.candidates),
        )

    @property
    def usable_matches(self):
        """
        :return:
            A list of every usable :class:`RecipientMatch`, in the same
            order as :attr:`.candidates`
        """

        return [
            match
            for candidate in self.candidates
            for match in candidate.matches
            if match.usable
        ]


def _certificate_ski(certificate):
    """
    :param certificate:
        An x509.Certificate object

    :return:
        None or a byte string of the certificate's subject key identifier
    """

    return certificate.key_identifier


def _certificate_matches_issuer_serial(certificate, issuer_and_serial):
    """
    Compares a certificate against an IssuerAndSerialNumber value using the
    RFC 5280 name comparison rules.

    :param certificate:
        An x509.Certificate object

    :param issuer_and_serial:
        An IssuerAndSerialNumber object

    :return:
        A boolean
    """

    return (
        certificate.issuer == issuer_and_serial['issuer']
        and certificate.serial_number == issuer_and_serial['serial_number'].native
    )


def _certificate_matches_ski(certificate, subject_key_identifier):
    """
    :param certificate:
        An x509.Certificate object

    :param subject_key_identifier:
        A byte string of the subject key identifier from a recipient entry

    :return:
        A boolean
    """

    certificate_ski = _certificate_ski(certificate)
    return certificate_ski is not None and certificate_ski == subject_key_identifier


def _key_usage_allows(certificate, required_usage):
    """
    Checks the key usage extension of a certificate. A certificate without a
    key usage extension is unrestricted. When the extension is present, the
    required usage bit (``"key_encipherment"`` for key transport,
    ``"key_agreement"`` for key agreement) must be asserted.

    :param certificate:
        An x509.Certificate object

    :param required_usage:
        A unicode string from x509.KeyUsage._map

    :return:
        A boolean
    """

    key_usage = certificate.key_usage_value
    if key_usage is None:
        return True
    return required_usage in key_usage.native


def _algorithm_support(key_encryption_algorithm):
    """
    Determines whether the key encryption algorithm of a recipient entry is one
    asn1crypto can describe. The OID must be registered on
    KeyEncryptionAlgorithmId and, when parameters are present, they must parse
    against the registered parameter specification.

    :param key_encryption_algorithm:
        A KeyEncryptionAlgorithm object

    :return:
        A tuple of (status unicode string or None when supported, reason
        unicode string or None)
    """

    algorithm_id = key_encryption_algorithm['algorithm']
    if algorithm_id.dotted not in KeyEncryptionAlgorithmId._map:
        return (
            RecipientMatch.STATUS_UNKNOWN_ALGORITHM,
            algorithm_id.dotted
        )

    try:
        parameters = key_encryption_algorithm['parameters']
        if isinstance(parameters, (Void, Null)):
            return (None, None)

        if isinstance(parameters, Any):
            parameters.parsed
    except (ValueError, TypeError) as e:
        return (
            RecipientMatch.STATUS_UNSUPPORTED_PARAMETERS,
            e.args[0] if e.args else algorithm_id.native
        )

    return (None, None)


def _match_status(certificate, key_encryption_algorithm, required_usage):
    """
    Combines the algorithm support and key usage checks into a single status.

    :param certificate:
        An x509.Certificate object

    :param key_encryption_algorithm:
        A KeyEncryptionAlgorithm object

    :param required_usage:
        A unicode string from x509.KeyUsage._map

    :return:
        A tuple of (status unicode string, reason unicode string or None)
    """

    status, reason = _algorithm_support(key_encryption_algorithm)
    if status is not None:
        return status, reason

    if not _key_usage_allows(certificate, required_usage):
        return RecipientMatch.STATUS_INVALID_KEY_USAGE, required_usage

    return RecipientMatch.STATUS_USABLE, None


def _match_key_trans_recipient(recipient_info, certificates):
    """
    Enumerates the local certificates selected by a KeyTransRecipientInfo.

    :param recipient_info:
        A KeyTransRecipientInfo object

    :param certificates:
        A list of x509.Certificate objects

    :return:
        A list of RecipientMatch objects
    """

    identifier = recipient_info['rid']
    identifier_name = identifier.name
    key_encryption_algorithm = recipient_info['key_encryption_algorithm']
    encrypted_key = recipient_info['encrypted_key'].native

    matches = []
    for certificate in certificates:
        if identifier_name == 'issuer_and_serial_number':
            if not _certificate_matches_issuer_serial(certificate, identifier.chosen):
                continue
            match_basis = RecipientMatch.MATCH_ISSUER_AND_SERIAL
        else:
            if not _certificate_matches_ski(certificate, identifier.chosen.native):
                continue
            match_basis = RecipientMatch.MATCH_SUBJECT_KEY_IDENTIFIER

        status, reason = _match_status(
            certificate,
            key_encryption_algorithm,
            'key_encipherment'
        )
        matches.append(RecipientMatch(
            recipient_info_type='ktri',
            match_basis=match_basis,
            certificate=certificate,
            key_encryption_algorithm=key_encryption_algorithm,
            encrypted_key=encrypted_key,
            status=status,
            reason=reason,
        ))

    return matches


def _match_key_agreement_recipient(recipient_info, certificates):
    """
    Enumerates, per member of the RecipientEncryptedKeys sequence, the local
    certificates selected by a KeyAgreeRecipientInfo. Each member keeps its
    structural index so the layered ownership of the encrypted keys inside the
    single recipient entry is preserved.

    :param recipient_info:
        A KeyAgreeRecipientInfo object

    :param certificates:
        A list of x509.Certificate objects

    :return:
        A list of RecipientMatch objects
    """

    key_encryption_algorithm = recipient_info['key_encryption_algorithm']

    matches = []
    for index, recipient_encrypted_key in enumerate(
        recipient_info['recipient_encrypted_keys']
    ):
        identifier = recipient_encrypted_key['rid']
        identifier_name = identifier.name
        encrypted_key = recipient_encrypted_key['encrypted_key'].native

        for certificate in certificates:
            if identifier_name == 'issuer_and_serial_number':
                if not _certificate_matches_issuer_serial(certificate, identifier.chosen):
                    continue
                match_basis = RecipientMatch.MATCH_ISSUER_AND_SERIAL
            else:
                subject_key_identifier = \
                    identifier.chosen['subject_key_identifier'].native
                if not _certificate_matches_ski(certificate, subject_key_identifier):
                    continue
                match_basis = RecipientMatch.MATCH_SUBJECT_KEY_IDENTIFIER

            status, reason = _match_status(
                certificate,
                key_encryption_algorithm,
                'key_agreement'
            )
            matches.append(RecipientMatch(
                recipient_info_type='kari',
                match_basis=match_basis,
                certificate=certificate,
                key_encryption_algorithm=key_encryption_algorithm,
                encrypted_key=encrypted_key,
                status=status,
                reason=reason,
                recipient_encrypted_key_index=index,
            ))

    return matches


def _normalize_certificates(certificates):
    """
    Validates the certificates argument of recipient_selection() and always
    returns a list.

    :param certificates:
        An x509.Certificate object, or a list of them

    :return:
        A list of x509.Certificate objects

    :raises:
        TypeError - when any entry is not an x509.Certificate
    """

    if isinstance(certificates, Certificate):
        certificates = [certificates]
    else:
        certificates = list(certificates)

    for certificate in certificates:
        if not isinstance(certificate, Certificate):
            raise TypeError(unwrap(
                '''
                certificates must be an x509.Certificate or a list of
                x509.Certificate objects, not %s
                ''',
                type(certificate).__name__
            ))

    return certificates


def _enumerate_recipient_candidates(recipient_infos, certificates):
    """
    Walks every RecipientInfo and retains one RecipientInfoCandidate for each
    entry that selects at least one local certificate. Candidates are sorted on
    content-derived keys so the result does not depend on the encoding order of
    the RecipientInfos SET.

    :param recipient_infos:
        A RecipientInfos object

    :param certificates:
        A list of x509.Certificate objects

    :return:
        A tuple of (candidates list, ktri/kari count, other entry count)
    """

    candidates = []
    recipient_info_count = 0
    other_recipient_info_count = 0

    for recipient_info in recipient_infos:
        recipient_info_name = recipient_info.name

        if recipient_info_name == 'ktri':
            recipient_info_count += 1
            matches = _match_key_trans_recipient(recipient_info.chosen, certificates)
        elif recipient_info_name == 'kari':
            recipient_info_count += 1
            matches = _match_key_agreement_recipient(recipient_info.chosen, certificates)
        else:
            # KEK, password and other recipient infos are never certificate
            # based, so they can never select a local certificate.
            other_recipient_info_count += 1
            continue

        if not matches:
            continue

        candidate = RecipientInfoCandidate(
            recipient_info_type=recipient_info_name,
            recipient_info=recipient_info.chosen,
            matches=matches,
        )
        candidates.append((recipient_info.chosen.dump(), candidate))

    candidates.sort(key=lambda item: item[0])
    return (
        [candidate for _, candidate in candidates],
        recipient_info_count,
        other_recipient_info_count,
    )


class EncryptedContentInfo(Sequence):
    _fields = [
        ('content_type', ContentType),
        ('content_encryption_algorithm', EncryptionAlgorithm),
        ('encrypted_content', OctetString, {'implicit': 0, 'optional': True}),
    ]


class EnvelopedData(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('originator_info', OriginatorInfo, {'implicit': 0, 'optional': True}),
        ('recipient_infos', RecipientInfos),
        ('encrypted_content_info', EncryptedContentInfo),
        ('unprotected_attrs', CMSAttributes, {'implicit': 1, 'optional': True}),
    ]

    def recipient_selection(self, certificates):
        """
        Enumerates the recipient entries against one or more local
        certificates and returns the full set of matches with the reason each
        entry was selected. No private key is used and no decryption is
        attempted, so the result is safe to inspect before touching any key
        material.

        Both IssuerAndSerialNumber and SubjectKeyIdentifier identifiers are
        supported. For KeyAgreeRecipientInfo, every member of the
        RecipientEncryptedKeys sequence is evaluated separately and keeps its
        position inside the parent entry. The returned candidates are ordered
        independently of the encoding order of the RecipientInfos SET.

        :param certificates:
            An x509.Certificate object, or a list of them, representing the
            local credentials that recipient entries may address

        :return:
            A RecipientSelection object. Its ``status`` attribute distinguishes
            ``"no_match"``, ``"ambiguous"`` (one identity with multiple
            different ciphertexts), ``"usable"`` and ``"unsupported"`` (the
            matches are blocked by an unknown algorithm, unparseable
            parameters or an unsuitable certificate key usage)
        """

        certificates = _normalize_certificates(certificates)

        candidates, recipient_info_count, other_recipient_info_count = \
            _enumerate_recipient_candidates(self['recipient_infos'], certificates)

        return RecipientSelection(
            candidates=candidates,
            recipient_info_count=recipient_info_count,
            other_recipient_info_count=other_recipient_info_count,
        )


class SignedAndEnvelopedData(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('recipient_infos', RecipientInfos),
        ('digest_algorithms', DigestAlgorithms),
        ('encrypted_content_info', EncryptedContentInfo),
        ('certificates', CertificateSet, {'implicit': 0, 'optional': True}),
        ('crls', CertificateRevocationLists, {'implicit': 1, 'optional': True}),
        ('signer_infos', SignerInfos),
    ]


class DigestedData(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('digest_algorithm', DigestAlgorithm),
        ('encap_content_info', None),
        ('digest', OctetString),
    ]

    def _encap_content_info_spec(self):
        # If the encap_content_info is version v1, then this could be a PKCS#7
        # structure, or a CMS structure. CMS wraps the encoded value in an
        # Octet String tag.

        # If the version is greater than 1, it is definite CMS
        if self['version'].native != 'v1':
            return EncapsulatedContentInfo

        # Otherwise, the ContentInfo spec from PKCS#7 will be compatible with
        # CMS v1 (which only allows Data, an Octet String) and PKCS#7, which
        # allows Any
        return ContentInfo

    _spec_callbacks = {
        'encap_content_info': _encap_content_info_spec
    }


class EncryptedData(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('encrypted_content_info', EncryptedContentInfo),
        ('unprotected_attrs', CMSAttributes, {'implicit': 1, 'optional': True}),
    ]


class AuthenticatedData(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('originator_info', OriginatorInfo, {'implicit': 0, 'optional': True}),
        ('recipient_infos', RecipientInfos),
        ('mac_algorithm', HmacAlgorithm),
        ('digest_algorithm', DigestAlgorithm, {'implicit': 1, 'optional': True}),
        # This does not require the _spec_callbacks approach of SignedData and
        # DigestedData since AuthenticatedData was not part of PKCS#7
        ('encap_content_info', EncapsulatedContentInfo),
        ('auth_attrs', CMSAttributes, {'implicit': 2, 'optional': True}),
        ('mac', OctetString),
        ('unauth_attrs', CMSAttributes, {'implicit': 3, 'optional': True}),
    ]


class AuthEnvelopedData(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('originator_info', OriginatorInfo, {'implicit': 0, 'optional': True}),
        ('recipient_infos', RecipientInfos),
        ('auth_encrypted_content_info', EncryptedContentInfo),
        ('auth_attrs', CMSAttributes, {'implicit': 1, 'optional': True}),
        ('mac', OctetString),
        ('unauth_attrs', CMSAttributes, {'implicit': 2, 'optional': True}),
    ]

    def recipient_selection(self, certificates):
        """
        Enumerates the recipient entries of authenticated enveloped data -
        behaves identically to
        :meth:`EnvelopedData.recipient_selection`.

        :param certificates:
            An x509.Certificate object, or a list of them

        :return:
            A RecipientSelection object
        """

        certificates = _normalize_certificates(certificates)

        candidates, recipient_info_count, other_recipient_info_count = \
            _enumerate_recipient_candidates(self['recipient_infos'], certificates)

        return RecipientSelection(
            candidates=candidates,
            recipient_info_count=recipient_info_count,
            other_recipient_info_count=other_recipient_info_count,
        )


class CompressionAlgorithmId(ObjectIdentifier):
    _map = {
        '1.2.840.113549.1.9.16.3.8': 'zlib',
    }


class CompressionAlgorithm(Sequence):
    _fields = [
        ('algorithm', CompressionAlgorithmId),
        ('parameters', Any, {'optional': True}),
    ]


class CompressedData(Sequence):
    _fields = [
        ('version', CMSVersion),
        ('compression_algorithm', CompressionAlgorithm),
        ('encap_content_info', EncapsulatedContentInfo),
    ]

    _decompressed = None

    @property
    def decompressed(self):
        if self._decompressed is None:
            if zlib is None:
                raise SystemError('The zlib module is not available')
            self._decompressed = zlib.decompress(self['encap_content_info']['content'].native)
        return self._decompressed


class SMIMEEncryptionKeyPreference(Choice):
    _alternatives = [
        ('issuer_and_serial_number', IssuerAndSerialNumber, {'implicit': 0}),
        ('recipient_key_id', RecipientKeyIdentifier, {'implicit': 1}),
        ('subject_alt_key_identifier', PublicKeyInfo, {'implicit': 2}),
    ]

    def _setup(self):
        super(SMIMEEncryptionKeyPreference, self)._setup()
        # This creates backwards compatible shims for two
        # incorrect format alternative names that were in old versions
        self._name_map['recipientKeyId'] = self._name_map['recipient_key_id']
        self._name_map['subjectAltKeyIdentifier'] = self._name_map['subject_alt_key_identifier']


class SMIMEEncryptionKeyPreferences(SetOf):
    _child_spec = SMIMEEncryptionKeyPreference


class SMIMECapabilityIdentifier(Sequence):
    _fields = [
        ('capability_id', EncryptionAlgorithmId),
        ('parameters', Any, {'optional': True}),
    ]


class SMIMECapabilites(SequenceOf):
    _child_spec = SMIMECapabilityIdentifier


class SetOfSMIMECapabilites(SetOf):
    _child_spec = SMIMECapabilites


ContentInfo._oid_specs = {
    'data': OctetString,
    'signed_data': SignedData,
    'enveloped_data': EnvelopedData,
    'signed_and_enveloped_data': SignedAndEnvelopedData,
    'digested_data': DigestedData,
    'encrypted_data': EncryptedData,
    'authenticated_data': AuthenticatedData,
    'compressed_data': CompressedData,
    'authenticated_enveloped_data': AuthEnvelopedData,
}


EncapsulatedContentInfo._oid_specs = {
    'signed_data': SignedData,
    'enveloped_data': EnvelopedData,
    'signed_and_enveloped_data': SignedAndEnvelopedData,
    'digested_data': DigestedData,
    'encrypted_data': EncryptedData,
    'authenticated_data': AuthenticatedData,
    'compressed_data': CompressedData,
    'authenticated_enveloped_data': AuthEnvelopedData,
}


CMSAttribute._oid_specs = {
    'content_type': SetOfContentType,
    'message_digest': SetOfOctetString,
    'signing_time': SetOfTime,
    'counter_signature': SignerInfos,
    'signature_time_stamp_token': SetOfContentInfo,
    'cms_algorithm_protection': SetOfCMSAlgorithmProtection,
    'microsoft_nested_signature': SetOfContentInfo,
    'microsoft_time_stamp_token': SetOfContentInfo,
    'encrypt_key_pref': SMIMEEncryptionKeyPreferences,
    'smime_capabilities': SetOfSMIMECapabilites,
}
