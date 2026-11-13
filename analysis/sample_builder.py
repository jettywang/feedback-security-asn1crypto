# coding: utf-8
"""
Builds small, synthetic PKCS#12 evidence samples for tests and demonstrations.

The samples are fully decrypted PKCS#12 structures assembled with asn1crypto's
own ASN.1 types. The private values are toy RSA components used only to derive
public material; no real secret is embedded and no password cracking is
involved.

Two scenarios are produced:

 - name_collision: two different public keys share a friendlyName and a
   certificate subject, while a key/certificate pair exists only through
   matching public key material
 - missing_local_key_id: a genuine key/certificate pair has no localKeyId on
   either side, but its public keys match exactly
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import os

from asn1crypto import algos, cms, core, keys, pkcs12, x509


TOY_KEYS = {
    'alpha': {
        'p': 61,
        'q': 53,
        'e': 17,
        'serial': 0x1001,
        'friendly_name': 'Collision Identity',
    },
    'beta': {
        'p': 41,
        'q': 79,
        'e': 17,
        'serial': 0x1002,
        'friendly_name': 'Collision Identity',
    },
    'gamma': {
        'p': 61,
        'q': 89,
        'e': 17,
        'serial': 0x2001,
        'friendly_name': 'No Local Key Id',
    },
}

_SUBJECT = {
    'common_name': 'Collision Identity',
    'organization_name': 'Evidence Lab',
}


def build_samples(directory):
    """
    Writes the two sample PFX files into directory.

    :param directory:
        A filesystem directory that will be created if needed

    :return:
        A dict of the generated paths keyed by sample name
    """

    if not os.path.exists(directory):
        os.makedirs(directory)
    paths = {}
    name_collision = build_name_collision()
    missing_local_key_id = build_missing_local_key_id()
    paths['name_collision'] = os.path.join(directory, 'name-collision.p12')
    paths['missing_local_key_id'] = os.path.join(directory, 'missing-local-key-id.p12')
    with open(paths['name_collision'], 'wb') as handle:
        handle.write(name_collision)
    with open(paths['missing_local_key_id'], 'wb') as handle:
        handle.write(missing_local_key_id)
    return paths


def build_name_collision():
    """
    Returns a PKCS#12 byte string where a certificate and a key share a
    friendlyName and subject but have different public key material, and a
    second certificate shares the public key material of the key.
    """

    alpha = _key_bag('alpha', local_key_id=b'\xAA' * 20, friendly_name='Collision Identity')
    beta_cert = _certificate_bag('beta', local_key_id=b'\xCC' * 20, friendly_name='Collision Identity')
    alpha_cert = _certificate_bag('alpha', local_key_id=b'\xAA' * 20, friendly_name='Collision Identity')
    contents = pkcs12.SafeContents([alpha, beta_cert, alpha_cert])
    return _pfx_from_contents(contents)


def build_missing_local_key_id():
    """
    Returns a PKCS#12 byte string where the key and certificate match by public
    key material but neither carries a localKeyId attribute.
    """

    gamma_key = _key_bag('gamma', None, 'No Local Key Id')
    gamma_cert = _certificate_bag('gamma', None, 'No Local Key Id')
    contents = pkcs12.SafeContents([gamma_key, gamma_cert])
    return _pfx_from_contents(contents)


def _pfx_from_contents(contents, mac=False):
    authenticated_safe = pkcs12.AuthenticatedSafe([
        cms.ContentInfo({
            'content_type': 'data',
            'content': core.OctetString(contents.dump()),
        }),
    ])
    pfx = pkcs12.Pfx({
        'version': 'v3',
        'auth_safe': cms.ContentInfo({
            'content_type': 'data',
            'content': core.OctetString(authenticated_safe.dump()),
        }),
    })
    return pfx.dump()


def _toy_private_key(name):
    spec = TOY_KEYS[name]
    p = spec['p']
    q = spec['q']
    e = spec['e']
    n = p * q
    phi = (p - 1) * (q - 1)
    d = _mod_inverse(e, phi)
    return keys.PrivateKeyInfo.wrap(keys.RSAPrivateKey({
        'version': 'two-prime',
        'modulus': core.Integer(n),
        'public_exponent': core.Integer(e),
        'private_exponent': core.Integer(d),
        'prime1': core.Integer(p),
        'prime2': core.Integer(q),
        'exponent1': core.Integer(d % (p - 1)),
        'exponent2': core.Integer(d % (q - 1)),
        'coefficient': core.Integer(_mod_inverse(q, p)),
    }), 'rsa')


def _toy_public_key(name):
    spec = TOY_KEYS[name]
    p = spec['p']
    q = spec['q']
    return keys.PublicKeyInfo.wrap(keys.RSAPublicKey({
        'modulus': core.Integer(p * q),
        'public_exponent': core.Integer(spec['e']),
    }), 'rsa')


def _certificate(name):
    public_key = _toy_public_key(name)
    subject = x509.Name.build(_SUBJECT)
    signature_algorithm = algos.SignedDigestAlgorithm({'algorithm': 'sha256_rsa'})
    tbs = x509.TbsCertificate({
        'version': 'v3',
        'serial_number': core.Integer(TOY_KEYS[name]['serial']),
        'signature': signature_algorithm,
        'issuer': subject,
        'validity': x509.Validity({
            'not_before': x509.Time(name='utc_time', value=core.UTCTime('2026-01-01T00:00:00Z')),
            'not_after': x509.Time(name='utc_time', value=core.UTCTime('2027-01-01T00:00:00Z')),
        }),
        'subject': subject,
        'subject_public_key_info': public_key,
    })
    return x509.Certificate({
        'tbs_certificate': tbs,
        'signature_algorithm': signature_algorithm,
        'signature_value': core.OctetBitString(b'\x00' * 16),
    })


def _key_bag(name, local_key_id, friendly_name):
    return _key_bag_from_value(_toy_private_key(name), local_key_id, friendly_name)


def _key_bag_from_value(private_key, local_key_id, friendly_name=None):
    attributes = []
    if local_key_id is not None:
        attributes.append(pkcs12.Attribute({
            'type': 'local_key_id',
            'values': [core.OctetString(local_key_id)],
        }))
    if friendly_name is not None:
        attributes.append(pkcs12.Attribute({
            'type': 'friendly_name',
            'values': [core.BMPString(friendly_name)],
        }))
    bag = {
        'bag_id': 'key_bag',
        'bag_value': private_key,
    }
    if attributes:
        bag['bag_attributes'] = pkcs12.Attributes(attributes)
    return pkcs12.SafeBag(bag)


def _certificate_bag(name, local_key_id, friendly_name):
    return _certificate_bag_from_value(_certificate(name), local_key_id, friendly_name)


def _certificate_bag_from_value(certificate, local_key_id, friendly_name=None):
    attributes = []
    if local_key_id is not None:
        attributes.append(pkcs12.Attribute({
            'type': 'local_key_id',
            'values': [core.OctetString(local_key_id)],
        }))
    if friendly_name is not None:
        attributes.append(pkcs12.Attribute({
            'type': 'friendly_name',
            'values': [core.BMPString(friendly_name)],
        }))
    bag = {
        'bag_id': 'cert_bag',
        'bag_value': pkcs12.CertBag({
            'cert_id': 'x509',
            'cert_value': core.ParsableOctetString(certificate.dump()),
        }),
    }
    if attributes:
        bag['bag_attributes'] = pkcs12.Attributes(attributes)
    return pkcs12.SafeBag(bag)


def _mod_inverse(value, modulus):
    original_modulus = modulus
    x0, x1 = 0, 1
    while value > 1:
        quotient = value // modulus
        value, modulus = modulus, value - quotient * modulus
        x0, x1 = x1, x0 - quotient * x1
    return x0 % original_modulus
