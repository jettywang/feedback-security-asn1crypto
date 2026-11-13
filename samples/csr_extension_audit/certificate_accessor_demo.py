# coding: utf-8
"""
Show that x509.Certificate convenience accessors share the same last-wins
behavior. _set_extensions() loops over the extensions and does setattr() for
each known name; duplicate extnIDs therefore collapse silently and the accessor
returns whichever occurrence was encoded last.

A backend must not assume "the library raised" just because the data ended up
inside a Certificate instead of a CSR.
"""
from __future__ import print_function

from asn1crypto import core, keys, x509

from build_samples import bc_extension, san_extension


def main():
    tbs = x509.TbsCertificate({
        'version': 'v3',
        'serial_number': 1,
        'signature': {'algorithm': 'sha256_rsa'},
        'issuer': x509.Name.build({'common_name': 'demo-ca'}),
        'validity': {
            'not_before': x509.Time(name='general_time',
                                    value='20260101000000Z'),
            'not_after': x509.Time(name='general_time',
                                   value='20270101000000Z'),
        },
        'subject': x509.Name.build({'common_name': 'conflict.example'}),
        'subject_public_key_info': {
            'algorithm': {'algorithm': 'rsa'},
            'public_key': keys.RSAPublicKey(
                {'modulus': 1, 'public_exponent': 65537}
            ),
        },
        'extensions': x509.Extensions([
            bc_extension(ca=False, critical=True),
            san_extension(['safe.example'], critical=False),
            bc_extension(ca=True, path_len=2, critical=False),
            san_extension(['evil.example'], critical=True),
        ]),
    })
    cert = x509.Certificate({
        'tbs_certificate': tbs,
        'signature_algorithm': {'algorithm': 'sha256_rsa'},
        'signature_value': core.OctetBitString(b'\x00'),
    })

    print('encoded extension count       :', len(tbs['extensions']))
    print('basic_constraints_value.ca    :',
          cert.basic_constraints_value['ca'].native)
    print('basic_constraints path_len    :',
          cert.basic_constraints_value['path_len_constraint'].native)
    san = cert.subject_alt_name_value
    print('subject_alt_name_value        :', [g.native for g in san])
    print('critical_extensions           :', sorted(cert.critical_extensions))
    print('-> first, constrained leaf claim is gone; last claim wins silently')


if __name__ == '__main__':
    main()
