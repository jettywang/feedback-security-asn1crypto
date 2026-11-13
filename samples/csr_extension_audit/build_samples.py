# coding: utf-8
"""
Build PKCS#10 CSRs that contain ambiguous extensionRequest attribute layouts.

Every CSR is built from plain asn1crypto data structures and then signed with a
local RSA key through the OpenSSL CLI, so the generated requests are real,
self-signature-valid PKCS#10 objects rather than hand-fuzzed DER.

Scenarios (see README.md for the full matrix):
  01_baseline_wellformed     - one attribute, one value, unique extnIDs (control)
  02_dup_attribute           - two separate extensionRequest attributes
  03_multi_value             - one attribute whose SET holds TWO Extensions values
  04_dup_extnid              - one Extensions SEQUENCE containing the same OID twice
  05_ms_and_standard         - MS enrollment attributes + standard extensionRequest,
                               and the standard request carries conflicting CA/SAN data
  06_unknown_critical        - a critical extension at an OID the parser does not know

Usage:
    python build_samples.py [output_dir]
"""
from __future__ import unicode_literals, print_function

import json
import os
import subprocess
import sys
import tempfile

from asn1crypto import algos, core, csr, keys, pem, x509

EXTENSION_REQUEST_OID = '1.2.840.113549.1.9.14'
UNKNOWN_OID = '1.3.6.1.4.1.99999.7.1'  # private arc, intentionally unmapped


def run(cmd):
    proc = subprocess.run(cmd, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError('%s failed: %s' % (cmd[0], proc.stderr.decode()))
    return proc.stdout


def make_key(out_dir, name='ca-demo-rsa.key'):
    """Generate a 2048-bit RSA key and return (key_path, PublicKeyInfo)."""
    key_path = os.path.join(out_dir, name)
    run([
        'openssl', 'genpkey', '-algorithm', 'RSA',
        '-pkeyopt', 'rsa_keygen_bits:2048', '-out', key_path,
    ])
    pub_der = run(['openssl', 'pkey', '-in', key_path, '-pubout', '-outform', 'DER'])
    return key_path, keys.PublicKeyInfo.load(pub_der)


def sign_cri(key_path, cri_der):
    """SHA-256 with RSA (PKCS#1 v1.5) over the DER of CertificationRequestInfo."""
    work = tempfile.mkdtemp()
    tbs_path = os.path.join(work, 'cri.der')
    sig_path = os.path.join(work, 'sig.bin')
    with open(tbs_path, 'wb') as f:
        f.write(cri_der)
    run([
        'openssl', 'pkeyutl', '-sign', '-inkey', key_path,
        '-rawin', '-digest', 'sha256', '-in', tbs_path, '-out', sig_path,
    ])
    with open(sig_path, 'rb') as f:
        return f.read()


def extension(extn_id, critical, parsed=None, raw=None):
    """Build an x509.Extension; parsed objects or raw extnValue bytes are allowed."""
    if parsed is not None:
        extn_value = core.ParsableOctetString(parsed=parsed)
    else:
        extn_value = core.ParsableOctetString(raw)
    return x509.Extension({
        'extn_id': extn_id,
        'critical': critical,
        'extn_value': extn_value,
    })


def bc_extension(ca, path_len=None, critical=True):
    kwargs = {'ca': ca}
    if path_len is not None:
        kwargs['path_len_constraint'] = path_len
    return extension('basic_constraints', critical, parsed=x509.BasicConstraints(kwargs))


def san_extension(dns_names, critical=False):
    general_names = x509.GeneralNames(
        [x509.GeneralName(name='dns_name', value=name) for name in dns_names]
    )
    return extension('subject_alt_name', critical, parsed=general_names)


def eku_extension(eku_names, critical=False):
    return extension(
        'extended_key_usage', critical,
        parsed=x509.ExtKeyUsageSyntax(list(eku_names)),
    )


def extension_request_attribute(extensions_list):
    """One CRIAttribute of type extensionRequest holding one Extensions value."""
    return csr.CRIAttribute({
        'type': 'extension_request',
        'values': csr.SetOfExtensions([x509.Extensions(extensions_list)]),
    })


def ms_csp_attribute():
    return csr.CRIAttribute({
        'type': 'microsoft_enrollment_csp_provider',
        'values': csr.SetOfMicrosoftEnrollmentCSProvider([
            csr.MicrosoftEnrollmentCSProvider({
                'keyspec': 1,
                'cspname': core.BMPString('Microsoft RSA SChannel Cryptographic Provider'),
                'signature': core.BitString(()),
            })
        ]),
    })


def ms_client_info_attribute():
    return csr.CRIAttribute({
        'type': 'microsoft_request_client_info',
        'values': csr.SetOfMicrosoftRequestClientInfo([
            csr.MicrosoftRequestClientInfo({
                'clientid': 5,
                'machinename': 'windows.host.example.net',
                'username': 'locuser',
                'processname': 'MMC.EXE',
            })
        ]),
    })


def ms_os_version_attribute():
    return csr.CRIAttribute({
        'type': 'microsoft_os_version',
        'values': csr.SetOfDirectoryString([
            x509.DirectoryString(name='utf8_string', value='6.2.9200.2')
        ]),
    })


def build_csr(out_dir, base_name, spki, key_path, attributes, subject_cn):
    cri = csr.CertificationRequestInfo({
        'version': 'v1',
        'subject': x509.Name.build({'common_name': subject_cn}),
        'subject_pk_info': spki,
        'attributes': csr.CRIAttributes(attributes),
    })
    signature = sign_cri(key_path, cri.dump())
    request = csr.CertificationRequest({
        'certification_request_info': cri,
        'signature_algorithm': algos.SignedDigestAlgorithm({'algorithm': 'sha256_rsa'}),
        'signature': core.OctetBitString(signature),
    })
    der_bytes = request.dump()
    der_path = os.path.join(out_dir, base_name + '.der')
    pem_path = os.path.join(out_dir, base_name + '.pem')
    with open(der_path, 'wb') as f:
        f.write(der_bytes)
    with open(pem_path, 'wb') as f:
        f.write(pem.armor('CERTIFICATE REQUEST', der_bytes))
    return der_path, pem_path, der_bytes


def scenarios():
    """Return ordered (base_name, description, attribute_factory_args)."""
    return [
        (
            '01_baseline_wellformed',
            'control: single extensionRequest, single value, unique OIDs',
            'single',
        ),
        (
            '02_dup_attribute',
            'two sibling extensionRequest attributes make conflicting claims',
            'dup_attribute',
        ),
        (
            '03_multi_value',
            'one extensionRequest attribute whose SET contains two Extensions values',
            'multi_value',
        ),
        (
            '04_dup_extnid',
            'one Extensions value repeats basicConstraints and subjectAltName',
            'dup_extnid',
        ),
        (
            '05_ms_and_standard',
            'Microsoft enrollment attributes plus a standard extensionRequest',
            'ms_and_standard',
        ),
        (
            '06_unknown_critical',
            'critical extension at an OID absent from ExtensionId._map',
            'unknown_critical',
        ),
    ]


def build_all(out_dir):
    key_path, spki = make_key(out_dir)
    manifest = []

    # 01 baseline: harmless leaf-style request
    baseline_attrs = [
        extension_request_attribute([
            bc_extension(ca=False, critical=True),
            san_extension(['baseline.example'], critical=False),
        ])
    ]

    # 02 two extensionRequest attributes: first asks for a leaf SAN only,
    #    second asks for CA=true and a different SAN. Both are signed in one CSR.
    dup_attrs = [
        extension_request_attribute([
            bc_extension(ca=False, critical=True),
            san_extension(['public.example'], critical=False),
        ]),
        extension_request_attribute([
            bc_extension(ca=True, path_len=0, critical=True),
            san_extension(['internal.example', 'corp.example'], critical=True),
        ]),
    ]

    # 03 one attribute, but its SET wraps two distinct Extensions SEQUENCEs
    multi_value_attr = csr.CRIAttribute({
        'type': 'extension_request',
        'values': csr.SetOfExtensions([
            x509.Extensions([
                bc_extension(ca=False, critical=True),
                san_extension(['only.example']),
            ]),
            x509.Extensions([
                bc_extension(ca=True, critical=True),
                eku_extension(['server_auth', 'client_auth']),
            ]),
        ]),
    })

    # 04 duplicate extnIDs inside one Extensions SEQUENCE
    dup_extnid_attrs = [
        extension_request_attribute([
            bc_extension(ca=False, critical=True),
            san_extension(['safe.example'], critical=False),
            bc_extension(ca=True, path_len=2, critical=False),
            san_extension(['evil.example'], critical=True),
        ])
    ]

    # 05 Microsoft metadata attributes coexisting with the standard request.
    #    The MS attributes are not extensions; the extensionRequest still carries
    #    the same CA/SAN conflict a policy layer must decide on.
    ms_attrs = [
        ms_os_version_attribute(),
        ms_client_info_attribute(),
        ms_csp_attribute(),
        extension_request_attribute([
            bc_extension(ca=True, critical=True),
            san_extension(['windows.host.example.net', 'dc.corp.example'], critical=True),
            extension('microsoft_enroll_certtype', False,
                      parsed=core.BMPString('Machine')),
        ]),
    ]

    # 06 unknown OID marked critical: parser cannot map semantics, policy must
    #    decide whether to reject outright or process out-of-band.
    unknown_attrs = [
        extension_request_attribute([
            bc_extension(ca=False, critical=True),
            extension(UNKNOWN_OID, True, raw=b'\x30\x03\x02\x01\x2a'),
        ])
    ]

    table = {
        'single': baseline_attrs,
        'dup_attribute': dup_attrs,
        'multi_value': [multi_value_attr],
        'dup_extnid': dup_extnid_attrs,
        'ms_and_standard': ms_attrs,
        'unknown_critical': unknown_attrs,
    }

    for base_name, description, key in scenarios():
        der_path, pem_path, der_bytes = build_csr(
            out_dir, base_name, spki, key_path, table[key],
            base_name.split('_', 1)[1]
        )
        verify = subprocess.run(
            ['openssl', 'req', '-in', pem_path, '-noout', '-verify'],
            capture_output=True,
        )
        manifest.append({
            'name': base_name,
            'description': description,
            'der_file': os.path.basename(der_path),
            'pem_file': os.path.basename(pem_path),
            'der_sha256': _sha256(der_bytes),
            'der_length': len(der_bytes),
            'self_signature_valid': verify.returncode == 0,
        })

    with open(os.path.join(out_dir, 'manifest.json'), 'w') as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
    return manifest


def _sha256(data):
    import hashlib
    return hashlib.sha256(data).hexdigest()


if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'generated'
    )
    os.makedirs(target, exist_ok=True)
    for entry in build_all(target):
        print('%-26s sig_ok=%s %s' % (
            entry['name'], entry['self_signature_valid'], entry['der_sha256'][:16]
        ))
    print('output directory: %s' % target)
