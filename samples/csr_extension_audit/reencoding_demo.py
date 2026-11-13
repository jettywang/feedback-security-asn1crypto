# coding: utf-8
"""
Show how asn1crypto re-encoding moves data around without any merge logic in
the application. Two observations matter for a CA backend:

  1. CRIAttributes is a SetOf; SetOf._set_contents() sorts child encodings
     lexicographically every time contents are regenerated, so any mutation
     (append/delete/change) can reorder attributes compared with the received
     bytes. Attribute *identity* must therefore be tracked by index/OID on the
     parsed object, never by position after a dump().
  2. Parsed objects cache the original bytes; plain .dump() is byte-preserving
     even for ambiguous inputs, which is why a second parser sees exactly the
     same ambiguity. The library does not sanitize anything on your behalf.
"""
from __future__ import print_function

import os

from asn1crypto import csr, x509

from naive_antipatterns import load

GENERATED = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'generated')


def oid_order(request):
    return [a['type'].dotted for a in
            request['certification_request_info']['attributes']]


def main():
    path = os.path.join(GENERATED, '02_dup_attribute.der')
    original = open(path, 'rb').read()
    request = load(original)

    print('received attribute order :', oid_order(request))
    print('plain dump identical     :', request.dump() == original)
    print('force dump identical     :', request.dump(force=True) == original)

    # Mutate: append a challenge-password attribute, then re-encode. Both
    # extensionRequest entries survive, and the SET OF is re-sorted.
    challenge = csr.CRIAttribute({
        'type': 'challenge_password',
        'values': csr.SetOfDirectoryString([
            x509.DirectoryString(name='utf8_string', value='hunter2')
        ]),
    })
    request['certification_request_info']['attributes'].append(challenge)
    mutated = request.dump()
    reparsed = csr.CertificationRequest.load(mutated)
    print('after mutation, order    :', oid_order(reparsed))
    print('extensionRequest count   :', sum(
        1 for a in reparsed['certification_request_info']['attributes']
        if a['type'].dotted == '1.2.840.113549.1.9.14'
    ))
    print('challenge attr present   :', any(
        a['type'].dotted == '1.2.840.113549.1.9.7'
        for a in reparsed['certification_request_info']['attributes']
    ))


if __name__ == '__main__':
    main()
