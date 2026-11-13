# coding: utf-8
"""
PKCS#12 bag evidence analysis helpers.

This package intentionally works on already-decrypted PKCS#12 material. It
does not attempt password recovery or decryption.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

__all__ = [
    'analyze_pfx',
    'analyze_pfx_bytes',
    'load_pfx',
]


def analyze_pfx(path):
    from .evidence import analyze_pfx
    return analyze_pfx(path)


def analyze_pfx_bytes(data):
    from .evidence import analyze_pfx_bytes
    return analyze_pfx_bytes(data)


def load_pfx(path):
    from .evidence import load_pfx
    return load_pfx(path)
