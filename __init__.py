"""
virustotal 접근용 패키지
last update : 2017-05-22
author : jumpingwhale
"""

from .err import ResponseCodeError, KeyFormatError, OutOfKeyError, HashFormatError, RequestError, PrivilegeError
from .connections import Connection as VirusTotal
from .connections import isValidHash, isValidStatusCode

__all__ = [
    'ResponseCodeError', 'KeyFormatError', 'OutOfKeyError', 'HashFormatError', 'RequestError', 'PrivilegeError',
    'VirusTotal',
    'isValidHash', 'isValidStatusCode'
]


def connect(apikeys, private=False):
    return VirusTotal(apikeys=apikeys, private=private)