#!/usr/bin/env python
# -*- coding:utf-8 -*-

"""
virustotal 패키지
*****************

VirusTotal 의 Public/Private API 를 효율적으로 쓸 수 있도록 관련 기능을 제공하는 패키지
이 패키지(폴더)를 복/붙해둔다면 아래와같이 임포트해 사용할 수 있다::
    import virustotal
    con = virustotal.connect('MY_API_KEY', private=False)

이렇게 사용하면 __all__ 에 명시된 모든것을 쉽게 사용할 수 있다::
    from virutotal import *
    con = connect('MY_API_KEY', private=False)

"""

from .err import ResponseCodeError, KeyFormatError, OutOfKeyError, HashFormatError, RequestError, PrivilegeError
from .connections import Connection as VirusTotal
from .connections import isValidHash, isValidStatusCode, md5

__version__ = '1.1'

__all__ = [
    'ResponseCodeError', 'KeyFormatError', 'OutOfKeyError', 'HashFormatError', 'RequestError', 'PrivilegeError',
    'NoReportError',
    'VirusTotal',
    'isValidHash', 'isValidStatusCode', 'md5'
]


def connect(apikeys, private=False):
    return VirusTotal(apikeys=apikeys, private=private)

if __name__ == '__main__':
    pass
