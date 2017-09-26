#!/usr/bin/env python
# -*- coding:utf-8 -*-
"""
패키지의 실제 동작이 구현된 모듈, __init__.py 모듈의 connect() 함수는
이 패키지의 Connection 클래스를 생성하는 역할을 한다. pymysql 의 클래스 생성방식을 따랐다.
접속은 아래와 같이 할 수 있다.

:Example:
from virustotal import *
vt = conntect('MY_API_KEY', private=False)

동시에 여러 public 키 사용이 가능하다. 다수의 키 관리 클래스는 interval을 참고
"""

from .interval import PRIVATE_KEY_INTERVAL, PUBLIC_KEY_INTERVAL, Interval
from .err import *
import re
import hashlib

try:
    import requests
except ImportError:
    print('Import Error, Try \'pip install requests\'\n')

VIRUSTOTAL_URL = 'https://www.virustotal.com'


class Connection:
    """VirusTotal 쿼리 및 다운로드용 클래스

    파일명도 긁어오고 싶으나, public 에선 미지원
    웹 파싱으로 자동화시킬경우 Capcha 에걸림
    """

    def __init__(self, apikeys, private=False):
        """생성자

        :param apikeys: list, API 형식의 문자열로 구성된 리스트
        :param private: bool, PUBLIC/PRIVATE 모드 설정
        """

        self.apikeys = list()  # 생성시 받은 인자를 검증하고 키로 사용
        self.private = private
        self.interval = None  # 실행모드에 따라 쿼리 간격을 조절하는 변수

        # APIkeys 를 list 로 바꿔준다 (개인키의 경우 대게 한개만 전달)
        if isinstance(apikeys, str):
            apikeys = [apikeys, ]

        # API 키가 올바른지 검증한다
        for key in apikeys:
            if key is '':
                continue
            if isValidHash(key, apikey=True):
                self.apikeys.append(key)
            else:
                raise KeyFormatError('Invalid API key format. \'%s\'' % key)

        # 유효한 API 키 갯수를 검증한다
        if len(self.apikeys) < 1:
            raise OutOfKeyError('Out of API key.')

        # 여러개의 Public 키 사용을 위한 키관리 클래스, Interval 을 생성한다
        if self.private:
            self.interval = Interval(self.apikeys, interval=PRIVATE_KEY_INTERVAL, default=True)
        else:
            self.interval = Interval(self.apikeys, interval=PUBLIC_KEY_INTERVAL, default=True)

        self.headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": "VirusTotal query module by JumpingWhale"
        }

    def __del__(self):
        """소멸자

        :return:
        """
        pass

    def download(self, hash):
        """VirusTotal 에서 샘플을 다운로드 받는다

        https://www.virustotal.com/ko/documentation/private-api/#file-download

        Private 모드에서만 사용할 수 있다.
        :param hash: str, 다운받을 샘플 해쉬
        :return: bytearray
        """

        _url = VIRUSTOTAL_URL + '/vtapi/v2/file/download'

        # Public 모드로 실행중인지 검사한다
        if not self.private:
            raise PrivilegeError('VirusTotal is Running on PUBLIC mode')

        # 다운로드 받을 해쉬 유효성을 검증한다
        _hash = hash.strip()
        if not isValidHash(_hash):
            raise HashFormatError('[!] Invalid hash. \'%s\'' % _hash)

        # 파라미터를 설정한다
        _params = {'apikey': self.interval.pick(),
                   'hash': _hash}

        # 다운로드 한다
        try:
            _res = requests.get(_url, params=_params)
        except requests.RequestException as e:
            raise RequestError('%s' % str(e))

        # 응답코드를 검증한다
        if isValidStatusCode(_res.status_code):
            return _res.content
        return False

    def download_by_progress(self, hash):
        """VirusTotal 에서 샘플을 다운로드 받는 yield 함수

        https://www.virustotal.com/ko/documentation/private-api/#file-download

        Private 모드에서만 사용할 수 있다.
        :param hash: str, 다운받을 샘플 해쉬
        :return:
        """

        _url = VIRUSTOTAL_URL + '/vtapi/v2/file/download'

        # Public 모드로 실행중인지 검사한다
        if not self.private:
            raise PrivilegeError('VirusTotal is Running on PUBLIC mode')

        # 다운로드 받을 해쉬 유효성을 검증한다
        _hash = hash.strip()
        if not isValidHash(_hash):
            raise HashFormatError('Invalid hash. \'%s\'' % _hash)

        # 파라미터를 설정한다
        _params = {'apikey': self.interval.pick(),
                   'hash': _hash}

        # 다운로드 한다
        try:
            _res = requests.get(_url, params=_params, stream=True)

            # 응답코드를 검증한다
            if isValidStatusCode(_res.status_code):

                _downloaded = 0
                _filesize = int(_res.headers.get('content-length', 0))  # 다운받을 파일 크기

                for _chunk in _res.iter_content(chunk_size=1024):  # 다운로드 수행
                    _downloaded += len(_chunk)

                    _ret = {'filesize': _filesize,
                            'downloaded': _downloaded,
                            'chunk': _chunk}
                    yield _ret

        except requests.RequestException as e:
            raise RequestError('%s' % str(e))

    def report(self, hash):
        """VirusTotal 리포트를 가져온다.

        https://www.virustotal.com/ko/documentation/private-api/#get-report

        :param hash: str, 검색할 샘플 해쉬
        :return: dict
        """

        _url = VIRUSTOTAL_URL + '/vtapi/v2/file/report'

        # 해쉬 유효성을 검증한다
        _hash = hash.strip()
        if not isValidHash(hash):
            raise HashFormatError('Invalid hash. \'%s\'' % _hash)

        # 파라미터를 설정한다
        _params = {'apikey': self.interval.pick(),
                   'resource': _hash}
        if self.private: _params['allinfo'] = 1

        # 보고서를 쿼리한다
        try:
            _res = requests.get(_url, params=_params, headers=self.headers)
        except requests.RequestException as e:
            raise RequestError('%s' % str(e))

        # 응답코드를 검증한다
        if isValidStatusCode(_res.status_code):

            _report = _res.json()

            if _report['response_code']:
                return _report
            else:
                raise NoReportError('response_code:0, No report exists in virustotal')
        return False

    def url_report(self, url):
        """url 스캔 결과를 가져온다

        https://www.virustotal.com/ko/documentation/private-api/#url-report

        :param url:
        :return:
        """

        _url = VIRUSTOTAL_URL + '/vtapi/v2/url/report'

        # 파라미터를 설정한다
        _params = {'apikey': self.interval.pick(),
                   'resource': url}
        if self.private: _params['allinfo'] = 1

        # 보고서를 쿼리한다
        try:
            _res = requests.post(_url, params=_params, headers=self.headers)
        except requests.RequestException as e:
            raise RequestError('%s' % str(e))

        # 응답코드를 검증한다
        if isValidStatusCode(_res.status_code):

            _report = _res.json()

            if _report['response_code']:
                return _report
            else:
                raise NoReportError('response_code:0, No report exists in virustotal')
        return False

    def search(self, queryopt, offset=None):
        """조건을 주어 샘플을 검색한다 (recursive yield 함수)

        Private 키 종류에 상관없이, 일일 50000쿼리로 제한된다.
        VirusTotal Intelligence 의 Web UI를 통한 검색과 완전히 동일한 기능.
        `쿼리사용법`_ 을 보려면 VirusTotal Community 가입해야 가능.
        300 개 이상의 리턴에 대해선 offset 파라미터를 사용해야 한다. `API사용법`_ .

        .. _API사용법: https://www.virustotal.com/ko/documentation/private-api/#search
        .. _쿼리사용법: https://www.virustotal.com/intelligence/help/file-search/#search-modifiers
        :param queryopt:
        :return:
        """

        _url = VIRUSTOTAL_URL + '/vtapi/v2/file/search'

        # 파라미터를 설정한다
        _params = {'apikey': self.interval.pick(),
                   'query': queryopt}
        if offset: _params['offset'] = offset  # 결과가 300개 이상이경우, 다음 300개를 받기 위해 설정해준다

        # 보고서를 쿼리한다
        try:
            _res = requests.post(_url, params=_params, headers=self.headers)
        except requests.RequestException as e:
            raise RequestError('%s' % str(e))

        # 응답코드를 검증한다
        if isValidStatusCode(_res.status_code):

            _report = _res.json()

            if _report['response_code'] is 0:  # 예외처리
                raise NoReportError('response_code:0, Query \'%s\' matches no samples' % str(queryopt))
            elif _report['response_code'] is -1:  # 예외처리
                raise QueryOptionError('response_code:-1, Invalid query option \'%s\'' % str(queryopt))

            elif _report['response_code'] is 1:  # 실제 동작
                for _hash in _report['hashes']:  # 먼저 해쉬목록을 전달해주고
                    yield _hash
                if 'offset' in _report:  # 해쉬가 더 있을경우
                    yield from self.search(queryopt, offset=offset)  # 더 받아온다


def isValidStatusCode(status_code):
    """requests 모듈의 응답결과(status_code) 가 올바른지 확인한다.

    정상이 아닐경우 예외를 발생하는 메쏘드
    :param status_code: int()
    :return: bool()
    """

    if status_code is requests.codes.ok:
        return True
    elif status_code == 204:  # 쿼리제한 도달
        raise ResponseCodeError('status_code:204, API query limit reached')
    elif status_code == 403:  # 권한없음
        raise ResponseCodeError('status_code:403, Required privileges not exists in API key')
    elif status_code == 404:  # 다운로드 할 파일 없음
        raise ResponseCodeError('status_code:404, No sample exists in virustotal')
    return False


def isValidHash(hashStr, apikey=False):
    """해쉬문자열이 유효한지 검증한다

    :param hashStr: str()
    :param apikey: bool(), 검증할 문자열이 API key 일경우 True
    :return: bool()
    """

    patterns = [
        '^[a-fA-F0-9]{32}$',  # MD5
        '^[a-fA-F0-9]{40}$',  # SHA1
        '^[a-fA-F0-9]{64}$',  # SHA256 / Virustotal API Key
    ]

    if apikey:
        patterns = [patterns[2]]

    for pattern in patterns:
        match = re.match(pattern, hashStr)
        if match is not None:
            return True

    return False


def md5(filepath, blocksize=8192):
    """경로에 있는 파일의 MD5 해쉬 얻는다

    :param filepath: str, 파일 경로
    :param blocksize: int, 해쉬블럭
    :return: str, MD5 16진 문자열
    """

    md5 = hashlib.md5()

    fp = open(filepath, "rb")

    # 첫 블럭을 읽어온다
    buf = fp.read(blocksize)

    # 블럭이 없을 때까지 해쉬 업데이트
    while buf:
        md5.update(buf)
        buf = fp.read(blocksize)

    fp.close()

    # 계산된 값을 리턴
    return md5.hexdigest()


def sha256(filepath, blocksize=8192):
    """경로에 있는 파일의 SHA256 해쉬 얻는다

   :param filepath: str, 파일 경로
   :param blocksize: int, 해쉬블럭
   :return: str, SHA256 16진 문자열
   """

    sha_256 = hashlib.sha256()

    fp = open(filepath, "rb")

    # 첫 블럭을 읽어온다
    buf = fp.read(blocksize)

    # 블럭이 없을 때까지 해쉬 업데이트
    while buf:
        sha_256.update(buf)
        buf = fp.read(blocksize)

    fp.close()

    # 계산된 값을 리턴
    return sha_256.hexdigest()
