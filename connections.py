"""
VirusTotal 에 접근 및 실제 쿼리를 담당하는 모듈
"""

from .interval import PRIVATE_KEY_INTERVAL, PUBLIC_KEY_INTERVAL, Interval
from .err import *
import re
import hashlib


try:
    import requests
except ImportError:
    print('Import Error, Try \'pip install requests\'\n')


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
        if private:
            self.interval = Interval(self.apikeys, interval=PRIVATE_KEY_INTERVAL, default=True)
        else:
            self.interval = Interval(self.apikeys, interval=PUBLIC_KEY_INTERVAL, default=True)

    def __del__(self):
        """소멸자

        :return:
        """
        pass

    def download(self, hash):
        """VirusTotal 에서 샘플을 다운로드 받는다.
        Private 모드에서만 사용할 수 있다.
        :param hash: str, 다운받을 샘플 해쉬
        :return: bytearray
        """

        # Public 모드로 실행중인지 검사한다
        if self.interval.interval != PRIVATE_KEY_INTERVAL:
            raise PrivilegeError('VirusTotal is Running on PUBLIC mode')

        # 실수로 공백을 넣은 경우를 대비한다
        hash = hash.strip()

        # 다운로드 받을 해쉬 유효성을 검증한다
        if not isValidHash(hash):
            raise HashFormatError('[!] Invalid hash. \'%s\'' % hash)

        # 파라미터를 설정한다
        params = dict()
        params['apikey'] = self.interval.pop()
        params['hash'] = hash

        # 다운로드 한다
        try:
            response = requests.get('https://www.virustotal.com/vtapi/v2/file/download', params=params)
        except requests.RequestException as e:
            raise RequestError('[!] %s' % str(e))

        # 응답코드를 검증한다
        if isValidStatusCode(response.status_code):
            return response.content
        return False

    def download_by_progress(self, hash):
        """VirusTotal 에서 샘플을 다운로드 받는 yield 함수

        Private 모드에서만 사용할 수 있다.
        :param hash: str, 다운받을 샘플 해쉬
        :return:
        """

        # Public 모드로 실행중인지 검사한다
        if self.interval.interval != PRIVATE_KEY_INTERVAL:
            raise PrivilegeError('VirusTotal is Running on PUBLIC mode')

        # 실수로 공백을 넣은 경우를 대비한다
        hash = hash.strip()

        # 다운로드 받을 해쉬 유효성을 검증한다
        if not isValidHash(hash):
            raise HashFormatError('Invalid hash. \'%s\'' % hash)

        # 파라미터를 설정한다
        params = dict()
        params['apikey'] = self.interval.pick()
        params['hash'] = hash

        try:
            response = requests.get('https://www.virustotal.com/vtapi/v2/file/download', params=params, stream=True)

            # 응답코드를 검증한다
            if isValidStatusCode(response.status_code):

                downloaded = 0
                filesize = int(response.headers.get('content-length', 0))  # 다운받을 파일 크기

                for chunk in response.iter_content(chunk_size=1024):  # 다운로드 수행
                    downloaded += len(chunk)

                    content = dict()  # 결과 전송용 변수
                    content['filesize'] = filesize
                    content['downloaded'] = downloaded
                    content['chunk'] = chunk  # 다운받은 데이터
                    yield content

        except requests.RequestException as e:
            raise RequestError('%s' % str(e))

    def scan(self, hash):
        """VirusTotal 리포트를 가져온다.

        :param hash: str, 검색할 샘플 해쉬
        :return: dict
        """

        # 실수로 공백을 넣은 경우를 대비한다
        hash = hash.strip()

        # 해쉬 유효성을 검증한다
        if not isValidHash(hash):
            raise HashFormatError('Invalid hash. \'%s\'' % hash)

        # 파라미터를 설정한다
        params = dict()
        params['apikey'] = self.interval.pick()
        params['resource'] = hash
        headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": "VirusTotal query module by JumpingWhale"
        }

        # 보고서를 쿼리한다
        try:
            response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
        except requests.RequestException as e:
            raise RequestError('%s' % str(e))

        # 응답코드를 검증한다
        if isValidStatusCode(response.status_code):

            report = response.json()

            if report['response_code']:
                return report
            else:
                raise ResponseCodeError('response_code:0, No report exists in virustotal')

        return False


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

    try:
        fp = open(filepath, "rb")
    except IOError as e:
        print("file open error: " + e)
        return

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

    try:
        fp = open(filepath, "rb")
    except IOError as e:
        print("file open error: " + e)
        return

    # 첫 블럭을 읽어온다
    buf = fp.read(blocksize)

    # 블럭이 없을 때까지 해쉬 업데이트
    while buf:
        sha_256.update(buf)
        buf = fp.read(blocksize)

    fp.close()

    # 계산된 값을 리턴
    return sha_256.hexdigest()
