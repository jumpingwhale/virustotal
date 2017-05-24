from .interval import PRIVATE_KEY_INTERVAL, PUBLIC_KEY_INTERVAL, Interval
from .err import *
import re


try:
    import requests
except ImportError:
    print('[!] Import Error, Try \'pip install requests\'\n')


class Connection:
    """
    VirusTotal 쿼리 및 다운로드용 클래스

    파일명도 긁어오고 싶으나, public 에선 미지원
    웹 파싱으로 자동화시킬경우 Capcha 에걸림
    """

    def __init__(self, apikeys, private=False):

        self.apikeys = list()
        self.interval = None

        if type(apikeys) is not list:
            raise TypeError('[!] Accepted list() only, not \'%s\'' % type(apikeys))

        for key in apikeys:
            if isValidHash(key, apikey=True):
                self.apikeys.append(key)
            else:
                raise KeyFormatError('[!] Invalid API key. \'%s\'' % key)

        if len(self.apikeys) < 1:
            raise OutOfKeyError('[!] Out of API key.')

        # 여러개의 Public 키 사용을 위한 키관리 클래스, Interval 을 생성한다
        if private:
            self.interval = Interval(self.apikeys, interval=PRIVATE_KEY_INTERVAL, default=True)
        else:
            self.interval = Interval(self.apikeys, interval=PUBLIC_KEY_INTERVAL, default=True)

    def __del__(self):
        """
        destructor
        :return:
        """
        pass

    def download(self, hash):
        """
        VirusTotal 에서 샘플을 다운로드 받는다.
        Private Key 만 해당됨.
        :param hash: str(), 다운받을 샘플 해쉬
        :return: bytearray()
        """

        if self.interval.interval != PRIVATE_KEY_INTERVAL:
            raise PrivilegeError('VirusTotal is Running on PUBLIC mode')
        if not isValidHash(hash):
            raise HashFormatError('[!] Invalid hash. \'%s\'' % hash)

        params = dict()
        params['apikey'] = self.interval.pop()
        params['hash'] = hash

        response = requests.get('https://www.virustotal.com/vtapi/v2/file/download', params=params)

        if isValidStatusCode(response.status_code):
            return response.content
        return None

    def scan(self, hash):
        """
        VirusTotal 리포트를 가져온다.
        :param hash: str(), 검색할 샘플 해쉬
        :return: dict()
        """
        if not isValidHash(hash):
            raise HashFormatError('[!] Invalid hash. \'%s\'' % hash)

        params = dict()
        params['apikey'] = self.interval.pop()
        params['resource'] = hash
        headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": "VirusTotal query module by JumpingWhale"
        }

        try:
            response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
        except requests.RequestException as e:
            raise RequestError('%s' % str(e))

        if isValidStatusCode(response.status_code):
            return response.json()
        return None


def isValidStatusCode(status_code):
    """
    VirusTotal에서 제공하는 status_code 가 올바른지 확인한다.
    정상이 아닐경우 예외를 발생하는 메쏘드
    :param status_code: int()
    :return: bool()
    """
    if status_code is requests.codes.ok:
        return True
    elif status_code == 204:  # 쿼리제한 도달
        raise ResponseCodeError('[!] status_code:204, API query limit reached')
    elif status_code == 403:  # 권한없음
        raise ResponseCodeError('[!] status_code:403, Required privileges not exists in API key')
    return False

def isValidHash(hashStr, apikey=False):
        """
        해쉬문자열이 유효한지 검증한다
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