class Error(Exception):
    """상속용 기본 예외처리 클래스"""
    pass


class ResponseCodeError(Error):
    """VirusTotal 응답코드 에러"""
    def __init__(self, msg):
        super().__init__(msg)


class NoReportError(ResponseCodeError):
    """VirusTotal 리포트 없음 에러"""
    def __init__(self, msg):
        super().__init__(msg)


class QueryOptionError(ResponseCodeError):
    """Search modifier 오류 에러"""
    def __init__(self, msg):
        super().__init__(msg)


class KeyFormatError(Error):
    """API 키 형식 에러"""
    def __init__(self, msg):
        super().__init__(msg)


class OutOfKeyError(Error):
    """초기화시 유효한 API 키 없음 에러"""
    def __init__(self, msg):
        super().__init__(msg)


class HashFormatError(Error):
    """쿼리해쉬 형식 에러"""
    def __init__(self, msg):
        super().__init__(msg)


class RequestError(Error):
    """서버접근 관련 에러"""
    def __init__(self, msg):
        super().__init__(msg)


class PrivilegeError(Error):
    """Public/Private 키 권한 에러"""
    def __init__(self, msg):
        super().__init__(msg)
