"""
Interval 모듈
last update : 2017-05-22
author : jumpingwhale
"""
import time
import random

PUBLIC_KEY_INTERVAL = 15  # 단위:초
PRIVATE_KEY_INTERVAL = 0


class Interval:
    """
    여러 오브젝트가 한 번 사용하면 재사용을 위해
    특정 시간이 흘러야만 가능해지는 경우
    이를 컨트롤하기 위한 클래스
    default 는 최초 생성 시 리턴 가능 상태를 명시한다
    """

    def __init__(self, objects, interval=15, default=True):
        """
        :param objects: list() of objects
        :param interval: 설정 대기시간 (단위:초)
        :param default: 초기생성시 기본 리턴가능상태
        """
        # 설정한 오브젝트 리스트인지 검증, 리스트 형태만 지원
        if type(objects) is not list:
            raise TypeError('This class accepts \'list()\' only')

        # 생성시 기본 인터벌 설정(단위:초), 기본 1분에 4개
        self.interval = interval

        # 초기 True/False 값에 따라 기준시간 설정
        if default:
            currTime = time.time() - self.interval
        else:
            currTime = time.time()

        # 오브젝트 별 초기값 설정
        self.objects = dict()
        for object in objects:
            self.objects[object] = currTime

    def pop(self):
        """
        사용이 가능해진 오브젝트를 리턴한다
        :return: 생성때와 같은 타입의 오브젝트
        """
        object = self.getObject()
        return object

    def getObject(self):
        """
        오브젝트를 랜덤으로 선정해 True일경우
        해당 키를 반환한다
        딕셔너리키 == 오브젝트이름
        딕셔너리밸류 == 과거호출시점
        :return: 생성때와 같은 타입의 오브젝트
        """

        # 랜덤한 오브젝트 선정
        randomObject = random.choice(list(self.objects))

        # 과거 호출시점 기준, 현재 호출시점이 interval 을 넘길때까지
        while (time.time() - self.objects[randomObject]) < self.interval:
            # CPU 자원소모 방지
            time.sleep(1)
            # 다시 선정, (선정시까지 행 문제 있음, 쓰레드로 처리할것)
            randomObject = random.choice(list(self.objects))

        # 선정이 완료된 오브젝트 호출시점 초기화
        self.objects[randomObject] = time.time()

        return randomObject
