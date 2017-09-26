#!/usr/bin/env python
# -*- coding:utf-8 -*-

"""
interval 모듈
*************

어떤 오브젝트가 한 번 사용하면 재사용을 위해 특정 시간이 흘러야만 가능해지는 경우
다수의 오브젝트를 동시해 관리해, 대기시간을 줄이기 위한 모듈
주 목적은 virustotal 의 public 키 여러개를 효율적으로 사용하기 위함

..warning::
    virustotal 은 바보가 아니다
"""

import time
import random

PUBLIC_KEY_INTERVAL = 15  # 단위:초
PRIVATE_KEY_INTERVAL = 0


class Interval:
    """interval 모듈의 주 기능이 구현된 Interval 클래스"""

    def __init__(self, objects, interval=15, default=True):
        """초기 리턴 가능 여부 등 기본값을 설정한다

        :param objects: 아무 자료형으로 이뤄진 리스트
        :type objects: list
        :param interval: 설정 대기시간 (단위:초)
        :type interval: int
        :param default: 생성시 기본 가용성 여부
        :type default: bool
        """

        # 설정한 오브젝트 리스트인지 검증, 리스트 형태만 지원
        if type(objects) is not list:
            raise TypeError('This class accepts \'list()\' only')

        # 생성시 기본 인터벌 설정(단위:초), 기본 1분에 4개
        self.interval = interval

        # default 값에 따라 초기시간 설정
        if default:
            _lastUsed = time.time() - self.interval
        else:
            _lastUsed = time.time()

        # 오브젝트 별 초기값 설정
        self.objects = dict()
        for _object in objects:
            self.objects[_object] = _lastUsed  # 오브젝트들은 가장 최근 사용된 시간을 갖고있다.

    def pick(self):
        """사용이 가능해진 오브젝트를 리턴한다

        :return _randomObject: 생성때와 같은 타입의 오브젝트
        :rtype: any
        """

        # 랜덤한 오브젝트 선정
        _randomObject = random.choice(list(self.objects))

        # 과거 호출시점 기준, 현재 호출시점이 interval 을 넘길때까지
        while (time.time() - self.objects[_randomObject]) < self.interval:  # self.objects 에는 각 오브젝트의 최근 접근 시간이 담겨있다
            # CPU 자원소모 방지
            time.sleep(1)
            # 다시 선정
            _randomObject = random.choice(list(self.objects))  # TODO: 선정시까지 hanging 문제 있음, 쓰레드로 처리할것

        # 선정이 완료된 오브젝트 호출시점 초기화
        self.objects[_randomObject] = time.time()

        return _randomObject
