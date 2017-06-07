# VirusTotal Package #
VirusTotal 에 편하게 접근하기 위한 Python3 패키지.
아래와 같은 식으로 사용한다.
```
import virustotal
vt = virustotal.connect('MY-APU-KEY', False)
report = vt.scan('MD5-SHA1-SHA256')
print(str(report['scans']))
```

# update log #
2017/06/07 - 파일경로를 받아 해쉬계산기능 추가
