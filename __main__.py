#!/usr/bin/env python
# -*- coding:utf-8 -*-
"""
virustotal 패키지
_________________


패키지 단독 실행시 cmd 로 쿼리를 할 수 있다
e.g.) python -m virustotal MYAPIKEY HASHVALSUE
"""

from .connections import Connection
import argparse
import json


def main():

    parser = argparse.ArgumentParser(description='Retrieve VirusTotal scan report')
    parser.add_argument('apikey', type=str, help='your virustotal api key')
    parser.add_argument('hash', metavar='MD5', type=str, nargs='+', help='MD5, SHA1, SHA256 hash values to query')
    parser.add_argument('-o', '--out', type=str, help='specify to save result as file')

    args = parser.parse_args()

    key = [args.apikey]
    hashes = args.hash
    outFile = args.out

    conn = Connection(key, private=False)

    result = ''
    for hash in hashes:
        tmp = json.dumps(conn.report(hash), indent=2)
        title = '[%s]' % hash
        print(tmp)
        result += title + '\n' + tmp + '\n'

    if outFile is not None:
        with open(outFile, 'w') as out:
            out.write(result)

if __name__ == '__main__':
    main()
