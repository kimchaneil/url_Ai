import requests  # API 사용
import json  # json 파일 사용
import socket
from urllib.parse import urlparse


def location(ipaddr):  # https://www.ip2location.io/
    payload = {'key': '7050356337ACDB5B8B84E37C649E0FCB', 'ip': ipaddr, 'format': 'json'}
    result = requests.get('https://api.ip2location.io/', params=payload)
    return json.loads(result.text)


def urlToIP(url):  # 주어진 주소로부터 호스트 이름과 포트 알아내기
    o = urlparse(fix_url(url))
    hostname = o.hostname
    port = o.port or (443 if o.scheme == 'https' else 80)
    try:
        ip_addr = socket.getaddrinfo(hostname, port)[0][4][0]
        return ip_addr
    except:
        return 1  # 예외처리 해야됨 안되는 url 많음*********************************************


def fix_url(url):
    try:
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            return response.url
    except:
        pass
    if url.startswith('http://'):
        return 'https://' + url[len('http://'):]
    elif url.startswith('https://'):
        return url
    return 'https://' + url