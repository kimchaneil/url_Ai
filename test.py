########################################################
# 최종본
########################################################

########################################################
# 라이브러리1 : GUI만들때만 필요한 것들.

import numpy as np
import pandas as pd #csv파일을 읽어올때
import matplotlib.pyplot as plt #그래프
import seaborn as sns #그래프 형태

from sklearn.model_selection import train_test_split #데이터 셋을 분리 : 트레인&테스트
from sklearn.model_selection import KFold, cross_val_score, cross_val_predict #
from sklearn import metrics #메트릭을 확인.

#머신러닝 메소드
from sklearn import svm
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import AdaBoostClassifier
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.ensemble import BaggingClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.neural_network import MLPClassifier
from sklearn.svm import SVC
from sklearn.metrics import classification_report
from sklearn.ensemble import StackingClassifier
from sklearn.ensemble import VotingClassifier
from sklearn.utils import resample
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.feature_selection import SelectKBest, chi2

import tkinter as tk
from tkinter import ttk
from tkinter import Toplevel
from PIL import Image, ImageTk  # PIL 라이브러리 사용
from tkinter import messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import random
import pandas as pd
from tkinterhtml import HtmlFrame  # 추가된 부분
import joblib
import time

import warnings
warnings.filterwarnings("ignore", category=FutureWarning)

import whois
from urllib.parse import urlparse, urlunparse, unquote, parse_qs
import urllib.request
import socket
import requests
from bs4 import BeautifulSoup
import re
from datetime import datetime
import pandas as pd
import random
import time
import datetime
from datetime import date,timedelta
import os
import csv
import sys
import tldextract
import joblib
import json
import dns.resolver #오류 뜨면 [pip install dnspython]을 먼저 해보기~
import ssl
import timeout_decorator #함수 실행시간 제한.





###########################################################
###########################################################



# 함수 모음



#########################################################
# 임시 함수 : 훗날 모델 함수로 대체될 부분. query부분이 url이 들어갈 부분이다.
def example(query):
    tmp_data = []

    time.sleep(5.5)

    if query == 'example1':
        model_result1 = 'safe'
        model_result2 ='malicious'
        model_result3 ='malicious'
        model_result4 ='safe'
        model_result5 ='malicious'
        model_result6 ='safe'
        model_result7 ='malicious'
        model_result8 ='safe'
        result1 = 'malicious' #전체 결과
        result2 = 'safe' #AI모델 결과
        result3 = 'malicious' #DGA모델 결과
        probabilities = [round(random.uniform(75, 100), 2) for _ in range(12)]  # 전체 확률, AI확률, DGA확률, 신뢰도

    elif query == 'example2':
        model_result1 = 'safe'
        model_result2 ='malicious'
        model_result3 ='malicious'
        model_result4 ='safe'
        model_result5 ='malicious'
        model_result6 ='malicious'
        model_result7 ='safe'
        model_result8 ='malicious'
        result1 = 'safe'
        result2 = 'safe'
        result3 = 'malicious'
        probabilities = [round(random.uniform(50,75), 2) for _ in range(12)]

    elif query == 'https://cgefwetuyfrsjery.square.site/':
        model_result1 = 'malicious'
        model_result2 ='malicious'
        model_result3 ='safe'
        model_result4 ='malicious'
        model_result5 ='malicious'
        model_result6 ='malicious'
        model_result7 ='malicious'
        model_result8 ='malicious'
        result1 = 'malicious'
        result2 = 'malicious'
        result3 = 'malicious'
        probabilities = [round(random.uniform(68,92), 2) for _ in range(12)]

    else:
        model_result1 = 'malicious'
        model_result2 = 'safe'
        model_result3 = 'malicious'
        model_result4 = 'safe'
        model_result5 = 'malicious'
        model_result6 = 'malicious'
        model_result7 = 'safe'
        model_result8 = 'safe'
        result1 = 'malicious'
        result2 = 'safe'
        result3 = 'safe'
        probabilities = [round(random.uniform(75, 100), 2) for _ in range(12)]

    return model_result1, probabilities[0], model_result2, probabilities[1], model_result3, probabilities[2], model_result4, probabilities[3], \
                model_result5, probabilities[4], model_result6, probabilities[5], model_result7, probabilities[6], model_result8, probabilities[7], \
                result1, result2, result3, probabilities[8], probabilities[9], probabilities[10], probabilities[11]
# 함수에서 반환되는 값(실제 모델 함수에서 반환될 값과 똑같이 설정함)
# 모델별 결과값(예측값, 확률값), 전체 결과값(모든 모델), AI결과값, DGA결과값, 전체 예측 확률, AI 예측확률, DGA예측확률, 예측 신뢰도

#########################################################
# 실제 함수 : 모델 구현, 특징값 추출
# 어휘특징 추출함수
# domain_count
# 어휘특징 추출함수
# domain_count

# 특징값 추출 함수

# 도메인 개수
def count_domain(url):
    try:
        parsed_url = urlparse(url)
        subdomains = parsed_url.hostname.split(".")
        return len(subdomains) - 1 if subdomains[0] != "www" else len(subdomains) - 2

    except:
        return 0  # 서브도메인이 없을때 오류가 발생하므로 0을 반환!


# 숫자,문자,특수문자중 어떤것 인지 확인
def get_char_type(char):
    if char.isdigit():
        return "num"
    elif char.isalpha():
        return "alpha"
    elif not char.isalnum():
        return "special"
    else:
        return "unknown"


# 문자열의 정렬도, 문자, 특수문자, 숫자가 얼마나 많이 섞여져 있는지 확인 후 비율을 출력, 랜덤한 정도를 확인가능.
def is_random_strings(url):
    total_count, change_count = 0, 0  # 카운트 초기화
    for i in range(len(url) - 1):
        char1 = url[i]
        char2 = url[i + 1]
        if get_char_type(char1) != get_char_type(char2):
            total_count += 1
            change_count += 1
        else:
            total_count += 1

    return round(change_count / total_count, 4) if total_count != 0 else 0  # 자릿수 제한해서 출력


# large_alphabet_percentage : url내 문자중 대문자의 비율
def upper_alphabet_percentage(url):
    total_chars = len(url)
    uppercase_chars = sum(1 for char in url if char.isupper())
    return round(uppercase_chars / total_chars, 4) if total_chars != 0 else 0  # 소수점 자릿수 4자리로 제한해서 출력


# url_length,url_path_length,url_netloc_length,url_tld length, url_path_level,
def url_length(url):
    urlLength = len(url)
    return urlLength


# url path의 길이, 폴더의 개수(path_level)
def url_path(url):
    path = urllib.parse.urlparse(url).path
    path_level = path.count('/')
    return len(path), path_level


# url netloc의 길이
def url_netloc(url):
    netloc = urllib.parse.urlparse(url).netloc
    host_level = netloc.count('.')
    return len(netloc), host_level


# url tld길이
def url_tld_length(url):
    extracted = tldextract.extract(url)
    tld_length = len(extracted.suffix)
    return tld_length


######################################################################################
# 악성 키워드 모음
mark_list = ['http:', 'https:', '.', '//', '-', '@', 'www', '=', '_', '~', '?']  # 하나하나 확인할 리스트
mark_list2 = ['&', '#', '%', ';']  # 한번에 확인할 문자 리스트
malicious_list = ['login', 'phishing', 'malware', 'exploit', 'virus', 'trojan', 'spyware', 'ransomware', 'botnet',
                  'keylogger', 'backdoor', 'rootkit', 'spam', 'scam', 'fake'
    , '.exe', '.dll', 'bat', 'xyz', '.info', '.club', '.ru', 'cn', 'kp', 'gov', 'mil', 'bitcoin']  # 이 순서대로 반환될것.
number_list = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0']
keywords = ["sql", "injection", "xss", "cross-site", "scripting", "csrf", "malware", "virus", "trojan", 'onlinebanking',
            'paypal', 'ebay', 'amazon', 'facebook', 'twitter', '=',
            "google analytics", "facebook pixel", "twitter conversion tracking", "linkedin insight tag",
            "pinterest conversion tag", "snapchat pixel",
            "bing ads conversion tracking", "taboola pixel", "quora pixel", "tawk.to", "intercom", "zendesk", "drift",
            "hotjar", "mixpanel", "segment", "google tag manager",
            "facebook for developers", "linkedin marketing solutions", "twitter ads", "adroll", "google ads",
            "doubleclick", "youtube tracking", "vimeo analytics",
            "soundcloud tracking", "mixcloud tracking", "spotify tracking", "apple app store tracking",
            "google play store tracking", "firebase analytics", "utm_", "tracking_id",
            'admin', 'password', 'eval', 'exec', 'SELECT', 'UNION', 'DROP', 'script', 'iframe', 'onerror', 'alert',
            'document.cookie', 'document.write', 'location.href']  # 통합된 키워드들들


######################################################################################


def url_number_string_contain(url):
    numberContainCount = 0
    tmp_string_contain = [url.count(string) for string in number_list]
    for i in range(len(tmp_string_contain)):
        numberContainCount += tmp_string_contain[i]
    return numberContainCount


def url_mark_contain(url):
    tmp_marks_contain = [url.count(char) for char in mark_list]
    return tmp_marks_contain  # 리스트 형태로 반환.


def url_mark_contain2(url):
    markContainCount = 0
    tmp_string_contain = [url.count(string) for string in mark_list2]
    for i in range(len(tmp_string_contain)):
        markContainCount += tmp_string_contain[i]
    return markContainCount


def url_malicious_string_contain(url):
    maliciousContainCount = 0
    tmp_string_contain = [url.count(string) for string in malicious_list]
    for i in range(len(tmp_string_contain)):
        maliciousContainCount += tmp_string_contain[i]
    return maliciousContainCount


# query_length,query_count,is_query_encoding,query_contain

# 쿼리가 존재하면 쿼리와 관련된 정보들을 리스트 형태로 반환.
def query_exist_features(url):
    query_features = []  # 리스트를 선언 및 초기화, 쿼리의 특징값들을 넣을겁니다.
    query = urlparse(url).query  # 쿼리를 문자열로 불러온다.
    params = urllib.parse.parse_qs(query)
    query_params = parse_qs(urlparse(url).query)  # 쿼리의 개수를 구한다.
    decoded_query = unquote(query)  # unquote는 URL 인코딩된 문자열을 디코딩하는 함수

    # 쿼리가 존재하면 특징값을 추출하고 없으면 0을 출력.
    if query:
        query_features.append(len(query))  # 쿼리 길이.
        query_features.append(1) if parse_qs(query) == parse_qs(unquote(query)) else query_features.append(
            0)  # 인코딩 유무를 확인, 인코딩했으면 1을 안했으면 0을 반환.
        query_features.append(sum(1 for keyword in keywords if keyword in decoded_query) + sum(
            1 for keyword in keywords if keyword in query))  # 쿼리자체와 디코딩된 것내에 악성 행위관련 키워드 개수
        query_features.append(len(query_params))  # 쿼리의 개수

    else:
        query_features.extend([0, 0, 0, 0])  # 쿼리가 없으면 0000을 반환,

    return query_features


# IP 주소가 URL에서 도메인 이름의 대안으로 사용되거나 16진수로 변환되어 나타내어질때 표시
def Ip_in_url(url):
    domain = urlparse(url).hostname  # urlparse를 이용하여 URL에서 도메인을 추출합니다

    ip_list = re.findall(r'(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f]{8}',
                         url)  # 문자열 패턴을 찾는 re.findall()함수를 사용하여 IP패턴이 url에 존재하는지 확인후 리스트에 추가가
    ip_list.extend(re.findall(r'(?:\d{1,3}\-){3}\d{1,3}|[0-9A-Fa-f]{8}', url))  # 가끔은 ip를 000-000-000-000형태로 나타내기도 함.
    ip_list.extend(re.findall(r"0x[\da-fA-F]{2}\.0x[\da-fA-F]{2}\.0x[\da-fA-F]{2}\.0x[\da-fA-F]{2}",
                              url))  # ip가 16진수형태(.)로 나타내어질때도 있음.
    ip_list.extend(re.findall(r"0x[\da-fA-F]{2}\-0x[\da-fA-F]{2}\-0x[\da-fA-F]{2}\-0x[\da-fA-F]{2}",
                              url))  # ip가 16진수형태(-)로 나타내어질때도 있음.

    # IP 주소가 URL에서 나타나는 경우 1을, 아니면 0을 반환
    return 1 if (len(ip_list) > 0 or any(ip.startswith("0x") for ip in ip_list)) else 0


# url단축 기능 사용여부를 확인하고 출력.
def is_shortened_url(url):
    shortening_services = ['bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co']
    parsed_url = urlparse(url)

    return 1 if parsed_url.netloc in shortening_services else 0


# 파싱특징 = 포트번호 생성일~현재, 현재~만료일, 전체수명, 포트번호 출력, abnormal유무
def parse_features(url):
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        creation_date = whois.whois(domain).creation_date  # 도메인의 생성일
        expiration_date = whois.whois(domain).expiration_date  # 도메인의의 만료일자.

        if type(creation_date) is list:
            creation_date = creation_date[0]  # 리스트로 반환될때 첫번째 것을 저장
        if creation_date:
            days_since_creation = (datetime.datetime.now() - creation_date).days  # 생성된 이후 현재

        if type(expiration_date) is list:
            expiration_date = expiration_date[0]  # 리스트로 반환될때 첫번째 것을 저장.
        if expiration_date:
            days_left = (expiration_date - datetime.datetime.now()).days  # 만료날짜까지 남은 날짜

        days_whole = days_since_creation + days_left  # 전체 수명

        if parsed_url.port is not None:
            port = parsed_url.port
        if parsed_url.scheme == 'http':
            port = 80
        elif parsed_url.scheme == 'https':
            port = 443
        else:
            port = -1

        w = whois.whois(url)
        is_abnormal = 1 if 'abuse_emails' in w or 'abuse_contact_email' in w else 0

        return port, days_since_creation, days_left, days_whole, is_abnormal

    except:
        return -1, -1, -1, -1, -1


# request특징 : 외부개체 로드비율, 트래픽 길이 출력
def request_features(url):
    try:
        response = requests.get(url)
        return len(response.content)

    except:
        return -1


# https 요청을 하여 요청 성공 시 URL 앞에 스키마를를 붙여주는 함수
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


# url과 label(안전 or 위험)을 입력값으로 하여 url의 모든 특징값을 리스트 형태로 출력해주는 함수, 시간제한을 설정했다.
def find_save_feature(url, label):
    tmp_features = []  # 특징값들을 저장할 리스트로 여기서 선언하고 초기화 해준다.

    # 어휘적 특징
    tmp_features.append(url)  # url자체
    tmp_features.append(label)  # 라벨(정답값값)
    tmp_features.append(count_domain(url))  # 도메인의 개수
    tmp_features.append(is_random_strings(url))  # 도메인의 랜덤정도
    tmp_features.append(upper_alphabet_percentage(url))  # 도메인내 대문자 비율
    tmp_features.extend(url_mark_contain(
        url))  # 특정 기호들('//','-','@','www','&','#','%','=', '_', '~', ';') 포함 유무, 각 기호별 개수를 리스트로 반환하므로 extend사용!
    tmp_features.append(url_mark_contain2(url))  # 기여도가 낮은 기호들을 통합하여 개수 출력.
    tmp_features.append(url_malicious_string_contain(url))  # 특정 문자열 포함 개수
    tmp_features.append(url_number_string_contain(url))  # 숫자 포함 개수
    tmp_features.append(url_length(url))  # url의 길이
    tmp_features.extend(url_path(url))  # url path의 길이, 레벨
    tmp_features.extend(url_netloc(url))  # url netloc의 길이, 호스트 레벨
    tmp_features.append(url_tld_length(url))  # url tld길이
    tmp_features.extend(query_exist_features(url))  # url의 쿼리 유무 및 쿼리의 4가지 특징값 반환
    tmp_features.append(Ip_in_url(url))  # IP가 도메인의 대안으로 사용됐는지 확인.
    tmp_features.append(is_shortened_url(url))  # url의 단축 서비스 사용유무 확인.
    # 외부 특징
    tmp_features.extend(parse_features(url))  # 포트번호 생성일~현재, 현재~만료일, 전체수명, abnormal유무
    tmp_features.append(request_features(url))  # 트래픽 길이 출력
    # 결과 출력.
    print("%s의 특징값%d개 추출완료" % (url, len(tmp_features)))

    return tmp_features


model1 = joblib.load('C:/Users/Administrator/Desktop/ai/ai/model_1.h5')
model2 = joblib.load('C:/Users/Administrator/Desktop/ai/ai/model_2.h5')
model3 = joblib.load('C:/Users/Administrator/Desktop/ai/ai/model_3.h5')
model4 = joblib.load('C:/Users/Administrator/Desktop/ai/ai/model_4.h5')
model5 = joblib.load('C:/Users/Administrator/Desktop/ai/ai/model_GB.h5')
model6 = joblib.load('C:/Users/Administrator/Desktop/ai/ai/model_HGB.h5')
model7 = joblib.load('C:/Users/Administrator/Desktop/ai/ai/model_RF.h5')

#####################################################################################
# [9/21]새롭게 추가되고 수정된 부분!#####################################################
#####################################################################################

# {{*중요!*}}
# 거의 다 완성형이긴 하지만 DGA 결과 출력 함수,proccess_cnn(url)에 모델 경로 지정해줘야 하고
# DGA결과 출력되는 함수에서 안전하면 정답값을 safe, 위험하면 정답값을 malicous로 출력하도록 정정해야함.


# 라이브러리(일단 DGA 부분은 주석처리 해놓고 따로 빼서 계속 실행 성공시켜보자)
'''
from tensorflow import keras
from DGA import max_len, tokenizer, tokenizerLabel
import tldextract  # 메인 도메인만 추출 (Ex)youtube.com)
import numpy as np


# DGA 결과 출력 함수
def proccess_cnn(url):
    reArr = ["1", "2"]
    model = keras.models.load_model("D:/models/CNN.h5")  # 모델 경로 지정해야함!!! {***}

    # 도메인 추출
    domain_parts = tldextract.extract(url)
    main_domain = domain_parts.domain + "." + domain_parts.suffix

    tokenizer.fit_on_texts(main_domain)
    sequences = tokenizer.texts_to_sequences(main_domain)

    tokenData = []
    for i in sequences:
        tokenData.append(i[0])

    padded_data = tokenData + [0] * (max_len - len(tokenData))

    org_per = model.predict([padded_data])
    predicted_class = np.argmax(org_per)  # 가장 높은 확률을 가진 인덱스
    per = float(org_per[0][predicted_class]) * 100

    label = tokenizerLabel.word_index
    for i in label:
        if label[i] == predicted_class:
            reArr[0] = i
    reArr[1] = per

    return [reArr[0],
            round(reArr[1], 4)]  # [0]에는 결과 [1]에는 확률을 리턴, {***}reArr[0]값을 안전이면 safe, 위험이면 malicious가 출력되게 바꿔야함!!!{***}
'''
# DGA 임시 함수
def proccess_cnn(url):
    probability = round(random.uniform(0.5, 0.98), 2)
    return [random.choice(['safe', 'malicious']),probability]

# 최종 함수
def url_final_result(url, model1, model2, model3, model4, model5, model6, model7):
    tmp_features, data, tmp_data = [], [], []
    url = fix_url(url)  # url을 우선 완전하게!

    # url 특징값 추출
    tmp_features.append(count_domain(url))  # 도메인의 개수
    tmp_features.append(is_random_strings(url))  # 도메인의 랜덤정도
    tmp_features.append(upper_alphabet_percentage(url))  # 도메인내 대문자 비율
    tmp_features.extend(url_mark_contain(
        url))  # 특정 기호들('//','-','@','www','&','#','%','=', '_', '~', ';') 포함 유무, 각 기호별 개수를 리스트로 반환하므로 extend사용!
    tmp_features.append(url_mark_contain2(url))  # 기여도가 낮은 기호들을 통합하여 개수 출력.
    tmp_features.append(url_malicious_string_contain(url))  # 특정 문자열 포함 개수
    tmp_features.append(url_number_string_contain(url))  # 숫자 포함 개수
    tmp_features.append(url_length(url))  # url의 길이
    tmp_features.extend(url_path(url))  # url path의 길이, 레벨
    tmp_features.extend(url_netloc(url))  # url netloc의 길이, 호스트 레벨
    tmp_features.append(url_tld_length(url))  # url tld길이
    tmp_features.extend(query_exist_features(url))  # url의 쿼리 유무 및 쿼리의 4가지 특징값 반환
    tmp_features.append(Ip_in_url(url))  # IP가 도메인의 대안으로 사용됐는지 확인.
    tmp_features.append(is_shortened_url(url))  # url의 단축 서비스 사용유무 확인.
    # 외부 특징
    tmp_features.extend(parse_features(url))  # 포트번호 생성일~현재, 현재~만료일, 전체수명, abnormal유무
    tmp_features.append(request_features(url))  # 트래픽 길이 출력
    data.append(tmp_features)

    columns_name = ['domain_count', 'is_random_strings', 'upper_alphabet_percentage',
                    'http contain_count', 'https contain_count', '. contain_count', '// contain_count', '#NAME?',
                    '@ contain_count', 'www contain_count', '#NAME?.1',
                    '_ contain_count', '~ contain_count', '? contain_count', '&,#,%,; contain_count',
                    'string_contain_count', 'number_count',
                    'url_length', 'url_path_length', 'url_path_level', 'url_netloc_length', 'url_netloc_level',
                    'url_tld_length',
                    'query_length', 'query_encoding', 'query_malicious_count', 'query_count',
                    'ip_in_url', 'tiny_url',
                    'port_number', 'domain_run_day', 'domain_remain_day', 'domain_whole_life', 'traffic_length',
                    'is_abnormal_url']

    data.insert(0, columns_name)  # 컬럼명
    input_data = pd.DataFrame(data[1:], columns=data[0])  # 특징값 추출후 입력 데이터 생성(데이터프레임)

    # 모델별 예측
    for model in [model1, model2, model3, model4, model5, model6, model7]:
        predicted_class = model.predict(input_data)  # 예측한 정답(클래스)값을 출력
        tmp_answer = 0 if predicted_class == 0 else 1
        predicted_probabilities = model.predict_proba(input_data)  # 예측이 맞을 확률 출력,
        # 결과 출력 및 반환
        if tmp_answer == 0:
            answer = 'safe'
            tmp_data.append([answer, round(predicted_probabilities.flatten()[0], 4)])  # 모델별 파일 추가
        elif tmp_answer == 1:
            answer = 'malicious'
            tmp_data.append([answer, round(predicted_probabilities.flatten()[1], 4)])  # 모델별 파일 추가

    # dga까지 tmp_data에 추가!
    tmp_data.append(proccess_cnn(url))

    # 모델별 결과 취합
    # tmp_data에 모델별 정보가 저장되어 있음.
    weights = [0.16, 0.125, 0.115, 0.14, 0.16, 0.14, 0.16, 0]  # 머신러닝 모델별 가중치
    all_weights = [0.145, 0.11, 0.1, 0.125, 0.145, 0.125, 0.145, 0.095]  # 전체 모델별 가중치
    benign_count, benign_prob, malicious_count, malicious_prob, all_benign_count, all_benign_prob, all_malicious_count, all_malicious_prob = 0, 0, 0, 0, 0, 0, 0, 0

    for i in range(len(tmp_data)):
        if tmp_data[i][0] == 'safe':
            all_benign_count += all_weights[i]
            benign_count += weights[i]
            benign_prob += weights[i] * tmp_data[i][1]
            all_benign_prob += all_weights[i] * tmp_data[i][1]
        else:
            all_malicious_count += all_weights[i]
            malicious_count += weights[i]
            malicious_prob += weights[i] * tmp_data[i][1]
            all_malicious_prob += all_weights[i] * tmp_data[i][1]

    if all_benign_count >= all_malicious_count:
        # AI값 저장
        if benign_count >= malicious_count:
            AI_answer = 'safe'  # AI의 답
            AI_prob = round(benign_prob / benign_count, 4) * 100
        else:
            AI_answer = 'malicious'
            AI_prob = round(malicious_prob / malicious_count, 4) * 100

        # DGA값 저장
        DGA_answer = tmp_data[7][0]  # DGA정답
        DGA_prob = round(tmp_data[7][1], 4) * 100  # DGA확률

        # 전체 확률 및 신뢰도 저장
        Total_answer = 'safe'  # 전체정답
        Total_prob = round(all_benign_prob / all_benign_count, 4) * 100  # 전체확률
        Truth_prob = round(all_benign_count, 4) * 100  # 신뢰도


    else:
        # AI값 저장
        if benign_count >= malicious_count:
            AI_answer = 'safe'  # AI의 답
            AI_prob = round(benign_prob / benign_count, 4) * 100
        else:
            AI_answer = 'malicious'
            AI_prob = round(malicious_prob / malicious_count, 4) * 100

        # DGA값 저장
        DGA_answer = tmp_data[7][0]  # DGA정답
        DGA_prob = round(tmp_data[7][1], 4) * 100  # DGA확률

        # 전체 확률 및 신뢰도 저장
        Total_answer = 'malicious'  # 전체정답
        Total_prob = round(all_malicious_prob / all_malicious_count, 4) * 100  # 전체확률
        Truth_prob = round(all_malicious_count, 4) * 100 # 신뢰도

    return tmp_data[0][0], tmp_data[0][1] * 100, tmp_data[1][0], tmp_data[1][1] * 100, tmp_data[2][0], tmp_data[2][1] * 100, tmp_data[3][0], \
        tmp_data[3][1] * 100, tmp_data[4][0], tmp_data[4][1] * 100, tmp_data[5][0], tmp_data[5][1] * 100, tmp_data[6][0], \
        tmp_data[6][1] * 100, tmp_data[7][0], tmp_data[7][1] * 100, Total_answer, AI_answer, DGA_answer, Total_prob, AI_prob, DGA_prob, Truth_prob

# 모델 불러오기
model1 = joblib.load('C:/Users/Administrator/Desktop/ai/ai/model_RF.h5')
model2 = joblib.load('C:/Users/Administrator/Desktop/ai/ai/model_GB.h5')
model3 = joblib.load('C:/Users/Administrator/Desktop/ai/ai/model_HGB.h5')
model4 = joblib.load('C:/Users/Administrator/Desktop/ai/ai/model_1.h5')
model5 = joblib.load('C:/Users/Administrator/Desktop/ai/ai/model_2.h5')
model6 = joblib.load('C:/Users/Administrator/Desktop/ai/ai/model_3.h5')
model7 = joblib.load('C:/Users/Administrator/Desktop/ai/ai/model_4.h5')


#  GUI에 탭을 생성하는 함수

def create_tab(notebook, text):


    # 새 탭 생성, 위젯 저장을 위한 .Frame()함수를 선언.
    tab = ttk.Frame(notebook)
    notebook.add(tab, text=text) #탭을 생성.


    # 탭에 내용 추가를 가능케 하는 부분.
    content_frame = ttk.Frame(tab)
    content_frame.pack(fill="both", expand=True)


#########################################################
    # 첫번째 탭, HOME탭
    import threading

    if text == "HOME":
        # 로딩화면 띄우는 함수


        #################################################################
        # 검색하기전 HOME탭


        # 제목 설정 -> 텍스트 입력을 위한 레이블 생성
        title_label = ttk.Label(content_frame, text="AI기반 URL 악성여부 탐지", font=("Helvetica", 24))
        title_label.pack(pady=(10, 20))

        # 검색을 위한 프레임 생성(프레임내 검색에 필요한 다양한 기능이 담긴다)
        search_frame = ttk.Frame(content_frame)
        search_frame.pack(side="top", pady=(0, 10)) # 배치 설정

        # (***)검색 입력란 설명 라벨 생성
        search_label = ttk.Label(search_frame, text="검사할 URL 입력:")
        search_label.pack(side="left", padx=5)

        # 검색 입력란 생성 -> query라는 변수로 받아온다. (즉, query = 우리가 입력받을 url)
        search_entry = ttk.Entry(search_frame, width=30)
        search_entry.pack(side="left", padx=5)

        # 검색 버튼 생성, 검색 버튼 클릭시 perform_search(search_entry.get()) 함수 실행
        search_button = ttk.Button(search_frame, text="검사", command=lambda: perform_search(search_entry.get()))
        search_button.pack(side="left", padx=5)

        # 검색 버튼 스타일 초기화, 사실 그냥 이쁘라고 한것!
        search_button.configure(style="TButton")

        # 검색 결과 표시 라벨
        loading_label = ttk.Label(content_frame, text="", wraplength=400)
        loading_label.pack(pady=10)
        result_label = ttk.Label(content_frame, text="", wraplength=400)
        result_label.pack(pady=10)

        # 검색 결과 시각화를 위한 그래프, 앞서 설정한 content_frame의 자식 위젯으로 입력.
        figure, axes = plt.subplots(1, 8, figsize=(30, 3))
        canvas = FigureCanvasTkAgg(figure, master=content_frame)
        canvas.get_tk_widget().pack()

        # 초기 막대 그래프 설정, 아직 서브플롯(ax)을 받아오지 않았기 때문에 그래프에는 어떠한 값도 뜨지 않는다.
        labels = ['MODEL1:RF', 'MODEL2:GB', 'MODEL3:HGB','ENSEMBLE MODEL1','ENSEMBLE MODEL2','ENSEMBLE MODEL3','ENSEMBLE MODEL4','[DGA] BILSTM'] #그래프에 들어갈 라벨값 8개
        for i, ax in enumerate(axes):
            ax.bar([''], [0], color='blue', alpha=0.7)
            ax.set_ylim(50, 100)  # Y 축 범위 설정
            if i == 0:
                ax.set_yticks([50, 100])
                ax.set_yticklabels(["50%  ", "100%  "], ha="center", fontsize=7)
                ax.set_xlabel(labels[i], rotation=0, ha="center", fontsize=5.5)
            else:
                ax.set_yticks([50, 100])
                ax.set_yticklabels(["50%", "100%"], ha="center", fontsize=0)
                ax.set_xlabel(labels[i], rotation=0, ha="center", fontsize=5.5)

            canvas.get_tk_widget().pack()  # 이 코드를 추가하여 각 subplot 캔버스를 포장합니다.



        # CSV 파일을 읽어와 특정 컬럼 데이터를 표에 표시
        csv_file = "C:\Download\캡스톤_urls_dataset2.csv"  # 저장한 CSV 파일 경로를 지정하세요.
        data1 = pd.read_csv(csv_file, encoding='cp1252') #인코딩 방식 지정후 csv파일 불러옴.
        data = data1.sample(n=500) #500개의 데이터를 랜덤 선택.

        # 표 초기화
        treeview = ttk.Treeview(content_frame, columns=['url'], show="headings")
        treeview.heading('url', text=f'현재 URL 데이터셋 : {len(data1)}개') #표의 제목 설정.
        treeview.column('url', width=400) #표 가로폭을 넓게 설정.

        for _, row in data.iterrows():
            url = row['url']
            label = row['label'] #악성 여부 판단을 위해 라벨값을 불러옴.

            # 'label'을 통해 악성여부를 판단하여 값에 따라 글자색 설정
            if label == 0:
                color = 'blue'
            else:
                color = 'red'

            # URL을 표에 추가하고 글자색 설정
            treeview.insert("", "end", values=(url,), tags=(color,))
            treeview.tag_configure(color, foreground=color)  # 글자색 설정

        # 표에 스크롤바 추가, 역시 컨텐트 프레임에 저장후 사용하며 수직 스크롤로 =설정.
        vsb = ttk.Scrollbar(content_frame, orient="vertical", command=treeview.yview)
        treeview.configure(yscrollcommand=vsb.set) #vsb.set는 수직 스크롤을 의미.
        vsb.pack(side="right", fill="y") #위치를 설정.
        treeview.pack(side="right", padx=10)

        ##################################################################
        # 검색 버튼 클릭 시 HOME탭
        def perform_search(query):

            def loading_task():
                search_button.configure(state="disabled")  # 검사 버튼 비활성화
                search_button.configure(text="검사중...")

                # 여기서 example() 함수를 호출하여 결과를 가져옵니다.
                model_result1, model_prob1, model_result2, model_prob2, model_result3, model_prob3, model_result4, model_prob4, \
                    model_result5, model_prob5, model_result6, model_prob6, model_result7, model_prob7, model_result8, model_prob8, \
                    result1, result2, result3, probability1, probability2, probability3, probability4 = url_final_result(query, model1, model2, model3, model4, model5, model6, model7)

                # 결과를 업데이트합니다.

                current_result = {"result1": "", "result2": "", "result3": "", "probabilities": [0, 0, 0]}
                current_result["result1"] = result1
                current_result["result2"] = result2
                current_result["result3"] = result3
                current_result["probabilities"] = [probability1, probability2, probability3]


                style = ttk.Style()

                # 검색 결과를 업데이트합니다.
                current_result["result1"] = result1
                current_result["result2"] = result2
                current_result["result3"] = result3
                current_result["probabilities"] = [probability1, probability2, probability3]

                # "Title_Style.TLabel" 스타일을 정의하고, 폰트와 글자색을 설정
                style.configure("Title1_Style.TLabel", font=("Helvetica", 12), foreground="black")

                model_results = [model_result1, model_result2, model_result3, model_result4, model_result5,
                                 model_result6,
                                 model_result7, model_result8]
                model_probs = [model_prob1, model_prob2, model_prob3, model_prob4, model_prob5, model_prob6,
                               model_prob7,
                               model_prob8]
                results = [result1, result2, result3]

                # 그래프에 값을 추가, 악성 및 정상 여부에 따라 그래프 색깔 변경
                for i, ax in enumerate(axes):

                    ax.clear()  # 기존에 값이 있다면 초기화
                    if model_results[i] == 'safe':
                        ax.bar([''], [model_probs[i]], color='blue', alpha=0.7)  # .bar함수로 그래프 그리기
                    elif model_results[i] == 'malicious':
                        ax.bar([''], [model_probs[i]], color='red', alpha=0.7)

                    ax.set_ylim(50, 100)  # Y 축 범위 설정
                    if i == 0:
                        ax.set_yticks([50, 100])
                        ax.set_yticklabels(["50%  ", "100%  "], ha="center", fontsize=7)
                        ax.set_xlabel(labels[i], rotation=0, ha="center", fontsize=5.5)

                    elif i == 7:
                        if model_results[i] == 'safe':
                            ax.bar([''], [model_probs[i]], color='navy', alpha=0.7)  # .bar함수로 그래프 그리기
                        elif model_results[i] == 'malicious':
                            ax.bar([''], [model_probs[i]], color='darkred', alpha=0.7)
                        ax.set_yticks([50, 100])
                        ax.set_yticklabels(["50%  ", "100%  "], ha="center", fontsize=0)
                        ax.set_xlabel(labels[i], rotation=0, ha="center", fontsize=5.5)

                    else:
                        ax.set_yticks([50, 100])
                        ax.set_yticklabels(["50%", "100%"], ha="center", fontsize=0)
                        ax.set_xlabel(labels[i], rotation=0, ha="center", fontsize=5.5)

                    ax.text(0, 51, f'{model_probs[i]}%', ha='center', va='center', fontsize=8.5,
                            color='white')  # 텍스트 추가



                canvas.get_tk_widget().pack()  # 이 코드를 추가하여 각 subplot 캔버스를 포장합니다.
                canvas.draw_idle()  # 변경 내용(그래프)를 화면에 출력.

                ########################################################
                # 결과값 레이블에 입력

                # 레이블 텍스트 스타일 설정값들

                style.configure("Title_Style.TLabel", font=("Helvetica", 12), foreground="black")  # 제목 텍스트 스타일
                style.configure("Explanation_Style.TLabel", font=("Helvetica", 8), foreground="black")  # 제목 텍스트 스타일
                style.configure("Good_Style.TLabel", font=("Helvetica", 10), foreground="blue")  # 좋은 결과의 텍스트 스타일
                style.configure("Bad_Style.TLabel", font=("Helvetica", 10), foreground="red")  # 나쁜 결과의 텍스트 스타일
                style.configure("normal_Style.TLabel", font=("Helvetica", 10), foreground="black")  # 나쁜 결과의 텍스트 스타일
                style.configure("Red.Horizontal.TProgressbar", troughcolor="red", background="red")  # 바 빨간색으로 설정
                style.configure("Blue.Horizontal.TProgressbar", troughcolor="blue", background="blue")  # 바 파란색으로 설정

                # 프로그레스바 스타일 설정 : 이부분 좀 복잡했음..
                pb_style_blue = ttk.Style()
                pb_style_red = ttk.Style()
                pb_style_blue.theme_use("default")  # 디폴트 옵션 설정
                pb_style_red.theme_use("default")

                # 초기화
                pb_style_blue.layout('text1.Horizontal.TProgressbar',
                                     [('Horizontal.Progressbar.trough',
                                       {'children': [('Horizontal.Progressbar.pbar',
                                                      {'side': 'left', 'sticky': 'ns'})],
                                        'sticky': 'nswe'}),
                                      ('Horizontal.Progressbar.label', {'sticky': 'nswe'})])

                pb_style_red.layout('text2.Horizontal.TProgressbar',
                                    [('Horizontal.Progressbar.trough',
                                      {'children': [('Horizontal.Progressbar.pbar',
                                                     {'side': 'left', 'sticky': 'ns'})],
                                       'sticky': 'nswe'}),
                                     ('Horizontal.Progressbar.label', {'sticky': 'nswe'})])

                # 스타일을 지정. (텍스트 가운데, 색깔 설정)
                pb_style_blue.configure('text_blue.Horizontal.TProgressbar', text='0 %', anchor='center',
                                        foreground='white',
                                        background='blue')
                pb_style_red.configure('text_red.Horizontal.TProgressbar', text='0 %', anchor='center',
                                       foreground='white',
                                       background='red')

                # 이 부분은 가시성을 위한 공백
                result_title = ttk.Label(content_frame, text=" ")
                result_title.pack(side="top", padx=10)
                result_title = ttk.Label(content_frame, text=" ")
                result_title.pack(side="top", padx=10)

                # 레이블 테이블
                result_title = ttk.Label(content_frame, text=f"입력된 url에 대한 예측 결과", style="Title_Style.TLabel", font=("Helvetica", 12))
                result_title.pack(side="top", padx=10, fill="x")  # 왼쪽 하단에 위치
                result_title = ttk.Label(content_frame, text=f"", style="Title_Style.TLabel")
                result_title.pack(side="top", padx=10, fill="x")  # 왼쪽 하단에 위치

                # 전체 결과 레이블 : 결과에 따라 색깔 다르게 표시
                if result1 == 'safe':
                    result_label1 = ttk.Label(content_frame, text=f"전체 예측 결과 : [{result1}] {probability1}%",
                                              style="Good_Style.TLabel")
                    result_label1.pack(side="top", padx=10, fill="x")

                    probability4_frame = ttk.Frame(content_frame)
                    probability4_frame.pack(side="top", padx=10, fill="x")

                    probability4_progressbar = ttk.Progressbar(probability4_frame, length=200, maximum=100,
                                                               value=probability1,
                                                               style='text_blue.Horizontal.TProgressbar')
                    probability4_progressbar.pack(fill="x")

                else:
                    result_label1 = ttk.Label(content_frame, text=f"전체 예측 결과 : [{result1}] {probability1}% ",
                                              style="Bad_Style.TLabel")
                    result_label1.pack(side="top", padx=10, fill="x")

                    probability4_frame = ttk.Frame(content_frame)
                    probability4_frame.pack(side="top", padx=10, fill="x")

                    probability4_progressbar = ttk.Progressbar(probability4_frame, length=200, maximum=100,
                                                               value=probability1,
                                                               style='text_red.Horizontal.TProgressbar')
                    probability4_progressbar.pack(fill="x")

                # AI결과 레이블
                if result2 == 'safe':
                    result_label2 = ttk.Label(content_frame, text=f"AI 예측 결과 : [{result2}] {probability2}% ",
                                              style="Good_Style.TLabel")
                    result_label2.pack(side="top", padx=10, fill="x")

                    probability4_frame = ttk.Frame(content_frame)
                    probability4_frame.pack(side="top", padx=10, fill="x")

                    probability4_progressbar = ttk.Progressbar(probability4_frame, length=200, maximum=100,
                                                               value=probability2,
                                                               style='text_blue.Horizontal.TProgressbar')
                    probability4_progressbar.pack(fill="x")
                else:
                    result_label2 = ttk.Label(content_frame, text=f"AI 예측 결과 : [{result2}] {probability2}% ",
                                              style="Bad_Style.TLabel")
                    result_label2.pack(side="top", padx=10, fill="x")

                    probability4_frame = ttk.Frame(content_frame)
                    probability4_frame.pack(side="top", padx=10, fill="x")

                    probability4_progressbar = ttk.Progressbar(probability4_frame, length=200, maximum=100,
                                                               value=probability2,
                                                               style="text_red.Horizontal.TProgressbar")
                    probability4_progressbar.pack(fill="x")

                # DGA결과 레이블
                if result3 == 'safe':
                    result_label3 = ttk.Label(content_frame, text=f"DGA 예측 결과 : [{result3}] {probability3}% ",
                                              style="Good_Style.TLabel")
                    result_label3.pack(side="top", padx=10, fill="x")

                    probability4_frame = ttk.Frame(content_frame)
                    probability4_frame.pack(side="top", padx=10, fill="x")

                    probability4_progressbar = ttk.Progressbar(probability4_frame, length=200, maximum=100,
                                                               value=probability3,
                                                               style='text_blue.Horizontal.TProgressbar')
                    probability4_progressbar.pack(fill="x")

                else:
                    result_label3 = ttk.Label(content_frame, text=f"DGA 예측 결과 : [{result3}] {probability3}% ",
                                              style="Bad_Style.TLabel")
                    result_label3.pack(side="top", padx=10, fill="x")

                    probability4_frame = ttk.Frame(content_frame)
                    probability4_frame.pack(side="top", padx=10, fill="x")

                    probability4_progressbar = ttk.Progressbar(probability4_frame, length=200, maximum=100,
                                                               value=probability3,
                                                               style="text_red.Horizontal.TProgressbar")
                    probability4_progressbar.pack(fill="x")




                # 예측 신뢰도 레이블
                result_label4 = ttk.Label(content_frame, text=f"예측 신뢰도 : {probability4}%",
                                          style="normal_Style.TLabel")
                result_label4.pack(side="top", padx=10, fill="x")

                # 설명1
                explanation = ttk.Label(content_frame, text=f" ",
                                        style="Explanation_Style.TLabel")
                explanation.pack(side="top", padx=10, fill="x")  # 왼쪽 하단에 위치

                # 설명1
                # 설명1
                explanation = ttk.Label(content_frame,
                                        text=f"※ DGA(Domain Generation Algorithms)는 악의적인 목적하에 동적으로 생성되는 도메인을 의미하며, \n   그 생성여부 확률을 도메인이 예측합니다.",
                                        style="Explanation_Style.TLabel")
                explanation.pack(side="top", padx=10, fill="x")  # 왼쪽 하단에 위치

                # 설명2
                explanation = ttk.Label(content_frame,
                                        text=f"※ 예측 신뢰도는 8개의 모델별 예측결과간의 동일성이 어느정도 인지 나타내어 총 예측의 신뢰도를 보입니다. ",
                                        style="Explanation_Style.TLabel")
                explanation.pack(side="top", padx=10, fill="x")  # 왼쪽 하단에 위치

                search_button.configure(text="검사 완료")
                # 예를 들어, result_label 등을 업데이트하고 그래프를 다시 그릴 수 있습니다.

                # 로딩 메시지 감추고 검사 버튼 활성화
                search_button.configure(text="검사 완료")
                search_button.configure(state="normal")

            # 로딩을 위한 스레드를 시작
            loading_thread = threading.Thread(target=loading_task)
            loading_thread.start()

            search_button.configure(text="검사중...")





            result_label.config(text="모델별 검사결과", justify=tk.LEFT, font=("Helvetica", 12))








#######################################################
    # 2번째 탭, 설명탭

    elif text == "설명":

        ############################################################
        # 전체 구동 방식 이미지 로드

        image = Image.open("C:/Users/Administrator/Desktop/GUI자료/GUI자료/그림01.png")  # 동작 방식을 위한 이미지 불러오기
        image = image.resize((640, 320))  # 이미지 크기 조정 (선택 사항)

        # 이미지를 Tkinter PhotoImage로 변환, GUI에서 활용하기 위해
        photo = ImageTk.PhotoImage(image)

        # 이미지를 라벨에 표시
        label = tk.Label(content_frame, image=photo)
        label.image = photo  # 이미지에 대한 참조를 유지
        label.pack(fill="both", expand=False)
        label.configure(anchor="n", padx=10, pady=2.5)  # 이미지의 위치 조정


        ############################################################
        # 구동 내용 간단한 설명
        # HTML 형식으로 하며 필요한 내용은 나중에 추가하기

        title2 = '서비스 구동 과정'
        #공백 1(가독성 높이기 위해 그냥 구분하기 편하게 하려고 추가함)v
        text2_1 = "[1단계]사용자에게 전달 받은 URL과 머신러닝모델에서 필요한 특징값 35개를 추출합니다."
        #공백 1
        text2_2 = "특징값은 예측 결과가 특징값별 가중치, 악성 URL이 갖는 특징에 대한 논문을 참고하여 35개를 선정했으며 그 종류는 다음과 같습니다. "
        text2_3 = "- 개수 기반 : 도메인 개수, http개수, https개수, .개수, //개수, -개수, @개수, www개수, =개수, 개수, ~개수, ?개수, &#%개수, "
        text2_4 = "            악성문자열 개수, 숫자 개수, 쿼리 개수, 쿼리 악성 문자열 개수,url_path 깊이 "
        text2_5 = "- 길이 기반 : url 길이, url path 길이, url netloc 길이, url tld 길이, 쿼리 길이 "
        text2_6 = "- 유무 기반 : 쿼리 인코딩 유무, url내 ip포함유무, 단축서비스 유무"
        text2_7 = "- 비율 기반 : 랜덤한 정도, 대문자 알파벳 비율"
        text2_8 = "- 도메인 기반 : 포트번호, 도메인 생성일~현재, 현재~도메인 만료일, 도메인 전체수명, 트래픽길이, abnormal유무"
        #공백2
        text2_9 = "[2단계]입력받은 특징값과 URL을 다음 8개의 모델에 입력하며 모델은 최신화가 지속적으로 진행 "
        text2_10 = "- model1 = Random Forest Model : 다수의 결정 트리를 투표방식으로 조합하여 입력된 URL이 악성인지 정상인지 판단하는 모델"
        text2_11 = "- model2 = Gradient Boosting Model : 여러 약한 모델을 결합하여 이전 모델의 오차를 보완하면서 URL의 악성 여부를 판단하는데 사용 "
        text2_12 = "- model3 = Hist Gradient Boosting Model : 효율적인 히스토그램 기반 학습과 예측을 통해 URL의 악성 여부를 판단하며, 빠르고 정확한 결과를 제공"
        text2_13 = "- model4 = Ensemble Model1(RF-GB-ET-MLP-LR) : 다양한 모델의 강점을 활용하여  URL의 악성 여부에 대한 정확한 분류 성능을 제공"
        text2_14 = "- model5 = Ensemble Model1(DT-RF-KNN-MLP-LR) : K-최근접 이웃 모델을 포함한 다양한 알고리즘을 활용하여 URL의 악성 여부에 대한 높은 분류 정확도와 강건성을 제공 "
        text2_15 = "- model6 = Ensemble Model1(RF-GB-MLP-AB-HGB) : 에이다부스트모델을 포함한 다양한 머신 러닝 기법을 활용하여 URL의 악성 여부를 판단 "
        text2_16 = "- model7 = Ensemble Model1(KNN-GNB-MLP-RF-GB) : URL의 악성 여부를 다양한 관점에서 평가하며, 다중 모델의 다양성을 통해 악성 url에 대한 정확한 분류를 강화"
        text2_17 = "- model8 = BILSTM : 딥러닝 모델로 DGA에 대한 학습결과를 바탕으로 해당 URL의 도메인이 DGA에 의한 생성여부에 대해 예측값과 예측 확률을 출력"
        # 공백2
        text2_18 = "[3단계]다음 8개의 모델을 성능별로 가중치를 부여하는 가중 다수결 조합방식으로 종합하여 특정 URl이 악성인지 아닌지 여부를 최종 출력"
        # 공백1


        text_space = " " # 가독성을 위한 공백 처리

        title3 = '자세한 코드'
        text3_1 = "더 자세한 구동 방식과 코드에 대한 내용은 아래의 링크를 통해 확인할 수 있습니다."

        # 제목 폰트 설정
        title_font = ("Helvetica", 12, "bold")

        # 구동 과정 제목
        title2_label = tk.Label(content_frame, text="서비스 구동 과정", font=title_font)
        title2_label.pack()

        # 구동 과정 내용
        text2 = text_space + "\n" + text2_1 + "\n" + text2_2 + "\n" + text_space + "\n" + text2_3 + "\n" + text2_4+ "\n" + text2_5 + "\n" + text2_6 \
                + "\n" + text2_7 + "\n" + text2_8 + "\n" + text_space + "\n" + text_space + "\n" + text2_9 + "\n" + text_space + "\n" + text2_10 + "\n" + text2_11 + "\n" + text2_12 + "\n" + text2_13 + "\n" + text2_14 + "\n" + text2_15 \
                + "\n" + text2_16 + "\n" + text2_17 + "\n" + text_space + "\n" + text_space + "\n" + text2_18 + "\n" + text_space
        text2_widget = tk.Text(content_frame, wrap="word", width=40, height=27)
        text2_widget.insert("1.0", text2)
        text2_widget.pack(fill="both", expand=False)

        # 자세한 코드 제목
        title3_label = tk.Label(content_frame, text="자세한 코드", font=title_font)
        title3_label.pack()

        # 자세한 코드 내용
        text3 = text_space + "\n" + text3_1
        text3_widget = tk.Text(content_frame, wrap="word", width=40, height=1)
        text3_widget.insert("1.0", text3)
        text3_widget.pack(fill="both", expand=True)



        ############################################################

        # 하이퍼링크 추가
        def open_link(event):
            import webbrowser
            webbrowser.open("https://www.notion.so/061ea585276d442c849b208c8af01a79") #자세한 설명을 넣을 노션 링크

        link_label = tk.Label(root, text="구동원리, 코드 등에 대한 자세한 설명을 위한 링크(클릭)", fg="blue", cursor="hand2")
        link_label.pack(side="bottom")  # 링크를 아래로 배치
        link_label.bind("<Button-1>", open_link)


#######################################################
    # 3번째 탭, 팀원

    elif text == "팀원":

        # 각 팀원들에 대한 정보, 나중에 실제에 맞게 수정해야하며 사진 링크도 필요.
        team_members = [
            {
                "name": "강민성",
                "affiliation": "중부대학교 정보보호학과",
                "student_id": "91812050",
                "role": "모델 제작, GUI",
                "image_path": "C:/Users/Administrator/Desktop/GUI자료/GUI자료/얼굴 이미지1.png"
            },
            {
                "name": "강수진",
                "affiliation": "중부대학교 정보보호학과",
                "student_id": "91900560",
                "role": "모델 제작, 웹",
                "image_path": "C:/Users/Administrator/Desktop/GUI자료/GUI자료/얼굴 이미지2.png"
            },
            {
                "name": "문동준",
                "affiliation": "중부대학교 정보보호학과",
                "student_id": "91714026",
                "role": "모델 제작, 웹",
                "image_path": "C:/Users/Administrator/Desktop/GUI자료/GUI자료/얼굴 이미지3.png"
            },
            {
                "name": "주현우",
                "affiliation": "중부대학교 정보보호학과",
                "student_id": "91709394",
                "role": "모델 제작, GUI",
                "image_path": "C:/Users/Administrator/Desktop/GUI자료/GUI자료/얼굴 이미지4.png"
            },
            {
                "name": "오현진",
                "affiliation": "중부대학교 정보보호학과",
                "student_id": "92015269",
                "role": "웹",
                "image_path": "C:/Users/Administrator/Desktop/GUI자료/GUI자료/얼굴 이미지5.png"
            }
        ]

        # 각 팀원 정보를 순서대로 표시
        for member in team_members:
            member_frame = tk.Frame(content_frame) #역시나 프레임에 넣기
            member_frame.pack(fill="both", expand=True)

            # 팀원 이미지 표시
            image = Image.open(member["image_path"])
            image = image.resize((100, 120))  # 이미지 크기 조정
            photo = ImageTk.PhotoImage(image)

            image_label = tk.Label(member_frame, image=photo)
            image_label.image = photo
            image_label.pack(side="left") #이미지는 왼쪽으로 위치 지정.

            # 팀원 정보 텍스트 표시
            info_label = tk.Label(
                member_frame,
                text=f"이름: {member['name']}\n소속: {member['affiliation']}\n학번: {member['student_id']}\n맡은 분야: {member['role']}",
                font=("Helvetica", 10)  # 글씨체 및 크기 조정
            )
            info_label.pack(side="left") #인물 정보 역시 왼쪽에 붙인다.


#########################################################
# GUI전체 설정

from PIL import Image, ImageTk

# GUI의 메인 윈도우 생성
root = tk.Tk()
root.title("푹신푹신") #***이름 변경***
root.geometry("1050x830")

# 학교 로고 이미지를 불러와 표시
icon = ImageTk.PhotoImage(file="C:/Users/Administrator/Desktop/GUI자료/GUI자료/학교로고.png")
root.iconphoto(True, icon)

# 탭 위젯 생성
notebook = ttk.Notebook(root)

# 탭 추가
create_tab(notebook, "HOME")
create_tab(notebook, "설명")
create_tab(notebook, "팀원")

# 탭 위젯 배치
notebook.pack(fill="both", expand=True)

# 전체 GUI 배경색 설정
root.configure(bg="silver")

#이벤트 루프를 실행하는 메서드, 사용자와의 상호작용이 포함
root.mainloop()

#########################################################