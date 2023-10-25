# -*- coding: utf-8 -*-

########################################################
# 최종본
########################################################

########################################################
# 라이브러리1 : GUI만들때만 필요한 것들.

import pandas as pd #csv파일을 읽어올때
import random
import pandas as pd
import joblib
import time

import warnings
warnings.filterwarnings("ignore", category=FutureWarning)

import whois
from urllib.parse import urlparse, urlunparse, unquote, parse_qs
import urllib.request
import requests
import re
from datetime import datetime
import pandas as pd
import random
import time
import datetime
import tldextract
import joblib

from loadAI import proccess_cnn





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

#####################################################################################
# [9/21]새롭게 추가되고 수정된 부분!#####################################################
#####################################################################################

# {{*중요!*}}
# 거의 다 완성형이긴 하지만 DGA 결과 출력 함수,proccess_cnn(url)에 모델 경로 지정해줘야 하고
# DGA결과 출력되는 함수에서 안전하면 정답값을 safe, 위험하면 정답값을 malicous로 출력하도록 정정해야함.


# 라이브러리(일단 DGA 부분은 주석처리 해놓고 따로 빼서 계속 실행 성공시켜보자)

from tensorflow import keras
from DGA import max_len, tokenizer, tokenizerLabel
import tldextract  # 메인 도메인만 추출 (Ex)youtube.com)
import numpy as np

# 최종 함수
def url_final_result(url):
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
            tmp_data.append('safe')
            tmp_data.append(round(predicted_probabilities.flatten()[0], 4)*100)
        elif tmp_answer == 1:
            tmp_data.append('malicious')
            tmp_data.append(round(predicted_probabilities.flatten()[0], 4)*100)
    # dga까지 tmp_data에 추가!
    cnndata = proccess_cnn(url, dgaModel)
    for i in cnndata:
        tmp_data.append(i)

    # 모델별 결과 취합
    # tmp_data에 모델별 정보가 저장되어 있음.
    weights = [0.16, 0.125, 0.115, 0.14, 0.16, 0.14, 0.16, 0]  # 머신러닝 모델별 가중치
    all_weights = [0.145, 0.11, 0.1, 0.125, 0.145, 0.125, 0.145, 0.095]  # 전체 모델별 가중치
    benign_count, benign_prob, malicious_count, malicious_prob, all_benign_count, all_benign_prob, all_malicious_count, all_malicious_prob = 0, 0, 0, 0, 0, 0, 0, 0
    #0-1 2-3 2-4- 3-6
    for i in range(0, len(tmp_data), 2):
        j=i+1
        k=int(i/2)
        if tmp_data[i] == 'safe':
            all_benign_count += all_weights[k]
            benign_count += weights[k]
            benign_prob += weights[k] * tmp_data[j]
            all_benign_prob += all_weights[k] * tmp_data[j]
        else:
            all_malicious_count += all_weights[k]
            malicious_count += weights[k]
            malicious_prob += weights[k] * tmp_data[j]
            all_malicious_prob += all_weights[k] * tmp_data[j]

    if all_benign_count >= all_malicious_count:
        # AI값 저장
        if benign_count >= malicious_count:
            AI_answer = 'safe'  # AI의 답
            AI_prob = round(benign_prob / benign_count, 2)
        else:
            AI_answer = 'malicious'
            AI_prob = round(malicious_prob / malicious_count, 2)

        # 전체 확률 및 신뢰도 저장
        Total_answer = 'safe'  # 전체정답
        Total_prob = round(all_benign_prob / all_benign_count, 2)  # 전체확률
        Truth_prob = round(all_benign_count, 4) * 100 # 신뢰도

    else:
        # AI값 저장
        if benign_count >= malicious_count:
            AI_answer = 'safe'  # AI의 답
            AI_prob = round(benign_prob / benign_count, 2)
        else:
            AI_answer = 'malicious'
            AI_prob = round(malicious_prob / malicious_count, 2)
        # 전체 확률 및 신뢰도 저장
        Total_answer = 'malicious'  # 전체정답
        Total_prob = round(all_malicious_prob / all_malicious_count, 2)  # 전체확률
        Truth_prob = round(all_malicious_count, 4) * 100  # 신뢰도
    model_name = ['model1', 'model1_per', 'model2', 'model2_per', 'model3', 'model3_per','model4', 'model4_per', 'GB','GB_per', 'HGB', 'HGB_per', 'RF', 'RF_per', 'cnn', 'cnn_per']

    result = {name:value for name, value in zip(model_name, tmp_data)}
    result['AI_answer'] = AI_answer
    result['AI_prob'] = AI_prob
    result['Total_answer'] = Total_answer
    result['Total_prob'] = Total_prob
    result['Truth_prob'] = Truth_prob
    return result

model1 = joblib.load("./models/model_ensemble1.h5")
model2 = joblib.load("./models/model_ensemble2.h5")
model3 = joblib.load("./models/model_ensemble3.h5")
model4 = joblib.load("./models/model_ensemble4.h5")
model5 = joblib.load("./models/model_GB.h5")
model6 = joblib.load("./models/model_HGB.h5")
model7 = joblib.load("./models/model_RF.h5")
dgaModel = keras.models.load_model("./models/CNN.h5")