# AI기반 악성 URL판별 머신러닝 모델 코드


######################################################################################
######################################################################################
# 사용되는 라이브러리 모음
######################################################################################
######################################################################################



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
import warnings
warnings.filterwarnings("ignore", category=FutureWarning)



######################################################################################
######################################################################################
# 함수 모음, 여기는 그냥 함수만 모아놓은 곳!
######################################################################################
######################################################################################



# 어휘특징 추출함수
# domain_count
def count_domain(url):
  try:
    parsed_url = urlparse(url)
    subdomains = parsed_url.hostname.split(".")
    return len(subdomains) - 1 if subdomains[0] != "www" else len(subdomains) - 2

  except:
    return 0 #서브도메인이 없을때 오류가 발생하므로 0을 반환!

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
  total_count,change_count = 0,0 #카운트 초기화
  for i in range(len(url) - 1):
    char1 = url[i]
    char2 = url[i + 1]
    if get_char_type(char1) != get_char_type(char2):
      total_count += 1
      change_count += 1
    else:
      total_count += 1

  return round(change_count / total_count,4) if total_count !=0 else 0 #자릿수 제한해서 출력

# large_alphabet_percentage : url내 문자중 대문자의 비율
def upper_alphabet_percentage(url):
  total_chars = len(url)
  uppercase_chars = sum(1 for char in url if char.isupper())
  return round(uppercase_chars / total_chars,4) if total_chars !=0 else 0 #소수점 자릿수 4자리로 제한해서 출력

# url_length,url_path_length,url_netloc_length,url_tld length, url_path_level,
def url_length(url):
	urlLength = len(url)
	return urlLength

# url path의 길이, 폴더의 개수(path_level)
def url_path(url):
  path = urllib.parse.urlparse(url).path
  path_level = path.count('/')
  return len(path),path_level

# url netloc의 길이
def url_netloc(url):
  netloc = urllib.parse.urlparse(url).netloc
  host_level = netloc.count('.')
  return len(netloc),host_level

# url tld길이
def url_tld_length(url):
  extracted = tldextract.extract(url)
  tld_length = len(extracted.suffix)
  return tld_length


######################################################################################
# 악성 키워드 모음
mark_list = ['http:','https:','.','//','-','@','www','=', '_', '~','?'] #하나하나 확인할 리스트
mark_list2 = ['&','#','%',';'] #한번에 확인할 문자 리스트
malicious_list = ['login','phishing','malware','exploit', 'virus','trojan','spyware','ransomware','botnet','keylogger','backdoor','rootkit','spam','scam','fake'
                ,'.exe', '.dll', 'bat', 'xyz', '.info', '.club', '.ru', 'cn', 'kp', 'gov', 'mil', 'bitcoin'] #이 순서대로 반환될것.
number_list = ['1','2','3','4','5','6','7','8','9','0']
keywords = ["sql", "injection", "xss", "cross-site", "scripting", "csrf","malware", "virus", "trojan",'onlinebanking','paypal','ebay','amazon','facebook','twitter','=',
            "google analytics","facebook pixel","twitter conversion tracking","linkedin insight tag","pinterest conversion tag","snapchat pixel",
            "bing ads conversion tracking","taboola pixel","quora pixel","tawk.to","intercom","zendesk","drift","hotjar","mixpanel","segment","google tag manager",
            "facebook for developers","linkedin marketing solutions","twitter ads","adroll","google ads","doubleclick","youtube tracking","vimeo analytics",
            "soundcloud tracking","mixcloud tracking","spotify tracking","apple app store tracking","google play store tracking","firebase analytics","utm_", "tracking_id",
            'admin','password','eval','exec','SELECT','UNION','DROP','script','iframe','onerror','alert','document.cookie','document.write','location.href'] #통합된 키워드들들
######################################################################################


def url_number_string_contain(url):
  numberContainCount = 0
  tmp_string_contain =[url.count(string) for string in number_list]
  for i in range(len(tmp_string_contain)):
    numberContainCount += tmp_string_contain[i]
  return numberContainCount

def url_mark_contain(url):
  tmp_marks_contain=[url.count(char) for char in mark_list]
  return tmp_marks_contain # 리스트 형태로 반환.

def url_mark_contain2(url):
  markContainCount = 0
  tmp_string_contain =[url.count(string) for string in mark_list2]
  for i in range(len(tmp_string_contain)):
    markContainCount += tmp_string_contain[i]
  return markContainCount

def url_malicious_string_contain(url):
  maliciousContainCount = 0
  tmp_string_contain =[url.count(string) for string in malicious_list]
  for i in range(len(tmp_string_contain)):
    maliciousContainCount += tmp_string_contain[i]
  return maliciousContainCount
# query_length,query_count,is_query_encoding,query_contain

# 쿼리가 존재하면 쿼리와 관련된 정보들을 리스트 형태로 반환.
def query_exist_features(url):
  query_features = [] #리스트를 선언 및 초기화, 쿼리의 특징값들을 넣을겁니다.
  query = urlparse(url).query #쿼리를 문자열로 불러온다.
  params = urllib.parse.parse_qs(query)
  query_params = parse_qs(urlparse(url).query) #쿼리의 개수를 구한다.
  decoded_query = unquote(query) #unquote는 URL 인코딩된 문자열을 디코딩하는 함수

  # 쿼리가 존재하면 특징값을 추출하고 없으면 0을 출력.
  if query:
    query_features.append(len(query)) #쿼리 길이.
    query_features.append(1) if parse_qs(query) ==  parse_qs(unquote(query)) else query_features.append(0)  #인코딩 유무를 확인, 인코딩했으면 1을 안했으면 0을 반환.
    query_features.append(sum(1 for keyword in keywords if keyword in decoded_query) + sum(1 for keyword in keywords if keyword in query)) #쿼리자체와 디코딩된 것내에 악성 행위관련 키워드 개수
    query_features.append(len(query_params)) # 쿼리의 개수

  else:
    query_features.extend([0,0,0,0]) #쿼리가 없으면 0000을 반환,

  return query_features

# IP 주소가 URL에서 도메인 이름의 대안으로 사용되거나 16진수로 변환되어 나타내어질때 표시
def Ip_in_url(url):
	domain = urlparse(url).hostname # urlparse를 이용하여 URL에서 도메인을 추출합니다

	ip_list = re.findall(r'(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f]{8}', url) #문자열 패턴을 찾는 re.findall()함수를 사용하여 IP패턴이 url에 존재하는지 확인후 리스트에 추가가
	ip_list.extend(re.findall(r'(?:\d{1,3}\-){3}\d{1,3}|[0-9A-Fa-f]{8}', url))#가끔은 ip를 000-000-000-000형태로 나타내기도 함.
	ip_list.extend(re.findall(r"0x[\da-fA-F]{2}\.0x[\da-fA-F]{2}\.0x[\da-fA-F]{2}\.0x[\da-fA-F]{2}", url)) #ip가 16진수형태(.)로 나타내어질때도 있음.
	ip_list.extend(re.findall(r"0x[\da-fA-F]{2}\-0x[\da-fA-F]{2}\-0x[\da-fA-F]{2}\-0x[\da-fA-F]{2}", url)) #ip가 16진수형태(-)로 나타내어질때도 있음.

 	# IP 주소가 URL에서 나타나는 경우 1을, 아니면 0을 반환
	return 1 if (len(ip_list)>0 or any(ip.startswith("0x") for ip in ip_list)) else 0

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
    creation_date = whois.whois(domain).creation_date #도메인의 생성일
    expiration_date = whois.whois(domain).expiration_date #도메인의의 만료일자.

    if type(creation_date) is list:
      creation_date = creation_date[0] #리스트로 반환될때 첫번째 것을 저장
    if creation_date:
      days_since_creation = (datetime.datetime.now() - creation_date).days #생성된 이후 현재

    if type(expiration_date) is list:
      expiration_date = expiration_date[0] #리스트로 반환될때 첫번째 것을 저장.
    if expiration_date:
      days_left = (expiration_date - datetime.datetime.now()).days #만료날짜까지 남은 날짜

    days_whole = days_since_creation + days_left #전체 수명

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

    return port,days_since_creation,days_left,days_whole,is_abnormal

  except:
    return -1,-1,-1,-1,-1

# request특징 : 외부개체 로드비율, 트래픽 길이 출력
def request_features(url):
  try:
    response = requests.get(url)
    return len(response.content)

  except:
    return -1

# url과 label(안전 or 위험)을 입력값으로 하여 url의 모든 특징값을 리스트 형태로 출력해주는 함수, 시간제한을 설정했다.
def find_save_feature(url, label):
  tmp_features = [] #특징값들을 저장할 리스트로 여기서 선언하고 초기화 해준다.

  # 어휘적 특징
  tmp_features.append(url) # url자체
  tmp_features.append(label) #라벨(정답값값)
  tmp_features.append(count_domain(url)) #도메인의 개수
  tmp_features.append(is_random_strings(url)) #도메인의 랜덤정도
  tmp_features.append(upper_alphabet_percentage(url)) #도메인내 대문자 비율
  tmp_features.extend(url_mark_contain(url)) # 특정 기호들('//','-','@','www','&','#','%','=', '_', '~', ';') 포함 유무, 각 기호별 개수를 리스트로 반환하므로 extend사용!
  tmp_features.append(url_mark_contain2(url)) #기여도가 낮은 기호들을 통합하여 개수 출력.
  tmp_features.append(url_malicious_string_contain(url)) #특정 문자열 포함 개수
  tmp_features.append(url_number_string_contain(url)) #숫자 포함 개수
  tmp_features.append(url_length(url)) #url의 길이
  tmp_features.extend(url_path(url)) # url path의 길이, 레벨
  tmp_features.extend(url_netloc(url)) # url netloc의 길이, 호스트 레벨
  tmp_features.append(url_tld_length(url)) # url tld길이
  tmp_features.extend(query_exist_features(url)) #url의 쿼리 유무 및 쿼리의 4가지 특징값 반환
  tmp_features.append(Ip_in_url(url)) #IP가 도메인의 대안으로 사용됐는지 확인.
  tmp_features.append(is_shortened_url(url)) #url의 단축 서비스 사용유무 확인.
  # 외부 특징
  tmp_features.extend(parse_features(url)) # 포트번호 생성일~현재, 현재~만료일, 전체수명, abnormal유무
  tmp_features.append(request_features(url)) #트래픽 길이 출력
   # 결과 출력.
  print("%s의 특징값%d개 추출완료"%(url,len(tmp_features)))

  return tmp_features

# 어휘적 특징을 csv 형태로 저장하는 함수.
def save_csv(data,filename):

  # 학습을 용이하게 하기 위해 리스트내 요소들의 순서를 무작위로 바꿔준다.
  random.shuffle(data)

  # 리스트의 가장 첫번쨰 요소값(리스트)을 csv파일에서 사용할 컬럼명으로 지정해준다.
  columns_name = ['url','label','domain_count','is_random_strings','upper_alphabet_percentage',
       'http contain_count', 'https contain_count','. contain_count', '// contain_count','- contain_count','@ contain_count','www contain_count','= contain_count',
       '_ contain_count','~ contain_count','? contain_count','&,#,%,; contain_count',
       'string_contain_count','number_count',
       'url_length','url_path_length','url_path_level','url_netloc_length','url_netloc_level','url_tld_length',
       'query_length','query_encoding','query_malicious_count','query_count',
       'ip_in_url','tiny_url',
       'port_number', 'domain_run_day', 'domain_remain_day', 'domain_whole_life', 'is_abnormal_url','traffic_length']
  if data[0] != columns_name:
    data.insert(0,columns_name) #첫번째 요소값으로 선정(컬럼명으로 지정할것)

  print('='*60)

  # 데이터프레임 생성(0번째 컬럼명, 나머지는 데이터로 입력)
  df = pd.DataFrame(data[1:], columns=data[0])

  # 생성된 데이터 프레임을 표 형태로 출력(최대 10개의 데이터만 선별하여 출력)
  print("\n약 20개의 url에 대하여 생성된 특징값들로 다음과 같은 데이터셋을 생성.")
  print(df.to_string(index=False,max_rows = 20))

  # 앞에서 생성한 csv파일 형태로 저장, 파일명은 추후 변경 가능.
  df.to_csv(filename, index=False)

  # csv파일이 정상적으로 생성되었는지 최종 확인.
  if os.path.exists(filename):
    print('='*60)
    print("\ncsv파일로 저장 완료")

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

# 현재 시각 기준으로 openphish.com에서 악성url 500개를 불러와 학습할 url목록에 추가
def get_openphish_urls():
    url = 'https://openphish.com/feed.txt'
    response = requests.get(url)
    urls = response.content.decode().split('\n')
    urls = [url for url in urls if not url.startswith('#')]
    return urls[0:499]

# openphish에서 불러온 최신 url들의 특징값을 추출하고 이전의 csv파일에 추가로 저장하는 함수.
def realtime_add_data(org_dataset):
  # 최신 악성 url불러와 특징추출후 리스트에 저장.
  existing_items = set() #집합 설정
  new_data = [] #임시 특징값을 저장할 데이터 파일.
  tmp_urls = get_openphish_urls() #openphish.com에서 최신 url목록 500개를 불러온다.
  for tmp_url in tmp_urls:
    new_data.append(find_save_feature(tmp_url, 1)) # 특징값 추출

  # 기존 데이터셋에 저장.
  with open(org_dataset, 'r', newline='') as file:
    reader = csv.reader(file)
    lines_before = len(list(reader)) #csv파일에 추가전 길이를 미리 저장.
    for row in reader:
      existing_items.add(tuple(row)) #기존의 csv파일내의 자료들을 집합 형태로 변수에 저장, 집합값이므로 튜플 형태로 저장

  # CSV 파일에 중복되지 않는 데이터만만 추가
  with open(org_dataset, 'a', newline='') as file:
    writer = csv.writer(file)
    for row in new_data:
      if tuple(row) not in existing_items:
        existing_items.add(tuple(row))
        with open(org_dataset, 'a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(row)

  # CSV 파일 라인 수 계산 (추가한 후)
  with open(org_dataset, 'r') as file:
    reader = csv.reader(file)
    lines_after = len(list(reader))

  # 결과 출력
  print("\nCSV 파일 추가 전 라인 수:", lines_before)
  print("CSV 파일 추가 후 라인 수:", lines_after)
  print('최신화된된 데이터셋으로 학습모델 다시저장.')
  test_model(org_dataset)

# 하나씩 하기 귀찮아 만든 모든 모델에 대해 테스트및 .h5파일로 저장하는 함수
def test_model(csv_dataset):
  current_time = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S") #현재 시간 불러오기기
  data = pd.read_csv(csv_dataset, encoding='cp1252')   # CSV 파일에서 새로 학습할 데이터 읽어오기

  #data 전처리
  data.drop(['url'], axis=1, inplace=True) # 필요없는 컬럼 삭제
  data = data.astype(float) # 데이터 타입을 숫자나 소수 형태로 변경


	###############################################
	## 모델 성능 높이기 ##
	## 1. 데이터 정규화 ##
	## 2. 데이터 불균형 처리 ##


	## 1. 데이터 불균형 처리
  normal_samples = data[data['label'] == 0]
  malicious_samples = data[data['label'] == 1]
	# 정상 url을 악성 url의 개수에 맞게 복제
  normal_upsampled = resample(normal_samples, replace=True, n_samples=len(malicious_samples), random_state=42)
	# 복제된 정상 url들과 기존의 악성 url들을 결합
  data = pd.concat([malicious_samples, normal_upsampled])


	##2. 데이터 정규화
  X = data.drop("label", axis=1)  # 특징값
  y = data["label"]  # 라벨
  scaler = StandardScaler()
  X = scaler.fit_transform(X)

	################################################

  # 데이터를 train용과 test용으로 구분한다.
  train, test = train_test_split(data, test_size=0.2, random_state=2019) #train 0.8, test 0.2로 구분

  X_train = train.drop(['label'], axis=1) #x에는 label이 필요하지 않으므로 drop
  y_train = train.label #y는 결과값이므로 label를 입력.

  X_test = test.drop(['label'], axis=1) #위와 같은 이유로 drop
  y_test = test.label #y는 결과값이므로 label를 입력.

  print('='*60)
  print(current_time, '기준 데이터 셋에 대한 학습을 진행\n')
  label_counts = data['label'].value_counts()
  label_counts.plot(kind='bar')
  plt.xlabel('label')
  plt.ylabel('Count')
  plt.title('Distribution of Data by label')
  plt.show() #현재 데이터 셋 분포 그래프로 확인.
  print('데이터셋 수l : ',len(train)+len(test), '\n')
  print('결과')


  estimators1 = [('rf',RandomForestClassifier()),
                ('gb', GradientBoostingClassifier()),
                ('et',ExtraTreesClassifier()),
                ('mlp',MLPClassifier()),
                ('lr', LogisticRegression())]

  estimators2 = [('dt',DecisionTreeClassifier()),
                 ('rf', RandomForestClassifier()),
                 ('knn', KNeighborsClassifier()),
                 ('mlp',MLPClassifier()),
                 ('lr', LogisticRegression())]

  estimators3 = [('rf',RandomForestClassifier()),
                 ('gb', GradientBoostingClassifier()),
                 ('mlp',MLPClassifier()),
                 ('ab',AdaBoostClassifier()),
                 ('hgb',HistGradientBoostingClassifier())]

  estimators4 = [('knn', KNeighborsClassifier()),
                 ('mlp',MLPClassifier()),
                 ('rf',RandomForestClassifier()),
                 ('GNB',GaussianNB())]

  estimators = [estimators1,estimators2,estimators3]

  estimators2 = [estimators4]

  # 모델들, 가능한 많은 모델들을 구현해봤다.
  # DecisionTreeClassifier,KNeighborsClassifier,GaussianNB,MLPClassifier,RandomForestClassifier,LogisticRegression,AdaBoostClassifier,GradientBoostingClassifier,ExtraTreesClassifier,HistGradientBoostingClassifier,SVM
  models = {
    'RF': RandomForestClassifier(n_estimators=100),
    'GB' : GradientBoostingClassifier(n_estimators=100, learning_rate=0.1, max_depth=3, random_state=42),
    'HGB' : HistGradientBoostingClassifier(max_depth=3, random_state=42)
    }

  # 단일 모델 결과 출력 및 저장.
  for name, model in models.items():
		# 1차 학습
    model.fit(X_train, y_train)


    y_pred = model.predict(X_test) #예측
    print('%s : %.2f' % (name, metrics.accuracy_score(y_pred, y_test) * 100)) #예측값 추출
    filename = f"model_{name}_{current_time}_{metrics.accuracy_score(y_pred, y_test)}.h5" #정보들을 포함한 파일명을 실시간으로 생성성
    joblib.dump(model, '/content/drive/MyDrive/학교/4학년1학기/자료/models/'+filename) #예측 모델을 저장.


  stacking_model = StackingClassifier(estimators=estimators, final_estimator=LogisticRegression())
  voting_model = VotingClassifier(estimators=estimators, voting = 'soft')
  idx = 1

	# 조합모델 결과 출력(스택)
  for tmp_estimator in estimators:
    model = StackingClassifier(estimators=tmp_estimator, final_estimator=LogisticRegression())
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test) #예측
    print('모델조합 %d : %.2f' % (idx,metrics.accuracy_score(y_pred, y_test) * 100)) #예측값 추출
    filename = f"model_조합{idx}_{current_time}_{metrics.accuracy_score(y_pred, y_test)}.h5" #정보들을 포함한 파일명을 실시간으로 생성성
    joblib.dump(model, '/content/drive/MyDrive/학교/4학년1학기/자료/models/'+filename) #예측 모델을 저장.
    idx=idx+1

	# 조합모델 결과 출력(다수결)
  for tmp_estimator in estimators2:
    model = VotingClassifier(estimators=tmp_estimator, voting = 'soft')
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test) #예측
    print('모델조합 %d : %.2f' % (idx,metrics.accuracy_score(y_pred, y_test) * 100)) #예측값 추출
    filename = f"model_조합{idx}_{current_time}_{metrics.accuracy_score(y_pred, y_test)}.h5" #정보들을 포함한 파일명을 실시간으로 생성
    joblib.dump(model, '/content/drive/MyDrive/학교/4학년1학기/자료/models/'+filename) #예측 모델을 저장.
    idx=idx+1

  # 단일 모델 결과 출력 및 저장.
  for name, model in models.items():
    model.fit(X_train, y_train) #학습
    y_pred = model.predict(X_test) #예측
    print('%s : %.2f' % (name, metrics.accuracy_score(y_pred, y_test) * 100)) #예측값 추출
    filename = f"model_{name}_{current_time}_{metrics.accuracy_score(y_pred, y_test)}.h5" #정보들을 포함한 파일명을 실시간으로 생성성
    joblib.dump(model, '/content/drive/MyDrive/학교/4학년1학기/자료/models/'+filename) #예측 모델을 저장.

    stacking_model = StackingClassifier(estimators=estimators, final_estimator=LogisticRegression())
  idx = 1
  for tmp_estimator in [estimators1,estimators2,estimators3,estimators4]:
    model = StackingClassifier(estimators=tmp_estimator, final_estimator=LogisticRegression())
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test) #예측
    print('모델조합 %d : %.2f' % (idx,metrics.accuracy_score(y_pred, y_test) * 100)) #예측값 추출
    filename = f"model_조합{idx}_{current_time}_{metrics.accuracy_score(y_pred, y_test)}.h5" #정보들을 포함한 파일명을 실시간으로 생성성
    joblib.dump(model, '/content/drive/MyDrive/학교/4학년1학기/자료/models/'+filename) #예측 모델을 저장.
    idx=idx+1

# 위에서 생성한 데이터 파일(.h5)과 url을 입력값으로 하며 예측 정답값과 확률을 출력값으로 한다.
def url_result(model,url):
  tmp_features,data=[],[]
  url = fix_url(url) #url을 우선 완전하게!
  tmp_features.append(count_domain(url)) #도메인의 개수
  tmp_features.append(is_random_strings(url)) #도메인의 랜덤정도
  tmp_features.append(upper_alphabet_percentage(url)) #도메인내 대문자 비율
  tmp_features.extend(url_mark_contain(url)) # 특정 기호들('//','-','@','www','&','#','%','=', '_', '~', ';') 포함 유무, 각 기호별 개수를 리스트로 반환하므로 extend사용!
  tmp_features.append(url_mark_contain2(url)) #기여도가 낮은 기호들을 통합하여 개수 출력.
  tmp_features.append(url_malicious_string_contain(url)) #특정 문자열 포함 개수
  tmp_features.append(url_number_string_contain(url)) #숫자 포함 개수
  tmp_features.append(url_length(url)) #url의 길이
  tmp_features.extend(url_path(url)) # url path의 길이, 레벨
  tmp_features.extend(url_netloc(url)) # url netloc의 길이, 호스트 레벨
  tmp_features.append(url_tld_length(url)) # url tld길이
  tmp_features.extend(query_exist_features(url)) #url의 쿼리 유무 및 쿼리의 4가지 특징값 반환
  tmp_features.append(Ip_in_url(url)) #IP가 도메인의 대안으로 사용됐는지 확인.
  tmp_features.append(is_shortened_url(url)) #url의 단축 서비스 사용유무 확인.
  # 외부 특징
  tmp_features.extend(parse_features(url)) # 포트번호 생성일~현재, 현재~만료일, 전체수명, abnormal유무
  tmp_features.append(request_features(url)) #트래픽 길이 출력
  data.append(tmp_features)

  columns_name = ['domain_count','is_random_strings','upper_alphabet_percentage',
       'http contain_count', 'https contain_count','. contain_count', '// contain_count','#NAME?','@ contain_count','www contain_count','#NAME?.1',
       '_ contain_count','~ contain_count','? contain_count','&,#,%,; contain_count',
       'string_contain_count','number_count',
       'url_length','url_path_length','url_path_level','url_netloc_length','url_netloc_level','url_tld_length',
       'query_length','query_encoding','query_malicious_count','query_count',
       'ip_in_url','tiny_url',
       'port_number', 'domain_run_day', 'domain_remain_day', 'domain_whole_life', 'traffic_length','is_abnormal_url']

  data.insert(0,columns_name) #컬럼명
  input_data = pd.DataFrame(data[1:], columns=data[0]) # 입력 데이터 생성(데이터프레임)

  # 예측
  predicted_class = model.predict(input_data) #예측한 정답(클래스)값을 출력
  answer = 0 if predicted_class==0 else 1
  predicted_probabilities = model.predict_proba(input_data) #예측이 맞을 확률 출력,

  # 결과 출력 및 반환
  if answer == 0 :
    print("%s는 %f의 확률로 안전합니다. "%(url,predicted_probabilities.flatten()[0]))
    return answer, predicted_probabilities.flatten()[0]
  elif answer == 1:
    print("%s는 %f의 확률로 위험합니다. "%(url,predicted_probabilities.flatten()[1]))
    return answer, predicted_probabilities.flatten()[1]


########################################################################
# 모델 가중치 다수결 방식으로 종합후 최종 결과 확인하는 함수, 종합적으로 이 함수만 실행하면 됨.

# 위에서 생성한 데이터 파일(.h5)과 url을 입력값으로 하며 예측 정답값과 확률을 출력값으로 한다.
def url_final_result(url):
  model1 = joblib.load("./models/model_ensemble1.h5")
  model2 = joblib.load("./models/model_ensemble2.h5")
  model3 = joblib.load("./models/model_ensemble3.h5")
  model4 = joblib.load("./models/model_ensemble4.h5")
  model5 = joblib.load("./models/model_GB.h5")
  model6 = joblib.load("./models/model_HGB.h5")
  model7 = joblib.load("./models/model_RF.h5")
  tmp_features,data,tmp_data=[],[],[]
  url = fix_url(url) #url을 우선 완전하게!
  tmp_features.append(count_domain(url)) #도메인의 개수
  tmp_features.append(is_random_strings(url)) #도메인의 랜덤정도
  tmp_features.append(upper_alphabet_percentage(url)) #도메인내 대문자 비율
  tmp_features.extend(url_mark_contain(url)) # 특정 기호들('//','-','@','www','&','#','%','=', '_', '~', ';') 포함 유무, 각 기호별 개수를 리스트로 반환하므로 extend사용!
  tmp_features.append(url_mark_contain2(url)) #기여도가 낮은 기호들을 통합하여 개수 출력.
  tmp_features.append(url_malicious_string_contain(url)) #특정 문자열 포함 개수
  tmp_features.append(url_number_string_contain(url)) #숫자 포함 개수
  tmp_features.append(url_length(url)) #url의 길이
  tmp_features.extend(url_path(url)) # url path의 길이, 레벨
  tmp_features.extend(url_netloc(url)) # url netloc의 길이, 호스트 레벨
  tmp_features.append(url_tld_length(url)) # url tld길이
  tmp_features.extend(query_exist_features(url)) #url의 쿼리 유무 및 쿼리의 4가지 특징값 반환
  tmp_features.append(Ip_in_url(url)) #IP가 도메인의 대안으로 사용됐는지 확인.
  tmp_features.append(is_shortened_url(url)) #url의 단축 서비스 사용유무 확인.
  # 외부 특징
  tmp_features.extend(parse_features(url)) # 포트번호 생성일~현재, 현재~만료일, 전체수명, abnormal유무
  tmp_features.append(request_features(url)) #트래픽 길이 출력
  data.append(tmp_features)

  columns_name = ['domain_count','is_random_strings','upper_alphabet_percentage',
       'http contain_count', 'https contain_count','. contain_count', '// contain_count','#NAME?','@ contain_count','www contain_count','#NAME?.1',
       '_ contain_count','~ contain_count','? contain_count','&,#,%,; contain_count',
       'string_contain_count','number_count',
       'url_length','url_path_length','url_path_level','url_netloc_length','url_netloc_level','url_tld_length',
       'query_length','query_encoding','query_malicious_count','query_count',
       'ip_in_url','tiny_url',
       'port_number', 'domain_run_day', 'domain_remain_day', 'domain_whole_life', 'traffic_length','is_abnormal_url']

  data.insert(0,columns_name) #컬럼명
  input_data = pd.DataFrame(data[1:], columns=data[0]) # 특징값 추출후 입력 데이터 생성(데이터프레임)

  # 가중 다수결 앙셈블 방식을 활용해 7개 모델에 대한 최종 결과 출력.
  for model in [model1, model2, model3, model4, model5, model6, model7]:
    predicted_class = model.predict(input_data) #예측한 정답(클래스)값을 출력
    answer = 0 if predicted_class==0 else 1
    predicted_probabilities = model.predict_proba(input_data) #예측이 맞을 확률 출력,
    # 결과 출력 및 반환
    if answer == 0 :
      #print("%s는 %f의 확률로 안전합니다. "%(url,predicted_probabilities.flatten()[0]))
      tmp_data.append([answer,round(predicted_probabilities.flatten()[0],4)])
    elif answer == 1:
      #print("%s는 %f의 확률로 위험합니다. "%(url,predicted_probabilities.flatten()[1]))
      tmp_data.append([answer,round(predicted_probabilities.flatten()[1],4)])

  weights = [0.16, 0.125, 0.115, 0.14, 0.16, 0.14, 0.16] #모델별로 부여할 가중치, numpy배열로 변환
  benign_count,benign_prob, malicious_count, malicious_prob = 0,0,0,0
  for i in range(len(data)):
    if tmp_data[i][0] == 0:
      benign_count += weights[i]
      benign_prob += weights[i]*tmp_data[i][1]
    else:
      malicious_count += weights[i]
      malicious_prob += weights[i]*tmp_data[i][1]

  # if benign_count >= malicious_count:
  #   answer = '안전'
  #   prob = round(benign_prob/benign_count,4)
  #   tmpArr = [answer, round(prob,4)*100]
  #   return tmpArr

  # else:
  #   answer = '위험'
  #   prob = round(malicious_prob/malicious_count,4)
  #   tmpArr = [answer, round(prob,4)*100]
  #   return tmpArr
  if benign_count >= malicious_count:
    answer = 'safe'
    prob = round(benign_prob/benign_count,4)
  else:
    answer = 'dan'
    prob = round(malicious_prob/malicious_count,4)
  result = {name:value for name, value in zip(columns_name, tmp_features)}
  result['url_result'] = answer
  result['url_per'] = round(prob,4)*100
  return result



# -*- coding: utf-8 -*-