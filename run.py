# -*- coding: utf-8 -*-
from flask import Flask, render_template, request, jsonify
# render_template 라이브러리는 파이썬 파일과 같은 위치에 templates 폴더 안에 있는 html만 가능함
# jsonify json data를 내보내기 위함
from ipGeography import urlToIP, location
from result import url_final_result
import pandas as pd
import threading
from waitress import serve

app = Flask(__name__)


@app.route('/')
def index():
    # x 변수 html에 전달, html에서 {{x}}로 받음
    csv_file = "D:\AiURL\dataset\print.csv"
    data = pd.read_csv(csv_file, encoding='cp1252')
    # 데이터 프레임을 HTML 테이블로 변환
    random_rows = data.sample(n=500)
    # table_html = random_rows.to_html(classes='table table-striped', index=False)

    return render_template('index.html', table_html=random_rows)

@app.route('/code.html')
def code():
    return render_template('code.html')

@app.route('/team.html')
def team():
    return render_template('team.html')

@app.route('/index.html')
def home():
    # x 변수 html에 전달, html에서 {{x}}로 받음
    csv_file = "D:\AiURL\dataset\print.csv"
    data = pd.read_csv(csv_file, encoding='cp1252')
    # 데이터 프레임을 HTML 테이블로 변환
    random_rows = data.sample(n=500)
    # table_html = random_rows.to_html(classes='table table-striped', index=False)

    return render_template('index.html', table_html=random_rows)

@app.route('/process_url', methods=['POST'])
def process_url():
    url = request.json['url']
    ip = urlToIP(url)
    if ip == 1:
        data = {'error': 1}
        return jsonify(data)
    locate = location(ip)
    resulturl = url_final_result(url)
    resulturl['country'] = locate['country_name']  # 나라
    resulturl['region'] = locate['region_name']  #지역
    resulturl['city'] = locate['city_name']  # 도시
    resulturl['lat'] = locate['latitude']  # 위도
    resulturl['lng'] = locate['longitude']  # 경도
    resulturl['error'] = 0
    resulturl['url'] = url
    resulturl['ip'] = ip
    print(resulturl)
    return jsonify(resulturl)

if __name__ == '__main__':
    # Flask 애플리케이션을 백그라운드 쓰레드에서 실행합니다.
    thread = threading.Thread(target=app.run, kwargs={'host': '0.0.0.0', 'port': 8080})
    thread.start()

    # Waitress를 사용해 백그라운드 서버를 실행합니다.
    serve(app, host='0.0.0.0', port=8080)