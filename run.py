from flask import Flask, render_template, request, jsonify
# render_template 라이브러리는 파이썬 파일과 같은 위치에 templates 폴더 안에 있는 html만 가능함
# jsonify json data를 내보내기 위함
from ipGeography import urlToIP, location
from loadAI import proccess_cnn
from URL import url_final_result

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')
    # x 변수 html에 전달, html에서 {{x}}로 받음
@app.route('/code.html')
def code():
    return render_template('code.html')
    # x 변수 html에 전달, html에서 {{x}}로 받음
@app.route('/team.html')
def team():
    return render_template('team.html')
    # x 변수 html에 전달, html에서 {{x}}로 받음
@app.route('/index.html')
def home():
    return render_template('index.html')
    # x 변수 html에 전달, html에서 {{x}}로 받음

@app.route('/process_url', methods=['POST'])
def process_url():
    url = request.json['url']
    ip = urlToIP(url)
    if ip == 1:
        data = {'error': 1}
        return jsonify(data)
    locate = location(ip)
    cnn = proccess_cnn(url)
    resulturl = url_final_result(url)
    resulturl['country'] = locate['country_name']  # 나라
    resulturl['region'] = locate['region_name']  #지역
    resulturl['city'] = locate['city_name']  # 도시
    resulturl['lat'] = locate['latitude']  # 위도
    resulturl['lng'] = locate['longitude']  # 경도
    resulturl['error'] = 0
    resulturl['url'] = url
    resulturl['ip'] = ip
    resulturl['cnn_result'] = cnn[0]
    resulturl['cnn_per'] = cnn[1]
    print(resulturl)
    return jsonify(resulturl)

if __name__ == '__main__':
    app.run(debug=True)  # debug=True : 개발 중 수정한 파일이 실시간으로 반영되어 재가동 됨