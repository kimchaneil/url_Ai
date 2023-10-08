var map
var allInputs = "";
var csvFilePath = "../../dataset/print.csv";

function initMap() { //초기 지도 설정
    var myLatLng = {lat: 37.713766, lng: 126.889334};

    // 지도 만들고 중앙으로 옮기기
    map = new google.maps.Map(document.getElementById('map'), {
        zoom: 16,
        center: myLatLng
    });

    // 마커 추가
    var marker = new google.maps.Marker({
        position: myLatLng,
        map: map,
        title: '푹신푹신'
    });

    // 마커에 표시할 정보
    var infowindow = new google.maps.InfoWindow({
        content: 'Latitude: ' + myLatLng.lat + '<br>Longitude: ' + myLatLng.lng
    });
        marker.addListener('click', function() {
        infowindow.open(map, marker);
    });
}

// 샘플링 함수 호출

function checkURL() {
    var url = document.getElementById("input").value;
    fetch("http://127.0.0.1:5000/process_url", {
        method: "POST", //기본값 GET
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url }), //json객체를 문자열로 변환해서 전달
    })
    .then(response => response.json())
    .then(function (data) {
        if (data.error==1){
            alert("잘못된 URL 입니다."); //URL이 삭제되었거나 변경되어 존재하지 않아 리다이렉션 되거나 접속이 되지 않음
        }
        else {
            addMarker(data);
            var cnndata = "DGA 예측 결과 :  [" + data.cnn + "] " + data.cnn_per + "%" 
            changeText("resultDga", cnndata)
            var urldata = "AI 예측 결과 :  [" + data.AI_answer + "] " + data.AI_prob + "%"
            changeText("resultURL", urldata)
            var totaldata = "전체 예측 결과 :  [" + data.Total_answer + "] " + data.Total_prob + "%"
            changeText("resultTotal", totaldata)
            var trustdata = "예측 신뢰도 : " + data.Truth_prob + "%" 
            changeText("trustRsult", trustdata)
            // {'model1': 'safe', 'model1_per': 98.42, 'model2': 'safe', 'model2_per': 98.11, 'model3': 'safe', 'model3_per': 98.45, 'model4': 'safe', 
            //  'model4_per': 99.5, 'GB': 'safe', 'GB_per': 96.13000000000001, 'HGB': 'safe', 'HGB_per': 95.92, 'RF': 'safe', 'RF_per': 99.0, 'CNN': 'safe',
            //  'CNN_per': 99.9763, 'AI_answer': 'safe', 'AI_prob': 97.9123, 'Total_answer': 'safe', 'Total_prob': 98.1082, 'Truth_prob': 99.0}
            var summaryData = [data["model1_per"], data["model2_per"], data["model3_per"], data["model4_per"], data["GB_per"], data["HGB_per"], data["RF_per"], data["cnn_per"]]
            myChart.data.datasets[0].data = summaryData;
            myChart.update();
            var element = document.getElementById("map");
            hideLoading(); // 작업 완료시 로딩 표시를 숨깁니다.
            element.scrollIntoView({behavior: 'smooth', block: 'end'});
        }
    })
    .catch(function (error) {
        logErrorAndHandle(error);
        alert("Error");
    });
}
//http://www.germany-secure.com/449941/deu/problem/B0024YZ354/sec/konto_verifizieren/ 접속 안됨
function addMarker(data) {
    var lat = parseFloat(data.lat);
    var lng = parseFloat(data.lng);
    var latLng = {lat: lat, lng: lng};
    var newCenter = new google.maps.LatLng(latLng);
    map.setCenter(newCenter);
    map.setZoom(12);
    var marker = new google.maps.Marker({
        position: latLng,
        map: map,
        title: data.url
    });
    var infowindow = new google.maps.InfoWindow({
        content: 'URL :' + data.url + '<br>IP :' + data.ip + '<br>Country :' + data.country + '<br>region :' + data.region + '<br>City :' + data.city + '<br>Latitude: ' + latLng.lat + '<br>Longitude: ' + latLng.lng
    });
    marker.addListener('click', function() {
        infowindow.open(map, marker);
    });
}
function logInput(data) {
    var userInput = 'URL :' + data.url + 'IP :' + data.ip + 'Country :' + data.country //+ 'region :' + data.region + 'City :' + data.city + 'Latitude: ' + latLng.lat + 'Longitude: ' + latLng.lng
    allInputs += userInput + "\n";
    document.getElementById("log_inputs").value = allInputs;
}
function changeText(url_ID, data) {
    var dataContainer = document.getElementById(url_ID);
    dataContainer.innerHTML = data;
}
function showLoading() {
    var show = document.getElementById('loadingContainer');
    show.style.display = "block";
    checkURL()
}

function hideLoading() {
    var hide = document.getElementById('loadingContainer');
    hide.style.display = "none";
}
function logErrorAndHandle(error) {
    // 에러 로그 출력
    console.error("An error occurred:", error);

    // 에러 처리 또는 추가 작업 수행 가능
    // 예: 사용자에게 메시지 표시 또는 다른 동작 수행
}