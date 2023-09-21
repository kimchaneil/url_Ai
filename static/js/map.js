var map
var allInputs = "";
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
function initChart() {
    
}

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
            alert("URL 삭제, 변경"); //URL이 삭제되었거나 변경되어 존재하지 않아 리다이렉션 되거나 접속이 되지 않음
        }
        else {
            addMarker(data);
            //logInput(data);
            var cnndata = "결과" + data.cnn_result + data.cnn_per + "%" 
            changeText("resultDga", cnndata)
            var urldata = "결과" + data.url_result + data.url_per + "%"
            changeText("resultURL", urldata)
            var summaryData = [data["http contain_count"], data["https contain_count"], data[". contain_count"], data["// contain_count"], data["- contain_count"], data["- contain_count"], data["@ contain_count"], data["www contain_count"], data["= contain_count"], data["_ contain_count"], data["~ contain_count"], data["? contain_count"], data["&,#,%,; contain_count"], data["string_contain_count"], data["number_count"]]
            myChart.data.datasets[0].data = summaryData;
            myChart.update();

            var element = document.getElementById("map");
            element.scrollIntoView({behavior: 'smooth', block: 'end'});
        }
        // {'domain_count': 1, 'is_random_strings': 0.3043, 'upper_alphabet_percentage': 0.0, 

        // 'http contain_count': 0, 'https contain_count': 1, 
        // '. contain_count': 2, '// contain_count': 1, '#NAME?': 0, '@ contain_count': 0, 'www contain_count': 1, '#NAME?.1': 0, '_ contain_count': 0, 
        // '~ contain_count': 0, '? contain_count': 0, '&,#,%,; contain_count': 0, 'string_contain_count': 0, 'number_count': 0,

        // 'url_length': 24, 
        // 'url_path_length': 1, 'url_path_level': 1, 'url_netloc_length': 15, 'url_netloc_level': 2, 'url_tld_length': 3, 'query_length': 0,
        // 'query_encoding': 0, 'query_malicious_count': 0, 'query_count': 0, 'ip_in_url': 0, 'tiny_url': 0, 'port_number': 443, 'domain_run_day': 6789, 
        // 'domain_remain_day': 149, 'domain_whole_life': 6938, 'traffic_length': 0, 'is_abnormal_url': 866406,

        // 'url_result': 'safe', 'url_per': 97.37, 
        // 'country': 'United States of America', 'region': 'California', 'city': 'Mountain View', 'lat': 37.405992, 'lng': -122.078515, 'error': 0, 'url': 'https://www.youtube.com', 'ip': '172.217.25.174',
        // 'cnn_result': 'non', 'cnn_per': 99.97628331184387}
    })
    .catch(function (error) {
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
    const dataContainer = document.getElementById(url_ID);
    dataContainer.innerHTML = data;
}