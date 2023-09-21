// JSON 데이터를 가져와서 HTML 테이블로 표시하는 함수
function displayJSONData() {
    // JSON 데이터 (예시)
    var jsonData = [
        { "id": 1, "name": "John Doe", "email": "john@example.com" },
        { "id": 2, "name": "Jane Smith", "email": "jane@example.com" },
        { "id": 3, "name": "Bob Johnson", "email": "bob@example.com" }
    ];

    // HTML 테이블의 tbody 요소 선택
    var tbody = document.querySelector("#data-table tbody");

    // JSON 데이터를 순회하면서 테이블에 추가
    jsonData.forEach(function(item) {
        var row = document.createElement("tr");
        row.innerHTML = "<td>" + item.id + "</td><td>" + item.name + "</td><td>" + item.email + "</td>";
        tbody.appendChild(row);
    });
}

// 페이지가 로드될 때 JSON 데이터 표시 함수 호출
document.addEventListener("DOMContentLoaded", function() {
    displayJSONData();
});