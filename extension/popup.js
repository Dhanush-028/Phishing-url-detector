const API_URL = "http://127.0.0.1:5000";

let currentUrl = "";

chrome.tabs.query(
    {active:true,currentWindow:true},
    tabs => {

        currentUrl = tabs[0].url;

        document.getElementById("currentUrl").textContent =
            currentUrl;
    }
);

document.getElementById("scanBtn")
.addEventListener("click", async () => {

    const resultBox =
        document.getElementById("result");

    resultBox.innerHTML =
        "Scanning...";

    try{

        const response = await fetch(
            API_URL + "/predict",
            {
                method:"POST",
                headers:{
                    "Content-Type":"application/json"
                },
                body:JSON.stringify({
                    url: currentUrl
                })
            }
        );

        const data = await response.json();

        const score =
            (data.confidence * 100).toFixed(1);

        let cls = "safe";

        if(data.confidence >= 0.8)
            cls = "danger";
        else if(data.confidence >= 0.5)
            cls = "warning";

        const domain = new URL(currentUrl).hostname;

let indicators = "";

if(data.top_features && data.top_features.length){

    indicators = `
        <div style="margin-top:10px">
            <b>Threat Indicators</b>
        </div>
    `;

    data.top_features.forEach(f => {
        indicators += `
            <div style="
                margin-top:5px;
                color:#f85149;
                font-size:13px;
            ">
                ⚠ ${f.feature}
            </div>
        `;
    });

}else{

    indicators = `
        <div style="
            margin-top:10px;
            color:#3fb950;
            font-size:13px;
        ">
            ✓ No suspicious indicators detected
        </div>
    `;
}

const boxColor =
    data.confidence >= 0.8
    ? "#f85149"
    : data.confidence >= 0.5
    ? "#e3b341"
    : "#3fb950";

resultBox.innerHTML = `
<div style="
    margin-top:10px;
    padding:12px;
    border-radius:10px;
    border:2px solid ${boxColor};
">

    <div style="
        font-size:18px;
        font-weight:bold;
        color:${boxColor};
        margin-bottom:10px;
    ">
        ${data.label}
    </div>

    <div><b>Domain:</b> ${domain}</div>

    <div style="margin-top:6px">
        <b>Threat Score:</b> ${score}%
    </div>

    <div style="margin-top:6px">
        <b>Risk Level:</b> ${data.risk.level}
    </div>

    <div style="margin-top:6px">
        <b>Scan Time:</b> ${data.latency_ms} ms
    </div>

    <hr style="margin:12px 0">

    <div>
        <b>Security Checks</b>
    </div>

    <div style="
        margin-top:5px;
        color:#3fb950;
    ">
        ✓ URL Analysed Successfully
    </div>

    ${indicators}

    <button
        id="reportBtn"
        style="
            width:100%;
            margin-top:15px;
            padding:10px;
            border:none;
            border-radius:8px;
            background:#58a6ff;
            color:black;
            font-weight:bold;
            cursor:pointer;
        ">
        Open Full Report
    </button>

</div>
`;

        document
        .getElementById("reportBtn")
        .addEventListener("click",()=>{

            chrome.tabs.create({
                url:
                API_URL +
                "/report?url=" +
                encodeURIComponent(currentUrl)
            });

        });

    }
    catch(err){

        resultBox.innerHTML =
            "<span class='danger'>Connection failed</span>";

    }
});