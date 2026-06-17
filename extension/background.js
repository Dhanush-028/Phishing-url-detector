const API_URL = "http://127.0.0.1:5000";

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {

    if (changeInfo.status !== "complete")
        return;

    if (!tab.url)
        return;

    if (
        tab.url.startsWith("chrome://") ||
        tab.url.startsWith("edge://") ||
        tab.url.startsWith("about:") ||
        tab.url.startsWith("chrome-extension://")
    ) {
        return;
    }

    try {

        console.log("Scanning:", tab.url);

        const response = await fetch(
            API_URL + "/predict",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    url: tab.url
                })
            }
        );

        const data = await response.json();

        console.log(
            "Result:",
            data.label,
            data.confidence
        );

        // ==========================
        // Security Badge System
        // ==========================

        if (data.confidence >= 0.80) {

            chrome.action.setBadgeText({
                text: "!"
            });

            chrome.action.setBadgeBackgroundColor({
                color: "#f85149"
            });

        }
        else if (data.confidence >= 0.50) {

            chrome.action.setBadgeText({
                text: "?"
            });

            chrome.action.setBadgeBackgroundColor({
                color: "#e3b341"
            });

        }
        else {

            chrome.action.setBadgeText({
                text: "OK"
            });

            chrome.action.setBadgeBackgroundColor({
                color: "#3fb950"
            });

        }

        // ==========================
        // Phishing Alert
        // ==========================

        if (data.confidence >= 0.80) {

            chrome.notifications.create({
                type: "basic",
                iconUrl: chrome.runtime.getURL("icon128.png"),
                title: "⚠ Phishing Warning",
                message:
                    `Risk Score: ${(data.confidence * 100).toFixed(1)}%

Avoid entering passwords or personal information.`
            });

            console.log(
                "PHISHING DETECTED",
                data.confidence
            );
        }

    }
    catch (err) {

        console.error(
            "Background Scan Failed:",
            err
        );

    }

});