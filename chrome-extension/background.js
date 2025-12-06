// listens for message from content.js
// forwards them to Flask backend

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.hoveredWebsiteUrl) {
        fetch("http://localhost:5000/process-url", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                url: message.hoveredWebsiteUrl
            })
        })
        .then(response => response.json())
        .then(data => {
            console.log("Flask response:", data);
        })
        .catch(err => console.error("Error:", err));
    }
});