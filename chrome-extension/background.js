// listens for message from content.js
// forwards them to Flask backend

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.hoveredWebsiteUrl) {
        // fetch("http://localhost:5000/process-url", {
        //     method: "POST",
        //     redirect: "follow",
        //     headers: {
        //         "Content-Type": "application/json"
        //     },
        //     body: JSON.stringify({
        //         url: message.hoveredWebsiteUrl
        //     })
        // })
        // .catch(error => {
        //     console.error("Error during fetch request:", error);
        // });

        const url = 'http://localhost:5000/process-url?hoveredUrl=' + message.hoveredWebsiteUrl;

        chrome.tabs.create({ url: url });
    }
});