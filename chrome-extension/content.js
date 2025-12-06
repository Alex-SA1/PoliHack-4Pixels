// runs on web pages
// adds events, handles the web content

function markSelectedLink(websiteLinkElement) {
    websiteLinkElement.style.color = "red";
}

function unmarkSelectedLink(websiteLinkElement) {
    websiteLinkElement.style.color = "";
}

let mouseOverTimer;
let currentHoveredElement = null;

function showPopup(websiteLinkElement, websiteUrl) {
    const overlay = document.createElement('div');
    overlay.classList.add('popup-overlay');

    const content = document.createElement('div');
    content.classList.add('popup-content');

    const closeButton = document.createElement('span');
    closeButton.classList.add('popup-close');
    closeButton.id = 'popup-close';
    closeButton.textContent = '×';

    const title = document.createElement('h3');
    title.textContent = 'Do you want to see advanced security details about the website?';

    const buttonContainer = document.createElement('div');
    buttonContainer.classList.add('btn-container');

    const button = document.createElement('button');
    button.textContent = 'View Security Details';
    button.classList.add('popup-button');

    buttonContainer.appendChild(button);

    content.appendChild(closeButton);
    content.appendChild(title);
    content.appendChild(buttonContainer);

    overlay.appendChild(content);

    document.body.appendChild(overlay);

    overlay.style.position = 'fixed';
    overlay.style.top = '0';
    overlay.style.left = '0';
    overlay.style.width = '100%';
    overlay.style.height = '100%';
    overlay.style.display = 'flex';
    overlay.style.justifyContent = 'center';
    overlay.style.alignItems = 'center';
    overlay.style.backgroundColor = 'rgba(0, 0, 0, 0.7)';
    overlay.style.zIndex = '1000';

    content.style.backgroundColor = '#333';
    content.style.color = '#fff';
    content.style.padding = '30px';
    content.style.borderRadius = '8px';
    content.style.boxShadow = '0 4px 10px rgba(0, 0, 0, 0.5)';
    content.style.width = '600px';
    content.style.textAlign = 'center';
    content.style.position = 'relative';

    closeButton.style.position = 'absolute';
    closeButton.style.top = '10px';
    closeButton.style.right = '10px';
    closeButton.style.fontSize = '24px';
    closeButton.style.cursor = 'pointer';
    closeButton.style.color = '#fff';

    title.style.margin = '0 0 30px 0';
    title.style.fontSize = '20px';
    title.style.fontWeight = 'bold';
    title.style.lineHeight = '1.4';

    buttonContainer.style.display = 'flex';
    buttonContainer.style.justifyContent = 'center';
    buttonContainer.style.alignItems = 'center';
    buttonContainer.style.width = '100%';
    buttonContainer.style.height = '100%';
    buttonContainer.style.margin = '0 auto';

    button.style.backgroundColor = '#73851cff';
    button.style.color = '#fff';
    button.style.border = 'none';
    button.style.padding = '10px 15px';
    button.style.fontSize = '18px';
    button.style.fontWeight = '600';
    button.style.cursor = 'pointer';
    button.style.borderRadius = '6px';
    button.style.transition = 'all 0.3s ease';
    button.style.width = '100%';
    button.style.height = '100%';
    button.style.maxWidth = '320px';
    button.style.boxShadow = '0 2px 5px rgba(0, 0, 0, 0.3)';
    button.style.display = 'block';
    button.style.margin = '0 auto';

    button.addEventListener('mouseover', function() {
        button.style.transform = 'translateY(-2px)';
        button.style.boxShadow = '0 4px 8px rgba(0, 0, 0, 0.4)';
    });
    
    button.addEventListener('mouseout', function() {
        button.style.transform = 'translateY(0)';
        button.style.boxShadow = '0 2px 5px rgba(0, 0, 0, 0.3)';
    });

    button.addEventListener('click', function () {
        chrome.runtime.sendMessage({
                                    hoveredWebsiteUrl: websiteUrl
                                });
    });

    closeButton.addEventListener('click', function () {
        overlay.style.display = 'none';
        document.body.removeChild(overlay);

        document.addEventListener('mouseover', handleMouseOver);
        currentHoveredElement = null;

        if (websiteLinkElement != null) {
            unmarkSelectedLink(websiteLinkElement);
        }
    });


    overlay.addEventListener('click', function (event) {
        if (event.target === overlay) {
            overlay.style.display = 'none';
            document.body.removeChild(overlay);
        }
    });
}


function handleMouseOver(event) {
    // Google Search Results
    if (window.location.hostname === "www.google.com" && window.location.pathname === '/search' && event.target) {
        // the first <a> in search result div structure is the main link of the result
        let hoveredTarget = event.target;
        let websiteLinkElement = hoveredTarget.closest('a');

        clearTimeout(mouseOverTimer);

        console.log("aici");

        if (websiteLinkElement) {
            const websiteUrl = websiteLinkElement.href;
            
            if (websiteUrl) {
                try {
                    if (hoveredTarget !== currentHoveredElement) {
                        currentHoveredElement = hoveredTarget;
                        if (mouseOverTimer) {
                            clearTimeout(mouseOverTimer);
                        }

                        mouseOverTimer = setTimeout(function () {
                                
                        // stop the listening on hover to process the current website
                        document.removeEventListener('mouseover', handleMouseOver);
                        showPopup(websiteLinkElement, websiteUrl);
                        markSelectedLink(websiteLinkElement);
                            
                        }, 3000);
                    }
                    
                    
                } catch (err) {
                    console.log("Error handling the hovered url!");
                }
            }
        }
    }
    else {
        // In Website Links
        if (event.target && event.target.tagName === 'A') {
            const websiteUrl = event.target.href;
            
            clearTimeout(mouseOverTimer);
        
            console.log(websiteUrl);
            if (websiteUrl) {
                try {
                    const hoveredTarget = event.target;
                    if (hoveredTarget !== currentHoveredElement) {
                        
                        currentHoveredElement = hoveredTarget;
                        
                        clearTimeout(mouseOverTimer);

                        mouseOverTimer = setTimeout(function() {

                                // stop the listening on hover to process the current website
                                document.removeEventListener('mouseover', handleMouseOver);
                                showPopup(null, websiteUrl);
                        }, 3000);
                    }
                } catch (err) {
                    console.log("Error handling the hovered url!");
                }
            }
        }
    }
};

document.addEventListener('mouseover', handleMouseOver);

