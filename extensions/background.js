// background.js
let socket = null;
let lastCheckedUrl = '';
let tabsWithContentScript = new Set(); // Track tabs with content script

// Add listener for content script ready message
chrome.runtime.onMessage.addListener((message, sender) => {
    if (sender.tab) {
        tabsWithContentScript.add(sender.tab.id);
    }
});

// Clean up when tabs are closed
chrome.tabs.onRemoved.addListener((tabId) => {
    tabsWithContentScript.delete(tabId);
});

// Modified sendMessageToTab function
async function sendMessageToTab(tab, message) {
    if (!tab || !tabsWithContentScript.has(tab.id)) {
        console.log('Tab not ready for messages:', tab?.id);
        return;
    }

    try {
        await chrome.tabs.sendMessage(tab.id, message);
    } catch (error) {
        console.log('Error sending message to tab:', error);
        tabsWithContentScript.delete(tab.id);
    }
}

function connectWebSocket() {
    console.log('Attempting to connect to WebSocket...');
    
    socket = new WebSocket('wss://phishing-detection-system-jig1.onrender.com/ws');

    socket.onopen = function(e) {
        console.log('WebSocket connected!');
        checkCurrentTab();
    };

    socket.onmessage = async function(event) {
        console.log('Received message:', event.data);
        try {
            const result = JSON.parse(event.data);
            console.log('Parsed result:', result);
            
            if (result.type === 'pong') {
                console.log('Received pong from server');
                return;
            }
            
            // Modified message sending
            const tabs = await chrome.tabs.query({active: true, currentWindow: true});
            if (tabs[0]) {
                await sendMessageToTab(tabs[0], {
                    action: "show_warning",
                    result: result
                });
            }
        } catch (e) {
            console.error('Error processing message:', e);
        }
    };

    socket.onclose = function(event) {
        console.log('WebSocket disconnected, reconnecting in 5 seconds...');
        setTimeout(connectWebSocket, 5000);
    };

    socket.onerror = function(error) {
        console.error('WebSocket Error:', error);
    };
}

function checkCurrentTab() {
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        if (tabs[0] && socket && socket.readyState === WebSocket.OPEN) {
            const url = tabs[0].url;
            if (url && !url.startsWith('chrome://') && url !== lastCheckedUrl) {
                console.log('Checking URL:', url);
                socket.send(JSON.stringify({type: 'check_url', url: url}));
                lastCheckedUrl = url;
            }
        }
    });
}

// Listen for tab updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url && 
        !tab.url.startsWith('chrome://') && 
        socket && socket.readyState === WebSocket.OPEN &&
        tab.url !== lastCheckedUrl) {
        console.log('Tab updated:', tab.url);
        socket.send(JSON.stringify({type: 'check_url', url: tab.url}));
        lastCheckedUrl = tab.url;
    }
});

// Initial connection
connectWebSocket();

// Keep alive
setInterval(() => {
    if (socket && socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({ type: 'ping' }));
    }
}, 30000);