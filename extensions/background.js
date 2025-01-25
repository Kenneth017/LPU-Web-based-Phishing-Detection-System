// background.js
let socket = null;
let tabsWithContentScript = new Set();
let lastCheckedUrl = '';

// Listener for messages from content scripts
chrome.runtime.onMessage.addListener((message, sender) => {
    if (sender.tab) {
        tabsWithContentScript.add(sender.tab.id);
    }
    // Handle both types of URL check requests
    if (message.action === "checkUrl") {
        checkUrl(message.url, false); // Regular check
    } else if (message.action === "userInitiatedCheck") {
        checkUrl(message.url, true);  // User initiated check - save to history
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

function disconnectWebSocket() {
    if (socket) {
        socket.close();
        socket = null;
    }
}

function connectWebSocket() {
    if (socket && socket.readyState === WebSocket.OPEN) {
        return;  // Already connected
    }

    console.log('Attempting to connect to WebSocket...');
    
    socket = new WebSocket('wss://phishing-detection-system-jig1.onrender.com/ws');

    socket.onopen = function(e) {
        console.log('WebSocket connected!');
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
        console.log('WebSocket disconnected');
        socket = null;
        // Only reconnect if the extension is enabled
        chrome.management.getSelf(function(info) {
            if (info.enabled) {
                console.log('Reconnecting in 5 seconds...');
                setTimeout(connectWebSocket, 5000);
            }
        });
    };

    socket.onerror = function(error) {
        console.error('WebSocket Error:', error);
    };
}

// Modified checkUrl function
function checkUrl(url, saveToHistory = false) {
    if (socket && socket.readyState === WebSocket.OPEN && url !== lastCheckedUrl) {
        console.log('Checking URL:', url);
        console.log('Save to history:', saveToHistory);
        socket.send(JSON.stringify({
            type: 'check_url',
            url: url,
            analyze: true,
            saveToHistory: saveToHistory
        }));
        lastCheckedUrl = url;
    } else {
        console.log('WebSocket not ready or URL already checked. Unable to check URL.');
    }
}

// Tab update listener (single instance)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.active && tab.url && 
        !tab.url.startsWith('chrome://')) {
        checkUrl(tab.url, false);  // Automatic check - don't save to history
    }
});

// Tab activation listener (single instance)
chrome.tabs.onActivated.addListener((activeInfo) => {
    chrome.tabs.get(activeInfo.tabId, (tab) => {
        if (tab.url && !tab.url.startsWith('chrome://')) {
            checkUrl(tab.url, false);  // Automatic check - don't save to history
        }
    });
});

// Extension state management
chrome.management.getSelf(function(info) {
    if (info.enabled) {
        connectWebSocket();
    }
});

chrome.management.onEnabled.addListener(function(info) {
    if (info.id === chrome.runtime.id) {
        connectWebSocket();
    }
});

chrome.management.onDisabled.addListener(function(info) {
    if (info.id === chrome.runtime.id) {
        disconnectWebSocket();
    }
});

// Keep WebSocket connection alive with minimal pings
setInterval(() => {
    chrome.management.getSelf(function(info) {
        if (info.enabled && socket && socket.readyState === WebSocket.OPEN) {
            socket.send(JSON.stringify({ type: 'ping' }));
        }
    });
}, 30000);