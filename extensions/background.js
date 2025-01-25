// background.js
let socket = null;
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

// Check if the extension is enabled on startup
chrome.management.getSelf(function(info) {
    if (info.enabled) {
        connectWebSocket();
    }
});

// Listen for changes in the extension's state
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
