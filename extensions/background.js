let socket = null;
let lastCheckedUrl = '';

function connectWebSocket() {
    console.log('Attempting to connect to WebSocket...');
    
    // Use wss:// for secure WebSocket connection
    socket = new WebSocket('wss://phishing-detection-system-jig1.onrender.com/ws');

    socket.onopen = function(e) {
        console.log('WebSocket connected!');
        checkCurrentTab();
    };

    socket.onmessage = function(event) {
        console.log('Received message:', event.data);
        try {
            const result = JSON.parse(event.data);
            console.log('Parsed result:', result);
            
            if (result.type === 'pong') {
                console.log('Received pong from server');
                return;
            }
            
            // Always show notification, whether safe or unsafe
            chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
                if (tabs[0]) {
                    chrome.tabs.sendMessage(tabs[0].id, {
                        action: "show_warning",
                        result: result
                    }).catch(err => console.error('Error sending message to tab:', err));
                }
            });
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