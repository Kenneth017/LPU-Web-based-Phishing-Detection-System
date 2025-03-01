// background.js
let socket = null;
let tabsWithContentScript = new Set();
let analyzedDomains = new Map(); // Track analyzed domains per tab

// Function to extract domain from URL
function extractDomain(url) {
    try {
        const urlObj = new URL(url);
        return urlObj.hostname;
    } catch (e) {
        console.error('Invalid URL:', url);
        return '';
    }
}

// Function to check if URL should be analyzed
function shouldAnalyzeUrl(tabId, url) {
    if (!url) return false;
    
    // Skip chrome:// and other browser URLs
    if (url.startsWith('chrome://') || 
        url.startsWith('chrome-extension://') || 
        url.startsWith('about:') || 
        url.startsWith('edge://')) {
        return false;
    }

    const domain = extractDomain(url);
    
    // Check if this domain has been analyzed for this tab
    if (!analyzedDomains.has(tabId)) {
        analyzedDomains.set(tabId, new Set());
    }
    
    const tabDomains = analyzedDomains.get(tabId);
    if (tabDomains.has(domain)) {
        console.log('Domain already analyzed for this tab, skipping check:', domain);
        return false;
    }

    // Add the domain to the set of analyzed domains for this tab
    tabDomains.add(domain);
    return true;
}

// Listener for messages from content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (sender.tab) {
        tabsWithContentScript.add(sender.tab.id);
    }
    // Handle both types of URL check requests
    if (message.action === "checkUrl") {
        checkUrl(sender.tab.id, message.url, false); // Regular check
    } else if (message.action === "userInitiatedCheck") {
        checkUrl(sender.tab.id, message.url, true);  // User initiated check - save to history
    } else if (message.type === 'analyze_email') {
        console.log('Received email analysis request:', message);
        if (socket && socket.readyState === WebSocket.OPEN) {
            console.log('Sending email data for analysis');
            socket.send(JSON.stringify({
                type: 'analyze_email',
                data: message.data
            }));
        } else {
            console.log('WebSocket not ready. Unable to analyze email.');
            sendResponse({ error: 'WebSocket not connected' });
        }
        return true; // Indicates that the response is sent asynchronously
    }
});

// Clean up when tabs are closed
chrome.tabs.onRemoved.addListener((tabId) => {
    tabsWithContentScript.delete(tabId);
    analyzedDomains.delete(tabId);
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
            
            const tabs = await chrome.tabs.query({active: true, currentWindow: true});
            if (tabs[0]) {
                if (result.type === 'email_analysis_result') {
                    console.log('Received email analysis result');
                    await sendMessageToTab(tabs[0], {
                        action: "show_email_analysis",
                        result: result.data
                    });
                } else {
                    // Handle URL check results
                    await sendMessageToTab(tabs[0], {
                        action: "show_warning",
                        result: result
                    });
                }
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
function checkUrl(tabId, url, saveToHistory = false) {
    if (!shouldAnalyzeUrl(tabId, url)) {
        console.log('URL check skipped:', url);
        return;
    }

    if (socket && socket.readyState === WebSocket.OPEN) {
        console.log('Checking URL:', url);
        console.log('Save to history:', saveToHistory);
        socket.send(JSON.stringify({
            type: 'check_url',
            url: url,
            analyze: true,
            saveToHistory: saveToHistory
        }));
    } else {
        console.log('WebSocket not ready. Unable to check URL.');
    }
}

// Tab update listener
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.active && tab.url) {
        checkUrl(tabId, tab.url, false);  // Automatic check - don't save to history
    }
});

// Tab activation listener
chrome.tabs.onActivated.addListener((activeInfo) => {
    chrome.tabs.get(activeInfo.tabId, (tab) => {
        if (tab.url) {
            checkUrl(tab.id, tab.url, false);  // Automatic check - don't save to history
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
