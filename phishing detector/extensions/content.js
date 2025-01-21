console.log('Content script loaded');

chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    console.log('Content script received message:', request);
    
    if (request.action === "show_warning") {
        showNotification(request.result);
    }
    return true;
});

function showNotification(result) {
    // Remove any existing notifications
    const existingNotification = document.getElementById('phishguard-notification');
    if (existingNotification) {
        existingNotification.remove();
    }

    const notificationDiv = document.createElement('div');
    notificationDiv.id = 'phishguard-notification';
    
    // Set styles based on verdict
    const isSafe = !result.is_malicious;
    const backgroundColor = isSafe ? '#4CAF50' : '#ff4444';
    const icon = isSafe ? '✅' : '⚠️';
    
    notificationDiv.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        padding: 15px;
        background-color: ${backgroundColor};
        color: white;
        text-align: center;
        z-index: 999999;
        font-family: Arial, sans-serif;
        box-shadow: 0 2px 5px rgba(0,0,0,0.2);
        transition: opacity 0.3s ease-in-out;
    `;
    
    notificationDiv.innerHTML = `
        <div style="max-width: 1200px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center;">
            <div style="display: flex; align-items: center; gap: 10px;">
                <span style="font-size: 20px;">${icon}</span>
                <span>
                    <strong>${isSafe ? 'Safe Website' : 'Warning!'}</strong>
                    ${isSafe 
                        ? ' This website has been verified as safe.' 
                        : ` This site has been detected as ${result.main_verdict}.`}
                </span>
            </div>
            <button onclick="this.parentElement.parentElement.remove()" 
                    style="background: rgba(255,255,255,0.3); border: none; color: white; 
                           padding: 5px 15px; border-radius: 3px; cursor: pointer;">
                Dismiss
            </button>
        </div>
    `;
    
    document.body.prepend(notificationDiv);

    // Optionally auto-hide after some time for safe sites
    if (isSafe) {
        setTimeout(() => {
            if (notificationDiv.parentElement) {
                notificationDiv.style.opacity = '0';
                setTimeout(() => notificationDiv.remove(), 300);
            }
        }, 15000);
    }
}