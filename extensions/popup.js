// popup.js
document.getElementById('checkUrlButton').addEventListener('click', function() {
    const url = document.getElementById('urlInput').value;
    chrome.runtime.sendMessage({
        action: "userInitiatedCheck",
        url: url
    });
});