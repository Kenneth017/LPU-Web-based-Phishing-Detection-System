console.log('Popup script loaded');

document.addEventListener('DOMContentLoaded', function() {
    console.log('Popup DOM loaded');
    const statusDiv = document.getElementById('status');
    statusDiv.textContent = 'Checking connection...';
});