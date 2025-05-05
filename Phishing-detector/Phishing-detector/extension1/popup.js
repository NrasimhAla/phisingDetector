document.addEventListener('DOMContentLoaded', function() {
    const toggleButton = document.getElementById('toggleButton');
    const statusMessage = document.getElementById('statusMessage');
    const resultContainer = document.getElementById('result');
    const resultMessage = document.getElementById('resultMessage');

    // Load initial state
    chrome.storage.local.get(['enabled'], function(result) {
        toggleButton.checked = result.enabled !== false;
        updateStatusMessage(result.enabled !== false);
    });

    // Handle toggle button changes
    toggleButton.addEventListener('change', function() {
        const enabled = toggleButton.checked;
        chrome.storage.local.set({ enabled: enabled });
        updateStatusMessage(enabled);
    });

    function updateStatusMessage(enabled) {
        if (enabled) {
            statusMessage.textContent = 'Protection is enabled';
            statusMessage.className = 'message safe';
        } else {
            statusMessage.textContent = 'Protection is disabled';
            statusMessage.className = 'message warning';
        }
    }

    // Listen for messages from content script
    chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
        if (request.type === 'phishingResult') {
            showResult(request.isPhishing);
        }
    });

    function showResult(isPhishing) {
        resultContainer.style.display = 'block';
        
        if (isPhishing) {
            resultMessage.innerHTML = '<span class="result-icon">⚠️</span> Warning: This website might be phishing!';
            resultMessage.className = 'result warning';
        } else {
            resultMessage.innerHTML = '<span class="result-icon">✅</span> Safe to proceed';
            resultMessage.className = 'result safe';
        }
    }
}); 