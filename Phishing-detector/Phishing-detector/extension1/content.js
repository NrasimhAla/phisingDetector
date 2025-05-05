// Listen for clicks on links
document.addEventListener('click', function(event) {
  const link = event.target.closest('a');
  if (link) {
    // Stop the default link behavior immediately
    event.preventDefault();
    event.stopPropagation();
    
    // Check if extension is enabled
    try {
      chrome.storage.local.get(['enabled'], function(result) {
        if (chrome.runtime.lastError) {
          console.error('Extension error:', chrome.runtime.lastError);
          // If extension context is invalid, allow the link to proceed
          window.location.href = link.href;
          return;
        }

        if (result.enabled !== false) {
          const url = link.href;
          console.log('Link clicked:', url);
          
          // Show loading state
          showLoadingPopup();
          
          // Send URL to background script for analysis
          chrome.runtime.sendMessage({
            type: 'analyzeUrl',
            url: url
          }, function(response) {
            if (chrome.runtime.lastError) {
              console.error('Extension error:', chrome.runtime.lastError);
              // If extension context is invalid, allow the link to proceed
              window.location.href = link.href;
              return;
            }

            console.log('Received response:', response);
            if (response && response.isPhishing !== undefined) {
              // Send result back to popup
              chrome.runtime.sendMessage({
                type: 'phishingResult',
                isPhishing: response.isPhishing
              });
              
              // Show appropriate message with confirmation
              if (response.isPhishing) {
                showWarning();
              } else {
                showConfirmationPopup(link);
              }
            } else {
              // If no response, show confirmation popup
              showConfirmationPopup(link);
            }
          });
        } else {
          // If extension is disabled, proceed with the link
          window.location.href = link.href;
        }
      });
    } catch (error) {
      console.error('Error in content script:', error);
      // If any error occurs, allow the link to proceed
      window.location.href = link.href;
    }
  }
}, true); // Use capture phase to intercept before bubbling

// Listen for extension state changes
chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
  if (request.type === 'extensionStateChanged') {
    console.log('Extension state changed:', request.enabled);
  }
});

// Function to show loading state
function showLoadingPopup() {
  const popup = document.createElement('div');
  popup.style.cssText = `
    position: fixed;
    top: 0;
    left: 50%;
    transform: translateX(-50%);
    background-color: white;
    padding: 20px 40px;
    border-radius: 0 0 12px 12px;
    box-shadow: 0 8px 32px rgba(0,0,0,0.1);
    z-index: 2147483647;
    font-family: 'Segoe UI', Arial, sans-serif;
    text-align: center;
    min-width: 350px;
    border: 2px solid #2196F3;
    border-top: none;
    animation: slideDown 0.3s ease-out;
  `;

  const message = document.createElement('div');
  message.style.cssText = `
    color: #2196F3;
    font-size: 18px;
    font-weight: 600;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 12px;
  `;
  message.innerHTML = '<span style="font-size: 24px;">🔍</span> Analyzing website...';
  popup.appendChild(message);

  document.body.appendChild(popup);
  return popup;
}

// Function to show warning on the page
function showWarning() {
  const warning = document.createElement('div');
  warning.style.cssText = `
    position: fixed;
    top: 0;
    left: 50%;
    transform: translateX(-50%);
    background-color: #fff5f5;
    color: #c62828;
    padding: 20px 40px;
    border-radius: 0 0 12px 12px;
    box-shadow: 0 8px 32px rgba(0,0,0,0.1);
    z-index: 2147483647;
    font-family: 'Segoe UI', Arial, sans-serif;
    text-align: center;
    min-width: 350px;
    border: 2px solid #c62828;
    border-top: none;
    font-weight: 600;
    animation: slideDown 0.3s ease-out;
  `;
  warning.innerHTML = '<span style="font-size: 24px;">⚠️</span> Warning: This website might be phishing!';
  document.body.appendChild(warning);
  
  // Remove warning after 5 seconds
  setTimeout(() => {
    warning.style.animation = 'slideUp 0.3s ease-out';
    setTimeout(() => warning.remove(), 300);
  }, 5000);
}

// Function to show confirmation popup
function showConfirmationPopup(link) {
  const popup = document.createElement('div');
  popup.style.cssText = `
    position: fixed;
    top: 0;
    left: 50%;
    transform: translateX(-50%);
    background-color: white;
    padding: 25px;
    border-radius: 0 0 12px 12px;
    box-shadow: 0 8px 32px rgba(0,0,0,0.1);
    z-index: 2147483647;
    font-family: 'Segoe UI', Arial, sans-serif;
    text-align: center;
    min-width: 350px;
    border: 2px solid #4CAF50;
    border-top: none;
    animation: slideDown 0.3s ease-out;
  `;

  const message = document.createElement('div');
  message.style.cssText = `
    color: #2e7d32;
    font-size: 18px;
    font-weight: 600;
    margin-bottom: 25px;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 12px;
  `;
  message.innerHTML = '<span style="font-size: 24px;">✅</span> This website is safe to proceed';
  popup.appendChild(message);

  const buttonContainer = document.createElement('div');
  buttonContainer.style.cssText = `
    display: flex;
    justify-content: center;
    gap: 20px;
  `;

  const proceedButton = document.createElement('button');
  proceedButton.textContent = 'Proceed';
  proceedButton.style.cssText = `
    background-color: #4CAF50;
    color: white;
    border: none;
    padding: 12px 30px;
    border-radius: 8px;
    cursor: pointer;
    font-size: 16px;
    font-weight: 600;
    transition: all 0.3s ease;
    box-shadow: 0 4px 12px rgba(76, 175, 80, 0.2);
  `;

  const cancelButton = document.createElement('button');
  cancelButton.textContent = 'Cancel';
  cancelButton.style.cssText = `
    background-color: #f44336;
    color: white;
    border: none;
    padding: 12px 30px;
    border-radius: 8px;
    cursor: pointer;
    font-size: 16px;
    font-weight: 600;
    transition: all 0.3s ease;
    box-shadow: 0 4px 12px rgba(244, 67, 54, 0.2);
  `;

  // Add hover effects
  proceedButton.onmouseover = () => {
    proceedButton.style.backgroundColor = '#45a049';
    proceedButton.style.transform = 'translateY(-2px)';
    proceedButton.style.boxShadow = '0 6px 16px rgba(76, 175, 80, 0.3)';
  };
  proceedButton.onmouseout = () => {
    proceedButton.style.backgroundColor = '#4CAF50';
    proceedButton.style.transform = 'translateY(0)';
    proceedButton.style.boxShadow = '0 4px 12px rgba(76, 175, 80, 0.2)';
  };

  cancelButton.onmouseover = () => {
    cancelButton.style.backgroundColor = '#da190b';
    cancelButton.style.transform = 'translateY(-2px)';
    cancelButton.style.boxShadow = '0 6px 16px rgba(244, 67, 54, 0.3)';
  };
  cancelButton.onmouseout = () => {
    cancelButton.style.backgroundColor = '#f44336';
    cancelButton.style.transform = 'translateY(0)';
    cancelButton.style.boxShadow = '0 4px 12px rgba(244, 67, 54, 0.2)';
  };

  proceedButton.onclick = () => {
    popup.style.animation = 'slideUp 0.3s ease-out';
    setTimeout(() => {
      popup.remove();
      window.location.href = link.href;
    }, 300);
  };

  cancelButton.onclick = () => {
    popup.style.animation = 'slideUp 0.3s ease-out';
    setTimeout(() => popup.remove(), 300);
  };

  buttonContainer.appendChild(proceedButton);
  buttonContainer.appendChild(cancelButton);
  popup.appendChild(buttonContainer);
  document.body.appendChild(popup);
}

// Update CSS animations
const style = document.createElement('style');
style.textContent = `
  @keyframes slideDown {
    from {
      transform: translate(-50%, -100%);
      opacity: 0;
    }
    to {
      transform: translate(-50%, 0);
      opacity: 1;
    }
  }

  @keyframes slideUp {
    from {
      transform: translate(-50%, 0);
      opacity: 1;
    }
    to {
      transform: translate(-50%, -100%);
      opacity: 0;
    }
  }
`;
document.head.appendChild(style); 