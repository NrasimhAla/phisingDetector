// Initialize extension state
chrome.runtime.onInstalled.addListener(function() {
  // Set extension as enabled by default
  chrome.storage.local.set({ enabled: true });
});

// Function to check for obviously suspicious patterns
function checkSuspiciousPatterns(url) {
  try {
    const urlObj = new URL(url);
    const domain = urlObj.hostname.toLowerCase();
    
    // Check for URL shortening services
    const shortenerDomains = /bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net/;
    
    if (shortenerDomains.test(domain)) {
      console.log('URL shortener detected:', domain);
      return true;
    }

    // Check for too many subdomains
    const subdomainCount = domain.split('.').length - 2;
    if (subdomainCount > 3) {
      console.log('Too many subdomains detected:', domain);
      return true;
    }

    return false;
  } catch (error) {
    console.error('Error checking URL:', error);
    return true; // Be cautious on error
  }
}

// Listen for messages from content script
chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
  if (request.type === 'analyzeUrl') {
    const url = request.url;
    console.log('Analyzing URL:', url);

    // Send to backend for analysis
    fetch('http://localhost:5000/result', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: 'name=' + encodeURIComponent(url)
    })
    .then(response => {
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      return response.text();
    })
    .then(html => {
      try {
        // Extract result from HTML response
        const parser = new DOMParser();
        const doc = parser.parseFromString(html, 'text/html');
        const result = doc.querySelector('h3').textContent;
        
        console.log('Backend response:', result);
        
        // Parse the backend's response (1 or -1)
        const prediction = parseInt(result.trim());
        
        // Classify based on backend response:
        // 1 = phishing, -1 = safe
        sendResponse({ 
          isPhishing: prediction === 1,
          message: prediction === 1 ? 
            "Warning: This website might be phishing!" : 
            "This website appears to be safe."
        });
      } catch (error) {
        console.error('Error parsing backend response:', error);
        sendResponse({ 
          isPhishing: false,
          message: "Error: Invalid response from backend"
        });
      }
    })
    .catch(error => {
      console.error('Error:', error);
      sendResponse({ 
        isPhishing: false,
        message: "Error: Unable to analyze website"
      });
    });

    return true; // Keep the message channel open for async response
  }
}); 