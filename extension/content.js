// PhisGuard.AI Content Script
console.log('PhisGuard.AI: Content script loaded for', window.location.href);

// Listen for messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'analyzeEmail') {
    console.log('PhisGuard.AI: Received analyze request');
    
    // We should have a token from the popup
    const jwt_token = request.jwt_token;
    console.log('PhisGuard.AI: Received token:', jwt_token ? `${jwt_token.substring(0, 10)}...` : 'None');
    
    if (!jwt_token) {
      console.log('PhisGuard.AI: No token provided, cannot analyze');
      sendResponse({ 
        status: 'error', 
        message: 'Authentication required. Please log in again.' 
      });
      return true;
    }
    
    getEmailContent()
      .then(emailData => {
        if (emailData) {
          sendResponse({ status: 'processing' });
          analyzeEmail(emailData, jwt_token);
        } else {
          sendResponse({ status: 'error', message: 'Could not extract email content' });
        }
      })
      .catch(error => {
        console.error('PhisGuard.AI: Error extracting email', error);
        sendResponse({ status: 'error', message: error.toString() });
      });
    return true; // Keep the message channel open for async response
  }
});

// Extract email content from Gmail
function getEmailContent() {
  return new Promise((resolve, reject) => {
    try {
      // Target the main content area of an opened email in Gmail
      const emailBody = document.querySelector('.a3s.aiL');
      
      if (!emailBody) {
        reject(new Error('No email content found. Please open an email first.'));
        return;
      }
      
      // Extract email metadata
      const emailData = {
        subject: getEmailSubject(),
        from: getEmailSender(),
        selected_text: emailBody.innerText,
      };
      
      console.log('PhisGuard.AI: Extracted email data', { 
        subject: emailData.subject,
        from: emailData.from,
        textLength: emailData.selected_text.length
      });
      
      resolve(emailData);
    } catch (error) {
      console.error('PhisGuard.AI: Error in getEmailContent', error);
      reject(error);
    }
  });
}

// Extract the email subject
function getEmailSubject() {
  const subjectElement = document.querySelector('h2.hP');
  return subjectElement ? subjectElement.innerText : 'Unknown Subject';
}

// Extract the email sender
function getEmailSender() {
  const senderElement = document.querySelector('.gD');
  return senderElement ? senderElement.innerText : 'Unknown Sender';
}

// Analyze email by sending to backend
async function analyzeEmail(emailData, jwt_token) {
  try {
    // Try both localhost and 127.0.0.1 URLs
    const apiUrls = ['http://localhost:5000/analyze_email', 'http://127.0.0.1:5000/analyze_email'];
    
    console.log('PhisGuard.AI: Preparing to send data to backend:', {
      subject: emailData.subject,
      from: emailData.from,
      textLength: emailData.selected_text.length
    });
    
    // Try each URL until one works
    let response = null;
    let error = null;
    
    for (const apiUrl of apiUrls) {
      try {
        console.log(`PhisGuard.AI: Trying API URL: ${apiUrl}`);
        
        // Send the request with the token in the request body
        response = await fetch(apiUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            selected_text: emailData.selected_text,
            email_data: {
              subject: emailData.subject,
              from: emailData.from
            },
            jwt_token: jwt_token  // Include the token directly in the request
          })
        });
        
        // If we got here, the request worked
        break;
      } catch (err) {
        error = err;
        console.log(`PhisGuard.AI: Failed to connect to ${apiUrl}:`, err.message);
      }
    }
    
    // If we tried all URLs and none worked
    if (!response) {
      throw error || new Error('Failed to connect to API');
    }
    
    console.log('PhisGuard.AI: Response status:', response.status);
    
    const result = await response.json();
    console.log('PhisGuard.AI: Analysis result:', result);
    
    // Show result notification to user
    if (result.success) {
      console.log('PhisGuard.AI: Analysis successful, showing result');
      showAnalysisResult(result);
    } else if (result.needs_login) {
      console.log('PhisGuard.AI: Login required');
      showLoginNotification();
    } else {
      console.log('PhisGuard.AI: Analysis error:', result.message);
      showErrorNotification(result.message || 'An error occurred during analysis');
    }
    
    // Also send result to popup if it's open
    try {
      console.log('PhisGuard.AI: Sending result to popup');
      chrome.runtime.sendMessage({
        action: 'analysisResult',
        result: result
      });
    } catch (err) {
      console.log('PhisGuard.AI: Popup may not be open:', err);
    }
    
  } catch (error) {
    console.error('PhisGuard.AI: API error:', error);
    showErrorNotification('Network or server error');
    
    // Notify popup about the error
    try {
      chrome.runtime.sendMessage({
        action: 'analysisResult',
        result: {
          success: false,
          message: error.message || 'Network or server error'
        }
      });
    } catch (err) {
      console.log('PhisGuard.AI: Popup may not be open:', err);
    }
  }
}

// Display analysis result on the page
function showAnalysisResult(result) {
  removeExistingNotifications();
  
  const notification = document.createElement('div');
  notification.className = 'phisguard-notification';
  
  // Set colors based on result
  let bgColor, textColor, resultText;
  if (result.result === 'Phishing') {
    bgColor = '#FF4757';
    textColor = 'white';
    resultText = 'PHISHING DETECTED!';
  } else {
    bgColor = '#2ED573';
    textColor = 'white';
    resultText = 'Email appears safe';
  }
  
  notification.style = `
    position: fixed;
    top: 10px;
    right: 10px;
    padding: 15px;
    background-color: ${bgColor};
    color: ${textColor};
    border-radius: 5px;
    z-index: 10000;
    box-shadow: 0 2px 10px rgba(0,0,0,0.2);
    font-family: Arial, sans-serif;
    max-width: 300px;
  `;
  
  notification.innerHTML = `
    <div style="font-weight: bold; font-size: 16px; margin-bottom: 5px;">
      ${resultText}
    </div>
    <div style="font-size: 14px; margin-bottom: 10px;">
      Confidence: ${Math.round(result.final_confidence * 100)}%
    </div>
    <div style="font-size: 12px; color: ${textColor}; opacity: 0.8;">
      Click to dismiss
    </div>
  `;
  
  // Add click handler to dismiss
  notification.addEventListener('click', () => {
    document.body.removeChild(notification);
  });
  
  // Auto dismiss after 10 seconds
  setTimeout(() => {
    if (document.body.contains(notification)) {
      document.body.removeChild(notification);
    }
  }, 10000);
  
  document.body.appendChild(notification);
}

function showLoginNotification() {
  removeExistingNotifications();
  
  const notification = document.createElement('div');
  notification.className = 'phisguard-notification';
  notification.style = `
    position: fixed;
    top: 10px;
    right: 10px;
    padding: 15px;
    background-color: #FFA502;
    color: white;
    border-radius: 5px;
    z-index: 10000;
    box-shadow: 0 2px 10px rgba(0,0,0,0.2);
    font-family: Arial, sans-serif;
    max-width: 300px;
  `;
  
  notification.innerHTML = `
    <div style="font-weight: bold; font-size: 16px; margin-bottom: 5px;">
      Login Required
    </div>
    <div style="font-size: 14px; margin-bottom: 10px;">
      Please log in to analyze emails.
    </div>
    <button id="phisguard-login-btn" style="
      background-color: white;
      color: #333;
      border: none;
      padding: 5px 10px;
      border-radius: 3px;
      cursor: pointer;
      font-weight: bold;
    ">Login Now</button>
  `;
  
  document.body.appendChild(notification);
  
  // Add click handler for login button
  document.getElementById('phisguard-login-btn').addEventListener('click', () => {
    chrome.runtime.sendMessage({ action: 'openLoginPage' });
    if (document.body.contains(notification)) {
      document.body.removeChild(notification);
    }
  });
  
  // Auto dismiss after 10 seconds
  setTimeout(() => {
    if (document.body.contains(notification)) {
      document.body.removeChild(notification);
    }
  }, 10000);
}

function showErrorNotification(message) {
  removeExistingNotifications();
  
  const notification = document.createElement('div');
  notification.className = 'phisguard-notification';
  notification.style = `
    position: fixed;
    top: 10px;
    right: 10px;
    padding: 15px;
    background-color: #FF6B81;
    color: white;
    border-radius: 5px;
    z-index: 10000;
    box-shadow: 0 2px 10px rgba(0,0,0,0.2);
    font-family: Arial, sans-serif;
    max-width: 300px;
  `;
  
  notification.innerHTML = `
    <div style="font-weight: bold; font-size: 16px; margin-bottom: 5px;">
      Analysis Error
    </div>
    <div style="font-size: 14px; margin-bottom: 10px;">
      ${message}
    </div>
    <div style="font-size: 12px; color: white; opacity: 0.8;">
      Click to dismiss
    </div>
  `;
  
  // Add click handler to dismiss
  notification.addEventListener('click', () => {
    document.body.removeChild(notification);
  });
  
  // Auto dismiss after 10 seconds
  setTimeout(() => {
    if (document.body.contains(notification)) {
      document.body.removeChild(notification);
    }
  }, 10000);
  
  document.body.appendChild(notification);
}

function removeExistingNotifications() {
  const existingNotifications = document.querySelectorAll('.phisguard-notification');
  existingNotifications.forEach(notification => {
    document.body.removeChild(notification);
  });
}