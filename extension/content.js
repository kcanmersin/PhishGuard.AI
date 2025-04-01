// PhisGuard.AI Content Script
console.log('PhisGuard.AI: Content script loaded for', window.location.href);

// Listen for messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'analyzeEmail') {
    console.log('PhisGuard.AI: Received analyze request');
    
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
      const emailBody = document.querySelector('.a3s.aiL');
      
      if (!emailBody) {
        reject(new Error('No email content found. Please open an email first.'));
        return;
      }
      
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
    const apiUrls = ['http://localhost:5000/analyze_email', 'http://127.0.0.1:5000/analyze_email'];
    
    console.log('PhisGuard.AI: Preparing to send data to backend:', {
      subject: emailData.subject,
      from: emailData.from,
      textLength: emailData.selected_text.length
    });
    
    let response = null;
    let error = null;
    
    for (const apiUrl of apiUrls) {
      try {
        console.log(`PhisGuard.AI: Trying API URL: ${apiUrl}`);
        
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
            jwt_token: jwt_token
          })
        });
        
        break;
      } catch (err) {
        error = err;
        console.log(`PhisGuard.AI: Failed to connect to ${apiUrl}:`, err.message);
      }
    }
    
    if (!response) {
      throw error || new Error('Failed to connect to API');
    }
    
    console.log('PhisGuard.AI: Response status:', response.status);
    
    const result = await response.json();
    console.log('PhisGuard.AI: Analysis result:', result);
    
    // Only send result to popup
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