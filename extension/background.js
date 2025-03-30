// PhisGuard.AI Background Script
console.log('PhisGuard.AI: Background script loaded');

// Global variable to store the token - persists until browser is closed
let globalJwtToken = null;

// Message listener
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log('PhisGuard.AI Background: Received message', request.action);
  
  // Save token
  if (request.action === 'saveToken') {
    globalJwtToken = request.token;
    console.log('PhisGuard.AI Background: Token saved');
    sendResponse({ success: true });
  }
  
  // Get token
  else if (request.action === 'getToken') {
    console.log('PhisGuard.AI Background: Token requested');
    sendResponse({ token: globalJwtToken });
  }
  
  // Clear token (for logout)
  else if (request.action === 'clearToken') {
    globalJwtToken = null;
    console.log('PhisGuard.AI Background: Token cleared');
    sendResponse({ success: true });
  }
  
  return true; // Keep the message channel open for async response
});