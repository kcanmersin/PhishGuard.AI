// PhisGuard.AI popup script
document.addEventListener('DOMContentLoaded', function() {
  // Enable extended debug logging
  let DEBUG = false;
  
  function debug(...args) {
    if (DEBUG) {
      console.log('[PhisGuard Debug]', ...args);
    }
  }
  
  // Add debug button handler
  document.getElementById('debug-btn').addEventListener('click', function() {
    DEBUG = !DEBUG;
    console.log("Debug mode:", DEBUG ? "ON" : "OFF");
    if (DEBUG) {
      alert("Debug mode ON - Check browser console for logs");
    }
  });
  
  debug('Popup script loaded');
  
  // Elements
  const loginView = document.getElementById('login-view');
  const registerView = document.getElementById('register-view');
  const dashboardView = document.getElementById('dashboard-view');
  const loginForm = document.getElementById('login-form');
  const registerForm = document.getElementById('register-form');
  const registerLink = document.getElementById('register-link');
  const loginLink = document.getElementById('login-link');
  const logoutBtn = document.getElementById('logout-btn');
  const analyzeBtn = document.getElementById('analyze-btn');
  const usernameDisplay = document.getElementById('username-display');
  const loginStatus = document.getElementById('login-status');
  const registerStatus = document.getElementById('register-status');
  const analysisLoading = document.getElementById('analysis-loading');
  const resultContainer = document.getElementById('result-container');
  const resultTitle = document.getElementById('result-title');
  const resultConfidence = document.getElementById('result-confidence');
  const confidenceLevel = document.getElementById('confidence-level');

  // API URL
  // Try both localhost and 127.0.0.1
  const API_URL = 'http://localhost:5000';
  const BACKUP_API_URL = 'http://127.0.0.1:5000';
  
  // Check if user is logged in
  checkLoginStatus();
  
  // Event listeners
  registerLink.addEventListener('click', showRegisterView);
  loginLink.addEventListener('click', showLoginView);
  loginForm.addEventListener('submit', handleLogin);
  registerForm.addEventListener('submit', handleRegister);
  logoutBtn.addEventListener('click', handleLogout);
  analyzeBtn.addEventListener('click', analyzeCurrentEmail);
  
  // Listen for analysis results from content script
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'analysisResult') {
      displayAnalysisResult(message.result);
    }
  });

  // Function to make API request with retry on different URL
  function apiRequest(endpoint, options) {
    debug(`Making API request to ${API_URL}${endpoint}`);
    
    return fetch(`${API_URL}${endpoint}`, options)
      .catch(error => {
        // If the main URL fails, try the backup URL
        debug(`Error with primary URL, trying backup: ${error.message}`);
        return fetch(`${BACKUP_API_URL}${endpoint}`, options);
      });
  }
  
  // Function to check if user is already logged in
  function checkLoginStatus() {
    debug('Checking login status...');
    debug('Current cookies:', document.cookie);
    
    apiRequest('/check_token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      credentials: 'include', // Include cookies
      body: JSON.stringify({ token: "" }) // Empty token to prevent 400 errors
    })
    .then(response => {
      debug('Check token response status:', response.status);
      debug('Check token headers:', Object.fromEntries([...response.headers.entries()]));
      
      if (!response.ok) {
        throw new Error(`Invalid response: ${response.status}`);
      }
      
      return response.json();
    })
    .then(data => {
      debug('Check token response data:', data);
      
      if (data.valid) {
        debug('User is logged in as:', data.username);
        showDashboardView(data.username);
      } else {
        debug('User is not logged in');
        showLoginView();
      }
    })
    .catch(error => {
      debug('Error checking login status:', error.message);
      showLoginView();
    });
  }

  // Function to handle login
  function handleLogin(e) {
    e.preventDefault();
    
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    
    debug('Login attempt:', { username, password: '******' });
    
    if (!username || !password) {
      debug('Login validation failed: Missing fields');
      showStatus(loginStatus, 'Please enter both username and password', 'error');
      return;
    }
    
    // Show temporary status
    showStatus(loginStatus, 'Logging in...', 'warning');
    
    debug(`Sending login request to API`);
    
    apiRequest('/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      credentials: 'include', // Include cookies
      body: JSON.stringify({
        username: username,
        password: password
      })
    })
    .then(response => {
      debug('Login response status:', response.status);
      debug('Login response headers:', Object.fromEntries([...response.headers.entries()]));
      
      if (!response.ok) {
        return response.json().then(errorData => {
          throw new Error(errorData.message || 'Invalid username or password');
        });
      }
      
      return response.json();
    })
    .then(data => {
      debug('Login response data:', data);
      
      if (data.success) {
        debug('Login successful for user:', data.user.username);
        showStatus(loginStatus, 'Login successful!', 'success');
        
        // Store the token in chrome.storage for use by content script
        if (data.access_token) {
          chrome.storage.local.set({jwt_token: data.access_token}, function() {
            debug('Token saved to chrome.storage');
          });
        }
        
        // Check if cookie was set
        debug('Cookies after login:', document.cookie);
        
        setTimeout(() => {
          showDashboardView(data.user.username);
        }, 1000);
      } else {
        debug('Login failed:', data.message);
        showStatus(loginStatus, data.message || 'Login failed', 'error');
      }
    })
    .catch(error => {
      debug('Login error:', error.message);
      showStatus(loginStatus, error.message || 'Network or server error', 'error');
    });
  }

  // Function to handle registration
  function handleRegister(e) {
    e.preventDefault();
    debug('Register form submitted');
    
    const username = document.getElementById('reg-username').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('reg-password').value;
    
    debug('Register data:', { 
      username, 
      email, 
      passwordLength: password ? password.length : 0 
    });
    
    if (!username || !email || !password) {
      debug('Register validation failed: Missing fields');
      showStatus(registerStatus, 'Please fill all fields', 'error');
      return;
    }
    
    // Clear previous status
    registerStatus.classList.add('hidden');
    
    // Prepare request data
    const requestData = {
      username: username,
      email: email,
      password: password
    };
    
    debug('Register request data:', requestData);
    debug(`Sending registration request to ${API_URL}/register`);
    
    // Show temporary status
    showStatus(registerStatus, 'Registering...', 'warning');
    
    apiRequest('/register', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify(requestData)
    })
    .then(response => {
      debug('Register response status:', response.status);
      debug('Register response headers:', Object.fromEntries([...response.headers.entries()]));
      
      if (response.status === 400) {
        // For 400 errors, we should still be able to parse the JSON error message
        return response.json().then(errorData => {
          throw new Error(errorData.message || 'Username or email already exists');
        });
      }
      
      if (response.status === 201 || response.status === 200) {
        // Success case, might have empty body
        return response.text().then(text => {
          try {
            // Try to parse as JSON if possible
            return text ? JSON.parse(text) : { message: 'User registered successfully!' };
          } catch (e) {
            // If not valid JSON, use as text message
            return { message: text || 'User registered successfully!' };
          }
        });
      }
      
      // For other statuses, try to get response as text
      return response.text().then(text => {
        throw new Error(`Registration failed with status ${response.status}: ${text}`);
      });
    })
    .then(data => {
      debug('Registration successful!', data);
      showStatus(registerStatus, data.message || 'Registration successful! Please login.', 'success');
      setTimeout(() => {
        showLoginView();
      }, 2000);
    })
    .catch(error => {
      debug('Registration failed:', error.message);
      showStatus(registerStatus, error.message || 'Registration failed', 'error');
    });
  }

  // Function to handle logout
  function handleLogout() {
    // Since we're using cookies, we don't need to manually clear localStorage
    // Just redirect to login view
    showLoginView();
  }

  // Function to analyze current email
  function analyzeCurrentEmail() {
    // Show loading state
    analysisLoading.classList.remove('hidden');
    resultContainer.classList.add('hidden');
    
    debug('Requesting email analysis from content script');
    
    // Get the token from chrome.storage
    chrome.storage.local.get('jwt_token', function(result) {
      const jwt_token = result.jwt_token;
      debug('Retrieved token for analysis:', jwt_token ? `${jwt_token.substring(0, 10)}...` : 'None');
      
      // Send message to content script to analyze the current email
      chrome.tabs.query({active: true, currentWindow: true}, tabs => {
        if (!tabs || tabs.length === 0) {
          debug('No active tab found');
          analysisLoading.classList.add('hidden');
          alert('Error: Cannot access the current tab');
          return;
        }
        
        debug('Sending message to tab:', tabs[0].id);
        
        chrome.tabs.sendMessage(tabs[0].id, {
          action: 'analyzeEmail',
          jwt_token: jwt_token // Pass the token explicitly
        }, response => {
          if (chrome.runtime.lastError) {
            debug('Error sending message:', chrome.runtime.lastError);
            analysisLoading.classList.add('hidden');
            alert(`Error: ${chrome.runtime.lastError.message || 'Could not connect to the page'}`);
            return;
          }
          
          debug('Content script response:', response);
          
          if (!response || response.status === 'error') {
            analysisLoading.classList.add('hidden');
            alert(response?.message || 'Error: Unable to analyze email. Make sure you have an email open.');
          }
          // The rest of the process will be handled by the content script
          // and the result will be received via the message listener
        });
      });
    });
  }

  // Function to display analysis result
  function displayAnalysisResult(result) {
    analysisLoading.classList.add('hidden');
    
    if (!result.success) {
      if (result.needs_login) {
        showLoginView();
        showStatus(loginStatus, 'Session expired. Please login again.', 'warning');
      } else {
        alert(result.message || 'Error analyzing email');
      }
      return;
    }
    
    resultContainer.classList.remove('hidden');
    
    // Set result class and title
    if (result.result === 'Phishing') {
      resultContainer.className = 'result-container result-phishing';
      resultTitle.textContent = 'PHISHING DETECTED!';
    } else {
      resultContainer.className = 'result-container result-safe';
      resultTitle.textContent = 'Email appears safe';
    }
    
    // Display confidence
    const confidencePercent = Math.round(result.final_confidence * 100);
    resultConfidence.textContent = `Confidence: ${confidencePercent}%`;
    
    // Set confidence bar
    confidenceLevel.style.width = `${confidencePercent}%`;
    confidenceLevel.style.backgroundColor = result.result === 'Phishing' ? 
      '#dc3545' : '#28a745';
  }

  // Function to show login view
  function showLoginView() {
    loginView.classList.remove('hidden');
    registerView.classList.add('hidden');
    dashboardView.classList.add('hidden');
    loginStatus.classList.add('hidden');
    document.getElementById('username').value = '';
    document.getElementById('password').value = '';
  }

  // Function to show register view
  function showRegisterView() {
    loginView.classList.add('hidden');
    registerView.classList.remove('hidden');
    dashboardView.classList.add('hidden');
    registerStatus.classList.add('hidden');
  }

  // Function to show dashboard view
  function showDashboardView(username) {
    loginView.classList.add('hidden');
    registerView.classList.add('hidden');
    dashboardView.classList.remove('hidden');
    resultContainer.classList.add('hidden');
    analysisLoading.classList.add('hidden');
    usernameDisplay.textContent = username;
  }

  // Function to show status message
  function showStatus(element, message, type) {
    element.textContent = message;
    element.className = `status ${type}`;
    element.classList.remove('hidden');
  }
});