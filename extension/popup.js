// PhisGuard.AI popup script
document.addEventListener('DOMContentLoaded', function() {
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
  const modelResults = document.getElementById('model-results');
  const reasoningContainer = document.getElementById('reasoning-container');

  // API URL (try both localhost and 127.0.0.1)
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
    return fetch(`${API_URL}${endpoint}`, options)
      .catch(error => {
        // If the main URL fails, try the backup URL
        return fetch(`${BACKUP_API_URL}${endpoint}`, options);
      });
  }
  
  // Function to check if user is already logged in
  function checkLoginStatus() {
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
      if (!response.ok) {
        throw new Error(`Invalid response: ${response.status}`);
      }
      
      return response.json();
    })
    .then(data => {
      if (data.valid) {
        showDashboardView(data.username);
      } else {
        showLoginView();
      }
    })
    .catch(error => {
      showLoginView();
    });
  }

  // Function to handle login
  function handleLogin(e) {
    e.preventDefault();
    
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    
    if (!username || !password) {
      showStatus(loginStatus, 'Please enter both username and password', 'error');
      return;
    }
    
    // Show temporary status
    showStatus(loginStatus, 'Logging in...', 'warning');
    
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
      if (!response.ok) {
        return response.json().then(errorData => {
          throw new Error(errorData.message || 'Invalid username or password');
        });
      }
      
      return response.json();
    })
    .then(data => {
      if (data.success) {
        showStatus(loginStatus, 'Login successful!', 'success');
        
        // Store the token in chrome.storage for use by content script
        if (data.access_token) {
          chrome.storage.local.set({jwt_token: data.access_token}, function() {
            console.log('Token saved to chrome.storage');
          });
        }
        
        setTimeout(() => {
          showDashboardView(data.user.username);
        }, 1000);
      } else {
        showStatus(loginStatus, data.message || 'Login failed', 'error');
      }
    })
    .catch(error => {
      showStatus(loginStatus, error.message || 'Network or server error', 'error');
    });
  }

  // Function to handle registration
  function handleRegister(e) {
    e.preventDefault();
    
    const username = document.getElementById('reg-username').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('reg-password').value;
    
    if (!username || !email || !password) {
      showStatus(registerStatus, 'Please fill all fields', 'error');
      return;
    }
    
    // Clear previous status
    registerStatus.classList.add('hidden');
    
    // Show temporary status
    showStatus(registerStatus, 'Registering...', 'warning');
    
    apiRequest('/register', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify({
        username: username,
        email: email,
        password: password
      })
    })
    .then(response => {
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
      showStatus(registerStatus, data.message || 'Registration successful! Please login.', 'success');
      setTimeout(() => {
        showLoginView();
      }, 2000);
    })
    .catch(error => {
      showStatus(registerStatus, error.message || 'Registration failed', 'error');
    });
  }

  // Function to handle logout
  function handleLogout() {
    // Clear token
    chrome.storage.local.remove('jwt_token', function() {
      console.log('Token removed from chrome.storage');
    });
    localStorage.removeItem('jwtToken');
    sessionStorage.clear();
    
    // Go back to login view
    showLoginView();
  }

  // Function to analyze current email
  function analyzeCurrentEmail() {
    // Show loading state
    analysisLoading.classList.remove('hidden');
    resultContainer.classList.add('hidden');
    
    // Get the token from chrome.storage
    chrome.storage.local.get('jwt_token', function(result) {
      const jwt_token = result.jwt_token;
      
      // Send message to content script to analyze the current email
      chrome.tabs.query({active: true, currentWindow: true}, tabs => {
        if (!tabs || tabs.length === 0) {
          analysisLoading.classList.add('hidden');
          alert('Error: Cannot access the current tab');
          return;
        }
        
        chrome.tabs.sendMessage(tabs[0].id, {
          action: 'analyzeEmail',
          jwt_token: jwt_token // Pass the token explicitly
        }, response => {
          if (chrome.runtime.lastError) {
            analysisLoading.classList.add('hidden');
            alert(`Error: ${chrome.runtime.lastError.message || 'Could not connect to the page'}`);
            return;
          }
          
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
      resultTitle.innerHTML = '<i class="fas fa-exclamation-triangle"></i> PHISHING DETECTED!';
    } else {
      resultContainer.className = 'result-container result-safe';
      resultTitle.innerHTML = '<i class="fas fa-check-circle"></i> Email appears safe';
    }
    
    // Display confidence
    const confidencePercent = Math.round(result.final_confidence * 100);
    resultConfidence.textContent = `Confidence: ${confidencePercent}%`;
    
    // Set confidence bar
    confidenceLevel.style.width = `${confidencePercent}%`;
    confidenceLevel.style.backgroundColor = result.result === 'Phishing' ? 
      '#ef4444' : '#10b981';
    
    // Display individual model results
    if (modelResults) {
      // Show models section
      modelResults.classList.remove('hidden');
      
      // Clear previous results
      const modelResultsContent = modelResults.querySelector('.model-results-content');
      modelResultsContent.innerHTML = '';
      
      // Create model result elements
      const models = [
        { name: 'NLP Model 1', value: result.nlp_model1_confidence, key: 'nlp_model1_confidence' },
        { name: 'NLP Model 2', value: result.nlp_model2_confidence, key: 'nlp_model2_confidence' },
        { name: 'LLM Model 1', value: result.llm_model1_confidence, key: 'llm_model1_confidence' },
        { name: 'LLM Model 2', value: result.llm_model2_confidence, key: 'llm_model2_confidence' }
      ];
      
      models.forEach(model => {
        // Skip if model result is not available
        if (model.value === null || model.value === undefined) return;
        
        const modelDiv = document.createElement('div');
        modelDiv.className = 'model-result';
        
        const nameSpan = document.createElement('div');
        nameSpan.textContent = model.name;
        nameSpan.style.fontSize = '12px';
        nameSpan.style.marginBottom = '3px';
        
        const barContainer = document.createElement('div');
        barContainer.style.display = 'flex';
        barContainer.style.alignItems = 'center';
        
        const barBg = document.createElement('div');
        barBg.style.flex = '1';
        barBg.style.height = '8px';
        barBg.style.backgroundColor = '#e2e8f0';
        barBg.style.borderRadius = '4px';
        barBg.style.overflow = 'hidden';
        
        const bar = document.createElement('div');
        const percent = Math.round(model.value * 100);
        bar.style.width = `${percent}%`;
        bar.style.height = '100%';
        bar.style.backgroundColor = getConfidenceColor(model.value);
        
        const valueSpan = document.createElement('span');
        valueSpan.textContent = `${percent}%`;
        valueSpan.style.fontSize = '11px';
        valueSpan.style.marginLeft = '5px';
        valueSpan.style.minWidth = '35px';
        valueSpan.style.textAlign = 'right';
        
        barBg.appendChild(bar);
        barContainer.appendChild(barBg);
        barContainer.appendChild(valueSpan);
        
        modelDiv.appendChild(nameSpan);
        modelDiv.appendChild(barContainer);
        
        modelResultsContent.appendChild(modelDiv);
      });
    }
    
    // Display reasoning if available
    if (reasoningContainer && (result.llm_model1_reason || result.llm_model2_reason)) {
      // Show reasoning container
      reasoningContainer.classList.remove('hidden');
      
      // Clear previous content
      const reasoningContent = document.getElementById('reasoningContent');
      reasoningContent.innerHTML = '';
      
      // Add LLM reasoning
      if (result.llm_model1_reason) {
        const model1Title = document.createElement('div');
        model1Title.style.fontWeight = 'bold';
        model1Title.style.marginBottom = '5px';
        model1Title.textContent = 'LLM Model 1 Analysis:';
        
        const model1Text = document.createElement('p');
        model1Text.textContent = result.llm_model1_reason;
        model1Text.style.marginBottom = '10px';
        
        reasoningContent.appendChild(model1Title);
        reasoningContent.appendChild(model1Text);
      }
      
      if (result.llm_model2_reason) {
        const model2Title = document.createElement('div');
        model2Title.style.fontWeight = 'bold';
        model2Title.style.marginBottom = '5px';
        model2Title.textContent = 'LLM Model 2 Analysis:';
        
        const model2Text = document.createElement('p');
        model2Text.textContent = result.llm_model2_reason;
        
        reasoningContent.appendChild(model2Title);
        reasoningContent.appendChild(model2Text);
      }
      
      // Set up toggle button
      const toggleBtn = document.getElementById('toggleReasoning');
      toggleBtn.addEventListener('click', function() {
        const content = document.getElementById('reasoningContent');
        if (content.classList.contains('hidden')) {
          content.classList.remove('hidden');
          this.classList.add('active');
        } else {
          content.classList.add('hidden');
          this.classList.remove('active');
        }
      });
    } else {
      reasoningContainer.classList.add('hidden');
    }
  }
  
  // Helper function to get color based on confidence level
  function getConfidenceColor(value) {
    if (value >= 0.7) return '#ef4444'; // Danger/Red
    if (value >= 0.5) return '#f97316'; // Warning/Orange
    if (value >= 0.3) return '#eab308'; // Caution/Yellow
    return '#10b981'; // Safe/Green
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
    modelResults.classList.add('hidden');
    reasoningContainer.classList.add('hidden');
    usernameDisplay.textContent = username;
  }

  // Function to show status message
  function showStatus(element, message, type) {
    element.textContent = message;
    element.className = `status ${type}`;
    element.classList.remove('hidden');
  }
});