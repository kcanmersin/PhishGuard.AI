"""
NLP-based phishing detection module.
This module implements a rule-based phishing detection algorithm using 
natural language processing techniques.
"""

def check_phishing_with_nlp(text):
    """
    Enhanced NLP-based phishing detection using a comprehensive approach:
    
    1. Keyword matching with weighted scores
    2. URL analysis
    3. Urgency/threat detection
    4. Grammar and spelling analysis
    5. Suspicious request detection
    
    Args:
        text (str): The email text to analyze
        
    Returns:
        float: A confidence score between 0.0 and 1.0 where higher values 
              indicate a higher likelihood of phishing
    """
    text_lower = text.lower()
    
    # 1. Phishing keywords with weights
    phishing_keywords = {
        # Urgency indicators
        "urgent": 0.5, "immediately": 0.5, "alert": 0.4, "attention": 0.3, 
        "important update": 0.5, "expire": 0.4, "deadline": 0.3,
        
        # Action requests
        "click here": 0.7, "click below": 0.6, "click the link": 0.6,
        "download": 0.4, "sign in": 0.4, "login": 0.4, "verify": 0.5,
        
        # Sensitive information
        "password": 0.6, "username": 0.4, "account": 0.3, "credit card": 0.7,
        "social security": 0.8, "ssn": 0.8, "banking": 0.6, "pin": 0.7,
        
        # Financial triggers
        "bank": 0.4, "paypal": 0.5, "transaction": 0.4, "suspended": 0.6,
        "hold": 0.4, "fraud": 0.5, "unauthorized": 0.6,
        
        # Rewards and threats
        "winner": 0.7, "won": 0.6, "lottery": 0.8, "prize": 0.7, "reward": 0.6,
        "gift": 0.5, "congratulations": 0.5, "selected": 0.4,
        "threat": 0.8, "terminate": 0.7, "suspend": 0.6, "lock": 0.5,
        
        # Account status
        "verify your account": 0.8, "account verification": 0.8, 
        "confirm your information": 0.7, "update your information": 0.7,
        "suspicious activity": 0.8, "unusual activity": 0.7,
        
        # Security themes
        "security": 0.3, "secure": 0.3, "protection": 0.3,
        "official": 0.2, "authorized": 0.2, "certified": 0.2,
    }
    
    # Calculate keyword score
    keyword_score = 0
    keyword_weight = 0
    for keyword, weight in phishing_keywords.items():
        if keyword in text_lower:
            keyword_score += weight
            keyword_weight += 1
    
    # Normalize keyword score to 0-1 range
    if keyword_weight > 0:
        keyword_score = min(1.0, keyword_score / (keyword_weight * 1.5))
    else:
        keyword_score = 0.0
    
    # 2. URL analysis
    urls = []
    words = text_lower.split()
    for word in words:
        if word.startswith('http') or word.startswith('www.') or '.com' in word or '.net' in word or '.org' in word:
            urls.append(word)
    
    url_score = 0
    # Check for URL tricks - more than zero is suspicious
    if len(urls) > 0:
        url_score = min(1.0, len(urls) * 0.2)  # Each URL adds 0.2 to score, max 1.0
    
    # 3. Urgency/threat indicators
    urgency_phrases = [
        "as soon as possible", "urgent action", "immediate attention",
        "within 24 hours", "within 48 hours", "right away", "deadline",
        "time sensitive", "limited time", "act now", "hurry",
        "before it's too late", "before your account is"
    ]
    
    urgency_score = 0
    for phrase in urgency_phrases:
        if phrase in text_lower:
            urgency_score += 0.3
    urgency_score = min(1.0, urgency_score)
    
    # 4. Suspicious requests
    suspicious_phrases = [
        "verify your identity", "confirm your details", "update your account",
        "click this link", "open the attachment", "enter your", "fill out",
        "provide your", "submit your", "send us your", "need your information",
        "for verification purposes", "to avoid suspension"
    ]
    
    request_score = 0
    for phrase in suspicious_phrases:
        if phrase in text_lower:
            request_score += 0.3
    request_score = min(1.0, request_score)
    
    # 5. Poor grammar or misspellings is a phishing indicator
    # This is simplified - a real implementation would use more sophisticated methods
    grammar_indicators = [
        "kindly", "dear valued customer", "dear customer", "valued customer",
        "your account has", "we detected", "we have detected", "we noticed",
        "our system detected", "your account will be", "your account has been"
    ]
    
    grammar_score = 0
    for indicator in grammar_indicators:
        if indicator in text_lower:
            grammar_score += 0.2
    grammar_score = min(1.0, grammar_score)
    
    # Final score calculation with weights
    weights = {
        'keyword': 0.35,
        'url': 0.25,
        'urgency': 0.15,
        'request': 0.15,
        'grammar': 0.1
    }
    
    final_score = (
        keyword_score * weights['keyword'] +
        url_score * weights['url'] +
        urgency_score * weights['urgency'] +
        request_score * weights['request'] +
        grammar_score * weights['grammar']
    )
    
    # Add some debug logging
    print(f"📊 NLP Analysis Scores: keywords={keyword_score:.2f}, URLs={url_score:.2f}, " 
          f"urgency={urgency_score:.2f}, requests={request_score:.2f}, grammar={grammar_score:.2f}",
          flush=True)
    print(f"📊 NLP Final Score: {final_score:.2f}", flush=True)
    
    return min(final_score, 1.0)

def analyze_context(text):
    """
    Analyze the context of the email for special cases or exceptions.
    Some legitimate emails may contain language that triggers phishing 
    detection (e.g., password reset emails from legitimate sources).
    
    Args:
        text (str): The email text to analyze
        
    Returns:
        dict: Context information including domain legitimacy and special cases
    """
    text_lower = text.lower()
    
    # Check for legitimate domains in links
    trusted_domains = [
        "google.com", "microsoft.com", "apple.com", "amazon.com", 
        "facebook.com", "twitter.com", "linkedin.com", "github.com",
        "outlook.com", "live.com", "office365.com", "gmail.com"
    ]
    
    found_domains = []
    for domain in trusted_domains:
        if domain in text_lower:
            found_domains.append(domain)
    
    # Check for legitimate contexts
    legitimate_contexts = {
        "password_reset": [
            "you requested a password reset", 
            "reset your password", 
            "password reset link",
            "forgot your password"
        ],
        "account_verification": [
            "verify your email address",
            "confirm your email",
            "email verification"
        ],
        "security_notification": [
            "sign-in from a new device",
            "new sign-in",
            "security alert"
        ]
    }
    
    detected_contexts = []
    for context_type, phrases in legitimate_contexts.items():
        for phrase in phrases:
            if phrase in text_lower:
                detected_contexts.append(context_type)
                break
    
    return {
        "trusted_domains": found_domains,
        "legitimate_contexts": detected_contexts,
        "has_legitimate_context": len(detected_contexts) > 0,
        "has_trusted_domain": len(found_domains) > 0
    }

def get_specific_indicators(text):
    """
    Extract specific phishing indicators from the text to provide
    actionable feedback to the user.
    
    Args:
        text (str): The email text to analyze
        
    Returns:
        list: List of specific indicators found in the text
    """
    text_lower = text.lower()
    indicators = []
    
    # Look for suspicious URLs
    words = text_lower.split()
    suspicious_urls = []
    for word in words:
        if (word.startswith('http') or word.startswith('www.') or 
            '.com' in word or '.net' in word or '.org' in word):
            suspicious_urls.append(word)
    
    if suspicious_urls:
        indicators.append({
            "type": "suspicious_urls",
            "severity": "high",
            "description": f"Found {len(suspicious_urls)} potentially suspicious URLs"
        })
    
    # Look for urgent language
    urgent_phrases = ["urgent", "immediately", "right away", "as soon as possible"]
    found_urgent = [phrase for phrase in urgent_phrases if phrase in text_lower]
    if found_urgent:
        indicators.append({
            "type": "urgency",
            "severity": "medium",
            "description": "Email uses urgent language to create pressure"
        })
    
    # Look for sensitive information requests
    sensitive_phrases = ["password", "credit card", "social security", "bank account"]
    found_sensitive = [phrase for phrase in sensitive_phrases if phrase in text_lower]
    if found_sensitive:
        indicators.append({
            "type": "sensitive_info",
            "severity": "critical",
            "description": f"Email requests sensitive information: {', '.join(found_sensitive)}"
        })
    
    return indicators