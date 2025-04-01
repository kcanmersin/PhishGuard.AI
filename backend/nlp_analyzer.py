"""
NLP-based phishing detection module.
This module implements multiple rule-based phishing detection algorithms using 
natural language processing techniques.
"""
import re
import string
from collections import Counter

def check_phishing_with_nlp_model1(text):
    """
    NLP Model 1: Keyword and pattern-based approach
    
    Uses keyword matching with weighted scores, URL analysis,
    urgency detection, and suspicious request detection.
    
    Args:
        text (str): The email text to analyze
        
    Returns:
        float: A confidence score between 0.0 and 1.0 where higher values 
              indicate a higher likelihood of phishing
    """
    text_lower = text.lower()
    
    # Phishing keywords with weights
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
    
    # URL analysis
    urls = []
    words = text_lower.split()
    for word in words:
        if word.startswith('http') or word.startswith('www.') or '.com' in word or '.net' in word or '.org' in word:
            urls.append(word)
    
    url_score = 0
    # Check for URL tricks - more than zero is suspicious
    if len(urls) > 0:
        url_score = min(1.0, len(urls) * 0.2)  # Each URL adds 0.2 to score, max 1.0
    
    # Urgency/threat indicators
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
    
    # Suspicious requests
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
    
    # Poor grammar or misspellings is a phishing indicator
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
    print(f"📊 NLP Model 1 Scores: keywords={keyword_score:.2f}, URLs={url_score:.2f}, " 
          f"urgency={urgency_score:.2f}, requests={request_score:.2f}, grammar={grammar_score:.2f}",
          flush=True)
    print(f"📊 NLP Model 1 Final Score: {final_score:.2f}", flush=True)
    
    return min(final_score, 1.0)

def check_phishing_with_nlp_model2(text):
    """
    NLP Model 2: Enhanced statistical and linguistic analysis
    
    Focuses on statistical text features, uses n-grams, and employs linguistic patterns
    common in phishing emails. Includes analysis of:
    1. Text statistics (length, capitalization, punctuation)
    2. Domain-specific suspicious patterns
    3. Word n-grams common in phishing
    4. Lexical diversity and writing style
    
    Args:
        text (str): The email text to analyze
        
    Returns:
        float: A confidence score between 0.0 and 1.0 where higher values 
              indicate a higher likelihood of phishing
    """
    text_lower = text.lower()
    
    # 1. Statistical text features
    stats_score = 0
    
    # Check for excessive capitalization (shouting)
    caps_count = sum(1 for c in text if c.isupper())
    caps_ratio = caps_count / len(text) if len(text) > 0 else 0
    if caps_ratio > 0.2:  # If more than 20% is capitalized
        stats_score += 0.2
    
    # Check for excessive punctuation (especially ! and ?)
    punct_count = sum(1 for c in text if c in "!?.")
    punct_ratio = punct_count / len(text) if len(text) > 0 else 0
    if punct_ratio > 0.05:  # If more than 5% is punctuation
        stats_score += 0.2
    
    # Check for very short or very long texts
    if len(text) < 100:  # Very short emails are suspicious
        stats_score += 0.1
    elif len(text) > 3000:  # Very long emails are less likely to be phishing
        stats_score -= 0.2
    
    # 2. Domain-specific suspicious patterns
    domain_score = 0
    
    # Check for mentions of money or financial terms
    money_terms = ["$", "dollar", "eur", "euro", "money", "cash", "bitcoin", "btc", "crypto", "bank", "financial", "account", "payment"]
    money_mentions = sum(1 for term in money_terms if term in text_lower)
    domain_score += min(0.5, money_mentions * 0.05)  # Max 0.5 from money terms
    
    # Check for suspicious email domains
    suspicious_domains = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com"]
    domain_score += 0.3 if any(domain in text_lower for domain in suspicious_domains) else 0
    
    # 3. N-gram analysis
    ngram_score = 0
    
    # Common phishing bi-grams and tri-grams
    phishing_ngrams = [
        "click here", "verify account", "personal information", "account details", 
        "security reasons", "urgent action", "claim your", "form attached", 
        "kindly update", "banking details", "credit card", "this link", 
        "final notice", "your account has", "identity verification"
    ]
    
    ngram_count = sum(1 for ngram in phishing_ngrams if ngram in text_lower)
    ngram_score = min(0.7, ngram_count * 0.1)  # Max 0.7 from n-grams
    
    # 4. Lexical diversity and writing style
    style_score = 0
    
    # Calculate lexical diversity (unique words / total words)
    words = re.findall(r'\b\w+\b', text_lower)
    unique_words = set(words)
    lexical_diversity = len(unique_words) / len(words) if words else 0
    
    if lexical_diversity < 0.4:  # Low diversity is suspicious
        style_score += 0.3
        
    # Check for formal vs informal language
    formal_markers = ["sincerely", "regards", "dear", "respectfully", "to whom it may concern"]
    formal_count = sum(1 for marker in formal_markers if marker in text_lower)
    
    informal_markers = ["hey", "hi there", "hello there", "thanks", "cheers", "bye"]
    informal_count = sum(1 for marker in informal_markers if marker in text_lower)
    
    if formal_count > 0 and informal_count > 0:  # Mixing formal and informal is suspicious
        style_score += 0.2
    
    # Final weighted score
    weights = {
        'stats': 0.15,
        'domain': 0.25,
        'ngram': 0.40,
        'style': 0.20
    }
    
    final_score = (
        stats_score * weights['stats'] +
        domain_score * weights['domain'] +
        ngram_score * weights['ngram'] +
        style_score * weights['style']
    )
    
    # Debug logging
    print(f"📊 NLP Model 2 Scores: stats={stats_score:.2f}, domain={domain_score:.2f}, " 
          f"ngrams={ngram_score:.2f}, style={style_score:.2f}",
          flush=True)
    print(f"📊 NLP Model 2 Final Score: {final_score:.2f}", flush=True)
    
    return min(final_score, 1.0)

def extract_phishing_indicators(text):
    """Extract specific phishing indicators from the email text"""
    text_lower = text.lower()
    indicators = []
    
    # Check for urgent language
    urgent_words = ["urgent", "immediately", "right away", "as soon as possible", "warning"]
    if any(word in text_lower for word in urgent_words):
        indicators.append({
            "type": "urgency",
            "severity": "high",
            "description": "Email uses urgent language to pressure the recipient"
        })
    
    # Check for suspicious URLs
    words = text_lower.split()
    suspicious_urls = []
    for word in words:
        if (word.startswith('http') or word.startswith('www.') or '.com' in word or 
            '.net' in word or '.org' in word):
            suspicious_urls.append(word)
    
    if suspicious_urls:
        indicators.append({
            "type": "suspicious_links",
            "severity": "high",
            "description": f"Email contains {len(suspicious_urls)} link(s) that should be verified"
        })
    
    # Check for requests for sensitive information
    sensitive_phrases = ["password", "social security", "ssn", "credit card", "account number", "banking"]
    found_sensitive = [phrase for phrase in sensitive_phrases if phrase in text_lower]
    if found_sensitive:
        indicators.append({
            "type": "sensitive_info_request",
            "severity": "critical",
            "description": f"Email requests sensitive information: {', '.join(found_sensitive)}"
        })
    
    # Check for suspicious attachments
    attachment_words = ["attachment", "attached", "file", "document", "open the", "download"]
    if any(word in text_lower for word in attachment_words):
        indicators.append({
            "type": "suspicious_attachment",
            "severity": "medium",
            "description": "Email mentions attachments which may contain malware"
        })
    
    # Check for misspellings and poor grammar (simplified)
    grammar_indicators = ["kindly", "dear valued customer", "dear customer", "valued customer"]
    if any(indicator in text_lower for indicator in grammar_indicators):
        indicators.append({
            "type": "poor_writing",
            "severity": "low",
            "description": "Email contains phrasing commonly found in phishing attempts"
        })
    
    # Statistical anomalies
    words = re.findall(r'\b\w+\b', text_lower)
    if len(words) > 0:
        avg_word_length = sum(len(word) for word in words) / len(words)
        if avg_word_length < 3.5 or avg_word_length > 7:
            indicators.append({
                "type": "statistical_anomaly",
                "severity": "low",
                "description": "Email text has unusual word length patterns"
            })
    
    # If no indicators found
    if not indicators:
        indicators.append({
            "type": "no_obvious_indicators",
            "severity": "info",
            "description": "No obvious phishing indicators detected"
        })
    
    return indicators