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
    if not text or len(text.strip()) == 0:
        return 0.5  # Neutral score for empty text
        
    text_lower = text.lower()
    
    # Expanded phishing keywords with refined weights
    phishing_keywords = {
        # Urgency indicators
        "urgent": 0.6, "immediately": 0.6, "alert": 0.5, "attention": 0.4, 
        "important update": 0.6, "expire": 0.5, "deadline": 0.4, "emergency": 0.7,
        "act now": 0.7, "urgent action required": 0.8, "warning": 0.5, "important notice": 0.5,
        "time sensitive": 0.6, "limited time": 0.5, "last chance": 0.6,
        
        # Action requests
        "click here": 0.8, "click below": 0.7, "click the link": 0.7, "click on the link": 0.7,
        "download": 0.5, "sign in": 0.5, "login": 0.5, "verify": 0.6, "validate": 0.6,
        "follow the link": 0.7, "check this out": 0.4, "access now": 0.6, 
        "click to view": 0.7, "open the attachment": 0.8,
        
        # Sensitive information
        "password": 0.7, "username": 0.5, "account": 0.4, "credit card": 0.8,
        "social security": 0.9, "ssn": 0.9, "banking": 0.7, "pin": 0.8,
        "card number": 0.8, "date of birth": 0.7, "security question": 0.6,
        "mother's maiden name": 0.7, "passport": 0.7, "driver's license": 0.7,
        
        # Financial triggers
        "bank": 0.5, "paypal": 0.6, "transaction": 0.5, "suspended": 0.7,
        "hold": 0.5, "fraud": 0.6, "unauthorized": 0.7, "security breach": 0.7,
        "account locked": 0.7, "unusual activity": 0.7, "suspicious login": 0.7,
        "payment": 0.4, "transfer": 0.4, "direct deposit": 0.5, "blocked": 0.6,
        
        # Rewards and threats
        "winner": 0.8, "won": 0.7, "lottery": 0.9, "prize": 0.8, "reward": 0.7,
        "gift": 0.6, "congratulations": 0.6, "selected": 0.5, "exclusive offer": 0.6,
        "threat": 0.9, "terminate": 0.8, "suspend": 0.7, "lock": 0.6, "restricted": 0.6,
        "violation": 0.7, "penalty": 0.7, "legal action": 0.8, "investigation": 0.6,
        
        # Account status
        "verify your account": 0.9, "account verification": 0.9, 
        "confirm your information": 0.8, "update your information": 0.8,
        "suspicious activity": 0.9, "unusual activity": 0.8, "account access": 0.6,
        "unusual login attempt": 0.8, "security alert": 0.7, "account notice": 0.6,
        "unrecognized sign-in": 0.8, "verify your identity": 0.8,
        
        # Security themes
        "security": 0.4, "secure": 0.4, "protection": 0.4, "safety": 0.3,
        "official": 0.3, "authorized": 0.3, "certified": 0.3, "authenticated": 0.3,
        "encrypted": 0.3, "policy update": 0.4, "terms of service": 0.3,
        
        # Impersonation indicators
        "team": 0.3, "support team": 0.4, "customer service": 0.4, "help desk": 0.4,
        "technical support": 0.4, "administrator": 0.4, "service desk": 0.4,
        "account department": 0.5, "billing department": 0.5, "security team": 0.5
    }
    
    # Calculate keyword score with improved detection
    keyword_score = 0
    keyword_weight = 0
    detected_keywords = []
    
    for keyword, weight in phishing_keywords.items():
        # Check for keyword as a standalone phrase (with word boundaries)
        if re.search(r'\b' + re.escape(keyword) + r'\b', text_lower):
            keyword_score += weight
            keyword_weight += 1
            detected_keywords.append(keyword)
    
    # Special case: check for phrases that might indicate phishing
    phrase_indicators = [
        r"we\s+detected\s+suspicious\s+activity",
        r"unusual\s+log\s?in\s+attempt",
        r"confirm\s+your\s+(account|identity)",
        r"verify\s+your\s+(account|identity)",
        r"update\s+your\s+information",
        r"account\s+will\s+be\s+(suspended|locked|limited|blocked)",
        r"limited\s+access",
        r"requires\s+immediate\s+attention",
        r"security\s+measures",
        r"unauthorized\s+access\s+attempt",
        r"suspicious\s+transaction",
        r"log\s?in\s+from\s+unusual\s+location"
    ]
    
    for phrase in phrase_indicators:
        if re.search(phrase, text_lower):
            keyword_score += 0.7
            keyword_weight += 1
            detected_keywords.append(re.search(phrase, text_lower).group(0))
    
    # Normalize keyword score
    if keyword_weight > 0:
        # Modified normalization: allow higher scores for multiple matches
        keyword_score = min(1.0, keyword_score / (keyword_weight + 1))
    else:
        keyword_score = 0.0
    
    # Enhanced URL analysis
    url_regex = r'https?://\S+|www\.\S+|\S+\.(com|net|org|io|co|us|me|info|biz|edu|gov|mil)\S*'
    urls = re.findall(url_regex, text_lower)
    
    url_score = 0
    suspicious_url_indicators = 0
    
    # Base score for having URLs
    if len(urls) > 0:
        url_score += min(0.5, len(urls) * 0.15)  # Base score for number of URLs
    
    # Check for suspicious URL patterns
    for url in urls:
        # IP addresses instead of domain names
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            url_score += 0.3
            suspicious_url_indicators += 1
        
        # URL shorteners are suspicious
        shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'tiny.cc', 'is.gd', 'cli.gs', 'ow.ly']
        if any(shortener in url for shortener in shorteners):
            url_score += 0.3
            suspicious_url_indicators += 1
        
        # Suspicious TLDs
        suspicious_tlds = ['.xyz', '.top', '.club', '.work', '.live', '.info']
        if any(tld in url for tld in suspicious_tlds):
            url_score += 0.2
            suspicious_url_indicators += 1
        
        # URLs with numbers and special characters
        if re.search(r'\d{5,}', url) or re.search(r'[~@#$%^&*()=+[\]{}|<>]', url):
            url_score += 0.2
            suspicious_url_indicators += 1
        
        # Mismatched URLs (text says one domain but link goes to another)
        # This is a basic check, would need HTML parsing for full check
        url_text_mismatch = re.findall(r'(https?://\S+).*click.*(?!\\1)', text_lower)
        if url_text_mismatch:
            url_score += 0.4
            suspicious_url_indicators += 1
            
    # Cap the URL score
    url_score = min(1.0, url_score + (0.1 * suspicious_url_indicators))
    
    # Enhanced urgency/threat detection
    urgency_patterns = [
        r'within\s+\d+\s+(hour|minute|day|business day)',
        r'before\s+your\s+account\s+is',
        r'immediate\s+action\s+required',
        r'urgent\s+attention\s+needed',
        r'failure\s+to\s+comply',
        r'will\s+result\s+in',
        r'before\s+it\'?s?\s+too\s+late',
        r'expir(es|ed|ation|ing)',
        r'last\s+chance',
        r'final\s+notice',
        r'limited\s+time\s+offer',
        r'act\s+now',
        r'time\s+sensitive',
        r'respond\s+immediately',
        r'promptly'
    ]
    
    urgency_score = 0
    urgency_matches = 0
    
    for pattern in urgency_patterns:
        matches = re.findall(pattern, text_lower)
        if matches:
            urgency_score += 0.25
            urgency_matches += len(matches)
    
    # Higher score for multiple urgency indicators
    urgency_score = min(1.0, urgency_score + (0.1 * max(0, urgency_matches - 1)))
    
    # Suspicious request detection with added context
    suspicious_request_patterns = [
        r'(confirm|update|verify|validate|provide).{0,20}(password|username|email|account|card|personal|bank|credit)',
        r'(enter|fill|complete|submit).{0,20}(details|information|form)',
        r'(send|provide).{0,20}(photo|scan|picture|copy).{0,20}(id|identification|license|passport)',
        r'(click|follow).{0,20}(link|button)',
        r'(download|open).{0,20}(attachment|file|document)',
        r'(sign|log).{0,20}(in|on)',
        r'update.{0,20}(account|profile|information|details)',
        r'reset.{0,20}(password)',
        r'access.{0,20}(account|file|document)',
        r'get.{0,20}(started|access)'
    ]
    
    request_score = 0
    request_matches = 0
    
    for pattern in suspicious_request_patterns:
        matches = re.findall(pattern, text_lower)
        if matches:
            request_score += 0.25
            request_matches += len(matches)
    
    # Higher score for multiple suspicious requests
    request_score = min(1.0, request_score + (0.1 * max(0, request_matches - 1)))
    
    # Enhanced grammar and writing style analysis
    grammar_indicators = [
        # Typical phishing phrasing
        "kindly", "dear valued customer", "dear customer", "valued customer",
        "dear sir", "dear madam", "greetings of the day", "official notification",
        
        # Bad grammar/phrasing
        "please to", "been notify", "been informed", "we writing to",
        "hesitate to", "kindly revert", "do needful", "your earliest",
        
        # Inconsistent formality
        "hello dear", "hi valued", "dear customer hi",
        
        # System/administrative phrases
        "system administrator", "system detected", "account flagged",
        "automatic system", "automated message", "security system"
    ]
    
    grammar_score = 0
    grammar_matches = 0
    
    for indicator in grammar_indicators:
        if indicator in text_lower:
            grammar_score += 0.15
            grammar_matches += 1
    
    # Additional check for inconsistent capitalization
    sentences = re.split(r'[.!?]', text)
    cap_errors = 0
    
    for sentence in sentences:
        if sentence.strip():
            # Check for sentences that don't start with a capital letter
            first_word_match = re.search(r'^\s*(\w+)', sentence)
            if first_word_match and first_word_match.group(1)[0].islower():
                cap_errors += 1
    
    if cap_errors > 2:  # Allow a couple of mistakes
        grammar_score += 0.2
    
    # Check for excessive/unnecessary capitalization
    words = re.findall(r'\b\w+\b', text)
    all_caps_words = [word for word in words if word.isupper() and len(word) > 1]
    if len(all_caps_words) > 3:  # More than 3 all-caps words
        grammar_score += min(0.3, 0.05 * len(all_caps_words))
    
    grammar_score = min(1.0, grammar_score)
    
    # Check for sender/recipient mismatch (reference to emails/domains not in the 'from' field)
    # This is a simplified version, would normally check against the actual email headers
    domain_references = re.findall(r'@[\w.-]+\.\w+', text_lower)
    domain_mismatch_score = 0
    
    if len(domain_references) > 1:
        # Multiple domain references may indicate spoofing
        domain_mismatch_score = min(0.5, 0.15 * len(domain_references))
    
    # Final score calculation with refined weights
    weights = {
        'keyword': 0.30,
        'url': 0.25,
        'urgency': 0.15,
        'request': 0.15,
        'grammar': 0.10,
        'domain_mismatch': 0.05
    }
    
    final_score = (
        keyword_score * weights['keyword'] +
        url_score * weights['url'] +
        urgency_score * weights['urgency'] +
        request_score * weights['request'] +
        grammar_score * weights['grammar'] +
        domain_mismatch_score * weights['domain_mismatch']
    )
    
    # Debug logging
    print(f"📊 NLP Model 1 Scores: keywords={keyword_score:.2f}, URLs={url_score:.2f}, " 
          f"urgency={urgency_score:.2f}, requests={request_score:.2f}, "
          f"grammar={grammar_score:.2f}, domain_mismatch={domain_mismatch_score:.2f}",
          flush=True)
    
    if detected_keywords:
        print(f"📊 NLP Model 1 Keywords: {', '.join(detected_keywords[:5])}" + 
              (f" and {len(detected_keywords) - 5} more" if len(detected_keywords) > 5 else ""),
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
    if not text or len(text.strip()) == 0:
        return 0.5  # Neutral score for empty text
        
    text_lower = text.lower()
    
    # 1. Enhanced statistical text features
    stats_score = 0
    
    # Check for excessive capitalization (shouting)
    caps_count = sum(1 for c in text if c.isupper())
    caps_ratio = caps_count / len(text) if len(text) > 0 else 0
    if caps_ratio > 0.2:  # If more than 20% is capitalized
        stats_score += 0.3
    elif caps_ratio > 0.1:  # If more than 10% is capitalized
        stats_score += 0.15
    
    # Check for excessive punctuation (especially ! and ?)
    punct_count = sum(1 for c in text if c in "!?.")
    exclamation_count = sum(1 for c in text if c == "!")
    question_count = sum(1 for c in text if c == "?")
    
    punct_ratio = punct_count / len(text) if len(text) > 0 else 0
    if punct_ratio > 0.05:  # If more than 5% is punctuation
        stats_score += 0.2
    
    # Special attention to excessive exclamation points
    if exclamation_count > 3:
        stats_score += min(0.3, 0.05 * exclamation_count)
    
    # Multiple consecutive punctuation (e.g., !!! or ???)
    if re.search(r'[!?]{2,}', text):
        stats_score += 0.2
    
    # Check for email length - very short or very long
    if len(text) < 100:  # Very short emails are suspicious
        stats_score += 0.2
    elif len(text) > 5000:  # Very long emails are less likely to be phishing
        stats_score -= 0.3
    elif len(text) > 3000:  # Moderately long emails slightly less likely
        stats_score -= 0.2
    
    # Line break analysis - unusual patterns
    line_breaks = text.count('\n')
    if line_breaks > 0:
        line_break_ratio = line_breaks / len(text)
        if line_break_ratio > 0.1:  # Too many line breaks
            stats_score += 0.15
        elif line_break_ratio < 0.005 and len(text) > 1000:  # Too few line breaks in long text
            stats_score += 0.1
    
    # 2. Enhanced domain-specific suspicious patterns
    domain_score = 0
    
    # Expanded financial and sensitive terms
    financial_terms = [
        "$", "€", "£", "dollar", "eur", "euro", "money", "cash", "bitcoin", "btc", "crypto",
        "bank", "financial", "account", "payment", "transfer", "transaction", "balance",
        "credit", "debit", "loan", "deposit", "withdrawal", "wire", "routing", "billing",
        "invoice", "statement", "receipt", "tax", "refund", "rebate", "paypal", "venmo",
        "zelle", "ach", "direct deposit", "electronic transfer"
    ]
    
    sensitive_terms = [
        "password", "username", "login", "sign in", "authentication", "credential",
        "id", "identification", "identity", "ssn", "social security", "date of birth", 
        "dob", "address", "phone", "security question", "mother's maiden", "pin",
        "passcode", "secret", "verify", "validation", "confirm", "secure"
    ]
    
    official_terms = [
        "official", "authorized", "verified", "legitimate", "genuine", "authentic",
        "legal", "government", "federal", "state", "agency", "department", "administration",
        "office", "bureau", "division", "committee", "authority", "commission", "council"
    ]
    
    # Count occurrences of different types of terms
    financial_count = sum(1 for term in financial_terms if term in text_lower)
    sensitive_count = sum(1 for term in sensitive_terms if term in text_lower)
    official_count = sum(1 for term in official_terms if term in text_lower)
    
    # Calculate domain score based on term combinations and counts
    domain_score += min(0.5, financial_count * 0.05)  # Max 0.5 from financial terms
    domain_score += min(0.5, sensitive_count * 0.05)  # Max 0.5 from sensitive terms
    
    # Official terms combined with sensitive/financial is suspicious
    if official_count > 0 and (sensitive_count > 0 or financial_count > 0):
        domain_score += min(0.3, 0.1 * official_count)
    
    # Check for suspicious email domains
    suspicious_domains = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "mail.com"]
    legit_business_words = ["bank", "paypal", "amazon", "microsoft", "apple", "google", "facebook", "netflix", "ebay"]
    
    # Look for combination of business name with public email domain (e.g., amazon@gmail.com)
    domain_mismatch = False
    for business in legit_business_words:
        if business in text_lower:
            for domain in suspicious_domains:
                if domain in text_lower:
                    domain_mismatch = True
                    break
            if domain_mismatch:
                break
    
    if domain_mismatch:
        domain_score += 0.4
    
    # 3. Enhanced n-gram analysis
    ngram_score = 0
    
    # Expanded list of phishing n-grams, sorted by category
    phishing_ngrams = {
        # Action phrases
        "action_phrases": [
            "click here", "click below", "click link", "follow link", "open attachment",
            "download file", "visit link", "sign in now", "login now", "verify now",
            "update now", "confirm now", "act now", "respond now"
        ],
        
        # Account-related phrases
        "account_phrases": [
            "verify account", "confirm account", "update account", "account security",
            "account verification", "account update", "account confirmation", "account details",
            "account information", "account status", "account accessed", "account compromised"
        ],
        
        # Security-related phrases
        "security_phrases": [
            "security alert", "security notice", "security warning", "security update",
            "security breach", "security measure", "security protocol", "security team",
            "security department", "enhance security", "ensure security"
        ],
        
        # Information-related phrases
        "info_phrases": [
            "personal information", "sensitive information", "confidential information",
            "update information", "confirm information", "verify information",
            "provide information", "enter information", "submit information"
        ],
        
        # Urgency phrases
        "urgency_phrases": [
            "urgent action", "immediate action", "prompt action", "urgent attention",
            "limited time", "expires soon", "act quickly", "time sensitive",
            "final notice", "last chance", "avoid suspension", "prevent closure"
        ]
    }
    
    # Count ngrams by category for better analysis
    ngram_counts = {category: 0 for category in phishing_ngrams}
    
    for category, phrases in phishing_ngrams.items():
        for phrase in phrases:
            if phrase in text_lower:
                ngram_counts[category] += 1
    
    # Calculate score based on ngram category distribution
    for category, count in ngram_counts.items():
        if category == "action_phrases":
            ngram_score += min(0.4, count * 0.1)
        elif category == "account_phrases" or category == "info_phrases":
            ngram_score += min(0.5, count * 0.15)
        elif category == "security_phrases":
            ngram_score += min(0.3, count * 0.1)
        elif category == "urgency_phrases":
            ngram_score += min(0.5, count * 0.15)
    
    # Bonus for combinations across categories (more sophisticated phishing)
    categories_present = sum(1 for count in ngram_counts.values() if count > 0)
    if categories_present >= 3:  # If phrases from 3 or more categories are present
        ngram_score += 0.2
    
    ngram_score = min(1.0, ngram_score)
    
    # 4. Enhanced lexical diversity and writing style analysis
    style_score = 0
    
    # Calculate lexical diversity (unique words / total words)
    words = re.findall(r'\b\w+\b', text_lower)
    unique_words = set(words)
    
    if words:
        lexical_diversity = len(unique_words) / len(words)
        
        # Low diversity is suspicious (repetitive)
        if lexical_diversity < 0.4:
            style_score += 0.4
        elif lexical_diversity < 0.5:
            style_score += 0.2
        
        # Very high diversity can also be suspicious in certain contexts
        elif lexical_diversity > 0.95 and len(words) > 100:
            style_score += 0.2
    
    # Analyze sentence length
    sentences = re.split(r'[.!?]+', text)
    if sentences:
        sentence_lengths = [len(re.findall(r'\b\w+\b', s)) for s in sentences if s.strip()]
        if sentence_lengths:
            avg_sentence_length = sum(sentence_lengths) / len(sentence_lengths)
            
            # Very short or long sentences can be suspicious
            if avg_sentence_length < 3:
                style_score += 0.3
            elif avg_sentence_length > 25:
                style_score += 0.2
            
            # Check for inconsistent sentence lengths (large variance)
            if len(sentence_lengths) > 3:
                variance = sum((x - avg_sentence_length) ** 2 for x in sentence_lengths) / len(sentence_lengths)
                if variance > 100:  # High variance in sentence length
                    style_score += 0.2
    
    # Check for formal vs informal language mixing
    formal_markers = ["sincerely", "regards", "dear", "respectfully", "to whom it may concern", 
                       "yours truly", "cordially", "best regards", "yours faithfully"]
    informal_markers = ["hey", "hi there", "hello there", "thanks", "cheers", "bye", 
                         "cya", "see ya", "ttyl", "take care", "later"]
    
    formal_count = sum(1 for marker in formal_markers if marker in text_lower)
    informal_count = sum(1 for marker in informal_markers if marker in text_lower)
    
    # Mixing formal and informal style is suspicious
    if formal_count > 0 and informal_count > 0:
        style_score += 0.3
    
    # Check for overly formal language with action requests
    action_words = ["click", "download", "open", "visit", "check"]
    if formal_count > 1 and any(word in text_lower for word in action_words):
        style_score += 0.2
    
    # Check for typical phishing sign-offs
    phishing_signoffs = ["support team", "security team", "account team", "customer service",
                          "account department", "security department", "system administrator"]
    if any(signoff in text_lower for signoff in phishing_signoffs):
        style_score += 0.2
    
    style_score = min(1.0, style_score)
    
    # 5. Add content inconsistency detection (new category)
    inconsistency_score = 0
    
    # Check for inconsistency between subject and content
    # (This would be more effective with access to email headers)
    subject_indicators = ["subject:", "re:", "fw:"]
    for indicator in subject_indicators:
        if indicator in text_lower[:50]:  # Look for subject line at beginning
            subject_line = text_lower.split('\n')[0]
            # Check if subject mentions one topic but content is different
            if ("account" in subject_line and not "account" in text_lower[50:]) or \
               ("security" in subject_line and not "security" in text_lower[50:]) or \
               ("update" in subject_line and not "update" in text_lower[50:]) or \
               ("payment" in subject_line and not "payment" in text_lower[50:]):
                inconsistency_score += 0.3
                break
    
    # Check for content that starts with one topic and shifts to another
    content_parts = text_lower.split('\n\n')
    if len(content_parts) >= 2:
        first_part = content_parts[0]
        rest_parts = ' '.join(content_parts[1:])
        
        # Topic shift detection (based on key terms)
        topic_categories = {
            "account": ["account", "login", "password", "username"],
            "security": ["security", "breach", "unauthorized", "suspicious"],
            "payment": ["payment", "transaction", "money", "fund", "transfer"],
            "document": ["document", "attachment", "file", "report"]
        }
        
        # Check if first part focuses on one topic but later parts shift
        for topic, keywords in topic_categories.items():
            if any(keyword in first_part for keyword in keywords):
                has_shift = True
                for keyword in keywords:
                    if keyword in rest_parts:
                        has_shift = False
                        break
                if has_shift:
                    inconsistency_score += 0.25
                    break
    
    # Final weighted score with enhanced weights
    weights = {
        'stats': 0.15,
        'domain': 0.25,
        'ngram': 0.30,
        'style': 0.20,
        'inconsistency': 0.10
    }
    
    final_score = (
        stats_score * weights['stats'] +
        domain_score * weights['domain'] +
        ngram_score * weights['ngram'] +
        style_score * weights['style'] +
        inconsistency_score * weights['inconsistency']
    )
    
    # Debug logging
# Debug logging
    print(f"📊 NLP Model 2 Scores: stats={stats_score:.2f}, domain={domain_score:.2f}, " 
          f"ngrams={ngram_score:.2f}, style={style_score:.2f}, inconsistency={inconsistency_score:.2f}",
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