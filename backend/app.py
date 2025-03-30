"""
Main application file for PhisGuard.AI
This module initializes the Flask app and includes core functionality.
"""
import os
import sys
import logging
from flask import Flask, render_template, redirect, url_for
from flask_cors import CORS
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
# Groq API key for primary use
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
# OpenAI key is not valid, so don't use it
OPENAI_API_KEY = None
DATABASE_URI = os.getenv("SQLALCHEMY_DATABASE_URI")
JWT_SECRET = os.getenv("JWT_SECRET_KEY", 'your_jwt_secret_key')

# Configure logging
logging.basicConfig(level=logging.DEBUG)
sys.stdout.reconfigure(line_buffering=True)

# Initialize Flask app
app = Flask(__name__, template_folder="templates", static_folder="static")

# Enable CORS
CORS(app)

# Override database URI from environment
os.environ['SQLALCHEMY_DATABASE_URI'] = DATABASE_URI
os.environ['JWT_SECRET_KEY'] = JWT_SECRET

# Import database models and initialize
from models import init_db, db, User, PhishingText
init_db(app)

# Import analysis modules
from nlp_analyzer import check_phishing_with_nlp
from llm_analyzer import check_phishing_with_llm

# Import routes and register them
from routes import register_routes
register_routes(app)

# Basic routes for pages
@app.route('/')
def index():
    return redirect(url_for('login_page'))

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/register')
def register_page():
    return render_template('register.html')

@app.route('/dashboard')
def dashboard_page():
    return render_template('dashboard.html')

# Combined analysis function
def analyze_phishing(text):
    """
    Combined analysis using both NLP and LLM methods with weighted factors
    and detailed output.
    """
    # Get confidence scores from both methods
    nlp_confidence = check_phishing_with_nlp(text)
    
    # Use Groq API exclusively since OpenAI API key is not valid
    llm_confidence = check_phishing_with_llm(
        text=text, 
        api_key=None,  # Not using OpenAI
        use_groq=True,
        groq_api_key=GROQ_API_KEY
    )
    
    # Calculate a weighted final score
    # We can give more weight to the LLM as it's likely more accurate
    final_confidence = (nlp_confidence * 0.4) + (llm_confidence * 0.6)
    
    # Determine result
    result_str = "Phishing" if final_confidence > 0.5 else "Safe"
    
    # Add additional context based on confidence level
    if final_confidence > 0.8:
        severity = "High risk"
    elif final_confidence > 0.6:
        severity = "Medium risk"
    elif final_confidence > 0.4:
        severity = "Low risk"
    else:
        severity = "Very low risk"
    
    return {
        "result": result_str,
        "severity": severity,
        "nlp_confidence": nlp_confidence,
        "llm_confidence": llm_confidence,
        "final_confidence": final_confidence
    }

# Extract phishing indicators for the UI
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
    
    # If no indicators found
    if not indicators:
        indicators.append({
            "type": "no_obvious_indicators",
            "severity": "info",
            "description": "No obvious phishing indicators detected"
        })
    
    return indicators

# Make analysis functions available at module level
app.analyze_phishing = analyze_phishing
app.extract_phishing_indicators = extract_phishing_indicators

# Run the app
if __name__ == '__main__':
    app.run(debug=True)