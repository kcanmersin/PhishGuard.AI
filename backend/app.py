"""
Main application file for PhisGuard.AI
This module initializes the Flask app and includes core functionality.
"""
import os
import sys
import logging
from flask import Flask, render_template, redirect, url_for, jsonify
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
from nlp_analyzer import check_phishing_with_nlp_model1, check_phishing_with_nlp_model2, extract_phishing_indicators
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

# Enhanced multi-model analysis function
def analyze_phishing(text, selected_models=None):
    """
    Enhanced analysis using multiple NLP and LLM models with weighted factors
    and detailed output. Can selectively run only specified models.
    
    Args:
        text (str): The text to analyze
        selected_models (dict, optional): Dictionary of models to use for analysis
            e.g. {'nlp_model1': True, 'llm_model2': True}
    """
    if selected_models is None:
        selected_models = {
            'nlp_model1': True,
            'nlp_model2': True,
            'llm_model1': True,
            'llm_model2': True
        }
    
    # Initialize with defaults (neutral scores)
    nlp_model1_confidence = 0.5
    nlp_model2_confidence = 0.5
    llm_model1_confidence = 0.5
    llm_model2_confidence = 0.5
    llm_model1_reason = ""
    llm_model2_reason = ""
    
    # Get confidence scores only from selected models
    if selected_models.get('nlp_model1'):
        nlp_model1_confidence = check_phishing_with_nlp_model1(text)
    
    if selected_models.get('nlp_model2'):
        nlp_model2_confidence = check_phishing_with_nlp_model2(text)
    
    # Get confidence scores and reasoning from selected LLM models
    if selected_models.get('llm_model1') or selected_models.get('llm_model2'):
        llm_results = check_phishing_with_llm(
            text=text, 
            api_key=None,  # Not using OpenAI
            use_groq=True,
            groq_api_key=GROQ_API_KEY
        )
        
        if selected_models.get('llm_model1'):
            llm_model1_confidence, llm_model1_reason = llm_results[0]
        
        if selected_models.get('llm_model2'):
            llm_model2_confidence, llm_model2_reason = llm_results[1]
    
    # Calculate weights based on which models are selected
    active_models_count = sum(1 for model in selected_models.values() if model)
    if active_models_count == 0:
        return {
            "result": "Error",
            "severity": "Unknown",
            "error": "No models selected for analysis"
        }
    
    # Each selected model contributes equally
    weight_per_model = 1.0 / active_models_count
    
    # Calculate a weighted final score
    final_confidence = 0.0
    if selected_models.get('nlp_model1'):
        final_confidence += nlp_model1_confidence * weight_per_model
    if selected_models.get('nlp_model2'):
        final_confidence += nlp_model2_confidence * weight_per_model
    if selected_models.get('llm_model1'):
        final_confidence += llm_model1_confidence * weight_per_model
    if selected_models.get('llm_model2'):
        final_confidence += llm_model2_confidence * weight_per_model
    
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
    
    # Log the analysis results
    print(f"📊 Analysis Results:", flush=True)
    if selected_models.get('nlp_model1'):
        print(f"📊 NLP Model 1: {nlp_model1_confidence:.2f}", flush=True)
    if selected_models.get('nlp_model2'):
        print(f"📊 NLP Model 2: {nlp_model2_confidence:.2f}", flush=True)
    if selected_models.get('llm_model1'):
        print(f"📊 LLM Model 1 (Llama): {llm_model1_confidence:.2f}", flush=True)
    if selected_models.get('llm_model2'):
        print(f"📊 LLM Model 2 (Gemma): {llm_model2_confidence:.2f}", flush=True)
    print(f"📊 Final Confidence: {final_confidence:.2f} - {result_str} ({severity})", flush=True)
    
    return {
        "result": result_str,
        "severity": severity,
        "nlp_model1_confidence": nlp_model1_confidence if selected_models.get('nlp_model1') else None,
        "nlp_model2_confidence": nlp_model2_confidence if selected_models.get('nlp_model2') else None,
        "llm_model1_confidence": llm_model1_confidence if selected_models.get('llm_model1') else None,
        "llm_model2_confidence": llm_model2_confidence if selected_models.get('llm_model2') else None,
        "llm_model1_reason": llm_model1_reason if selected_models.get('llm_model1') else None,
        "llm_model2_reason": llm_model2_reason if selected_models.get('llm_model2') else None,
        "final_confidence": final_confidence
    }
# Make analysis functions available at module level
app.analyze_phishing = analyze_phishing
app.extract_phishing_indicators = extract_phishing_indicators

# Run the app
if __name__ == '__main__':
    app.run(debug=True)