"""
Database models and initialization for PhisGuard.AI
This module contains all database-related code including models and setup.
"""
import os
from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize SQLAlchemy without binding to an app yet
db = SQLAlchemy()
jwt = JWTManager()

def init_db(app):
    """Initialize database with the app"""
    # Configure app for database
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("SQLALCHEMY_DATABASE_URI")
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY")
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=365)
    
    # Initialize extensions with app
    db.init_app(app)
    jwt.init_app(app)
    
    # Create all tables
    with app.app_context():
        db.create_all()
        print("✅ Database initialized successfully")

class User(db.Model):
    """
    User model for authentication and storing user information.
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    def __repr__(self):
        return f"<User {self.username}>"

class PhishingText(db.Model):
    """
    Model for storing phishing analysis results.
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    selected_text = db.Column(db.Text, nullable=False)
    phishing_result = db.Column(db.String(100), nullable=False)
    
    # NLP confidence scores
    nlp_model1_confidence = db.Column(db.Float, nullable=False)
    nlp_model2_confidence = db.Column(db.Float, nullable=False)
    
    # LLM confidence scores
    llm_model1_confidence = db.Column(db.Float, nullable=False)
    llm_model2_confidence = db.Column(db.Float, nullable=False)
    
    # LLM reasoning
    llm_model1_reason = db.Column(db.Text, nullable=True)
    llm_model2_reason = db.Column(db.Text, nullable=True)
    
    # Combined result
    final_confidence = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Add fields for storing more detailed analysis
    severity = db.Column(db.String(50), nullable=True)
    indicators = db.Column(db.Text, nullable=True)  # Store as JSON string
    
    # Define the relationship with User
    user = db.relationship('User', backref=db.backref('texts', lazy=True))
    
    def __repr__(self):
        return f"<PhishingText {self.id} - {self.phishing_result}>"
    
    def to_dict(self):
        """Convert object to dictionary for API responses"""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "phishing_result": self.phishing_result,
            "nlp_model1_confidence": self.nlp_model1_confidence,
            "nlp_model2_confidence": self.nlp_model2_confidence,
            "llm_model1_confidence": self.llm_model1_confidence,
            "llm_model2_confidence": self.llm_model2_confidence,
            "llm_model1_reason": self.llm_model1_reason,
            "llm_model2_reason": self.llm_model2_reason,
            "final_confidence": self.final_confidence,
            "severity": self.severity,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "text_preview": self.selected_text[:100] + "..." if len(self.selected_text) > 100 else self.selected_text
        }