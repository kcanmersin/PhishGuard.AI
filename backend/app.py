import os
import requests
from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, decode_token
import hashlib
from flask_cors import CORS
import sys
import logging
from dotenv import load_dotenv
from datetime import timedelta, datetime

load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

logging.basicConfig(level=logging.DEBUG)
sys.stdout.reconfigure(line_buffering=True)

app = Flask(__name__, template_folder="templates", static_folder="static")

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("SQLALCHEMY_DATABASE_URI")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=365)

CORS(app)
db = SQLAlchemy(app)
jwt = JWTManager(app)

sys.stdout.reconfigure(line_buffering=True)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)

class PhishingText(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    selected_text = db.Column(db.Text, nullable=False)
    phishing_result = db.Column(db.String(100), nullable=False)
    nlp_confidence = db.Column(db.Float, nullable=False)
    llm_confidence = db.Column(db.Float, nullable=False)
    final_confidence = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('texts', lazy=True))
from flask_cors import cross_origin

@app.route('/analyze_email', methods=['POST'])
@cross_origin()
def analyze_email():
    try:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"error": "Request must contain JSON"}), 400
        
        jwt_token = data.get("jwt_token")
        
        email_content = data.get("selected_text", "").strip()
        email_data = data.get("email_data", {})
        analysis_mode = data.get("analysis_mode", "both")
        save_flag = data.get("save", False)
        
        if not email_content:
            return jsonify({"error": "Invalid 'selected_text' value"}), 400
        
        email_subject = email_data.get("subject", "")
        email_from = email_data.get("from", "")
        
        print(f"📧 Analyzing email: '{email_subject}' from {email_from}", flush=True)
        
        nlp_confidence = check_phishing_with_nlp(email_content)
        llm_confidence = check_phishing_with_llm(email_content)
        
        if analysis_mode == "nlp":
            final_confidence = nlp_confidence
        elif analysis_mode == "llm":
            final_confidence = llm_confidence
        else:
            final_confidence = (nlp_confidence + llm_confidence) / 2
        
        result_str = "Phishing" if final_confidence > 0.5 else "Safe"
        
        user = None
        if jwt_token:
            try:
                decoded = decode_token(jwt_token)
                current_user = decoded["sub"]
                user = User.query.filter_by(username=current_user).first()
                
                if user and save_flag:
                    new_text = PhishingText(
                        user_id=user.id,
                        selected_text=email_content,
                        phishing_result=result_str,
                        nlp_confidence=nlp_confidence,
                        llm_confidence=llm_confidence,
                        final_confidence=final_confidence
                    )
                    db.session.add(new_text)
                    db.session.commit()
                    save_flag = True
                    print(f"✅ Analysis saved for user: {current_user}", flush=True)
            except Exception as e:
                print(f"❌ Token validation error: {str(e)}", flush=True)
                save_flag = False
        
        return jsonify({
            "message": "Email analysis complete!",
            "result": result_str,
            "nlp_confidence": nlp_confidence,
            "llm_confidence": llm_confidence,
            "final_confidence": final_confidence,
            "saved": save_flag,
            "username": user.username if user else None
        }), 200
        
    except Exception as e:
        print(f"❌ Error in analyze_email: {str(e)}", flush=True)
        return jsonify({"error": "Internal Server Error"}), 500
from flask import request, jsonify
from flask_cors import cross_origin
from flask_jwt_extended import decode_token


@app.route('/check_token', methods=['POST', 'OPTIONS'])
@cross_origin(origins="*", supports_credentials=True)
def check_token():
    print("check_token endpoint'ine istek geldi", flush=True)
    print(f"HTTP Method: {request.method}", flush=True)
    print(f"Headers: {dict(request.headers)}", flush=True)
    
    if request.method == 'OPTIONS':
        response = jsonify({})
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
        response.headers.add("Access-Control-Allow-Methods", "POST,OPTIONS")
        return response, 200
    
    try:
        data = request.get_json(silent=True)
        print(f"Alınan veri: {data}", flush=True)
        
        if not data:
            print("JSON veri alınamadı", flush=True)
            return jsonify({"valid": False, "error": "No data provided"}), 400
        
        token = data.get("token")
        if not token:
            print("Token sağlanmadı", flush=True)
            return jsonify({"valid": False, "error": "No token provided"}), 400
        
        token_preview = f"{token[:10]}...{token[-10:]}" if len(token) > 20 else token
        print(f"İşlenen token: {token_preview}", flush=True)
        
        try:
            decoded = decode_token(token)
            username = decoded["sub"]
            user_id = decoded.get("id")
            
            print(f"Token başarıyla decode edildi. Kullanıcı: {username}", flush=True)
            
            user = User.query.filter_by(username=username).first()
            if not user:
                print(f"Kullanıcı bulunamadı: {username}", flush=True)
                return jsonify({"valid": False, "error": "User not found"}), 404
            
            print(f"Token geçerli. Kullanıcı: {username}, ID: {user.id}", flush=True)
            return jsonify({
                "valid": True,
                "username": username,
                "user_id": user.id
            }), 200
            
        except Exception as e:
            print(f"Token doğrulama hatası: {str(e)}", flush=True)
            return jsonify({"valid": False, "error": "Invalid token"}), 401
            
    except Exception as e:
        print(f"check_token endpoint'inde genel hata: {str(e)}", flush=True)
        return jsonify({"valid": False, "error": "Server error"}), 500
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

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
        return jsonify({"message": "Username or email already exists"}), 400
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    new_user = User(username=username, password=hashed_password, email=email)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User registered successfully!"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()
    if user and hashlib.sha256(password.encode()).hexdigest() == user.password:
        access_token = create_access_token(identity=user.username, additional_claims={"id": user.id})
        return jsonify(access_token=access_token), 200
    return jsonify({"message": "Invalid credentials"}), 401

def check_phishing_with_nlp(text):
    phishing_keywords = [
        "urgent", "click here", "password", "reset", "bank",
        "lottery", "account verification", "suspicious", "verify now"
    ]
    text_lower = text.lower()
    count = sum(1 for keyword in phishing_keywords if keyword in text_lower)
    confidence = count / len(phishing_keywords)
    return min(confidence, 1.0)

def check_phishing_with_llm(text):
    prompt = (
        "You are a phishing detection expert. Analyze the following email text and return only a numeric value between 0 and 1 "
        "that indicates the confidence that this text is a phishing attempt (0 means safe, 1 means definitely phishing). "
        "Return only the number without any additional text.\n\nEmail text:\n" + text
    )
    response = requests.post(
        "https://api.openai.com/v1/completions",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {OPENAI_API_KEY}"
        },
        json={
            "model": "text-davinci-003",
            "prompt": prompt,
            "temperature": 0.0,
            "max_tokens": 10
        }
    )
    if response.status_code == 200:
        response_data = response.json()
        try:
            confidence_str = response_data["choices"][0]["text"].strip()
            confidence = float(confidence_str)
            return max(0.0, min(confidence, 1.0))
        except Exception as e:
            print(f"Error parsing LLM response: {str(e)}", flush=True)
            return 0.5
    return 0.5

@app.route('/save_phishing_result', methods=['POST'])
def save_phishing_result():
    try:
        data = request.get_json(silent=True)
        raw_data = request.data.decode("utf-8")
        print(f"📦 Raw Request Data: {raw_data}", flush=True)
        print(f"📦 Parsed JSON Data: {data}", flush=True)
        if not data:
            return jsonify({"error": "Request must contain JSON"}), 400
        jwt_token = data.get("jwt_token")
        selected_text = data.get("selected_text", "").strip()
        analysis_mode = data.get("analysis_mode", "both")
        save_flag = data.get("save", True)
        if not jwt_token:
            return jsonify({"error": "'jwt_token' field is required"}), 400
        if not selected_text:
            return jsonify({"error": "Invalid 'selected_text' value"}), 400
        try:
            decoded = decode_token(jwt_token)
            current_user = decoded["sub"]
            print(f"👤 Authenticated User: {current_user}", flush=True)
        except Exception as e:
            print(f"❌ Error decoding JWT: {str(e)}", flush=True)
            return jsonify({"error": "Invalid JWT token"}), 401
        user = User.query.filter_by(username=current_user).first()
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        nlp_confidence = check_phishing_with_nlp(selected_text)
        llm_confidence = check_phishing_with_llm(selected_text)
        if analysis_mode == "nlp":
            final_confidence = nlp_confidence
        elif analysis_mode == "llm":
            final_confidence = llm_confidence
        else:
            final_confidence = (nlp_confidence + llm_confidence) / 2

        result_str = "Phishing" if final_confidence > 0.5 else "Safe"
        
        if save_flag:
            new_text = PhishingText(
                user_id=user.id,
                selected_text=selected_text,
                phishing_result=result_str,
                nlp_confidence=nlp_confidence,
                llm_confidence=llm_confidence,
                final_confidence=final_confidence
            )
            db.session.add(new_text)
            db.session.commit()
        
        return jsonify({
            "message": "Analysis complete!",
            "result": result_str,
            "nlp_confidence": nlp_confidence,
            "llm_confidence": llm_confidence,
            "final_confidence": final_confidence,
            "saved": save_flag
        }), 200
    except Exception as e:
        print(f"❌ Error in save_phishing_result: {str(e)}", flush=True)
        return jsonify({"error": "Internal Server Error"}), 500

@app.route('/get_dashboard_data', methods=['GET'])
def get_dashboard_data():
    token = request.args.get('token')
    if not token:
        return jsonify({"error": "Token is required"}), 400
    try:
        decoded = decode_token(token)
        current_user = decoded["sub"]
        print(f"Dashboard Data - Authenticated User: {current_user}", flush=True)
    except Exception as e:
        print(f"Token decode error: {str(e)}", flush=True)
        return jsonify({"error": "Invalid token"}), 401
    user = User.query.filter_by(username=current_user).first()
    if not user:
        return jsonify({"error": "User not found"}), 404
    results = PhishingText.query.filter_by(user_id=user.id).all()
    data = {
        "username": user.username,
        "results": [
            {
                "selected_text": r.selected_text,
                "phishing_result": r.phishing_result,
                "nlp_confidence": r.nlp_confidence,
                "llm_confidence": r.llm_confidence,
                "final_confidence": r.final_confidence,
                "created_at": r.created_at.strftime("%Y-%m-%d %H:%M:%S")
            }
            for r in results
        ]
    }
    return jsonify(data), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)