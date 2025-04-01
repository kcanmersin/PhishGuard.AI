"""
API endpoints for PhisGuard.AI
This module contains all API routes for the application.
"""
import json
import hashlib
from datetime import datetime
from flask import request, jsonify, current_app
from flask_cors import cross_origin
from flask_jwt_extended import create_access_token, decode_token

# Import models and database
from models import db, User, PhishingText

def register_routes(app):
    """Register all routes with the Flask app"""
    
    #-----------------
    # Authentication
    #-----------------
    
    @app.route('/register', methods=['POST'])
    def register():
        """
        Register a new user.
        Expects: username, password, email
        Returns: Success message
        """
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        email = data.get('email')
        
        # Validate input
        if not all([username, password, email]):
            return jsonify({"success": False, "message": "All fields are required"}), 400
            
        # Check if user already exists
        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            return jsonify({"success": False, "message": "Username or email already exists"}), 400
        
        # Hash password and create user
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        new_user = User(username=username, password=hashed_password, email=email)
        db.session.add(new_user)
        db.session.commit()
        
        return jsonify({"success": True, "message": "User registered successfully!"}), 201

    @app.route('/login', methods=['POST'])
    def login():
        """
        Authenticate a user and return a JWT token.
        Expects: username, password
        Returns: JWT token and user info
        """
        try:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
            
            print(f"Login attempt: User: {username}", flush=True)
            
            # Find user and verify password
            user = User.query.filter_by(username=username).first()
            if user and hashlib.sha256(password.encode()).hexdigest() == user.password:
                # Create access token
                access_token = create_access_token(
                    identity=user.username, 
                    additional_claims={"id": user.id}
                )
                
                # Update last login timestamp
                user.last_login = datetime.utcnow()
                db.session.commit()
                
                print(f"Login successful: {username}, Token: {access_token[:15]}...", flush=True)
                
                # Create response with token and user info
                response = jsonify({
                    "success": True,
                    "message": "Login successful",
                    "access_token": access_token,
                    "user": {
                        "id": user.id,
                        "username": user.username
                    }
                })
                
                return response, 200
            else:
                print(f"Login failed: {username}", flush=True)
                return jsonify({
                    "success": False,
                    "message": "Invalid username or password"
                }), 401
        except Exception as e:
            print(f"Login error: {str(e)}", flush=True)
            return jsonify({
                "success": False,
                "message": "An error occurred during login"
            }), 500

    @app.route('/verify_token', methods=['POST', 'OPTIONS'])
    @cross_origin(origins="*")
    def verify_token():
        """
        Verify if a token is valid.
        Expects: token
        Returns: Valid status and user info
        """
        if request.method == 'OPTIONS':
            response = jsonify({})
            response.headers.add("Access-Control-Allow-Origin", "*")
            response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
            response.headers.add("Access-Control-Allow-Methods", "POST,OPTIONS")
            return response, 200
        
        try:
            data = request.get_json(silent=True)
            if not data:
                return jsonify({"valid": False, "error": "No data provided"}), 400
            
            token = data.get("token")
            if not token:
                return jsonify({"valid": False, "error": "No token provided"}), 400
            
            token_preview = f"{token[:10]}...{token[-10:]}" if len(token) > 20 else token
            print(f"Verify token: {token_preview}", flush=True)
            
            try:
                # Decode and verify token
                decoded = decode_token(token)
                username = decoded["sub"]
                user_id = decoded.get("id")
                
                print(f"Token successfully verified: {username}", flush=True)
                
                # Check if user exists
                user = User.query.filter_by(username=username).first()
                if not user:
                    print(f"User not found: {username}", flush=True)
                    return jsonify({"valid": False, "error": "User not found"}), 404
                
                print(f"Token valid. User: {username}, ID: {user.id}", flush=True)
                return jsonify({
                    "valid": True,
                    "username": username,
                    "user_id": user.id
                }), 200
                
            except Exception as e:
                print(f"Token verification error: {str(e)}", flush=True)
                return jsonify({"valid": False, "error": "Invalid token"}), 200
                
        except Exception as e:
            print(f"General error in verify_token endpoint: {str(e)}", flush=True)
            return jsonify({"valid": False, "error": "Server error"}), 500

    @app.route('/check_token', methods=['POST', 'OPTIONS'])
    @cross_origin(origins="*", supports_credentials=True)
    def check_token():
        """
        Legacy endpoint for token verification. 
        Compatible with both cookie and request body tokens.
        """
        print("check_token endpoint called", flush=True)
        print(f"HTTP Method: {request.method}", flush=True)
        print(f"Headers: {dict(request.headers)}", flush=True)
        
        if request.method == 'OPTIONS':
            response = jsonify({})
            response.headers.add("Access-Control-Allow-Origin", "*")
            response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
            response.headers.add("Access-Control-Allow-Methods", "POST,OPTIONS")
            return response, 200
        
        try:
            # First check for token in cookies
            token = request.cookies.get('jwt_token')
            
            # If not in cookies, try request body
            if not token:
                data = request.get_json(silent=True)
                if data:
                    token = data.get("token")
            
            print(f"Check token - Token received: {token[:15] + '...' if token and len(token) > 30 else token}", flush=True)
            
            if not token:
                print("No token found", flush=True)
                return jsonify({"valid": False, "error": "No token provided"}), 200
            
            try:
                # Decode and verify token
                decoded = decode_token(token)
                username = decoded["sub"]
                
                print(f"Token successfully decoded. User: {username}", flush=True)
                
                # Check if user exists
                user = User.query.filter_by(username=username).first()
                if not user:
                    print(f"User not found: {username}", flush=True)
                    return jsonify({"valid": False, "error": "User not found"}), 200
                
                print(f"Token valid. User: {username}, ID: {user.id}", flush=True)
                return jsonify({
                    "valid": True,
                    "username": username,
                    "user_id": user.id
                }), 200
                
            except Exception as e:
                print(f"Token verification error: {str(e)}", flush=True)
                return jsonify({"valid": False, "error": "Invalid token"}), 200
                
        except Exception as e:
            print(f"General error in check_token endpoint: {str(e)}", flush=True)
            return jsonify({"valid": False, "error": "Server error"}), 500

    #-----------------
    # Phishing Analysis
    #-----------------
        
    @app.route('/analyze_email', methods=['POST', 'OPTIONS'])
    @cross_origin(origins="*")
    def analyze_email():
        """
        Analyze email text for phishing attempts.
        Expects: selected_text, email_data, jwt_token, models (optional)
        Returns: Analysis results with confidence scores and indicators
        """
        if request.method == 'OPTIONS':
            response = jsonify({})
            response.headers.add("Access-Control-Allow-Origin", "*")
            response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
            response.headers.add("Access-Control-Allow-Methods", "POST,OPTIONS")
            return response, 200
        
        try:
            data = request.get_json(silent=True)
            if not data:
                return jsonify({
                    "success": False, 
                    "message": "Invalid request format"
                }), 400
                
            email_content = data.get("selected_text", "").strip()
            email_data = data.get("email_data", {})
            selected_models = data.get("models", None)  # Get selected models if provided
            save_analysis = data.get("save_analysis", True)  # Default to saving
            
            print(f"📧 Email analysis request received: {email_data}", flush=True)
            if selected_models:
                print(f"📊 Selected models: {selected_models}", flush=True)
            
            if not email_content:
                return jsonify({
                    "success": False, 
                    "message": "Email content not found"
                }), 400
            
            # Get token from request
            jwt_token = data.get("jwt_token")
            if not jwt_token:
                print("No token found", flush=True)
                return jsonify({
                    "success": False,
                    "message": "You must be logged in to analyze emails",
                    "needs_login": True
                }), 200
            
            # Verify token
            try:
                decoded = decode_token(jwt_token)
                current_user = decoded["sub"]
                user = User.query.filter_by(username=current_user).first()
                
                if not user:
                    return jsonify({
                        "success": False,
                        "message": "User not found, please login again",
                        "needs_login": True
                    }), 200
                    
                print(f"✅ Token verified, user: {current_user}", flush=True)
            except Exception as e:
                print(f"❌ Token verification error: {str(e)}", flush=True)
                return jsonify({
                    "success": False,
                    "message": "Session invalid, please login again",
                    "needs_login": True
                }), 200
                
            # Log email details
            email_subject = email_data.get("subject", "")
            email_from = email_data.get("from", "")
            print(f"📧 Analyzing email: '{email_subject}' from: {email_from}", flush=True)
            
            # Enhanced phishing analysis with selected models
            analysis_result = current_app.analyze_phishing(email_content, selected_models)
            
            # Use the enhanced analysis result
            nlp_model1_confidence = analysis_result.get("nlp_model1_confidence")
            nlp_model2_confidence = analysis_result.get("nlp_model2_confidence") 
            llm_model1_confidence = analysis_result.get("llm_model1_confidence")
            llm_model2_confidence = analysis_result.get("llm_model2_confidence")
            llm_model1_reason = analysis_result.get("llm_model1_reason")
            llm_model2_reason = analysis_result.get("llm_model2_reason")
            final_confidence = analysis_result["final_confidence"]
            result_str = analysis_result["result"]
            severity = analysis_result["severity"]
            
            # Extract email indicators for better feedback
            indicators = current_app.extract_phishing_indicators(email_content)
            
            # Save analysis result to database if requested
            if save_analysis:
                new_text = PhishingText(
                    user_id=user.id,
                    selected_text=email_content,
                    phishing_result=result_str,
                    nlp_model1_confidence=nlp_model1_confidence if nlp_model1_confidence is not None else 0.5,
                    nlp_model2_confidence=nlp_model2_confidence if nlp_model2_confidence is not None else 0.5,
                    llm_model1_confidence=llm_model1_confidence if llm_model1_confidence is not None else 0.5,
                    llm_model2_confidence=llm_model2_confidence if llm_model2_confidence is not None else 0.5,
                    llm_model1_reason=llm_model1_reason,
                    llm_model2_reason=llm_model2_reason,
                    final_confidence=final_confidence,
                    severity=severity,
                    indicators=json.dumps(indicators)
                )
                db.session.add(new_text)
                db.session.commit()
                print(f"✅ Analysis result saved: {current_user}", flush=True)
            
            # Return success response with all model results
            return jsonify({
                "success": True,
                "message": "Email analysis completed",
                "result": result_str,
                "severity": severity,
                "nlp_model1_confidence": nlp_model1_confidence,
                "nlp_model2_confidence": nlp_model2_confidence,
                "llm_model1_confidence": llm_model1_confidence,
                "llm_model2_confidence": llm_model2_confidence,
                "llm_model1_reason": llm_model1_reason,
                "llm_model2_reason": llm_model2_reason,
                "final_confidence": final_confidence,
                "username": user.username,
                "indicators": indicators,
                "models": {
                    "nlp_model1": "Keyword & Pattern Analysis",
                    "nlp_model2": "Statistical & Linguistic Analysis",
                    "llm_model1": "Llama 3.3 70B",
                    "llm_model2": "Gemma 2 9B IT"
                }
            }), 200
                
        except Exception as e:
            print(f"❌ Analysis error: {str(e)}", flush=True)
            import traceback
            traceback.print_exc()
            return jsonify({
                "success": False,
                "message": "Server error"
            }), 500
    @app.route('/get_dashboard_data', methods=['GET'])
    def get_dashboard_data():
        """
        Get analysis history for the dashboard.
        Expects: token (query param)
        Returns: List of analysis results for the user
        """
        token = request.args.get('token')
        if not token:
            return jsonify({"success": False, "error": "Token is required"}), 400
        
        try:
            # Verify token
            decoded = decode_token(token)
            current_user = decoded["sub"]
            print(f"Dashboard Data - Authenticated User: {current_user}", flush=True)
            
            # Get user
            user = User.query.filter_by(username=current_user).first()
            if not user:
                return jsonify({"success": False, "error": "User not found"}), 404
            
            # Get analysis results
            results = PhishingText.query.filter_by(user_id=user.id).order_by(PhishingText.created_at.desc()).all()
            
            # Format results
            data = {
                "success": True,
                "username": user.username,
                "results": [
                    {
                        "id": r.id,
                        "selected_text": r.selected_text[:200] + "..." if len(r.selected_text) > 200 else r.selected_text,
                        "phishing_result": r.phishing_result,
                        "severity": r.severity,
                        "nlp_model1_confidence": r.nlp_model1_confidence,
                        "nlp_model2_confidence": r.nlp_model2_confidence,
                        "llm_model1_confidence": r.llm_model1_confidence,
                        "llm_model2_confidence": r.llm_model2_confidence,
                        "llm_model1_reason": r.llm_model1_reason,
                        "llm_model2_reason": r.llm_model2_reason,
                        "final_confidence": r.final_confidence,
                        "created_at": r.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                        "indicators": json.loads(r.indicators) if r.indicators else []
                    }
                    for r in results
                ],
                "models": {
                    "nlp_model1": "Keyword & Pattern Analysis",
                    "nlp_model2": "Statistical & Linguistic Analysis",
                    "llm_model1": "Llama 3.3 70B",
                    "llm_model2": "Gemma 2 9B IT"
                }
            }
            
            return jsonify(data), 200
            
        except Exception as e:
            print(f"Error in get_dashboard_data: {str(e)}", flush=True)
            import traceback
            traceback.print_exc()
            return jsonify({"success": False, "error": "Server error"}), 500
    
    @app.route('/delete_analysis', methods=['POST'])
    def delete_analysis():
        """
        Delete an analysis record.
        Expects: token, analysis_id
        Returns: Success message
        """
        try:
            data = request.get_json()
            token = data.get('token')
            analysis_id = data.get('analysis_id')
            
            if not token or not analysis_id:
                return jsonify({"success": False, "error": "Token and analysis_id are required"}), 400
            
            # Verify token
            decoded = decode_token(token)
            current_user = decoded["sub"]
            
            # Get user
            user = User.query.filter_by(username=current_user).first()
            if not user:
                return jsonify({"success": False, "error": "User not found"}), 404
            
            # Find the analysis record
            analysis = PhishingText.query.filter_by(id=analysis_id, user_id=user.id).first()
            if not analysis:
                return jsonify({"success": False, "error": "Analysis record not found"}), 404
            
            # Delete the record
            db.session.delete(analysis)
            db.session.commit()
            
            return jsonify({"success": True, "message": "Analysis record deleted successfully"}), 200
            
        except Exception as e:
            print(f"Error in delete_analysis: {str(e)}", flush=True)
            return jsonify({"success": False, "error": "Server error"}), 500