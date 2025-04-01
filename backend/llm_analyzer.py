"""
LLM-based phishing detection module using multiple models.
This module implements phishing detection algorithms using the Groq API
with multiple language models for analysis.
"""

import re
import json
import requests
import time

def check_phishing_with_llm(text, api_key=None, use_groq=True, groq_api_key=None):
    """
    Combined LLM-based phishing detection using multiple models
    
    Args:
        text (str): The email text to analyze
        api_key (str): OpenAI API key (fallback)
        use_groq (bool): Whether to use Groq API (True) or OpenAI (False)
        groq_api_key (str): Groq API key
        
    Returns:
        tuple: Two tuples (model1_score, model1_reason), (model2_score, model2_reason)
    """
    if not groq_api_key:
        print("❌ No valid API keys available for LLM analysis", flush=True)
        return (0.5, "No valid API key provided"), (0.5, "No valid API key provided")
    
    # Get results from both models
    model1_result = check_phishing_with_llama(text, groq_api_key)
    model2_result = check_phishing_with_gemma(text, groq_api_key)
    
    return model1_result, model2_result

def check_phishing_with_llama(text, groq_api_key):
    """
    Use Groq API with Llama 3.3 70B for phishing detection.
    
    Returns:
        tuple: (confidence_score, reasoning)
    """
    # Truncate very long texts to fit in LLM context
    max_text_length = 8000  # Llama-3.3-70b can handle longer context
    if len(text) > max_text_length:
        analysis_text = text[:max_text_length] + "... [text truncated]"
    else:
        analysis_text = text
        
    # Detailed prompt with criteria for evaluation and reasoning request
    prompt = (
        "You are a cybersecurity expert specializing in phishing detection. "
        "Analyze the following email for signs of phishing. Consider these factors:\n"
        "1. Urgency or threatening language\n"
        "2. Suspicious URLs or requests to click links\n"
        "3. Requests for personal or sensitive information\n"
        "4. Grammatical errors or unusual phrasing\n"
        "5. Impersonation of trusted entities\n"
        "6. Offers that seem too good to be true\n\n"
        "First, provide your reasoning by analyzing the email point by point. Then, "
        "rate this email's likelihood of being a phishing attempt on a scale of 0.0 to 1.0, "
        "where 0.0 means definitely legitimate and 1.0 means definitely phishing.\n\n"
        "Format your response exactly as follows:\n"
        "REASONING: Your detailed explanation here\n"
        "SCORE: The numerical score between 0.0 and 1.0\n\n"
        "Email text:\n" + analysis_text
    )
    
    # Try up to 3 times with exponential backoff in case of API rate limiting
    max_retries = 3
    for attempt in range(max_retries):
        try:
            print(f"🤖 Sending text to Groq Llama for analysis (length: {len(analysis_text)})", flush=True)
            
            response = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {groq_api_key}"
                },
                json={
                    "model": "llama-3.3-70b-versatile",  # Using Llama-3.3-70b for better accuracy
                    "messages": [
                        {"role": "system", "content": "You are a phishing detection expert that analyzes emails."},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.0,  # Keep temperature at 0 for consistent outputs
                    "max_tokens": 1500  # Allow more tokens for the reasoning
                },
                timeout=20  # Add timeout to prevent hanging
            )
            
            if response.status_code == 200:
                response_data = response.json()
                try:
                    response_text = response_data["choices"][0]["message"]["content"].strip()
                    
                    # Extract reasoning and score
                    reasoning_match = re.search(r'REASONING:(.*?)SCORE:', response_text, re.DOTALL)
                    score_match = re.search(r'SCORE:[\s]*([0-9]*[.]?[0-9]+)', response_text)
                    
                    reasoning = reasoning_match.group(1).strip() if reasoning_match else "No reasoning provided."
                    
                    if score_match:
                        score_text = score_match.group(1).strip()
                        confidence = float(score_text)
                        confidence = max(0.0, min(confidence, 1.0))  # Ensure score is between 0 and 1
                    else:
                        # Try to extract just a number if the format wasn't followed
                        number_match = re.search(r'([0-9]*[.])?[0-9]+', response_text)
                        if number_match:
                            confidence = float(number_match.group(0))
                            confidence = max(0.0, min(confidence, 1.0))
                        else:
                            confidence = 0.5  # Default if no score found
                    
                    print(f"🤖 Llama LLM returned confidence: {confidence}", flush=True)
                    return confidence, reasoning
                    
                except Exception as e:
                    print(f"❌ Error parsing Llama LLM response: {str(e)}", flush=True)
                    print(f"❌ Llama LLM raw response: {response_data}", flush=True)
                    return 0.5, f"Error parsing response: {str(e)}"
                    
            elif response.status_code == 429:  # Rate limit exceeded
                wait_time = (2 ** attempt) * 2  # Exponential backoff: 2, 4, 8 seconds
                print(f"⏱️ Rate limit exceeded, retrying in {wait_time} seconds...", flush=True)
                time.sleep(wait_time)
                continue
            else:
                print(f"❌ Groq API error for Llama: {response.status_code} - {response.text}", flush=True)
                return 0.5, f"API error: {response.status_code}"
                
        except Exception as e:
            print(f"❌ Error calling Groq for Llama: {str(e)}", flush=True)
            # Wait before retrying
            if attempt < max_retries - 1:  # Don't sleep on the last attempt
                wait_time = (2 ** attempt) * 2
                print(f"⏱️ Retrying in {wait_time} seconds...", flush=True)
                time.sleep(wait_time)
            else:
                return 0.5, f"Error: {str(e)}"
    
    # If we've exhausted all retries
    print("❌ All Groq API attempts for Llama failed", flush=True)
    return 0.5, "API call failed after multiple attempts"

def check_phishing_with_gemma(text, groq_api_key):
    """
    Use Groq API with Gemma 2 9B IT for phishing detection.
    
    Returns:
        tuple: (confidence_score, reasoning)
    """
    # Truncate very long texts to fit in LLM context
    max_text_length = 6000  # Gemma has smaller context
    if len(text) > max_text_length:
        analysis_text = text[:max_text_length] + "... [text truncated]"
    else:
        analysis_text = text
        
    # Detailed prompt with criteria for evaluation and reasoning request
    prompt = (
        "You are a cybersecurity expert specializing in phishing detection. "
        "Analyze the following email for signs of phishing. Consider these factors:\n"
        "1. Urgency or threatening language\n"
        "2. Suspicious URLs or requests to click links\n"
        "3. Requests for personal or sensitive information\n"
        "4. Grammatical errors or unusual phrasing\n"
        "5. Impersonation of trusted entities\n"
        "6. Offers that seem too good to be true\n\n"
        "First, provide your reasoning by analyzing the email point by point. Then, "
        "rate this email's likelihood of being a phishing attempt on a scale of 0.0 to 1.0, "
        "where 0.0 means definitely legitimate and 1.0 means definitely phishing.\n\n"
        "Format your response exactly as follows:\n"
        "REASONING: Your detailed explanation here\n"
        "SCORE: The numerical score between 0.0 and 1.0\n\n"
        "Email text:\n" + analysis_text
    )
    
    # Try up to 3 times with exponential backoff in case of API rate limiting
    max_retries = 3
    for attempt in range(max_retries):
        try:
            print(f"🤖 Sending text to Groq Gemma for analysis (length: {len(analysis_text)})", flush=True)
            
            response = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {groq_api_key}"
                },
                json={
                    "model": "gemma2-9b-it",  # Using Gemma 2 9B IT
                    "messages": [
                        {"role": "system", "content": "You are a cybersecurity expert specializing in phishing detection."},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.0,  # Keep temperature at 0 for consistent outputs
                    "max_tokens": 1500  # Allow more tokens for the reasoning
                },
                timeout=20  # Add timeout to prevent hanging
            )
            
            if response.status_code == 200:
                response_data = response.json()
                try:
                    response_text = response_data["choices"][0]["message"]["content"].strip()
                    
                    # Extract reasoning and score
                    reasoning_match = re.search(r'REASONING:(.*?)SCORE:', response_text, re.DOTALL)
                    score_match = re.search(r'SCORE:[\s]*([0-9]*[.]?[0-9]+)', response_text)
                    
                    reasoning = reasoning_match.group(1).strip() if reasoning_match else "No reasoning provided."
                    
                    if score_match:
                        score_text = score_match.group(1).strip()
                        confidence = float(score_text)
                        confidence = max(0.0, min(confidence, 1.0))  # Ensure score is between 0 and 1
                    else:
                        # Try to extract just a number if the format wasn't followed
                        number_match = re.search(r'([0-9]*[.])?[0-9]+', response_text)
                        if number_match:
                            confidence = float(number_match.group(0))
                            confidence = max(0.0, min(confidence, 1.0))
                        else:
                            confidence = 0.5  # Default if no score found
                    
                    print(f"🤖 Gemma LLM returned confidence: {confidence}", flush=True)
                    return confidence, reasoning
                    
                except Exception as e:
                    print(f"❌ Error parsing Gemma LLM response: {str(e)}", flush=True)
                    print(f"❌ Gemma LLM raw response: {response_data}", flush=True)
                    return 0.5, f"Error parsing response: {str(e)}"
                    
            elif response.status_code == 429:  # Rate limit exceeded
                wait_time = (2 ** attempt) * 2  # Exponential backoff: 2, 4, 8 seconds
                print(f"⏱️ Rate limit exceeded, retrying in {wait_time} seconds...", flush=True)
                time.sleep(wait_time)
                continue
            else:
                print(f"❌ Groq API error for Gemma: {response.status_code} - {response.text}", flush=True)
                return 0.5, f"API error: {response.status_code}"
                
        except Exception as e:
            print(f"❌ Error calling Groq for Gemma: {str(e)}", flush=True)
            # Wait before retrying
            if attempt < max_retries - 1:  # Don't sleep on the last attempt
                wait_time = (2 ** attempt) * 2
                print(f"⏱️ Retrying in {wait_time} seconds...", flush=True)
                time.sleep(wait_time)
            else:
                return 0.5, f"Error: {str(e)}"
    
    # If we've exhausted all retries
    print("❌ All Groq API attempts for Gemma failed", flush=True)
    return 0.5, "API call failed after multiple attempts"