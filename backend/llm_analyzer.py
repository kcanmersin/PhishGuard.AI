"""
LLM-based phishing detection module using Groq API.
This module implements a phishing detection algorithm using the Groq API
to analyze emails with advanced language models.
"""

import re
import json
import requests
import time

def check_phishing_with_llm(text, api_key=None, use_groq=True, groq_api_key=None):
    """
    Enhanced LLM-based phishing detection using a detailed prompt
    and robust error handling. Uses Groq API for faster and more efficient processing.
    
    Args:
        text (str): The email text to analyze
        api_key (str): OpenAI API key (fallback)
        use_groq (bool): Whether to use Groq API (True) or OpenAI (False)
        groq_api_key (str): Groq API key
        
    Returns:
        float: A confidence score between 0.0 and 1.0 where higher values 
              indicate a higher likelihood of phishing
    """
    # Always use Groq if we have a key
    if groq_api_key:
        return check_phishing_with_groq(text, groq_api_key)
    # Only use OpenAI as fallback if we have a valid key
    elif api_key and api_key.startswith("sk-"):
        return check_phishing_with_openai(text, api_key)
    else:
        # If no valid API keys, return a neutral score
        print("❌ No valid API keys available for LLM analysis", flush=True)
        return 0.5

def check_phishing_with_groq(text, groq_api_key):
    """
    Use Groq API for phishing detection.
    """
    # Truncate very long texts to fit in LLM context
    max_text_length = 8000  # Llama-3.3-70b can handle longer context
    if len(text) > max_text_length:
        analysis_text = text[:max_text_length] + "... [text truncated]"
    else:
        analysis_text = text
        
    # Detailed prompt with criteria for evaluation
    prompt = (
        "You are a cybersecurity expert specializing in phishing detection. "
        "Analyze the following email for signs of phishing. Consider these factors:\n"
        "1. Urgency or threatening language\n"
        "2. Suspicious URLs or requests to click links\n"
        "3. Requests for personal or sensitive information\n"
        "4. Grammatical errors or unusual phrasing\n"
        "5. Impersonation of trusted entities\n"
        "6. Offers that seem too good to be true\n\n"
        "Rate this email's likelihood of being a phishing attempt on a scale of 0.0 to 1.0, "
        "where 0.0 means definitely legitimate and 1.0 means definitely phishing.\n\n"
        "Return ONLY a single decimal number between 0.0 and 1.0 as your answer, with no additional text.\n\n"
        "Email text:\n" + analysis_text
    )
    
    # Try up to 3 times with exponential backoff in case of API rate limiting
    max_retries = 3
    for attempt in range(max_retries):
        try:
            print(f"🤖 Sending text to Groq for analysis (length: {len(analysis_text)})", flush=True)
            
            response = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {groq_api_key}"
                },
                json={
                    "model": "llama-3.3-70b-versatile",  # Using Llama-3.3-70b for better accuracy
                    "messages": [
                        {"role": "system", "content": "You are a phishing detection expert that only responds with a number between 0 and 1."},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.0,  # Keep temperature at 0 for consistent outputs
                    "max_tokens": 10
                },
                timeout=15  # Add timeout to prevent hanging
            )
            
            if response.status_code == 200:
                response_data = response.json()
                try:
                    confidence_str = response_data["choices"][0]["message"]["content"].strip()
                    # Extract just the number if there's any other text
                    number_match = re.search(r'([0-9]*[.])?[0-9]+', confidence_str)
                    if number_match:
                        confidence_str = number_match.group(0)
                    
                    confidence = float(confidence_str)
                    print(f"🤖 Groq LLM returned confidence: {confidence}", flush=True)
                    return max(0.0, min(confidence, 1.0))
                except Exception as e:
                    print(f"❌ Error parsing Groq LLM response: {str(e)}", flush=True)
                    print(f"❌ Groq LLM raw response: {response_data}", flush=True)
                    return 0.5
            elif response.status_code == 429:  # Rate limit exceeded
                wait_time = (2 ** attempt) * 2  # Exponential backoff: 2, 4, 8 seconds
                print(f"⏱️ Rate limit exceeded, retrying in {wait_time} seconds...", flush=True)
                time.sleep(wait_time)
                continue
            else:
                print(f"❌ Groq API error: {response.status_code} - {response.text}", flush=True)
                return 0.5
                
        except Exception as e:
            print(f"❌ Error calling Groq: {str(e)}", flush=True)
            # Wait before retrying
            if attempt < max_retries - 1:  # Don't sleep on the last attempt
                wait_time = (2 ** attempt) * 2
                print(f"⏱️ Retrying in {wait_time} seconds...", flush=True)
                time.sleep(wait_time)
            else:
                return 0.5
    
    # If we've exhausted all retries
    print("❌ All Groq API attempts failed", flush=True)
    return 0.5

def check_phishing_with_openai(text, api_key):
    """
    Use OpenAI API for phishing detection (fallback).
    """
    # Truncate very long texts to fit in LLM context
    max_text_length = 1500
    if len(text) > max_text_length:
        analysis_text = text[:max_text_length] + "... [text truncated]"
    else:
        analysis_text = text
        
    # More detailed prompt with criteria for evaluation
    prompt = (
        "You are a cybersecurity expert specializing in phishing detection. "
        "Analyze the following email for signs of phishing. Consider these factors:\n"
        "1. Urgency or threatening language\n"
        "2. Suspicious URLs or requests to click links\n"
        "3. Requests for personal or sensitive information\n"
        "4. Grammatical errors or unusual phrasing\n"
        "5. Impersonation of trusted entities\n"
        "6. Offers that seem too good to be true\n\n"
        "Rate this email's likelihood of being a phishing attempt on a scale of 0.0 to 1.0, "
        "where 0.0 means definitely legitimate and 1.0 means definitely phishing.\n\n"
        "Return ONLY a single decimal number between 0.0 and 1.0 as your answer, with no additional text.\n\n"
        "Email text:\n" + analysis_text
    )
    
    # Try up to 3 times with exponential backoff in case of API rate limiting
    max_retries = 3
    for attempt in range(max_retries):
        try:
            print(f"🤖 Sending text to OpenAI for analysis (length: {len(analysis_text)})", flush=True)
            
            response = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {api_key}"
                },
                json={
                    "model": "gpt-3.5-turbo",  # Using the more capable GPT-3.5 Turbo model
                    "messages": [
                        {"role": "system", "content": "You are a phishing detection expert that only responds with a number between 0 and 1."},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.0,  # Keep temperature at 0 for consistent outputs
                    "max_tokens": 10
                },
                timeout=10  # Add timeout to prevent hanging
            )
            
            if response.status_code == 200:
                response_data = response.json()
                try:
                    confidence_str = response_data["choices"][0]["message"]["content"].strip()
                    # Extract just the number if there's any other text
                    number_match = re.search(r'([0-9]*[.])?[0-9]+', confidence_str)
                    if number_match:
                        confidence_str = number_match.group(0)
                    
                    confidence = float(confidence_str)
                    print(f"🤖 OpenAI LLM returned confidence: {confidence}", flush=True)
                    return max(0.0, min(confidence, 1.0))
                except Exception as e:
                    print(f"❌ Error parsing OpenAI LLM response: {str(e)}", flush=True)
                    print(f"❌ OpenAI LLM raw response: {response_data}", flush=True)
                    return 0.5
            elif response.status_code == 429:  # Rate limit exceeded
                wait_time = (2 ** attempt) * 2  # Exponential backoff: 2, 4, 8 seconds
                print(f"⏱️ Rate limit exceeded, retrying in {wait_time} seconds...", flush=True)
                time.sleep(wait_time)
                continue
            else:
                print(f"❌ OpenAI API error: {response.status_code} - {response.text}", flush=True)
                return 0.5
                
        except Exception as e:
            print(f"❌ Error calling OpenAI: {str(e)}", flush=True)
            # Wait before retrying
            if attempt < max_retries - 1:  # Don't sleep on the last attempt
                wait_time = (2 ** attempt) * 2
                print(f"⏱️ Retrying in {wait_time} seconds...", flush=True)
                time.sleep(wait_time)
            else:
                return 0.5
    
    # If we've exhausted all retries
    print("❌ All OpenAI API attempts failed", flush=True)
    return 0.5