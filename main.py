import os
import requests
from fastapi import FastAPI, HTTPException, Request

app = FastAPI()

API_URL = "https://api-inference.huggingface.co/models/facebook/bart-large-mnli"
HEADERS = {}

@app.post("/scan")
async def scan_text(request: Request):
    try:
        body = await request.json()
        text_content = body.get("text", "")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON format submitted")

    if not text_content.strip():
        raise HTTPException(status_code=400, detail="No text provided")
    
    candidate_labels = ["financial pressure", "account suspension threat", "phishing link/lure", "normal communication"]
    
    payload = {
        "inputs": text_content,
        "parameters": {"candidate_labels": candidate_labels}
    }
    
    try:
        response = requests.post(API_URL, headers=HEADERS, json=payload)
        result = response.json()
        
        scores = dict(zip(result['labels'], result['scores']))
        
        # Calculate Threat Index (0 - 100%)
        threat_score = int((scores["financial pressure"] + scores["account suspension threat"] + scores["phishing link/lure"]) * 100)
        threat_score = min(threat_score, 100)
        
        # Map out the exact indicators detected
        detected_indicators = [label for label, score in scores.items() if score > 0.4 and label != "normal communication"]
        
        # Generate the strict string 'verdict' your Flutter app checks on line 152
        if threat_score >= 70:
            verdict_str = "SCAM"
        elif threat_score >= 35:
            verdict_str = "WARNING"
        else:
            verdict_str = "SAFE"
            
        # Return the exact key names your Flutter app uses (risk_score, keywords, analysis, verdict)
        return {
            "risk_score": threat_score,
            "keywords": detected_indicators,
            "analysis": f"Detected social engineering elements: {', '.join(detected_indicators) if detected_indicators else 'None detected'}.",
            "verdict": verdict_str
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI Engine analysis failure: {str(e)}")