import os
import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()

# Free Hugging Face Public Inference Endpoint API link
API_URL = "https://api-inference.huggingface.co/models/facebook/bart-large-mnli"
# Using a fallback token header authorization string if needed later
HEADERS = {}

class ScanRequest(BaseModel):
    text: str

@app.post("/scan")
async def scan_text(request: ScanRequest):
    if not request.text.strip():
        raise HTTPException(status_code=400, detail="No text provided")
    
    # Define our structural social engineering indicators
    candidate_labels = ["financial pressure", "account suspension threat", "phishing link/lure", "normal communication"]
    
    payload = {
        "inputs": request.text,
        "parameters": {"candidate_labels": candidate_labels}
    }
    
    try:
        # Route processing through Hugging Face's global engine infrastructure
        response = requests.post(API_URL, headers=HEADERS, json=payload)
        result = response.json()
        
        # Format map layout results
        scores = dict(zip(result['labels'], result['scores']))
        
        # Calculate a weighted Threat Index (0 - 100%)
        threat_score = int((scores["financial pressure"] + scores["account suspension threat"] + scores["phishing link/lure"]) * 100)
        
        detected_indicators = [label for label, score in scores.items() if score > 0.4 and label != "normal communication"]
        
        return {
            "threat_index": min(threat_score, 100),
            "indicators": detected_indicators,
            "raw_analysis": scores
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI Engine analysis failure: {str(e)}")