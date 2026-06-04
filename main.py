from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from transformers import pipeline

app = FastAPI()

# Initialize the classification pipeline (loads on server startup)
classifier = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")

class ScanRequest(BaseModel):
    text: str

@app.post("/scan")
async def scan_text(request: ScanRequest):
    if not request.text.strip():
        raise HTTPException(status_code=400, detail="No text provided")
    
    # Define semantic indicators of social engineering
    candidate_labels = ["financial pressure", "account suspension threat", "phishing link/lure", "normal communication"]
    
    # Run AI sequence classification
    result = classifier(request.text, candidate_labels)
    
    # Extract scores map
    scores = dict(zip(result['labels'], result['scores']))
    
    # Calculate a weighted Threat Index (0 - 100%)
    threat_score = int((scores["financial pressure"] + scores["account suspension threat"] + scores["phishing link/lure"]) * 100)
    
    # Identify high-risk triggers
    detected_indicators = [label for label, score in scores.items() if score > 0.4 and label != "normal communication"]
    
    return {
        "threat_index": min(threat_score, 100),
        "indicators": detected_indicators,
        "raw_analysis": scores
    }