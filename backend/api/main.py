from fastapi import FastAPI
from pydantic import BaseModel
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from inference.predict_pipeline import PredictionPipeline

app = FastAPI(title="Smishing Detection API")

# Initialize the pipeline
pipeline = PredictionPipeline()

class SMSRequest(BaseModel):
    message: str

class SMSResponse(BaseModel):
    status: str
    risk_score: float
    reason: str
    important_words: list

@app.post("/predict", response_model=SMSResponse)
async def predict_sms(request: SMSRequest):
    result = pipeline.predict(request.message)
    return SMSResponse(**result)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
