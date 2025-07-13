from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from threat_model.threat_summarizer.summarizer import summarize_threat
from threat_intel_aggregator.main import scheduled_job as collect_feeds

app = FastAPI()

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------- Request Models -----------

class IOCRequest(BaseModel):
    ioc: str
    model: str = "llama2"

class TriggerRequest(BaseModel):
    secret: str

# ----------- Config -----------

TRIGGER_SECRET = "socgen-feed-key"

# ----------- Routes -----------

@app.post("/api/summarize")
def summarize_endpoint(request: IOCRequest):
    try:
        result = summarize_threat(request.ioc, model=request.model)
        return {
            "timestamp": result["timestamp"],
            "input": result["input"],
            "summary": result["summary"],
            "severity": result["severity"],
            "corrected": result.get("corrected", False),
            "original_severity": result.get("original_severity")
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/trigger-feed")
def trigger_feed(request: TriggerRequest):
    if request.secret != TRIGGER_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized trigger key")

    try:
        collect_feeds()
        return {"status": "Feed job executed successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
