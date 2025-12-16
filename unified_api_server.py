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
    model: str = "llama3.2:latest"

class TriggerRequest(BaseModel):
    secret: str

# ----------- Config -----------

TRIGGER_SECRET = "socgen-feed-key"


# ----------- Routes -----------

@app.get("/")
def read_root():
    return {"message": "AI Threat Intel API is running", "docs_url": "/docs"}


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

@app.get("/api/summaries")
def get_summaries(limit: int = 50):
    try:
        from threat_model.threat_summarizer.mongo_client import collection
        
        # Fetch latest summaries
        summaries = list(collection.find(
            {}, 
            {"_id": 0}  # Exclude Mongo ID
        ).sort("timestamp", -1).limit(limit))
        
        return {"count": len(summaries), "summaries": summaries}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
