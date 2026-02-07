"""
Unified API Server for AI Threat Intelligence.

Features:
- Rate limiting (10 requests/minute per IP)
- Input validation with Pydantic
- CORS support
- Structured error responses
"""
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import re

from threat_model.threat_summarizer.summarizer import summarize_threat
from threat_intel_aggregator.main import scheduled_job as collect_feeds

# Rate limiter setup
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="AI Threat Intel API",
    description="API for threat intelligence analysis and IOC summarization",
    version="2.0.0",
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ----------- Request/Response Models -----------

class IOCRequest(BaseModel):
    """Request model for IOC summarization."""
    ioc: str = Field(..., min_length=1, max_length=500, description="The IOC to analyze")
    model: str = Field(default="llama3.2:latest", description="LLM model to use")
    
    @field_validator("ioc")
    @classmethod
    def validate_ioc(cls, v: str) -> str:
        """Basic IOC format validation."""
        v = v.strip()
        if not v:
            raise ValueError("IOC cannot be empty")
        # Block obvious injection attempts
        if any(char in v for char in ["<script>", "{{", "}}", "${", "`"]):
            raise ValueError("Invalid characters in IOC")
        return v


class TriggerRequest(BaseModel):
    """Request model for feed trigger."""
    secret: str = Field(..., min_length=1)


class SummaryResponse(BaseModel):
    """Response model for summarization."""
    timestamp: str
    input: str
    summary: str
    severity: str
    enrichment: str | None = None


class ErrorResponse(BaseModel):
    """Standard error response."""
    error: str
    detail: str | None = None


# ----------- Config -----------

TRIGGER_SECRET = "socgen-feed-key"


# ----------- Exception Handler -----------

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle all unhandled exceptions."""
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "detail": str(exc)},
    )


# ----------- Routes -----------

@app.get("/", tags=["Health"])
def read_root():
    """Health check endpoint."""
    return {
        "message": "AI Threat Intel API is running",
        "version": "2.0.0",
        "docs_url": "/docs",
    }


@app.get("/health", tags=["Health"])
def health_check():
    """Detailed health check."""
    return {"status": "healthy", "service": "ai-threat-intel"}


@app.post("/api/summarize", response_model=SummaryResponse, tags=["Analysis"])
@limiter.limit("10/minute")
def summarize_endpoint(request: Request, body: IOCRequest):
    """
    Analyze and summarize a threat indicator.
    
    Rate limited to 10 requests per minute per IP.
    """
    try:
        result = summarize_threat(body.ioc, model=body.model)
        return SummaryResponse(
            timestamp=result["timestamp"],
            input=result["input"],
            summary=result["summary"],
            severity=result["severity"],
            enrichment=result.get("enrichment"),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/trigger-feed", tags=["Admin"])
@limiter.limit("2/minute")
def trigger_feed(request: Request, body: TriggerRequest):
    """
    Manually trigger feed collection.
    
    Requires secret key authentication.
    Rate limited to 2 requests per minute.
    """
    if body.secret != TRIGGER_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized trigger key")

    try:
        collect_feeds()
        return {"status": "Feed job executed successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/summaries", tags=["Data"])
@limiter.limit("30/minute")
def get_summaries(request: Request, limit: int = Field(default=50, ge=1, le=200)):
    """
    Retrieve recent threat summaries from database.
    
    Args:
        limit: Maximum number of summaries to return (1-200).
    """
    try:
        from threat_model.threat_summarizer.mongo_client import collection

        summaries = list(
            collection.find({}, {"_id": 0})
            .sort("timestamp", -1)
            .limit(limit)
        )

        return {"count": len(summaries), "summaries": summaries}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ----------- Run with Uvicorn -----------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
