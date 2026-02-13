"""
Unified API Server for AI Threat Intelligence.

Features:
- Rate limiting (10 requests/minute per IP)
- Input validation with Pydantic
- CORS support
- Structured error responses
"""
from fastapi import FastAPI, HTTPException, Request, Query
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel, Field, field_validator
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from typing import List, Optional
from pathlib import Path
import json
import os

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
    model: str = Field(default="qwen2.5:7b", description="LLM model to use")
    
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


class EmailRequest(BaseModel):
    """Request model for sending email report."""
    severity_filter: str = Field(default="High", description="Filter by severity: All, Critical, High, Medium, Low")
    limit: int = Field(default=50, ge=1, le=200)


class SummaryResponse(BaseModel):
    """Response model for summarization with enhanced TTP mapping."""
    timestamp: str
    input: str
    summary: str
    severity: str
    enrichment: Optional[str] = None
    mitre_tactics: Optional[List[str]] = None  # Legacy field for backward compat
    mitre_ttps: Optional[List[dict]] = None  # Enhanced: [{technique_id, technique_name, tactic, confidence}]
    rag_context: Optional[List[str]] = None  # Retrieved MITRE context used
    recommendations: Optional[List[str]] = None


class IOCResponse(BaseModel):
    """Response model for IOC with hybrid confidence scoring."""
    feed: str
    ioc: str
    type: str
    severity: str
    confidence: float = Field(ge=0.0, le=1.0, description="Regex confidence score 0.0-1.0")
    fused_confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0, description="Fused confidence (0.4×regex + 0.6×LLM)")
    llm_confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0, description="LLM verification confidence")
    llm_verified: bool = Field(default=False, description="Whether LLM verification was performed")
    llm_reasoning: Optional[str] = Field(default=None, description="LLM reasoning for verification")
    deobfuscated: bool = Field(default=False, description="Whether IOC was deobfuscated")
    timestamp: str
    source_url: Optional[str] = None


# Allowed models for verification (prevents abuse of Ollama resources)
ALLOWED_VERIFIER_MODELS = {
    "qwen2.5:7b", "qwen2.5:3b", "llama3.2:3b", "llama3.1:8b",
    "mistral:7b", "gemma2:2b", "gemma2:9b",
}

# Allowed IOC types
ALLOWED_IOC_TYPES_API = {
    "auto", "ip", "ipv6", "domain", "url",
    "md5", "sha1", "sha256", "cve", "email",
}


class IOCVerifyRequest(BaseModel):
    """Request model for on-demand IOC verification."""
    ioc: str = Field(..., min_length=1, max_length=500)
    ioc_type: str = Field(default="auto", description="IOC type: ip, domain, url, md5, sha256, or auto")
    context: str = Field(default="", max_length=1000, description="Optional context text")
    model: str = Field(default="qwen2.5:7b", description="Ollama model for verification")
    
    @field_validator("ioc")
    @classmethod
    def validate_ioc_input(cls, v: str) -> str:
        """Sanitize IOC input."""
        v = v.strip()
        if not v:
            raise ValueError("IOC cannot be empty")
        # Block injection attempts
        if any(char in v for char in ["<script>", "{{", "}}", "${", "`"]):
            raise ValueError("Invalid characters in IOC")
        return v
    
    @field_validator("ioc_type")
    @classmethod
    def validate_ioc_type(cls, v: str) -> str:
        if v.lower() not in ALLOWED_IOC_TYPES_API:
            raise ValueError(f"Invalid IOC type. Allowed: {', '.join(sorted(ALLOWED_IOC_TYPES_API))}")
        return v.lower()
    
    @field_validator("model")
    @classmethod
    def validate_model(cls, v: str) -> str:
        if v not in ALLOWED_VERIFIER_MODELS:
            raise ValueError(f"Model not allowed. Allowed: {', '.join(sorted(ALLOWED_VERIFIER_MODELS))}")
        return v


class ErrorResponse(BaseModel):
    """Standard error response."""
    error: str
    detail: Optional[str] = None


# ----------- Config -----------

from config import TRIGGER_SECRET, DATA_DIR


# ----------- Exception Handler -----------

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle all unhandled exceptions."""
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "detail": str(exc)},
    )


# ----------- Health Routes -----------

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


# ----------- Analysis Routes -----------

@app.post("/api/summarize", response_model=SummaryResponse, tags=["Analysis"])
@limiter.limit("10/minute")
def summarize_endpoint(request: Request, body: IOCRequest):
    """
    Analyze and summarize a threat indicator with RAG-enhanced context.
    
    Returns:
    - Summary with MITRE ATT&CK TTP mappings including confidence scores
    - Retrieved MITRE context used for grounding
    - Actionable recommendations
    
    Rate limited to 10 requests per minute per IP.
    """
    try:
        result = summarize_threat(body.ioc, model=body.model)
        # Save summary to database
        from threat_model.threat_summarizer.mongo_client import upload_summary, upload_ioc
        upload_summary(result)
        
        # Also store the IOC itself for the IOC table
        from datetime import datetime, timezone, timedelta
        from threat_intel_aggregator.feed_collection.ioc_extractor import extract_iocs_with_confidence
        
        # IST timezone
        IST = timezone(timedelta(hours=5, minutes=30))
        timestamp = datetime.now(IST).isoformat()
        
        # Smart Type Detection for non-standard IOCs (Registry, File Paths)
        import re
        ioc_input = body.ioc.strip()
        detected_type = "unknown"
        smart_confidence = 0.0
        
        # Registry key patterns
        if re.search(r'^(HKEY_|HK[A-Z]{2,}\\|HKCU\\|HKLM\\)', ioc_input, re.IGNORECASE):
            detected_type = "registry_key"
            smart_confidence = 0.95
        # File path patterns (Windows)
        elif re.search(r'^[A-Za-z]:\\|\\\\[a-zA-Z0-9]', ioc_input):
            detected_type = "file_path"
            smart_confidence = 0.95
        # File path patterns (Unix - absolute paths only)
        elif re.search(r'^/[a-zA-Z0-9_\-.]+(/[a-zA-Z0-9_\-.]+)+', ioc_input):
            detected_type = "file_path"
            smart_confidence = 0.90

        # If we detected a specific type (Registry/File), use it immediately
        if detected_type != "unknown":
            ioc_data = {
                "ioc": ioc_input,
                "type": detected_type,
                "severity": result.get("severity", "Medium"),
                "confidence": smart_confidence,
                "feed": "Manual Analysis",
                "source_url": "dashboard",
                "timestamp": timestamp
            }
            upload_ioc(ioc_data)
        else:
            # Fallback to standard extraction for IPs, Domains, URLs, Hashes
            iocs = extract_iocs_with_confidence(body.ioc)
            
            if iocs:
                for ioc_match in iocs:
                    ioc_data = {
                        "ioc": ioc_match.value,
                        "type": ioc_match.ioc_type.value,
                        "severity": result.get("severity", "Medium"),
                        "confidence": ioc_match.confidence,
                        "feed": "Manual Analysis",
                        "source_url": "dashboard",
                        "timestamp": timestamp
                    }
                    upload_ioc(ioc_data)
            else:
                # If nothing extracted, try to identify IPs/Domains/Hashes loosely or just store as unknown
                # Simple fallback/unknown detection
                final_type = "unknown"
                final_conf = 0.5
                
                # Loose checks for single items that extractor might have missed or filtered
                if re.search(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc_input):
                    final_type = "ip"
                    final_conf = 0.8
                elif re.search(r'^[a-fA-F0-9]{32,64}$', ioc_input):
                    final_type = "hash"
                    final_conf = 0.9
                
                ioc_data = {
                    "ioc": ioc_input,
                    "type": final_type,
                    "severity": result.get("severity", "Medium"),
                    "confidence": final_conf,
                    "feed": "Manual Analysis",
                    "source_url": "dashboard",
                    "timestamp": timestamp
                }
                upload_ioc(ioc_data)

        return SummaryResponse(
            timestamp=result["timestamp"],
            input=result["input"],
            summary=result["summary"],
            severity=result["severity"],
            enrichment=result.get("enrichment"),
            mitre_tactics=result.get("mitre_tactics"),
            mitre_ttps=result.get("mitre_ttps"),
            rag_context=result.get("rag_context"),
            recommendations=result.get("recommendations"),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ----------- Feed Routes -----------

@app.get("/api/feeds", tags=["Feeds"])
@limiter.limit("30/minute")
def get_feeds(request: Request):
    """
    Get list of configured feeds and their health status.
    """
    try:
        from threat_intel_aggregator.feed_collection.config import load_feed_metadata
        from threat_intel_aggregator.feed_collection.health import load_health_data
        
        feeds = load_feed_metadata()
        health = load_health_data()
        
        result = []
        for feed in feeds:
            name = feed.get("name", "Unknown")
            feed_health = health.get(name, {})
            result.append({
                "name": name,
                "url": feed.get("url"),
                "category": feed.get("category"),
                "source_type": feed.get("source_type"),
                "priority": feed.get("priority", "medium"),
                "success_count": feed_health.get("success", 0),
                "failure_count": feed_health.get("failure", 0),
                "last_response_time": feed_health.get("last_response_time"),
            })
        
        return {
            "count": len(result),
            "feeds": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/feeds/stats", tags=["Feeds"])
@limiter.limit("30/minute")
def get_feed_stats(request: Request):
    """
    Get feed collection statistics.
    """
    try:
        from threat_intel_aggregator.feed_collection.collector import get_feed_stats
        stats = get_feed_stats()
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/feeds/collect", tags=["Feeds"])
@limiter.limit("2/minute")
def trigger_feed_collection(request: Request, body: TriggerRequest):
    """
    Manually trigger feed collection.
    
    Requires secret key authentication.
    """
    if body.secret != TRIGGER_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized trigger key")

    try:
        collect_feeds()
        return {"status": "Feed collection completed successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ----------- IOC Routes -----------

@app.get("/api/iocs", tags=["IOCs"])
@limiter.limit("30/minute")
def get_iocs(
    request: Request,
    limit: int = Query(default=100, ge=1, le=1000),
    ioc_type: Optional[str] = Query(default=None, description="Filter by type: ip, domain, url, hash"),
    severity: Optional[str] = Query(default=None, description="Filter by severity"),
):
    """
    Get extracted IOCs from collected feeds AND manual analysis.
    """
    try:
        iocs = []
        
        # Load IOCs from feeds (normalized_iocs.json)
        ioc_file = DATA_DIR / "normalized_iocs.json"
        if ioc_file.exists():
            with open(ioc_file) as f:
                iocs = json.load(f)
        
        # Also load IOCs from MongoDB (manual analysis)
        try:
            from threat_model.threat_summarizer.mongo_client import get_ioc_collection
            collection = get_ioc_collection()
            if collection is not None:
                mongo_iocs = list(collection.find({}, {"_id": 0}).sort("timestamp", -1).limit(500))
                # Merge with file IOCs, avoiding duplicates
                existing_values = {i.get("ioc") for i in iocs}
                for m_ioc in mongo_iocs:
                    if m_ioc.get("ioc") not in existing_values:
                        iocs.append(m_ioc)
        except Exception as e:
            print(f"[⚠️ MongoDB IOC fetch failed] {e}")
        
        # Apply filters
        if ioc_type:
            iocs = [i for i in iocs if ioc_type.lower() in i.get("type", "").lower()]
        if severity:
            iocs = [i for i in iocs if severity.lower() in i.get("severity", "").lower()]
        
        # Sort by timestamp and limit
        iocs = sorted(iocs, key=lambda x: x.get("timestamp", ""), reverse=True)[:limit]
        
        return {
            "count": len(iocs),
            "total_available": len(iocs),
            "iocs": iocs
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/iocs/stats", tags=["IOCs"])
@limiter.limit("30/minute")
def get_ioc_stats(request: Request):
    """
    Get IOC statistics by type and severity (includes manual analysis).
    """
    try:
        iocs = []
        
        # Load from file
        ioc_file = DATA_DIR / "normalized_iocs.json"
        if ioc_file.exists():
            with open(ioc_file) as f:
                iocs = json.load(f)
        
        # Also include MongoDB IOCs
        try:
            from threat_model.threat_summarizer.mongo_client import get_ioc_collection
            collection = get_ioc_collection()
            if collection is not None:
                mongo_iocs = list(collection.find({}, {"_id": 0}))
                existing_values = {i.get("ioc") for i in iocs}
                for m_ioc in mongo_iocs:
                    if m_ioc.get("ioc") not in existing_values:
                        iocs.append(m_ioc)
        except Exception:
            pass
        
        by_type = {}
        by_severity = {}
        by_feed = {}
        
        for ioc in iocs:
            # Count by type
            ioc_type = ioc.get("type", "unknown")
            by_type[ioc_type] = by_type.get(ioc_type, 0) + 1
            
            # Count by severity
            sev = ioc.get("severity", "unknown")
            by_severity[sev] = by_severity.get(sev, 0) + 1
            
            # Count by feed
            feed = ioc.get("feed", "unknown")
            by_feed[feed] = by_feed.get(feed, 0) + 1
        
        # Sort by_feed by count
        by_feed = dict(sorted(by_feed.items(), key=lambda x: x[1], reverse=True)[:20])
        
        return {
            "total": len(iocs),
            "by_type": by_type,
            "by_severity": by_severity,
            "top_feeds": by_feed
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/iocs/frequency", tags=["IOCs"])
@limiter.limit("30/minute")
def get_ioc_frequency(
    request: Request,
    period: str = Query(default="7d", description="Time period: 1d, 7d, 30d, 90d"),
    group_by: str = Query(default="severity", description="Group by: severity or type"),
):
    """
    Get IOC frequency data aggregated by time buckets and grouped by severity or type.
    Used for the Attack Frequency area chart on the dashboard.
    """
    from datetime import datetime, timedelta
    from collections import defaultdict

    try:
        iocs = []

        # Load from file
        ioc_file = DATA_DIR / "normalized_iocs.json"
        if ioc_file.exists():
            with open(ioc_file) as f:
                iocs = json.load(f)

        # Also include MongoDB IOCs
        try:
            from threat_model.threat_summarizer.mongo_client import get_ioc_collection
            collection = get_ioc_collection()
            if collection is not None:
                mongo_iocs = list(collection.find({}, {"_id": 0}))
                existing_values = {i.get("ioc") for i in iocs}
                for m_ioc in mongo_iocs:
                    if m_ioc.get("ioc") not in existing_values:
                        iocs.append(m_ioc)
        except Exception:
            pass

        # Determine time range and bucket format
        now = datetime.utcnow()
        period_config = {
            "1d":  {"delta": timedelta(days=1),  "fmt": "%H:00",       "label_fmt": "%H:00",       "step": timedelta(hours=1)},
            "7d":  {"delta": timedelta(days=7),  "fmt": "%Y-%m-%d",    "label_fmt": "%a",          "step": timedelta(days=1)},
            "30d": {"delta": timedelta(days=30), "fmt": "%Y-%m-%d",    "label_fmt": "%b %d",       "step": timedelta(days=1)},
            "90d": {"delta": timedelta(days=90), "fmt": "%Y-W%W",      "label_fmt": "Week %W",     "step": timedelta(weeks=1)},
        }

        if period not in period_config:
            raise HTTPException(status_code=400, detail=f"Invalid period. Must be one of: {', '.join(period_config.keys())}")

        cfg = period_config[period]
        start_time = now - cfg["delta"]

        # Generate all time buckets
        buckets = []
        current = start_time
        while current <= now:
            bucket_key = current.strftime(cfg["fmt"])
            bucket_label = current.strftime(cfg["label_fmt"])
            buckets.append({"key": bucket_key, "label": bucket_label})
            current += cfg["step"]

        # Deduplicate buckets while preserving order
        seen = set()
        unique_buckets = []
        for b in buckets:
            if b["key"] not in seen:
                seen.add(b["key"])
                unique_buckets.append(b)
        buckets = unique_buckets

        # Group IOCs into buckets
        group_field = "severity" if group_by == "severity" else "type"
        bucket_data = defaultdict(lambda: defaultdict(int))
        all_keys = set()

        for ioc in iocs:
            ts_str = ioc.get("timestamp", "")
            if not ts_str:
                continue

            try:
                # Parse ISO timestamp
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00")).replace(tzinfo=None)
            except (ValueError, TypeError):
                continue

            if ts < start_time:
                continue

            bucket_key = ts.strftime(cfg["fmt"])
            group_value = ioc.get(group_field, "unknown")
            # Normalize the group value
            if group_by == "severity":
                group_value = group_value.capitalize() if group_value else "Unknown"
            else:
                group_value = group_value.lower() if group_value else "unknown"

            bucket_data[bucket_key][group_value] += 1
            all_keys.add(group_value)

        # Determine keys order
        if group_by == "severity":
            ordered_keys = [k for k in ["Critical", "High", "Medium", "Low", "Unknown"] if k in all_keys]
        else:
            # Sort by total count descending, take top 8
            key_totals = defaultdict(int)
            for bd in bucket_data.values():
                for k, v in bd.items():
                    key_totals[k] += v
            ordered_keys = sorted(key_totals.keys(), key=lambda x: key_totals[x], reverse=True)[:8]

        # Build response data
        data = []
        for bucket in buckets:
            point = {"period": bucket["label"]}
            for key in ordered_keys:
                point[key] = bucket_data[bucket["key"]].get(key, 0)
            data.append(point)

        return {
            "group_by": group_by,
            "keys": ordered_keys,
            "data": data
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/iocs/verify", tags=["IOCs"])
@limiter.limit("5/minute")
def verify_ioc_endpoint(request: Request, body: IOCVerifyRequest):
    """
    On-demand LLM verification of a single IOC.
    
    Returns regex confidence, LLM confidence, and fused confidence score.
    """
    try:
        from threat_intel_aggregator.feed_collection.ioc_extractor import extract_iocs_with_confidence
        from threat_intel_aggregator.feed_collection.llm_ioc_verifier import get_llm_verifier
        from threat_intel_aggregator.feed_collection.confidence_fusion import fuse_with_penalty
        from threat_intel_aggregator.feed_collection.ioc_deobfuscator import deobfuscate_text
        
        # Deobfuscate first
        deobfuscated_text, was_deobfuscated = deobfuscate_text(body.ioc)
        
        # Regex extraction
        ioc_matches = extract_iocs_with_confidence(deobfuscated_text)
        
        if not ioc_matches:
            # No IOC found by regex — still try LLM verification
            regex_confidence = 0.5
            ioc_type = body.ioc_type if body.ioc_type != "auto" else "unknown"
        else:
            best_match = ioc_matches[0]
            regex_confidence = best_match.confidence
            ioc_type = str(best_match.ioc_type) if body.ioc_type == "auto" else body.ioc_type
        
        # LLM verification
        verifier = get_llm_verifier(model=body.model)
        verification = verifier.verify_ioc(
            ioc_value=body.ioc,
            ioc_type=ioc_type,
            context_snippet=body.context,
        )
        
        # Confidence fusion
        fused = fuse_with_penalty(
            regex_confidence=regex_confidence,
            llm_confidence=verification.llm_confidence,
            llm_is_valid=verification.is_valid_ioc,
        )
        
        return {
            "ioc": body.ioc,
            "ioc_type": ioc_type,
            "deobfuscated": was_deobfuscated,
            "regex_confidence": round(regex_confidence, 4),
            "llm_confidence": round(verification.llm_confidence, 4),
            "fused_confidence": round(fused, 4),
            "is_valid_ioc": verification.is_valid_ioc,
            "llm_reasoning": verification.reasoning,
            "llm_verified": verification.error is None,
            "model_used": verification.model_used,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ----------- Summary Routes -----------

@app.get("/api/summaries", tags=["Summaries"])
@limiter.limit("30/minute")
def get_summaries(
    request: Request, 
    limit: int = Query(default=50, ge=1, le=200),
    severity: Optional[str] = Query(default=None, description="Filter by severity"),
):
    """
    Retrieve recent threat summaries from database.
    """
    try:
        from threat_model.threat_summarizer.mongo_client import get_collection
        
        collection = get_collection()
        if collection is None:
            return {"count": 0, "summaries": [], "message": "MongoDB not configured"}
        
        query = {}
        if severity:
            query["severity"] = {"$regex": severity, "$options": "i"}
        
        summaries = list(
            collection.find(query, {"_id": 0})
            .sort("timestamp", -1)
            .limit(limit)
        )

        return {"count": len(summaries), "summaries": summaries}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/summaries/stats", tags=["Summaries"])
@limiter.limit("30/minute")
def get_summary_stats(request: Request):
    """
    Get summary statistics.
    """
    try:
        from threat_model.threat_summarizer.mongo_client import get_collection
        
        collection = get_collection()
        if collection is None:
            return {"total": 0, "by_severity": {}}
        
        total = collection.count_documents({})
        
        # Count by severity
        by_severity = {}
        for sev in ["Critical", "High", "Medium", "Low"]:
            count = collection.count_documents({"severity": {"$regex": sev, "$options": "i"}})
            if count > 0:
                by_severity[sev] = count
        
        return {"total": total, "by_severity": by_severity}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ----------- Report Routes -----------

@app.post("/api/reports/generate", tags=["Reports"])
@limiter.limit("5/minute")
def generate_report(request: Request, limit: int = Query(default=50, ge=1, le=100)):
    """
    Generate a PDF report of recent threat summaries.
    """
    try:
        from threat_model.threat_summarizer.mongo_client import get_collection
        from threat_model.threat_summarizer.pdf_generator import generate_pdf
        
        collection = get_collection()
        if collection is None:
            raise HTTPException(status_code=500, detail="MongoDB not configured")
        
        summaries = list(
            collection.find({}, {"_id": 0})
            .sort("timestamp", -1)
            .limit(limit)
        )
        
        if not summaries:
            raise HTTPException(status_code=404, detail="No summaries to generate report")
        
        pdf_path = generate_pdf(summaries, "threat_model/logs/api_report.pdf")
        
        return {
            "status": "success",
            "message": f"Report generated with {len(summaries)} summaries",
            "download_url": "/api/reports/download"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/reports/download", tags=["Reports"])
def download_report(request: Request):
    """
    Download the generated PDF report.
    """
    pdf_path = Path("threat_model/logs/api_report.pdf")
    if not pdf_path.exists():
        raise HTTPException(status_code=404, detail="No report available. Generate one first.")
    
    return FileResponse(
        path=pdf_path,
        filename="threat_intel_report.pdf",
        media_type="application/pdf"
    )


# ----------- Email Routes -----------

@app.post("/api/email/send", tags=["Email"])
@limiter.limit("3/minute")
def send_email_report(request: Request, body: EmailRequest):
    """
    Send an email report with threat summaries.
    """
    try:
        from threat_model.threat_summarizer.mongo_client import get_collection
        from threat_model.threat_summarizer.emailer import send_batch_email, is_email_configured
        
        if not is_email_configured():
            raise HTTPException(status_code=500, detail="Email not configured. Check .env file.")
        
        collection = get_collection()
        if collection is None:
            raise HTTPException(status_code=500, detail="MongoDB not configured")
        
        # Build query
        query = {}
        if body.severity_filter and body.severity_filter != "All":
            query["severity"] = {"$regex": body.severity_filter, "$options": "i"}
        
        summaries = list(
            collection.find(query, {"_id": 0})
            .sort("timestamp", -1)
            .limit(body.limit)
        )
        
        if not summaries:
            raise HTTPException(status_code=404, detail="No summaries match the filter")
        
        success = send_batch_email(summaries)
        
        if success:
            return {"status": "success", "message": f"Email sent with {len(summaries)} summaries"}
        else:
            raise HTTPException(status_code=500, detail="Failed to send email")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/email/status", tags=["Email"])
def get_email_status(request: Request):
    """
    Check if email is configured.
    """
    from threat_model.threat_summarizer.emailer import is_email_configured, EMAIL_USER, EMAIL_TO
    
    configured = is_email_configured()
    return {
        "configured": configured,
        "from": EMAIL_USER if configured else None,
        "to": EMAIL_TO if configured else None,
    }


# ----------- Legacy Route (backward compat) -----------

@app.post("/api/trigger-feed", tags=["Admin"], deprecated=True)
@limiter.limit("2/minute")
def trigger_feed_legacy(request: Request, body: TriggerRequest):
    """Legacy endpoint - use /api/feeds/collect instead."""
    return trigger_feed_collection(request, body)


# ----------- Run with Uvicorn -----------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
