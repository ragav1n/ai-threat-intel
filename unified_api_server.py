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
from datetime import datetime, timezone
from pathlib import Path
import json
import os
import re
import hmac

from threat_model.threat_summarizer.summarizer import summarize_threat
from threat_intel_aggregator.main import scheduled_job as collect_feeds
from threat_intel_aggregator.knowledge_graph.graph_manager import ThreatKnowledgeGraph

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

# Allowed severity values (prevents NoSQL regex injection)
ALLOWED_SEVERITIES = {"all", "critical", "high", "medium", "low", "unknown"}

# Allowed models for summarization
ALLOWED_SUMMARIZER_MODELS = {
    "qwen2.5:7b", "qwen2.5:3b", "llama3.2:3b", "llama3.1:8b",
    "mistral:7b", "gemma2:2b", "gemma2:9b",
}


def sanitize_query_string(value: str, max_length: int = 100) -> str:
    """Sanitize a user-provided string used in database queries.
    
    Strips regex metacharacters to prevent NoSQL regex injection.
    """
    if not value:
        return value
    value = value[:max_length].strip()
    # Remove regex metacharacters
    value = re.sub(r'[\\.*+?^${}()|\[\]]', '', value)
    return value


class IOCRequest(BaseModel):
    """Request model for IOC summarization."""
    ioc: str = Field(..., min_length=1, max_length=500, description="The IOC to analyze")
    model: str = Field(default="qwen2.5:7b", description="LLM model to use")
    
    @field_validator("ioc")
    @classmethod
    def validate_ioc(cls, v: str) -> str:
        """IOC format validation with injection protection."""
        v = v.strip()
        if not v:
            raise ValueError("IOC cannot be empty")
        # Block XSS, template injection, and shell metacharacters
        dangerous_patterns = ["<script>", "{{", "}}", "${", "`", ";", "&&", "||", "$(", "<!--"]
        if any(p in v for p in dangerous_patterns):
            raise ValueError("Invalid characters in IOC")
        return v
    
    @field_validator("model")
    @classmethod
    def validate_model(cls, v: str) -> str:
        if v not in ALLOWED_SUMMARIZER_MODELS:
            raise ValueError(f"Model not allowed. Allowed: {', '.join(sorted(ALLOWED_SUMMARIZER_MODELS))}")
        return v


class TriggerRequest(BaseModel):
    """Request model for feed trigger."""
    secret: str = Field(..., min_length=1, max_length=256)


class EmailRequest(BaseModel):
    """Request model for sending email report."""
    severity_filter: str = Field(default="High", description="Filter by severity: All, Critical, High, Medium, Low")
    limit: int = Field(default=50, ge=1, le=200)
    
    @field_validator("severity_filter")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        if v.lower() not in ALLOWED_SEVERITIES:
            raise ValueError(f"Invalid severity. Allowed: {', '.join(sorted(ALLOWED_SEVERITIES))}")
        return v


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


# ----------- Knowledge Graph Helper -----------

_kg_instance = None

def get_kg():
    """Returns the Knowledge Graph instance, refreshing from disk if needed."""
    global _kg_instance
    if _kg_instance is None:
        _kg_instance = ThreatKnowledgeGraph(read_only=True)
    else:
        _kg_instance.load()
    return _kg_instance


@app.on_event("shutdown")
def shutdown_event():
    """Gracefully close resources on shutdown."""
    global _kg_instance
    if _kg_instance:
        print("🛑 Closing Knowledge Graph connection...")
        _kg_instance.close()


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
    # Timing-safe comparison to prevent timing attacks
    if not hmac.compare_digest(body.secret, TRIGGER_SECRET):
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
    Get extracted IOCs. Prioritizes MongoDB for performance.
    """
    try:
        # Build query
        query = {}
        if ioc_type:
            query["type"] = ioc_type
        if severity:
            query["severity"] = severity

        # 1. Try MongoDB First (Indexed and fast)
        try:
            from threat_model.threat_summarizer.mongo_client import get_ioc_collection
            collection = get_ioc_collection()
            if collection is not None:
                # Default to ingested_at for freshness, but allow fallback
                sort_field = request.query_params.get("sortBy", "ingested_at")
                # Validate sort field
                if sort_field not in ["timestamp", "ingested_at", "confidence", "severity"]:
                    sort_field = "ingested_at"
                
                iocs = list(collection.find(query, {"_id": 0}).sort(sort_field, -1).limit(limit))
                if iocs:
                    # Fix: Ensure confidence is always populated for the frontend
                    for ioc in iocs:
                        if "confidence" not in ioc or ioc["confidence"] is None:
                            ioc["confidence"] = ioc.get("fused_confidence", 0.5)
                            
                    return {"count": len(iocs), "total_available": collection.count_documents(query), "iocs": iocs}
        except Exception as e:
            print(f"[⚠️ MongoDB fetch failed] {e}")

        # 2. Fallback to JSON (ONLY if MongoDB yielded nothing or failed)
        ioc_file = DATA_DIR / "normalized_iocs.json"
        if not iocs and ioc_file.exists():
            with open(ioc_file) as f:
                # Load with a generator or slice if possible? 
                # For now, just load and slice to prevent OOM
                iocs = json.load(f)
            
            # Apply Python-side filtering for fallback
            if ioc_type:
                safe_type = sanitize_query_string(ioc_type).lower()
                iocs = [i for i in iocs if safe_type in i.get("type", "").lower()]
            if severity:
                safe_sev = sanitize_query_string(severity).lower()
                iocs = [i for i in iocs if safe_sev in i.get("severity", "").lower()]
            
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
    Get IOC statistics. Optimized to use MongoDB aggregation.
    """
    try:
        # 1. Try MongoDB Aggregation (Fastest)
        try:
            from threat_model.threat_summarizer.mongo_client import get_ioc_collection
            collection = get_ioc_collection()
            if collection is not None:
                # Multi-facet aggregation for better performance
                pipeline = [
                    {"$facet": {
                        "total": [{"$count": "count"}],
                        "by_type": [
                            {"$group": {"_id": "$type", "count": {"$sum": 1}}},
                            {"$sort": {"count": -1}}
                        ],
                        "by_severity": [
                            {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
                            {"$sort": {"count": -1}}
                        ],
                        "top_feeds": [
                            {"$group": {"_id": "$feed", "count": {"$sum": 1}}},
                            {"$sort": {"count": -1}},
                            {"$limit": 20}
                        ]
                    }}
                ]
                facet_result = list(collection.aggregate(pipeline))[0]
                total = facet_result["total"][0]["count"] if facet_result["total"] else 0
                by_type = {item["_id"] or "unknown": item["count"] for item in facet_result["by_type"]}
                by_severity = {item["_id"] or "unknown": item["count"] for item in facet_result["by_severity"]}
                by_feed = {item["_id"] or "unknown": item["count"] for item in facet_result["top_feeds"]}
                
                return {
                    "total": total,
                    "by_type": by_type,
                    "by_severity": by_severity,
                    "top_feeds": by_feed
                }
        except Exception as e:
            print(f"[⚠️ MongoDB stats failed] {e}")

        # 2. Fallback to JSON (Slow)
        iocs = []
        ioc_file = DATA_DIR / "normalized_iocs.json"
        if ioc_file.exists():
            with open(ioc_file) as f:
                iocs = json.load(f)
        
        by_type = {}
        by_severity = {}
        by_feed = {}
        
        for ioc in iocs:
            ioc_type = ioc.get("type", "unknown")
            by_type[ioc_type] = by_type.get(ioc_type, 0) + 1
            sev = ioc.get("severity", "unknown")
            by_severity[sev] = by_severity.get(sev, 0) + 1
            feed = ioc.get("feed", "unknown")
            by_feed[feed] = by_feed.get(feed, 0) + 1
        
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
    from datetime import datetime, timedelta, timezone
    from collections import defaultdict
    
    try:
        # Determine time range
        # Determine time range
        now = datetime.now(timezone.utc)
        period_map = {"1d": 1, "7d": 7, "30d": 30, "90d": 90}
        days = period_map.get(period, 7)
        start_date = now - timedelta(days=days)
        start_date_str = start_date.strftime("%Y-%m-%dT%H:%M:%S")

        # 1. MongoDB Aggregation (Massively faster for 170k+ records)
        try:
            from threat_model.threat_summarizer.mongo_client import get_ioc_collection
            collection = get_ioc_collection()
            if collection is not None:
                group_field = "$severity" if group_by == "severity" else "$type"
                
                # MongoDB aggregation to bucket and group
                pipeline = [
                    # Filter by date window (Use ingested_at for activity graph if preferred, but user expects 'timestamp')
                    # Fallback to ingested_at if timestamp isn't reliable for activity
                    {"$match": {
                        "$or": [
                            {"ingested_at": {"$gte": start_date_str}},
                            {"timestamp": {"$gte": start_date_str}}
                        ]
                    }},
                    # Project simple date/hour bucket using string manipulation (safer than $dateFromString for mixed formats)
                    {"$project": {
                        "date_bucket": {
                            "$cond": {
                                "if": {"$ne": [period, "1d"]},
                                "then": {"$substr": [{"$ifNull": ["$ingested_at", "$timestamp"]}, 0, 10]},
                                "else": {"$substr": [{"$ifNull": ["$ingested_at", "$timestamp"]}, 0, 13]}
                            }
                        },
                        "group": group_field
                    }},
                    {"$group": {
                        "_id": {"date": "$date_bucket", "group": "$group"},
                        "count": {"$sum": 1}
                    }},
                    {"$sort": {"_id.date": 1}}
                ]
                
                results = list(collection.aggregate(pipeline))
                
                # Generate all buckets for padding
                buckets = []
                current = start_date
                step = timedelta(hours=1) if period == "1d" else timedelta(days=1)
                fmt = "%Y-%m-%d" if period != "1d" else "%Y-%m-%dT%H:00"
                label_fmt = "%b %d" if period != "1d" else "%H:00"
                
                while current <= now:
                    buckets.append({
                        "key": current.strftime(fmt),
                        "label": current.strftime(label_fmt)
                    })
                    current += step

                # Pivot results
                pivot = defaultdict(lambda: defaultdict(int))
                active_groups = set()
                for r in results:
                    pivot[r["_id"]["date"]][r["_id"]["group"]] = r["count"]
                    active_groups.add(r["_id"]["group"])

                # Order groups for UI consistency
                if group_by == "severity":
                    ordered_keys = ["Critical", "High", "Medium", "Low", "Unknown"]
                else:
                    ordered_keys = sorted(list(active_groups))

                # Final formatting
                chart_data = []
                for b in buckets:
                    point = {"period": b["label"]}
                    for k in ordered_keys:
                        # Normalize key name for UI
                        ui_key = k.capitalize() if group_by == "severity" else k
                        point[ui_key] = pivot[b["key"]].get(k, 0)
                    chart_data.append(point)

                return {
                    "group_by": group_by,
                    "keys": ordered_keys,
                    "data": chart_data
                }
        except Exception as e:
            print(f"⚠️ MongoDB Aggregation failed: {e}")
            # Fallback to empty if it fails to avoid breaking dashboard
            return {"group_by": group_by, "data": []}
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
            source_reliability=1.0,  # Manual analysis is self-trusted
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
            safe_sev = sanitize_query_string(severity)
            query["severity"] = {"$regex": f"^{safe_sev}$", "$options": "i"}
        
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
        from threat_model.threat_summarizer.mongo_client import get_collection, get_ioc_collection
        
        summary_coll = get_collection()
        ioc_coll = get_ioc_collection()
        
        # 1. Get Summary Stats (Processed Threats)
        summary_total = summary_coll.count_documents({}) if summary_coll is not None else 0
        summary_by_severity = {}
        if summary_coll is not None:
            for sev in ["Critical", "High", "Medium", "Low"]:
                count = summary_coll.count_documents({"severity": {"$regex": sev, "$options": "i"}})
                if count > 0:
                    summary_by_severity[sev] = count

        # 2. Get Raw IOC Stats (for real-time dashboard cards)
        # We merge these so the dashboard cards show the most impressive/accurate numbers
        if ioc_coll is not None:
            # High/Critical IOCs from raw data
            raw_critical = ioc_coll.count_documents({"severity": {"$regex": "Critical", "$options": "i"}})
            raw_high = ioc_coll.count_documents({"severity": {"$regex": "High", "$options": "i"}})
            
            # Combine or prefer higher number? 
            # Dashboard labels: "Critical Threats Detected" (Summaries) and "High Severity IOCs" (Raw)
            # We'll adjust the response to match what the dashboard expects
            combined_severity = {
                "Critical": summary_by_severity.get("Critical", 0), # Keep this for "Threats Detected"
                "High": max(summary_by_severity.get("High", 0), raw_high), # Use raw IOC count for "High Severity IOCs"
                "Medium": summary_by_severity.get("Medium", 0),
                "Low": summary_by_severity.get("Low", 0)
            }
        else:
            combined_severity = summary_by_severity

        return {
            "total": summary_total, 
            "by_severity": combined_severity,
            "raw_ioc_count": ioc_coll.count_documents({}) if ioc_coll is not None else 0
        }
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
            safe_sev = sanitize_query_string(body.severity_filter)
            query["severity"] = {"$regex": f"^{safe_sev}$", "$options": "i"}
        
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


# ----------- Knowledge Graph Routes -----------

@app.get("/api/knowledge-graph", tags=["Knowledge Graph"])
@limiter.limit("10/minute")
def get_knowledge_graph(
    request: Request,
    limit: int = Query(default=300, ge=1, le=500),
    min_confidence: float = Query(default=0.3, ge=0.0, le=1.0)
):
    """
    Get the current threat knowledge graph.
    Returns a high-centrality subgraph by default to maintain performance.
    """
    try:
        kg = get_kg()
        top_iocs = kg.get_top_nodes(n=limit)
        
        # Initial set of nodes (top IOCs)
        base_node_ids = {n["id"] for n in top_iocs if n.get("confidence", 0) >= min_confidence}
        
        # Subgraph of top-ranked IOCs and their interconnections
        subgraph = kg.graph.subgraph(base_node_ids)
        
        # Build final visualization data (Exclude context nodes)
        nodes = []
        visible_node_ids = set()
        for node_id, data in subgraph.nodes(data=True):
            # Double-check type filter even with subgraph restricted to IOCs
            if data.get("type", "").lower() != "context":
                nodes.append({
                    "data": {
                        "id": node_id,
                        **data
                    }
                })
                visible_node_ids.add(node_id)
            
        edges = []
        for u, v, k, data in subgraph.edges(data=True, keys=True):
            # Only return edges between visible nodes (IOCs)
            if u in visible_node_ids and v in visible_node_ids:
                edges.append({
                    "data": {
                        "id": f"{u}-{v}-{k}",
                        "source": u,
                        "target": v,
                        **data
                    }
                })
        
        return {
            "nodes": nodes,
            "edges": edges,
            "total_nodes": len(kg.graph.nodes),
            "total_edges": len(kg.graph.edges)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/knowledge-graph/query", tags=["Knowledge Graph"])
@limiter.limit("30/minute")
def query_knowledge_graph(
    request: Request,
    node: str = Query(..., description="The IOC or node ID to query"),
    depth: int = Query(default=1, ge=1, le=2)
):
    """
    Get the neighborhood of a specific node in the knowledge graph.
    """
    try:
        kg = get_kg()
        if not kg.graph.has_node(node):
            raise HTTPException(status_code=404, detail=f"Node '{node}' not found in graph")
            
        subgraph_nodes = {node}
        current_layer = {node}
        
        for _ in range(depth):
            next_layer = set()
            for n in current_layer:
                next_layer.update(kg.graph.neighbors(n))
                if kg.graph.is_directed():
                    # For directed graph, also get predecessors
                    next_layer.update(kg.graph.predecessors(n))
            subgraph_nodes.update(next_layer)
            current_layer = next_layer
            
        # Build response in Cytoscape format
        nodes = []
        for n_id in subgraph_nodes:
            nodes.append({"data": {"id": n_id, **kg.graph.nodes[n_id]}})
            
        edges = []
        for u, v, k, data in kg.graph.edges(data=True, keys=True):
            if u in subgraph_nodes and v in subgraph_nodes:
                edges.append({
                    "data": {
                        "id": f"{u}-{v}-{k}",
                        "source": u,
                        "target": v,
                        **data
                    }
                })
                
        return {
            "nodes": nodes,
            "edges": edges
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
@app.get("/api/knowledge-graph/node", tags=["Knowledge Graph"])
@limiter.limit("30/minute")
def get_node_details(
    request: Request,
    node: str = Query(..., description="The IOC or node ID to inspect")
):
    """
    Get detailed metadata for a single node, including its provenance from SQLite.
    """
    try:
        kg = get_kg()
        if not kg.graph.has_node(node):
            raise HTTPException(status_code=404, detail=f"Node '{node}' not found")
            
        data = dict(kg.graph.nodes[node])
        data["id"] = node
        
        # Get provenance and reviewed status from SQLite
        provenance = []
        reviewed = False
        try:
            with kg._get_db_conn() as conn:
                row = conn.execute(
                    "SELECT provenance, reviewed FROM node_metadata WHERE node_id = ?", 
                    (node,)
                ).fetchone()
                if row:
                    provenance = json.loads(row[0])
                    reviewed = bool(row[1])
        except Exception as e:
            print(f"⚠️ Metadata fetch error for {node}: {e}")
                
        data["provenance"] = provenance
        data["reviewed"] = data.get("reviewed", reviewed)
        return data
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/knowledge-graph/stats", tags=["Knowledge Graph"])
@limiter.limit("30/minute")
def get_knowledge_graph_stats(request: Request):
    """
    Get statistics about the knowledge graph.
    """
    try:
        kg = get_kg()
        import networkx as nx
        
        # Basic stats
        node_count = len(kg.graph.nodes)
        edge_count = len(kg.graph.edges)
        density = nx.density(kg.graph)
        
        # Node types distribution
        types = {}
        for _, data in kg.graph.nodes(data=True):
            t = data.get("type", "unknown")
            types[t] = types.get(t, 0) + 1
            
        return {
            "nodes": node_count,
            "edges": edge_count,
            "density": round(density, 6),
            "by_type": types,
            "schema_version": kg.SCHEMA_VERSION,
            "last_updated": datetime.fromtimestamp(kg._last_loaded_time, timezone.utc).isoformat() if kg._last_loaded_time else None
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ----------- Campaign Routes -----------

@app.get("/api/campaigns", tags=["Campaigns"])
@limiter.limit("30/minute")
def get_campaigns(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    sort_by: str = Query(default="last_seen", description="Sort by: last_seen, ioc_count, avg_confidence"),
    active_only: bool = Query(default=False, description="Only return campaigns active in last 48h"),
):
    """
    List detected threat campaigns.
    """
    try:
        from threat_intel_aggregator.feed_collection.mongo_writer import get_campaign_collection

        collection = get_campaign_collection()

        # Validate sort field
        allowed_sorts = {"last_seen", "ioc_count", "avg_confidence", "first_seen", "detected_at"}
        if sort_by not in allowed_sorts:
            sort_by = "last_seen"

        query = {}
        if active_only:
            from datetime import timedelta
            cutoff = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
            query["last_seen"] = {"$gte": cutoff}

        campaigns = list(
            collection.find(query, {"_id": 0, "ioc_members": 0})
            .sort(sort_by, -1)
            .limit(limit)
        )

        return {
            "count": len(campaigns),
            "total_available": collection.count_documents(query),
            "campaigns": campaigns,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/campaigns/stats", tags=["Campaigns"])
@limiter.limit("30/minute")
def get_campaign_stats(request: Request):
    """
    Get aggregate campaign statistics.
    """
    try:
        from threat_intel_aggregator.feed_collection.mongo_writer import get_campaign_collection
        from datetime import timedelta

        collection = get_campaign_collection()

        total = collection.count_documents({})
        cutoff_48h = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
        active = collection.count_documents({"last_seen": {"$gte": cutoff_48h}})

        # Aggregation for avg IOC count and top severity
        pipeline = [
            {"$facet": {
                "avg_ioc_count": [
                    {"$group": {"_id": None, "avg": {"$avg": "$ioc_count"}}}
                ],
                "total_iocs_in_campaigns": [
                    {"$group": {"_id": None, "total": {"$sum": "$ioc_count"}}}
                ],
                "largest_campaign": [
                    {"$sort": {"ioc_count": -1}},
                    {"$limit": 1},
                    {"$project": {"label": 1, "ioc_count": 1, "_id": 0}}
                ],
            }}
        ]
        facet_result = list(collection.aggregate(pipeline))
        facet = facet_result[0] if facet_result else {}

        avg_ioc = facet.get("avg_ioc_count", [{}])
        avg_ioc_count = avg_ioc[0].get("avg", 0) if avg_ioc else 0

        total_iocs = facet.get("total_iocs_in_campaigns", [{}])
        total_iocs_count = total_iocs[0].get("total", 0) if total_iocs else 0

        largest = facet.get("largest_campaign", [None])
        largest_campaign = largest[0] if largest else None

        return {
            "total_campaigns": total,
            "active_campaigns": active,
            "avg_ioc_count": round(avg_ioc_count, 1),
            "total_iocs_in_campaigns": total_iocs_count,
            "largest_campaign": largest_campaign,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/campaigns/timeline", tags=["Campaigns"])
@limiter.limit("30/minute")
def get_campaign_timeline(
    request: Request,
    period: str = Query(default="30d", description="Time period: 7d, 30d, 90d"),
):
    """
    Get time-series data of campaign activity for charting.
    """
    try:
        from threat_intel_aggregator.feed_collection.mongo_writer import get_campaign_collection
        from threat_intel_aggregator.campaign_detector.models import Campaign
        from threat_intel_aggregator.campaign_detector.temporal import build_campaign_timeline

        period_map = {"7d": 7, "30d": 30, "90d": 90}
        days = period_map.get(period, 30)

        collection = get_campaign_collection()
        raw_campaigns = list(collection.find({}, {"_id": 0}))

        # Reconstruct Campaign objects for timeline generation
        campaigns = []
        for doc in raw_campaigns:
            try:
                campaigns.append(Campaign.from_dict(doc))
            except Exception:
                continue

        timeline = build_campaign_timeline(campaigns, period_days=days)

        return {
            "period": period,
            "data": timeline,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/campaigns/{campaign_id}", tags=["Campaigns"])
@limiter.limit("30/minute")
def get_campaign_detail(
    request: Request,
    campaign_id: str,
):
    """
    Get full details of a single campaign, including IOC member list.
    """
    try:
        from threat_intel_aggregator.feed_collection.mongo_writer import get_campaign_collection

        collection = get_campaign_collection()
        campaign = collection.find_one({"campaign_id": campaign_id}, {"_id": 0})

        if not campaign:
            raise HTTPException(status_code=404, detail=f"Campaign '{campaign_id}' not found")

        return campaign
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ----------- Prediction Routes (Phase 4) -----------

@app.post("/api/predict/campaign/{campaign_id}", tags=["Predictions"])
@limiter.limit("2/minute")
def predict_campaign_ttp(
    request: Request,
    campaign_id: str,
    model: str = Query(default="qwen2.5:7b", description="LLM model for prediction"),
):
    """
    Run the agentic TTP prediction pipeline for a campaign.

    Uses a 3-step pipeline:
      1. Classify current MITRE ATT&CK kill chain stage
      2. Graph-informed reasoning about attacker's next move
      3. Probabilistic next-TTP prediction with defensive recommendations

    Rate limited to 2/min due to multiple LLM calls per prediction.
    """
    try:
        from threat_intel_aggregator.feed_collection.mongo_writer import (
            get_campaign_collection,
            get_prediction_collection,
            write_prediction_to_mongo,
        )
        from threat_intel_aggregator.predictive_graphrag.graph_traversal import GraphContextRetriever
        from threat_intel_aggregator.predictive_graphrag.ttp_predictor import TTPPredictor

        # 1. Fetch the campaign
        collection = get_campaign_collection()
        campaign = collection.find_one({"campaign_id": campaign_id}, {"_id": 0})
        if not campaign:
            raise HTTPException(status_code=404, detail=f"Campaign '{campaign_id}' not found")

        # 2. Retrieve rich context
        retriever = GraphContextRetriever(kg=get_kg())
        context = retriever.retrieve_campaign_context(campaign)

        # 3. Run agentic prediction pipeline
        predictor = TTPPredictor(model=model)
        prediction = predictor.predict(context)

        # 4. Persist prediction
        try:
            write_prediction_to_mongo(prediction)
        except Exception as e:
            print(f"⚠️ Prediction persistence failed: {e}")

        return prediction.to_dict()

    except HTTPException:
        raise
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/predict/stats", tags=["Predictions"])
@limiter.limit("30/minute")
def get_prediction_stats(request: Request):
    """
    Get aggregate prediction statistics.
    """
    try:
        from threat_intel_aggregator.feed_collection.mongo_writer import get_prediction_collection

        collection = get_prediction_collection()
        total = collection.count_documents({})

        if total == 0:
            return {
                "total_predictions": 0,
                "unique_campaigns_predicted": 0,
                "most_predicted_tactic": None,
                "avg_prediction_confidence": 0.0,
            }

        # Aggregate stats
        pipeline = [
            {"$facet": {
                "unique_campaigns": [
                    {"$group": {"_id": "$campaign_id"}},
                    {"$count": "count"},
                ],
                "tactic_distribution": [
                    {"$unwind": "$predictions"},
                    {"$group": {
                        "_id": "$predictions.tactic",
                        "count": {"$sum": 1},
                        "avg_confidence": {"$avg": "$predictions.confidence"},
                    }},
                    {"$sort": {"count": -1}},
                ],
                "avg_confidence": [
                    {"$unwind": "$predictions"},
                    {"$group": {
                        "_id": None,
                        "avg": {"$avg": "$predictions.confidence"},
                    }},
                ],
            }}
        ]

        facet = list(collection.aggregate(pipeline))
        facet = facet[0] if facet else {}

        unique = facet.get("unique_campaigns", [{}])
        unique_count = unique[0].get("count", 0) if unique else 0

        tactics = facet.get("tactic_distribution", [])
        most_predicted = tactics[0]["_id"] if tactics else None

        avg_conf = facet.get("avg_confidence", [{}])
        avg_confidence = avg_conf[0].get("avg", 0.0) if avg_conf else 0.0

        return {
            "total_predictions": total,
            "unique_campaigns_predicted": unique_count,
            "most_predicted_tactic": most_predicted,
            "avg_prediction_confidence": round(avg_confidence, 4),
            "tactic_distribution": {t["_id"]: t["count"] for t in tactics},
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/predict/history/{campaign_id}", tags=["Predictions"])
@limiter.limit("30/minute")
def get_prediction_history(
    request: Request,
    campaign_id: str,
    limit: int = Query(default=10, ge=1, le=50),
):
    """
    Get prediction history for a specific campaign.
    """
    try:
        from threat_intel_aggregator.feed_collection.mongo_writer import get_prediction_collection

        collection = get_prediction_collection()
        predictions = list(
            collection.find(
                {"campaign_id": campaign_id},
                {"_id": 0},
            )
            .sort("generated_at", -1)
            .limit(limit)
        )

        return {
            "campaign_id": campaign_id,
            "count": len(predictions),
            "predictions": predictions,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ----------- Run with Uvicorn -----------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
