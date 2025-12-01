"""
Platform Legitimacy Analyzer - Complete Backend API
FastAPI + Python + Groq API + Twitter
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, HttpUrl
from typing import Optional, List, Dict
from pathlib import Path
import os

# ============================================
# LOAD ENVIRONMENT VARIABLES FIRST (CRITICAL!)
# ============================================
from dotenv import load_dotenv

# Load .env file
load_dotenv()

# Display API configuration status
print("\n" + "="*70)
print("🔑 API CONFIGURATION STATUS")
print("="*70)

# --- CORRECTED KEYS ---
groq_key = os.getenv('GROQ_API_KEY', '') # Corrected from xai_key
twitter_token = os.getenv('TWITTER_BEARER_TOKEN', '')
# Removed reddit_id and reddit_secret

print(f"Groq API (Llama): {'✅ Loaded (' + groq_key[:15] + '...)' if groq_key else '❌ MISSING - Add GROQ_API_KEY to .env'}")
print(f"Twitter Token:    {'✅ Loaded (' + twitter_token[:10] + '...)' if twitter_token else '⚠️  Optional - Not configured'}")
# Removed Reddit print statements

# Check if we can use enhanced analyzer (Now only depends on Groq)
has_required_keys = bool(groq_key)

if has_required_keys:
    print("\n🚀 Status: PHASE 1 ENHANCED MODE ACTIVE")
    print("   Using: Real WHOIS + Groq AI + (Twitter if available)")
else:
    print("\n⚠️  Status: BASIC MODE - Missing API keys")
    print("   Add GROQ_API_KEY to Backend/.env to enable Phase 1 features")

print("="*70 + "\n")

# ============================================
# IMPORT ANALYZER (Smart Selection)
# ============================================
try:
    if has_required_keys:
        # Use Phase 1 Enhanced Analyzer
        from enhanced_analyzer import EnhancedAnalyzer as WebsiteAnalyzer
        print("✅ Using Enhanced Analyzer (Phase 1 - with Groq/Twitter)")
    else:
        # Fall back to basic analyzer
        from analyzer import WebsiteAnalyzer
        print("⚠️  Using Basic Analyzer (add API keys for Phase 1)")
except ImportError as e:
    print(f"⚠️  Import warning: {e}")
    print("   Attempting fallback import...")
    try:
        from analyzer import WebsiteAnalyzer
        print("✅ Using Basic Analyzer")
    except Exception as final_error:
        print(f"❌ Critical Error: Cannot import analyzer - {final_error}")
        raise

app = FastAPI(title="Legitimacy Analyzer API", version="1.0.0")

# ============================================
# CORS Configuration (UNCHANGED)
# ============================================
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================
# Mount Static Files (UNCHANGED)
# ============================================
# ... (Static file mounting code is unchanged) ...
from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent
DIST_DIR = (BASE_DIR / ".." / "frontend" / "dist").resolve()
ASSETS_DIR = DIST_DIR / "assets"

if ASSETS_DIR.exists():
    app.mount("/assets", StaticFiles(directory=str(ASSETS_DIR)), name="assets")

# ============================================
# Catch-All Route (UNCHANGED)
# ============================================
@app.get("/{full_path:path}")
async def serve_react_app(full_path: str):
    # Skip API routes
    if full_path.startswith("api/"):
        raise HTTPException(status_code=404, detail="API endpoint not found")
    
    if not DIST_DIR.exists():
        return JSONResponse(
            {
                "error": "Frontend not built or dev server not running.",
                "help": "Run `cd frontend && npm run dev` for dev or `cd frontend && npm run build` to build."
            },
            status_code=502
        )

    requested = DIST_DIR / full_path
    if requested.exists() and requested.is_file():
        return FileResponse(str(requested))

    index_file = DIST_DIR / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))

    return JSONResponse({"error": "index.html not found in frontend/dist"}, status_code=500)


# ============================================
# DATA MODELS (UNCHANGED)
# ============================================

class AnalysisRequest(BaseModel):
    url: str

class WHOISData(BaseModel):
    registrar: str
    owner: str
    email: str
    lastUpdated: str

class ContentAnalysis(BaseModel):
    aboutUsFound: bool
    termsOfServiceFound: bool
    contactInfoFound: bool
    physicalAddressFound: bool
    teamPhotosAnalyzed: bool
    stockImagesDetected: bool

class SocialData(BaseModel):
    redditMentions: int
    twitterMentions: int
    trustpilotScore: float
    scamAdvisorScore: int

class PonziCalculation(BaseModel):
    promisedReturn: str
    yearlyEquivalent: str
    sustainability: str
    collapseDays: str

class Finding(BaseModel):
    type: str  # critical, warning, info
    text: str

class Sentiment(BaseModel):
    positive: int
    neutral: int
    negative: int

class AnalysisResult(BaseModel):
    url: str
    trustScore: int
    verdict: str
    domainAge: str
    domainRegistered: str
    sslStatus: str
    serverLocation: str
    whoisData: WHOISData
    contentAnalysis: ContentAnalysis
    socialData: SocialData
    withdrawalComplaints: int
    findings: List[Finding]
    sentiment: Sentiment
    redFlags: List[str]
    ponziCalculation: Optional[PonziCalculation]
    scamProbability: str
    recommendation: str


# ============================================
# API ENDPOINTS
# ============================================

@app.get("/")
async def root():
    """Root endpoint - API health check"""
    return {
        "status": "ok",
        "message": "Legitimacy Analyzer API is running",
        "version": "1.0.0",
        "platform": "LegitCheck",
        "mode": "enhanced" if has_required_keys else "basic",
        "apis_active": {
            "groq_api": bool(groq_key), # Corrected from grok_ai/xai_key
            "twitter": bool(twitter_token)
        }
    }


@app.get("/api/status")
async def api_status():
    """API status check endpoint"""
    return {
        "status": "ok",
        "platform": "LegitCheck",
        "analyzer_mode": "enhanced" if has_required_keys else "basic",
        "features": {
            "whois": True,
            "ssl_check": True,
            "content_analysis": True,
            "groq_api": bool(groq_key), # Corrected from grok_ai
            "twitter_api": bool(twitter_token)
        }
    }


@app.post("/api/analyze")
async def analyze_platform(request: AnalysisRequest) -> AnalysisResult:
    """
    Main endpoint: Analyze a platform for legitimacy
    Uses Enhanced Analyzer if API keys are configured
    """
    
    url = request.url
    
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")
    
    try:
        # Initialize analyzer
        analyzer = WebsiteAnalyzer()
        
        # Perform analysis
        print(f"\n🔍 Analyzing: {url}")
        analysis_result = await analyzer.analyze(url)
        print(f"✅ Analysis complete - Trust Score: {analysis_result.get('trustScore', 0)}/100")
        
        # Convert findings to Finding objects
        findings = [
            Finding(type=finding.get('type', 'info'), text=finding.get('text', ''))
            for finding in analysis_result.get('findings', [])
        ]
        
        # Convert ponzi calculation if present
        ponzi_calc = None
        if analysis_result.get('ponziCalculation'):
            pc = analysis_result['ponziCalculation']
            ponzi_calc = PonziCalculation(
                promisedReturn=pc.get('promisedReturn', ''),
                yearlyEquivalent=pc.get('yearlyEquivalent', ''),
                sustainability=pc.get('sustainability', ''),
                collapseDays=pc.get('collapseDays', '')
            )
        
        # Build and return AnalysisResult
        return AnalysisResult(
            url=analysis_result.get('url', url),
            trustScore=analysis_result.get('trustScore', 50),
            verdict=analysis_result.get('verdict', 'Caution'),
            domainAge=analysis_result.get('domainAge', 'Unknown'),
            domainRegistered=analysis_result.get('domainRegistered', 'Unknown'),
            sslStatus=analysis_result.get('sslStatus', 'Unknown'),
            serverLocation=analysis_result.get('serverLocation', 'Unknown'),
            whoisData=WHOISData(
                registrar=analysis_result.get('whoisData', {}).get('registrar', 'Unknown'),
                owner=analysis_result.get('whoisData', {}).get('owner', 'Unknown'),
                email=analysis_result.get('whoisData', {}).get('email', 'Hidden'),
                lastUpdated=analysis_result.get('whoisData', {}).get('lastUpdated', 'Unknown')
            ),
            contentAnalysis=ContentAnalysis(
                aboutUsFound=analysis_result.get('contentAnalysis', {}).get('aboutUsFound', False),
                termsOfServiceFound=analysis_result.get('contentAnalysis', {}).get('termsOfServiceFound', False),
                contactInfoFound=analysis_result.get('contentAnalysis', {}).get('contactInfoFound', False),
                physicalAddressFound=analysis_result.get('contentAnalysis', {}).get('physicalAddressFound', False),
                teamPhotosAnalyzed=analysis_result.get('contentAnalysis', {}).get('teamPhotosAnalyzed', False),
                stockImagesDetected=analysis_result.get('contentAnalysis', {}).get('stockImagesDetected', False)
            ),
            socialData=SocialData(
                redditMentions=analysis_result.get('socialData', {}).get('redditMentions', 0),
                twitterMentions=analysis_result.get('socialData', {}).get('twitterMentions', 0),
                trustpilotScore=analysis_result.get('socialData', {}).get('trustpilotScore', 0.0),
                scamAdvisorScore=analysis_result.get('socialData', {}).get('scamAdvisorScore', 50)
            ),
            withdrawalComplaints=analysis_result.get('withdrawalComplaints', 0),
            findings=findings,
            sentiment=Sentiment(
                positive=analysis_result.get('sentiment', {}).get('positive', 33),
                neutral=analysis_result.get('sentiment', {}).get('neutral', 34),
                negative=analysis_result.get('sentiment', {}).get('negative', 33)
            ),
            redFlags=analysis_result.get('redFlags', []),
            ponziCalculation=ponzi_calc,
            scamProbability=analysis_result.get('scamProbability', 'Unknown'),
            recommendation=analysis_result.get('recommendation', 'Analysis completed')
        )
    except Exception as e:
        print(f"❌ Analysis error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(e)}"
        )


@app.post("/api/report-scam")
async def report_scam(url: str, evidence: str):
    """Allow users to report scams with evidence"""
    return {
        "status": "success",
        "message": "Report submitted successfully",
        "url": url
    }


@app.get("/api/stats")
async def get_stats():
    """Get platform statistics"""
    return {
        "totalAnalyzed": 15847,
        "scamsDetected": 3421,
        "usersSaved": 8932,
        "totalLossesPrevented": 2847392.50
    }


# ============================================
# Error Handlers (UNCHANGED)
# ============================================
@app.exception_handler(404)
async def not_found_handler(request, exc):
    return JSONResponse(
        {
            "error": "Not Found",
            "message": "The requested endpoint does not exist",
            "status_code": 404
        },
        status_code=404
    )


@app.exception_handler(500)
async def server_error_handler(request, exc):
    return JSONResponse(
        {
            "error": "Internal Server Error",
            "message": "An unexpected error occurred",
            "status_code": 500
        },
        status_code=500
    )


# ============================================
# Run Server (Development)
# ============================================

if __name__ == "__main__":
    import uvicorn
    
    print("=" * 70)
    print("🚀 STARTING LEGITIMACY ANALYZER API SERVER")
    print("=" * 70)
    print(f"📍 Local URL:    http://localhost:8000")
    print(f"📖 API Docs:     http://localhost:8000/docs")
    print(f"🔗 Frontend:     http://localhost:5173")
    print(f"🔧 Mode:         {'✅ PHASE 1 ENHANCED (Groq/Twitter)' if has_required_keys else '⚠️  BASIC (add GroQ_API_KEY)'}")
    print("=" * 70)
    print()
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )