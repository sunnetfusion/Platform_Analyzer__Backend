import os
import re
import ssl
import socket
import whois
import asyncio
from datetime import datetime
from urllib.parse import urlparse
from typing import Optional, Dict, List, Any

from fastapi import FastAPI, HTTPException, Header
from starlette.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from supabase import create_client, Client
from groq import Groq

# --- 1. CONFIGURATION & INITIALIZATION ---
app = FastAPI(title="Platform Analyzer API", version="2.0.0")

# Initialize Supabase
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_KEY")
supabase: Optional[Client] = create_client(SUPABASE_URL, SUPABASE_KEY) if SUPABASE_URL and SUPABASE_KEY else None

# Initialize Groq
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
groq_client = Groq(api_key=GROQ_API_KEY) if GROQ_API_KEY else None

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173", 
        "https://platform-analyzer-frontend.vercel.app", 
        "https://*.vercel.app"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- 2. DATA MODELS ---
class AnalyzeRequest(BaseModel):
    url: str

class JobAnalyzeRequest(BaseModel):
    job_url: Optional[str] = None
    job_description: Optional[str] = None
    company_name: Optional[str] = None
    salary: Optional[str] = None
    recruiter_email: Optional[str] = None

class Finding(BaseModel):
    type: str  # "critical", "warning", "info", "success"
    text: str

class AnalysisResult(BaseModel):
    url: str
    trustScore: int
    verdict: str
    domainAge: str
    domainRegistered: str
    sslStatus: str
    serverLocation: str
    findings: List[Finding]
    recommendation: str
    scamProbability: str
    domain: str = ""

# --- 3. AUTHENTICATION HELPER ---

async def get_user_id(authorization: Optional[str]) -> Optional[str]:
    """Helper to extract user ID from Supabase Auth token."""
    if not authorization or not supabase:
        return None
    try:
        token = authorization.replace("Bearer ", "")
        user_res = supabase.auth.get_user(token)
        if user_res.user:
            return user_res.user.id
    except Exception:
        pass
    return None

# --- 4. JOB ANALYSIS HELPERS ---

def perform_job_logic_checks(request: JobAnalyzeRequest) -> List[Finding]:
    findings = []
    desc = (request.job_description or "").lower()
    
    # 1. Payment Red Flags
    if any(k in desc for k in ['pay upfront', 'processing fee', 'buy equipment', 'wire transfer', 'crypto']):
        findings.append(Finding(type="critical", text="Requests upfront payment or non-standard financial transfers."))

    # 2. Salary vs Experience
    if request.salary and ("no experience" in desc or "entry level" in desc):
        # Simple heuristic: if salary mentions high numbers with no exp
        if any(char.isdigit() for char in request.salary):
            findings.append(Finding(type="warning", text="High salary expectations for entry-level role detected."))

    # 3. Email Check
    if request.recruiter_email:
        if any(prov in request.recruiter_email.lower() for prov in ["@gmail.com", "@yahoo.com", "@outlook.com", "@hotmail.com"]):
            findings.append(Finding(type="warning", text="Recruiter is using a free public email address instead of a corporate domain."))

    return findings

async def get_ai_job_insight(request: JobAnalyzeRequest) -> str:
    if not groq_client:
        return "AI Analysis unavailable (Missing API Key)."
    
    prompt = f"""
    Act as a Professional Fraud Investigator. Analyze this job posting for potential SCAM indicators:
    
    COMPANY: {request.company_name or 'Unknown'}
    JOB URL: {request.job_url or 'Not Provided'}
    SALARY: {request.salary or 'Not Disclosed'}
    RECRUITER EMAIL: {request.recruiter_email or 'Not Provided'}
    DESCRIPTION: {request.job_description[:1500] if request.job_description else 'No description provided.'}
    
    Provide a concise (2-3 sentence) verdict. Mention specific red flags if found.
    """
    
    try:
        completion = await asyncio.to_thread(
            groq_client.chat.completions.create,
            messages=[{"role": "user", "content": prompt}],
            model="llama-3.3-70b-versatile",
        )
        return completion.choices[0].message.content
    except Exception as e:
        return f"AI Analysis failed: {str(e)}"

# --- 5. WEBSITE ANALYSIS ENGINE ---

class EnhancedAnalyzer:
    def __init__(self):
        self.whitelist = {"google.com", "linkedin.com", "microsoft.com", "apple.com", "github.com", "indeed.com"}

    async def get_whois_data(self, domain: str):
        try: return await asyncio.to_thread(whois.whois, domain)
        except: return None

    async def analyze_url(self, url: str) -> Dict[str, Any]:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().replace('www.', '') or parsed.path.split('/')[0]
        findings = []
        score = 75
        
        if any(w in domain for w in self.whitelist):
            return {
                "url": url, "trustScore": 100, "verdict": "Legit", "domainAge": "Established",
                "domainRegistered": "N/A", "sslStatus": "Valid", "serverLocation": "Global",
                "findings": [{"type": "success", "text": "Verified Trusted Platform"}],
                "recommendation": "This is a verified legitimate platform.",
                "scamProbability": "0%", "domain": domain
            }

        w_data = await self.get_whois_data(domain)
        reg_date, age_str = "Unknown", "Unknown"
        
        if w_data and w_data.creation_date:
            date = w_data.creation_date[0] if isinstance(w_data.creation_date, list) else w_data.creation_date
            reg_date = date.strftime("%Y-%m-%d")
            age_days = (datetime.now() - date).days
            age_str = f"{age_days // 365} Years" if age_days > 365 else f"{age_days} Days"
            if age_days < 180:
                score -= 35
                findings.append({"type": "critical", "text": f"Domain is very new ({age_str}). Scammers often use fresh domains."})
        else:
            score -= 20
            findings.append({"type": "warning", "text": "Domain registration details are hidden or private."})

        score = max(0, min(100, score))
        verdict = "Legit" if score > 75 else "Caution" if score > 45 else "Scam"
        
        return {
            "url": url, "trustScore": score, "verdict": verdict, "domainAge": age_str,
            "domainRegistered": reg_date, "sslStatus": "Valid", "serverLocation": "Cloud",
            "findings": findings, "recommendation": f"Analysis suggests this platform is {verdict.lower()}.",
            "scamProbability": f"{100 - score}%", "domain": domain
        }

analyzer = EnhancedAnalyzer()

# --- 6. ENDPOINTS ---

@app.post("/api/analyze", response_model=AnalysisResult)
async def analyze_platform(request: AnalyzeRequest, authorization: Optional[str] = Header(None)):
    user_id = await get_user_id(authorization)
    if not user_id:
        raise HTTPException(status_code=401, detail="Please sign in to analyze websites.")

    result_data = await analyzer.analyze_url(request.url)
    
    if supabase:
        try:
            supabase.table("analyses").insert({
                "type": "website", "url": request.url, "domain": result_data["domain"],
                "trust_score": result_data["trustScore"], "verdict": result_data["verdict"], "user_id": user_id
            }).execute()
        except: pass

    return result_data

@app.post("/api/analyze/job")
async def analyze_job(request: JobAnalyzeRequest, authorization: Optional[str] = Header(None)):
    """Handles the full Job Analysis form from your frontend."""
    user_id = await get_user_id(authorization)
    if not user_id:
        raise HTTPException(status_code=401, detail="Please sign in to analyze job postings.")

    # 1. Run Technical & Logic Checks
    findings = perform_job_logic_checks(request)
    
    # 2. Run AI Analysis
    ai_recommendation = await get_ai_job_insight(request)
    
    # 3. Scoring Logic
    score = 85
    if any(f.type == "critical" for f in findings): score -= 45
    if any(f.type == "warning" for f in findings): score -= 15
    if not request.job_description or len(request.job_description) < 50: score -= 10
    
    score = max(0, min(100, score))
    verdict = "Scam" if score < 40 else "Caution" if score < 75 else "Legit"

    # 4. Log to Supabase
    if supabase:
        try:
            supabase.table("analyses").insert({
                "type": "job", 
                "url": request.job_url or "N/A", 
                "domain": request.company_name or "Unknown",
                "trust_score": score, 
                "verdict": verdict,
                "user_id": user_id
            }).execute()
        except: pass

    return {
        "trust_score": score,
        "verdict": verdict,
        "findings": findings,
        "ai_analysis": ai_recommendation,
        "recommendation": ai_recommendation
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)