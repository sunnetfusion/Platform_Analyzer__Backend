# main.py - UPDATED VERSION with Supabase Comments Integration
from fastapi import FastAPI, HTTPException, Header
from starlette.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, List, Any
import ssl
import socket
import whois
from datetime import datetime
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import re
import os
from supabase import create_client, Client
from groq import Groq

# Initialize FastAPI app
app = FastAPI(title="Platform Analyzer API")

# Initialize Supabase
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_KEY")

if SUPABASE_URL and SUPABASE_KEY:
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
    print("✅ Supabase connected")
else:
    supabase = None
    print("⚠️ Supabase credentials not set")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "https://platform-analyzer-frontend.vercel.app",
        "https://*.vercel.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Data models
class AnalyzeRequest(BaseModel):
    url: str
    platform: Optional[str] = None

class JobAnalyzeRequest(BaseModel):
    job_url: Optional[str] = None
    job_description: Optional[str] = None
    company_name: Optional[str] = None
    salary: Optional[str] = None
    recruiter_email: Optional[str] = None

class CommentRequest(BaseModel):
    url: str
    user_name: str
    rating: int
    experience: str
    comment: str
    was_scammed: bool = False

class SignUpRequest(BaseModel):
    name: str
    email: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str


# Routes
@app.get("/")
async def root():
    return {
        "status": "online",
        "message": "Platform Analyzer API is running",
        "version": "2.0.0",
        "supabase": "connected" if supabase else "not configured"
    }

# ============================================
# AUTHENTICATION ENDPOINTS (No changes needed)
# ============================================

@app.post("/auth/signup")
async def signup(request: SignUpRequest):
    """User sign up with Supabase"""
    try:
        if not supabase:
            raise HTTPException(
                status_code=503, 
                detail="Authentication service not configured. Please contact administrator."
            )
        
        print(f"Signup attempt for: {request.email}")
        
        response = supabase.auth.sign_up({
            "email": request.email,
            "password": request.password,
            "options": {
                "data": {
                    "name": request.name
                }
            }
        })
        
        print(f"Supabase response: {response}")
        
        if response.user:
            token = response.session.access_token if response.session else None
            
            if not token:
                return {
                    "token": None,
                    "user": {
                        "id": response.user.id,
                        "email": response.user.email,
                        "name": request.name
                    },
                    "message": "Sign up successful! Please check your email to verify your account before signing in.",
                    "needs_verification": True
                }
            
            return {
                "token": token,
                "user": {
                    "id": response.user.id,
                    "email": response.user.email,
                    "name": request.name
                },
                "message": "Sign up successful!",
                "needs_verification": False
            }
        else:
            raise HTTPException(status_code=400, detail="Sign up failed. Please try again.")
            
    except Exception as e:
        error_msg = str(e)
        print(f"Signup error: {error_msg}")
        
        if "already registered" in error_msg.lower() or "already exists" in error_msg.lower():
            raise HTTPException(status_code=400, detail="This email is already registered. Please sign in instead.")
        elif "invalid" in error_msg.lower() and "email" in error_msg.lower():
            raise HTTPException(status_code=400, detail="Invalid email format. Please check and try again.")
        elif "weak password" in error_msg.lower() or "password" in error_msg.lower():
            raise HTTPException(status_code=400, detail="Password must be at least 6 characters long.")
        else:
            raise HTTPException(status_code=500, detail=f"Sign up error: {error_msg}")

@app.post("/auth/login")
async def login(request: LoginRequest):
    """User login with Supabase"""
    try:
        if not supabase:
            raise HTTPException(
                status_code=503, 
                detail="Authentication service not configured. Please contact administrator."
            )
        
        print(f"Login attempt for: {request.email}")
        
        response = supabase.auth.sign_in_with_password({
            "email": request.email,
            "password": request.password
        })
        
        print(f"Login response received")
        
        if response.user and response.session:
            return {
                "token": response.session.access_token,
                "user": {
                    "id": response.user.id,
                    "email": response.user.email,
                    "name": response.user.user_metadata.get("name", "")
                }
            }
        else:
            raise HTTPException(status_code=401, detail="Invalid email or password")
            
    except Exception as e:
        error_msg = str(e)
        print(f"Login error: {error_msg}")
        
        if "invalid" in error_msg.lower() or "credentials" in error_msg.lower():
            raise HTTPException(status_code=401, detail="Invalid email or password. Please try again.")
        elif "not confirmed" in error_msg.lower() or "email not confirmed" in error_msg.lower():
            raise HTTPException(status_code=401, detail="Please verify your email before signing in. Check your inbox.")
        else:
            raise HTTPException(status_code=500, detail=f"Login error: {error_msg}")

@app.get("/auth/user")
async def get_user(authorization: Optional[str] = Header(None)):
    """Get current user from token"""
    try:
        if not supabase or not authorization:
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        token = authorization.replace("Bearer ", "")
        response = supabase.auth.get_user(token)
        
        if response.user:
            return {
                "user": {
                    "id": response.user.id,
                    "email": response.user.email,
                    "name": response.user.user_metadata.get("name", "")
                }
            }
        else:
            raise HTTPException(status_code=401, detail="Invalid token")
            
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Authentication error: {str(e)}")

@app.post("/auth/google")
async def google_auth():
    """Get Google OAuth URL"""
    try:
        if not supabase:
            raise HTTPException(status_code=503, detail="Authentication service not available")
        
        return {
            "url": f"{SUPABASE_URL}/auth/v1/authorize?provider=google",
            "message": "Redirect user to this URL for Google sign-in"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ============================================
# COMMENTS ENDPOINTS (UPDATED FOR SUPABASE)
# ============================================

def get_user_from_token(authorization: Optional[str]) -> Optional[Dict[str, Any]]:
    """Extract user from authorization token"""
    if not authorization or not supabase:
        return None
    
    try:
        token = authorization.replace("Bearer ", "")
        response = supabase.auth.get_user(token)
        
        if response.user:
            return {
                "id": response.user.id,
                "email": response.user.email,
                "name": response.user.user_metadata.get("name", "")
            }
    except Exception as e:
        print(f"Token validation error: {e}")
    
    return None

@app.post("/api/comments")
async def add_comment(comment: CommentRequest, authorization: Optional[str] = Header(None)):
    """Add user comment/review for a website - NOW SAVES TO SUPABASE"""
    try:
        if not supabase:
            raise HTTPException(status_code=503, detail="Database service not available")
        
        # Get user from token (optional for now, but recommended)
        user = get_user_from_token(authorization)
        
        # Clean and normalize URL
        url = comment.url.lower().strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        domain = urlparse(url).netloc.replace('www.', '')
        
        # Prepare comment data
        comment_data = {
            "domain": domain,
            "user_id": user["id"] if user else None,
            "user_name": comment.user_name,
            "rating": max(1, min(5, comment.rating)),
            "experience": comment.experience,
            "comment": comment.comment,
            "was_scammed": comment.was_scammed
        }
        
        # Insert into Supabase
        result = supabase.table("comments").insert(comment_data).execute()
        
        if result.data:
            return {
                "status": "success",
                "message": "Comment added successfully",
                "comment": result.data[0]
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to save comment")
            
    except Exception as e:
        print(f"Error adding comment: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/comments/{domain}")
async def get_comments(domain: str):
    """Get all comments for a domain - FROM SUPABASE"""
    try:
        if not supabase:
            raise HTTPException(status_code=503, detail="Database service not available")
        
        # Clean domain
        domain = domain.lower().replace('www.', '')
        
        # Fetch comments from Supabase
        result = supabase.table("comments")\
            .select("*")\
            .eq("domain", domain)\
            .order("created_at", desc=True)\
            .execute()
        
        comments = result.data if result.data else []
        
        # Calculate statistics
        total_comments = len(comments)
        
        if total_comments > 0:
            avg_rating = sum(c["rating"] for c in comments) / total_comments
            scam_reports = sum(1 for c in comments if c["was_scammed"])
            experience_breakdown = {
                "positive": sum(1 for c in comments if c["experience"] == "positive"),
                "neutral": sum(1 for c in comments if c["experience"] == "neutral"),
                "negative": sum(1 for c in comments if c["experience"] == "negative")
            }
        else:
            avg_rating = 0
            scam_reports = 0
            experience_breakdown = {"positive": 0, "neutral": 0, "negative": 0}
        
        # Format comments for frontend (convert created_at to timestamp)
        formatted_comments = []
        for c in comments:
            formatted_comments.append({
                "id": c["id"],
                "user_name": c["user_name"],
                "rating": c["rating"],
                "experience": c["experience"],
                "comment": c["comment"],
                "was_scammed": c["was_scammed"],
                "timestamp": c["created_at"],
                "helpful_count": c["helpful_count"]
            })
        
        return {
            "domain": domain,
            "total_comments": total_comments,
            "average_rating": round(avg_rating, 1),
            "scam_reports": scam_reports,
            "experience_breakdown": experience_breakdown,
            "comments": formatted_comments
        }
        
    except Exception as e:
        print(f"Error fetching comments: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/comments/{comment_id}/helpful")
async def mark_helpful(comment_id: int, domain: str, authorization: Optional[str] = Header(None)):
    """Mark a comment as helpful - SUPABASE VERSION"""
    try:
        if not supabase:
            raise HTTPException(status_code=503, detail="Database service not available")
        
        # Get user from token (optional for now)
        user = get_user_from_token(authorization)
        
        # Check if user already voted (if authenticated)
        if user:
            existing_vote = supabase.table("helpful_votes")\
                .select("*")\
                .eq("comment_id", comment_id)\
                .eq("user_id", user["id"])\
                .execute()
            
            if existing_vote.data:
                return {
                    "status": "already_voted",
                    "message": "You already marked this as helpful"
                }
        
        # Insert vote
        vote_data = {
            "comment_id": comment_id,
            "user_id": user["id"] if user else None
        }
        
        result = supabase.table("helpful_votes").insert(vote_data).execute()
        
        if result.data:
            # Get updated helpful count (trigger already incremented it)
            comment = supabase.table("comments")\
                .select("helpful_count")\
                .eq("id", comment_id)\
                .single()\
                .execute()
            
            return {
                "status": "success",
                "helpful_count": comment.data["helpful_count"] if comment.data else 0
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to record vote")
            
    except Exception as e:
        print(f"Error marking helpful: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ============================================
# WEBSITE ANALYSIS ENDPOINTS (NO CHANGES)
# ============================================

def get_domain_age(url: str) -> Dict[str, Any]:
    """Get domain registration date and calculate age"""
    try:
        domain = urlparse(url).netloc.replace('www.', '')
        w = whois.whois(domain)
        
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        if creation_date:
            age_days = (datetime.now() - creation_date).days
            age_years = age_days / 365
            
            return {
                "age": f"{age_years:.1f} years" if age_years >= 1 else f"{age_days} days",
                "registered": creation_date.strftime("%Y-%m-%d"),
                "registrar": w.registrar if hasattr(w, 'registrar') and w.registrar else "Unknown",
                "age_days": age_days
            }
    except Exception as e:
        print(f"WHOIS error: {e}")
    
    return {
        "age": "Unknown",
        "registered": "Unknown",
        "registrar": "Unknown",
        "age_days": 0
    }


# ============================================
# JOB ANALYZER HELPERS
# ============================================

def analyze_email_domain(email: str) -> Dict[str, Any]:
    """Check if email is from corporate domain or free email service"""
    if not email:
        return {"is_corporate": False, "domain": "Unknown", "risk": "Unknown"}
    
    free_email_providers = [
        'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 
        'aol.com', 'icloud.com', 'mail.com', 'protonmail.com',
        'yandex.com', 'zoho.com', 'gmx.com'
    ]
    
    try:
        domain = email.split('@')[1].lower()
        is_corporate = domain not in free_email_providers
        risk_level = "Low" if is_corporate else "High"
        return {
            "is_corporate": is_corporate,
            "domain": domain,
            "risk": risk_level,
            "provider": "Corporate Email" if is_corporate else "Free Email Service",
        }
    except Exception:
        return {"is_corporate": False, "domain": "Invalid", "risk": "Critical"}


def detect_job_red_flags(description: str, salary: str = "") -> List[Dict[str, str]]:
    """Detect common job scam red flags in job description"""
    red_flags: List[Dict[str, str]] = []
    text = description.lower()
    
    # Financial red flags
    financial_scam_keywords = [
        'pay upfront', 'processing fee', 'training fee', 'background check fee',
        'starter kit', 'pay for training', 'investment required', 'buy equipment',
        'wire transfer', 'cryptocurrency', 'bitcoin', 'send money first',
    ]
    
    for keyword in financial_scam_keywords:
        if keyword in text:
            red_flags.append({
                "type": "critical",
                "category": "Financial",
                "text": f"Requests upfront payment: '{keyword}' - MAJOR RED FLAG",
            })
            break
    
    # Too good to be true
    too_good_keywords = [
        'guaranteed income', 'make money fast', 'get rich quick',
        'no experience required', 'earn $', 'passive income',
        'work from home and earn', 'easy money',
    ]
    
    if any(keyword in text for keyword in too_good_keywords):
        red_flags.append({
            "type": "warning",
            "category": "Unrealistic",
            "text": "Promises guaranteed/easy income - Often a scam indicator",
        })
    
    # High salary for low/no experience
    if salary and any(keyword in text for keyword in ['no experience', 'entry level', 'no degree']):
        if any(amount in salary for amount in ['$100k', '$150k', '$200k', '$5000/week', '$10000']):
            red_flags.append({
                "type": "warning",
                "category": "Salary",
                "text": "Very high salary for entry-level position - Verify legitimacy",
            })
    
    # Vague job description
    if len(text) < 100:
        red_flags.append({
            "type": "warning",
            "category": "Description",
            "text": "Extremely short/vague job description - Lack of detail is suspicious",
        })
    
    # Urgency tactics
    urgency_keywords = [
        'urgent', 'immediate start', 'hire today', 'apply now',
        'limited time', 'act fast', 'only today', 'first come first serve',
    ]
    
    if any(keyword in text for keyword in urgency_keywords):
        red_flags.append({
            "type": "warning",
            "category": "Pressure",
            "text": "Uses urgency/pressure tactics - Common in scam job postings",
        })
    
    # Personal info requests
    personal_info_keywords = [
        'social security', 'ssn', 'bank account', 'credit card',
        'passport', 'driver license number', 'routing number',
    ]
    
    if any(keyword in text for keyword in personal_info_keywords):
        red_flags.append({
            "type": "critical",
            "category": "Privacy",
            "text": "Requests sensitive personal information upfront - DO NOT PROVIDE",
        })
    
    # Grammar and spelling issues
    grammar_indicators = ['!!!', 'URGENT!!!', 'ACT NOW!!!']
    if any(indicator in description for indicator in grammar_indicators):
        red_flags.append({
            "type": "warning",
            "category": "Professionalism",
            "text": "Excessive punctuation/caps - Unprofessional communication",
        })
    
    return red_flags


def analyze_salary_reasonableness(salary: str, job_title: str = "", location: str = "") -> Dict[str, Any]:
    """Analyze if salary is reasonable or suspiciously high/low"""
    if not salary:
        return {
            "is_reasonable": True,
            "assessment": "No salary information provided",
            "risk": "Unknown",
        }
    
    # Extract numeric salary values
    salary_numbers = re.findall(r'\$?(\d+)[,]?(\d+)?', salary)
    
    if not salary_numbers:
        return {
            "is_reasonable": True,
            "assessment": "Salary format unclear",
            "risk": "Low",
        }
    
    # Combine numbers (handle commas)
    try:
        salary_value = int(''.join(salary_numbers[0]))
    except Exception:
        salary_value = 0
    
    # Determine if weekly, monthly, or yearly
    is_weekly = 'week' in salary.lower() or '/week' in salary.lower()
    is_monthly = 'month' in salary.lower() or '/month' in salary.lower()
    
    if is_weekly:
        yearly_equivalent = salary_value * 52
    elif is_monthly:
        yearly_equivalent = salary_value * 12
    else:
        yearly_equivalent = salary_value
    
    # Suspiciously high (likely scam)
    if yearly_equivalent > 300000 and 'entry' in job_title.lower():
        return {
            "is_reasonable": False,
            "assessment": f"${yearly_equivalent:,}/year for entry-level is EXTREMELY suspicious",
            "yearly_equivalent": f"${yearly_equivalent:,}",
            "risk": "Critical",
        }
    elif yearly_equivalent > 500000:
        return {
            "is_reasonable": False,
            "assessment": f"${yearly_equivalent:,}/year is unusually high - Verify carefully",
            "yearly_equivalent": f"${yearly_equivalent:,}",
            "risk": "High",
        }
    
    # Suspiciously low (possible exploitation)
    elif yearly_equivalent < 15000 and 'full time' in salary.lower():
        return {
            "is_reasonable": False,
            "assessment": f"${yearly_equivalent:,}/year for full-time is below minimum wage",
            "yearly_equivalent": f"${yearly_equivalent:,}",
            "risk": "High",
        }
    
    # Reasonable range
    else:
        return {
            "is_reasonable": True,
            "assessment": "Salary appears within reasonable range",
            "yearly_equivalent": f"${yearly_equivalent:,}" if yearly_equivalent > 0 else "Unknown",
            "risk": "Low",
        }


def verify_company_online(company_name: str, company_website: str = "") -> Dict[str, Any]:
    """Verify company has legitimate online presence"""
    if not company_name:
        return {
            "has_website": False,
            "has_linkedin": False,
            "has_glassdoor": False,
            "legitimacy_score": 0,
            "findings": [],
        }
    
    legitimacy_score = 50  # Start at neutral
    findings: List[str] = []
    
    # Check if company website exists and is accessible
    has_website = False
    if company_website:
        try:
            response = requests.head(company_website, timeout=5, allow_redirects=True)
            if response.status_code == 200:
                has_website = True
                legitimacy_score += 20
                findings.append("✓ Company website is accessible")
        except Exception:
            findings.append("✗ Company website is not accessible or doesn't exist")
            legitimacy_score -= 15
    
    if not has_website and not company_website:
        findings.append("⚠ No company website provided - Difficult to verify")
        legitimacy_score -= 10
    
    return {
        "has_website": has_website,
        "website_accessible": has_website,
        "has_linkedin": False,
        "has_glassdoor": False,
        "legitimacy_score": max(0, min(100, legitimacy_score)),
        "findings": findings,
    }


def analyze_job_posting_url(url: str) -> Dict[str, Any]:
    """Analyze the job posting URL for legitimacy"""
    if not url:
        return {"is_legitimate_platform": False, "platform": "Unknown", "trust_level": "Unknown", "domain": ""}
    
    legitimate_job_platforms = {
        'linkedin.com': {'name': 'LinkedIn', 'trust': 'Very High'},
        'indeed.com': {'name': 'Indeed', 'trust': 'High'},
        'glassdoor.com': {'name': 'Glassdoor', 'trust': 'High'},
        'monster.com': {'name': 'Monster', 'trust': 'High'},
        'ziprecruiter.com': {'name': 'ZipRecruiter', 'trust': 'High'},
        'careerbuilder.com': {'name': 'CareerBuilder', 'trust': 'High'},
        'dice.com': {'name': 'Dice', 'trust': 'High'},
        'simplyhired.com': {'name': 'SimplyHired', 'trust': 'Medium'},
        'craigslist.org': {'name': 'Craigslist', 'trust': 'Medium'},
    }
    
    try:
        domain = urlparse(url).netloc.lower().replace('www.', '')
        
        for platform_domain, info in legitimate_job_platforms.items():
            if platform_domain in domain:
                return {
                    "is_legitimate_platform": True,
                    "platform": info['name'],
                    "trust_level": info['trust'],
                    "domain": domain,
                }
        
        # Unknown platform
        return {
            "is_legitimate_platform": False,
            "platform": "Unknown/Unverified",
            "trust_level": "Low",
            "domain": domain,
        }
    except Exception:
        return {
            "is_legitimate_platform": False,
            "platform": "Invalid URL",
            "trust_level": "Unknown",
            "domain": "Invalid",
        }


def calculate_job_trust_score(
    email_analysis: Dict[str, Any],
    red_flags: List[Dict[str, str]],
    salary_analysis: Dict[str, Any],
    company_verification: Dict[str, Any],
    platform_analysis: Dict[str, Any],
) -> tuple:
    """Calculate overall trust score for job posting"""
    
    score = 60  # Start at neutral
    findings: List[Dict[str, str]] = []
    
    # Email domain analysis (20 points)
    if email_analysis.get("is_corporate"):
        score += 20
        findings.append({
            "type": "info",
            "text": f"✓ Corporate email domain ({email_analysis.get('domain')}) - Legitimate indicator",
        })
    else:
        score -= 15
        findings.append({
            "type": "warning",
            "text": f"⚠ Free email service ({email_analysis.get('domain')}) - Not from company domain",
        })
    
    # Platform analysis (15 points)
    if platform_analysis.get("is_legitimate_platform"):
        trust_level = platform_analysis.get("trust_level")
        platform_name = platform_analysis.get("platform")
        if trust_level == "Very High":
            score += 15
            findings.append({
                "type": "info",
                "text": f"✓ Posted on {platform_name} - Trusted platform",
            })
        elif trust_level == "High":
            score += 10
            findings.append({
                "type": "info",
                "text": f"✓ Posted on {platform_name} - Reputable platform",
            })
        else:
            score += 5
            findings.append({
                "type": "info",
                "text": f"Posted on {platform_name} - Exercise caution",
            })
    else:
        score -= 10
        findings.append({
            "type": "warning",
            "text": "⚠ Posted on unknown/unverified platform - Verify carefully",
        })
    
    # Red flags (critical impact)
    critical_flags = [f for f in red_flags if f.get("type") == "critical"]
    warning_flags = [f for f in red_flags if f.get("type") == "warning"]
    
    if critical_flags:
        score -= len(critical_flags) * 25
        for flag in critical_flags:
            findings.append({"type": "critical", "text": f"🚨 {flag.get('text')}"})
    
    if warning_flags:
        score -= len(warning_flags) * 10
        for flag in warning_flags:
            findings.append({"type": "warning", "text": f"⚠ {flag.get('text')}"})
    
    # Salary analysis
    if not salary_analysis.get("is_reasonable", True):
        findings.append({
            "type": "warning",
            "text": f"⚠ Salary concern: {salary_analysis.get('assessment')}",
        })
        score -= 15
    
    # Company verification
    legitimacy_score = company_verification.get("legitimacy_score", 0)
    if legitimacy_score > 70:
        score += 10
    elif legitimacy_score < 40:
        score -= 10
    
    for finding in company_verification.get("findings", []):
        findings.append({"type": "info", "text": finding})
    
    # Ensure score is within bounds
    score = max(0, min(100, score))
    
    return score, findings


def get_job_verdict(score: int) -> str:
    """Get verdict based on job trust score"""
    if score >= 70:
        return "Legitimate Job"
    elif score >= 40:
        return "Exercise Caution"
    else:
        return "Likely Scam"

def check_ssl(url: str) -> Dict[str, Any]:
    """Check SSL certificate status"""
    try:
        hostname = urlparse(url).netloc
        context = ssl.create_default_context()
        
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return {
                        "valid": False,
                        "issuer": "None",
                        "expires": "N/A"
                    }
                issuer = "Unknown"
                try:
                    issuer_raw = cert.get('issuer', ())
                    issuer_items = []
                    for rdn in issuer_raw:
                        if isinstance(rdn, (list, tuple)):
                            for attr in rdn:
                                if isinstance(attr, (list, tuple)) and len(attr) >= 2:
                                    k = attr[0]
                                    v = attr[1]
                                    if isinstance(k, bytes):
                                        try:
                                            k = k.decode()
                                        except Exception:
                                            k = str(k)
                                    if isinstance(v, bytes):
                                        try:
                                            v = v.decode()
                                        except Exception:
                                            v = str(v)
                                    issuer_items.append((k, v))
                    issuer_dict = dict(issuer_items)
                    issuer = issuer_dict.get('organizationName') or issuer_dict.get('O') or issuer_dict.get('organizationUnitName') or issuer_dict.get('commonName') or issuer_dict.get('CN') or "Unknown"
                except Exception as _:
                    issuer = "Unknown"
                return {
                    "valid": True,
                    "issuer": issuer,
                    "expires": cert.get('notAfter')
                }
    except Exception as e:
        print(f"SSL error: {e}")
        return {
            "valid": False,
            "issuer": "None",
            "expires": "N/A"
        }

def analyze_content(url: str) -> Dict[str, Any]:
    """Scrape and analyze website content"""
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        text = soup.get_text().lower()
        
        has_about = bool(soup.find('a', href=re.compile(r'about', re.I)))
        has_contact = bool(soup.find('a', href=re.compile(r'contact', re.I)))
        has_terms = bool(soup.find('a', href=re.compile(r'terms', re.I)))
        
        address_pattern = r'\d+\s+[\w\s]+(?:street|st|avenue|ave|road|rd|boulevard|blvd)'
        has_address = bool(re.search(address_pattern, text, re.I))
        
        phone_pattern = r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'
        has_phone = bool(re.search(phone_pattern, text))
        
        scam_keywords = ['guaranteed profit', 'get rich quick', 'no risk', 'double your money', 
                        'limited time offer', 'act now', 'urgent', 'secret method']
        red_flags = [kw for kw in scam_keywords if kw in text]
        
        stock_image_sites = ['shutterstock', 'istockphoto', 'gettyimages', 'dreamstime']
        images = soup.find_all('img')
        stock_images = sum(1 for img in images if any(site in str(img.get('src', '')) for site in stock_image_sites))
        
        page_text = ' '.join(soup.stripped_strings)[:2000]
        
        return {
            "aboutUsFound": has_about,
            "termsOfServiceFound": has_terms,
            "contactInfoFound": has_contact,
            "physicalAddressFound": has_address,
            "phoneNumberFound": has_phone,
            "stockImagesDetected": stock_images > 0,
            "stockImageCount": stock_images,
            "redFlagKeywords": red_flags,
            "pageContent": page_text
        }
    except Exception as e:
        print(f"Content analysis error: {e}")
        return {
            "aboutUsFound": False,
            "termsOfServiceFound": False,
            "contactInfoFound": False,
            "physicalAddressFound": False,
            "phoneNumberFound": False,
            "stockImagesDetected": False,
            "stockImageCount": 0,
            "redFlagKeywords": [],
            "pageContent": ""
        }

def calculate_trust_score(domain_info: Dict[str, Any], ssl_info: Dict[str, Any], 
                         content_info: Dict[str, Any]) -> tuple:
    """Calculate trust score based on various factors"""
    score = 60
    findings = []
    
    age_days = domain_info.get("age_days", 0)
    if age_days > 365 * 5:
        score += 25
        findings.append({"type": "info", "text": f"Domain is {domain_info['age']} old - Very established"})
    elif age_days > 365 * 2:
        score += 15
        findings.append({"type": "info", "text": f"Domain is {domain_info['age']} old - Established presence"})
    elif age_days > 365:
        score += 5
        findings.append({"type": "info", "text": f"Domain is {domain_info['age']} old - Moderately established"})
    elif age_days > 180:
        findings.append({"type": "warning", "text": f"Domain is relatively new ({domain_info['age']})"})
    elif age_days > 90:
        score -= 5
        findings.append({"type": "warning", "text": f"Domain is quite new ({domain_info['age']}) - Exercise caution"})
    else:
        score -= 15
        findings.append({"type": "critical", "text": f"Very new domain ({domain_info['age']}) - Higher risk"})
    
    if ssl_info["valid"]:
        score += 15
        findings.append({"type": "info", "text": "Valid SSL certificate found - Secure connection"})
    else:
        score -= 25
        findings.append({"type": "critical", "text": "No valid SSL certificate - UNSAFE for sensitive data"})
    
    content_score = 0
    
    if content_info["aboutUsFound"]:
        content_score += 3
        findings.append({"type": "info", "text": "About page found - Transparent about identity"})
    
    if content_info["contactInfoFound"]:
        content_score += 5
        findings.append({"type": "info", "text": "Contact information found - Reachable"})
    else:
        findings.append({"type": "warning", "text": "No obvious contact information found"})
    
    if content_info["termsOfServiceFound"]:
        content_score += 3
        findings.append({"type": "info", "text": "Terms of Service found - Professional"})
    
    if content_info["physicalAddressFound"]:
        content_score += 8
        findings.append({"type": "info", "text": "Physical address found - Legitimate business location"})
    
    if content_info.get("phoneNumberFound"):
        content_score += 5
        findings.append({"type": "info", "text": "Phone number found - Direct contact available"})
    
    score += content_score
    
    if content_info["stockImagesDetected"]:
        stock_count = content_info.get("stockImageCount", 0)
        if stock_count > 5:
            score -= 15
            findings.append({"type": "critical", "text": f"Many stock images detected ({stock_count}) - Potentially fake team"})
        elif stock_count > 2:
            score -= 8
            findings.append({"type": "warning", "text": f"Stock images detected ({stock_count}) - Verify authenticity"})
        else:
            score -= 3
            findings.append({"type": "warning", "text": "Some stock images detected"})
    
    if content_info["redFlagKeywords"]:
        penalty = min(len(content_info["redFlagKeywords"]) * 8, 30)
        score -= penalty
        findings.append({"type": "critical", "text": f"Scam keywords detected: {', '.join(content_info['redFlagKeywords'][:3])}"})
    
    score = max(0, min(100, score))
    
    return score, findings

def detect_website_type(domain: str, page_content: str) -> str:
    """Detect the type of website to apply appropriate analysis"""
    domain_lower = domain.lower()
    content_lower = page_content.lower()
    
    edu_indicators = ['.edu', 'university', 'college', 'school', 'academy', 'institute', 'education']
    if any(ind in domain_lower for ind in edu_indicators) or any(ind in content_lower for ind in ['student', 'faculty', 'research', 'academic']):
        return 'educational'
    
    gov_indicators = ['.gov', '.gov.', 'government', 'ministry', 'department']
    if any(ind in domain_lower for ind in gov_indicators):
        return 'government'
    
    news_indicators = ['news', 'press', 'media', 'journal', 'magazine', 'blog']
    if any(ind in domain_lower for ind in news_indicators):
        return 'media'
    
    ecommerce_indicators = ['shop', 'store', 'cart', 'checkout', 'buy now', 'add to cart', 'product']
    if any(ind in content_lower for ind in ecommerce_indicators):
        return 'ecommerce'
    
    financial_indicators = ['invest', 'trading', 'forex', 'crypto', 'profit', 'returns', 'portfolio']
    if any(ind in content_lower for ind in financial_indicators):
        return 'financial'
    
    nonprofit_indicators = ['donate', 'charity', 'nonprofit', 'foundation', 'ngo', 'volunteer']
    if any(ind in content_lower for ind in nonprofit_indicators):
        return 'nonprofit'
    
    return 'general'

def adjust_score_by_website_type(score: int, website_type: str, findings: List[Dict[str, str]]) -> tuple:
    """Apply context-aware adjustments based on website type"""
    adjustments = []
    
    if website_type == 'educational':
        score += 10
        adjustments.append({"type": "info", "text": "Educational institution detected - Higher trust baseline"})
    elif website_type == 'government':
        score += 15
        adjustments.append({"type": "info", "text": "Government website detected - Official source"})
    elif website_type == 'media':
        score += 5
        adjustments.append({"type": "info", "text": "News/Media website detected"})
    elif website_type == 'nonprofit':
        score += 5
        adjustments.append({"type": "info", "text": "Non-profit organization detected"})
    elif website_type == 'financial':
        adjustments.append({"type": "warning", "text": "Financial/Investment platform - Requires thorough verification"})
    elif website_type == 'ecommerce':
        adjustments.append({"type": "info", "text": "E-commerce platform detected - Verify seller reputation"})
    
    findings.extend(adjustments)
    return max(0, min(100, score)), findings

def get_verdict(score: int) -> str:
    """Get verdict based on trust score"""
    if score >= 70:
        return "Legit"
    elif score >= 40:
        return "Caution"
    else:
        return "Scam"

def analyze_with_groq(domain: str, page_content: str, domain_info: Dict[str, Any], 
                      ssl_info: Dict[str, Any]) -> Optional[str]:
    """Use Groq AI to analyze the website content for scam indicators"""
    try:
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            print("GROQ_API_KEY not set, skipping AI analysis")
            return None
        
        client = Groq(api_key=api_key)
        
        prompt = f"""Analyze this website for legitimacy and scam indicators:

Domain: {domain}
Domain Age: {domain_info.get('age', 'Unknown')}
SSL Certificate: {'Valid' if ssl_info.get('valid') else 'Invalid'}

Website Content (first 2000 chars):
{page_content}

Provide a brief analysis covering:
1. Overall legitimacy assessment (1-2 sentences)
2. Top 3 red flags or concerns (if any)
3. Top 3 positive indicators (if any)

Keep response under 200 words."""

        chat_completion = client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": "You are a cybersecurity expert specializing in scam detection and website legitimacy analysis."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            model="llama-3.3-70b-versatile",
            temperature=0.3,
            max_tokens=300
        )
        
        return chat_completion.choices[0].message.content
    except Exception as e:
        print(f"Groq analysis error: {e}")
        return None

def check_google_safe_browsing(url: str) -> Dict[str, Any]:
    """Check URL against Google Safe Browsing API for malware/phishing"""
    try:
        api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
        if not api_key:
            print("GOOGLE_SAFE_BROWSING_API_KEY not set, skipping malware check")
            return {
                "is_safe": True,
                "threats": [],
                "threat_types": [],
                "checked": False,
            }
        
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        
        payload = {
            "client": {
                "clientId": "platform-analyzer",
                "clientVersion": "1.0.0",
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        
        response = requests.post(api_url, json=payload, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            
            if "matches" in data and len(data["matches"]) > 0:
                threats: List[str] = []
                threat_types: List[str] = []
                
                for match in data["matches"]:
                    threat_type = match.get("threatType", "UNKNOWN")
                    threat_types.append(threat_type)
                    
                    if threat_type == "MALWARE":
                        threats.append("⚠️ MALWARE DETECTED - Site distributes malicious software")
                    elif threat_type == "SOCIAL_ENGINEERING":
                        threats.append("⚠️ PHISHING DETECTED - Site attempts to steal personal information")
                    elif threat_type == "UNWANTED_SOFTWARE":
                        threats.append("⚠️ UNWANTED SOFTWARE - Site may install harmful programs")
                    elif threat_type == "POTENTIALLY_HARMFUL_APPLICATION":
                        threats.append("⚠️ HARMFUL APPLICATION - Site contains dangerous applications")
                
                return {
                    "is_safe": False,
                    "threats": threats,
                    "threat_types": threat_types,
                    "checked": True,
                }
            
            return {
                "is_safe": True,
                "threats": [],
                "threat_types": [],
                "checked": True,
            }
        else:
            print(f"Safe Browsing API error: {response.status_code}")
            return {
                "is_safe": True,
                "threats": [],
                "threat_types": [],
                "checked": False,
            }
    except Exception as e:
        print(f"Safe Browsing check error: {e}")
        return {
            "is_safe": True,
            "threats": [],
            "threat_types": [],
            "checked": False,
        }


def check_suspicious_patterns(url: str, domain: str) -> Dict[str, Any]:
    """Check for suspicious URL patterns and typosquatting"""
    warnings: List[str] = []
    risk_score = 0
    
    # Check for suspicious TLDs
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.top', '.xyz', '.club', '.work', '.click']
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            warnings.append(f"Suspicious TLD detected: {tld} - Often used for scams")
            risk_score += 15
            break
    
    # Check for excessive subdomains
    parts = domain.split('.')
    if len(parts) > 3:
        warnings.append("Multiple subdomains detected - Possible phishing attempt")
        risk_score += 10
    
    # Check for typosquatting of popular brands
    popular_brands = ['google', 'facebook', 'amazon', 'paypal', 'microsoft', 'apple', 
                      'netflix', 'instagram', 'twitter', 'linkedin', 'youtube']
    
    for brand in popular_brands:
        if brand in domain.lower() and not domain.lower().startswith(brand):
            warnings.append(f"Possible typosquatting - Contains '{brand}' but isn't official site")
            risk_score += 20
            break
    
    # Check for excessive hyphens (common in phishing)
    if domain.count('-') > 2:
        warnings.append("Excessive hyphens in domain - Suspicious pattern")
        risk_score += 10
    
    # Check for numbers in domain (sometimes suspicious)
    if any(char.isdigit() for char in domain.replace('.', '')):
        # Only flag if combined with other suspicious patterns
        if risk_score > 0:
            warnings.append("Numbers in domain combined with other suspicious patterns")
            risk_score += 5
    
    # Check URL length (very long URLs are suspicious)
    if len(url) > 100:
        warnings.append("Extremely long URL - Possible obfuscation attempt")
        risk_score += 10
    
    # Check for @ symbol (used in phishing to hide real domain)
    if '@' in url:
        warnings.append("@ symbol in URL - Common phishing technique")
        risk_score += 25
    
    # Check for IP address instead of domain
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    if re.search(ip_pattern, domain):
        warnings.append("IP address used instead of domain name - High risk")
        risk_score += 20
    
    return {
        "warnings": warnings,
        "risk_score": risk_score,
        "is_suspicious": risk_score > 15,
    }


@app.post("/api/analyze-job")
async def analyze_job(request: JobAnalyzeRequest):
    """Analyze job posting for authenticity and scam indicators"""
    try:
        print("Analyzing job posting...")
        
        # Extract data from request
        job_url = request.job_url or ""
        job_description = request.job_description or ""
        company_name = request.company_name or ""
        salary = request.salary or ""
        recruiter_email = request.recruiter_email or ""
        
        # If job URL provided, try to scrape content
        company_website = ""
        if job_url and not job_description:
            try:
                headers = {'User-Agent': 'Mozilla/5.0'}
                response = requests.get(job_url, headers=headers, timeout=10)
                soup = BeautifulSoup(response.text, 'html.parser')
                job_description = soup.get_text()[:5000]  # First 5000 chars
            except Exception as e:
                print(f"Failed to scrape job URL: {e}")
        
        # Perform analyses
        email_analysis = analyze_email_domain(recruiter_email)
        red_flags = detect_job_red_flags(job_description, salary)
        salary_analysis = analyze_salary_reasonableness(salary, company_name)
        company_verification = verify_company_online(company_name, company_website)
        platform_analysis = analyze_job_posting_url(job_url)
        
        # Calculate trust score
        trust_score, findings = calculate_job_trust_score(
            email_analysis,
            red_flags,
            salary_analysis,
            company_verification,
            platform_analysis,
        )
        
        verdict = get_job_verdict(trust_score)
        
        # Determine risk level
        if trust_score >= 70:
            risk_level = "Low Risk"
            recommendation = (
                "This job posting appears legitimate based on our analysis. However, "
                "always verify company details and never send money or sensitive information "
                "before being formally hired."
            )
        elif trust_score >= 40:
            risk_level = "Medium Risk"
            recommendation = (
                f"Exercise caution with this job posting. Trust score: {trust_score}/100. "
                "We recommend additional research: verify the company exists, check reviews "
                "on Glassdoor, and confirm the recruiter's identity on LinkedIn before proceeding."
            )
        else:
            risk_level = "High Risk"
            recommendation = (
                f"⚠️ WARNING: This job posting shows multiple red flags indicating it may be a scam. "
                f"Trust score: {trust_score}/100. We strongly recommend avoiding this opportunity "
                "and reporting it to the job board."
            )
        
        # Prepare response
        return {
            "trustScore": trust_score,
            "verdict": verdict,
            "riskLevel": risk_level,
            "recommendation": recommendation,
            "findings": findings,
            "emailAnalysis": {
                "email": recruiter_email or "Not provided",
                "isCorporate": email_analysis.get("is_corporate", False),
                "domain": email_analysis.get("domain", "Unknown"),
                "provider": email_analysis.get("provider", "Unknown"),
                "risk": email_analysis.get("risk", "Unknown"),
            },
            "salaryAnalysis": {
                "providedSalary": salary or "Not specified",
                "isReasonable": salary_analysis.get("is_reasonable", True),
                "assessment": salary_analysis.get("assessment", ""),
                "yearlyEquivalent": salary_analysis.get("yearly_equivalent", "Unknown"),
                "risk": salary_analysis.get("risk", "Unknown"),
            },
            "companyVerification": {
                "companyName": company_name or "Not provided",
                "hasWebsite": company_verification.get("has_website", False),
                "legitimacyScore": company_verification.get("legitimacy_score", 0),
            },
            "platformAnalysis": {
                "jobUrl": job_url or "Not provided",
                "isLegitimate": platform_analysis.get("is_legitimate_platform", False),
                "platform": platform_analysis.get("platform", "Unknown"),
                "trustLevel": platform_analysis.get("trust_level", "Unknown"),
            },
            "redFlags": red_flags,
            "totalRedFlags": len(red_flags),
            "criticalFlags": len([f for f in red_flags if f.get("type") == "critical"]),
        }
    except Exception as e:
        print(f"Job analysis error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Job analysis failed: {str(e)}")


@app.get("/api/job-analyzer-status")
async def job_analyzer_status():
    """Check if job analyzer is available"""
    return {
        "status": "online",
        "message": "Job Analyzer API is ready",
        "version": "1.0.0",
    }

@app.post("/api/analyze")
async def analyze_platform(request: AnalyzeRequest):
    """Full website analysis with all checks"""
    try:
        url = request.url
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        print(f"Analyzing: {url}")
        
        domain = urlparse(url).netloc.lower().replace('www.', '')
        
        KNOWN_LEGITIMATE = {
            'instagram.com', 'facebook.com', 'twitter.com', 'x.com', 'youtube.com',
            'linkedin.com', 'tiktok.com', 'reddit.com', 'pinterest.com', 'snapchat.com',
            'whatsapp.com', 'telegram.org', 'discord.com', 'amazon.com', 'ebay.com',
            'paypal.com', 'google.com', 'microsoft.com', 'apple.com', 'netflix.com', 'spotify.com'
        }
        
        if domain in KNOWN_LEGITIMATE:
            return {
                "url": url,
                "trustScore": 95,
                "verdict": "Legit",
                "domainAge": "Established",
                "domainRegistered": "Long-standing platform",
                "sslStatus": "Valid SSL Certificate",
                "serverLocation": "Global CDN",
                "whoisData": {
                    "registrar": "Major Registrar",
                    "owner": "Verified Corporation",
                    "email": "Legal Contact",
                    "lastUpdated": datetime.now().strftime("%Y-%m-%d")
                },
                "contentAnalysis": {
                    "aboutUsFound": True,
                    "termsOfServiceFound": True,
                    "contactInfoFound": True,
                    "physicalAddressFound": True,
                    "teamPhotosAnalyzed": True,
                    "stockImagesDetected": False
                },
                "socialData": {
                    "redditMentions": 0,
                    "twitterMentions": 0,
                    "trustpilotScore": 0,
                    "scamAdvisorScore": 95
                },
                "withdrawalComplaints": 0,
                "findings": [
                    {"type": "info", "text": "✓ Well-established, globally recognized platform"},
                    {"type": "info", "text": "✓ Valid SSL certificate and security measures"},
                    {"type": "info", "text": "✓ Trusted by millions of users worldwide"}
                ],
                "sentiment": {"positive": 80, "neutral": 15, "negative": 5},
                "redFlags": [],
                "ponziCalculation": None,
                "scamProbability": "Very Low",
                "recommendation": f"This is a legitimate, well-known platform. It's safe to use, but always follow standard security practices.",
                "peopleExperience": {
                    "experienceScore": 95,
                    "userExperienceRating": "Excellent",
                    "hasTestimonials": True,
                    "hasSocialProof": True,
                    "hasSupport": True
                }
            }
        
        domain_info = get_domain_age(url)
        ssl_info = check_ssl(url)
        content_info = analyze_content(url)
        
        malware_check = check_google_safe_browsing(url)
        suspicious_patterns = check_suspicious_patterns(url, domain)
        
        # Get user comments from SUPABASE
        try:
            comments_result = supabase.table("comments")\
                .select("*")\
                .eq("domain", domain)\
                .execute() if supabase else None
            
            user_comments_data = comments_result.data if comments_result and comments_result.data else []
        except Exception as e:
            print(f"Error fetching comments: {e}")
            user_comments_data = []
        
        user_comment_count = len(user_comments_data)
        user_scam_reports = sum(1 for c in user_comments_data if c.get("was_scammed", False))
        user_avg_rating = sum(c.get("rating", 0) for c in user_comments_data) / user_comment_count if user_comment_count > 0 else 0
        
        website_type = detect_website_type(domain, content_info.get("pageContent", ""))
        
        trust_score, findings = calculate_trust_score(domain_info, ssl_info, content_info)
        trust_score, findings = adjust_score_by_website_type(trust_score, website_type, findings)
        
        ai_analysis = analyze_with_groq(domain, content_info.get("pageContent", ""), domain_info, ssl_info)
        
        if not malware_check["is_safe"]:
            trust_score = 0
            verdict = "Scam"
            findings = []
            
            for threat in malware_check["threats"]:
                findings.append({"type": "critical", "text": threat})
            
            findings.append({"type": "critical", "text": "🚨 DANGER: This site is flagged by Google Safe Browsing"})
            findings.append({"type": "critical", "text": "DO NOT enter any personal information or download anything"})
            
            return {
                "url": url,
                "trustScore": 0,
                "verdict": "Scam",
                "domainAge": domain_info["age"],
                "domainRegistered": domain_info["registered"],
                "sslStatus": "UNSAFE - Malware/Phishing Detected",
                "serverLocation": "⚠️ DANGEROUS SITE",
                "whoisData": {
                    "registrar": domain_info["registrar"],
                    "owner": "⚠️ MALICIOUS",
                    "email": "AVOID THIS SITE",
                    "lastUpdated": datetime.now().strftime("%Y-%m-%d")
                },
                "contentAnalysis": {
                    "aboutUsFound": False,
                    "termsOfServiceFound": False,
                    "contactInfoFound": False,
                    "physicalAddressFound": False,
                    "teamPhotosAnalyzed": False,
                    "stockImagesDetected": False
                },
                "socialData": {
                    "redditMentions": 0,
                    "twitterMentions": 0,
                    "trustpilotScore": 0,
                    "scamAdvisorScore": 0
                },
                "withdrawalComplaints": 0,
                "findings": findings,
                "sentiment": {"positive": 0, "neutral": 0, "negative": 100},
                "redFlags": malware_check["threat_types"],
                "ponziCalculation": None,
                "scamProbability": "CRITICAL - 100%",
                "recommendation": "🚨 CRITICAL WARNING: This website has been identified as malicious by Google Safe Browsing.",
                "peopleExperience": {
                    "experienceScore": 0,
                    "userExperienceRating": "DANGEROUS",
                    "hasTestimonials": False,
                    "hasSocialProof": False,
                    "hasSupport": False
                }
            }
        
        if suspicious_patterns["is_suspicious"]:
            trust_score -= suspicious_patterns["risk_score"]
            for warning in suspicious_patterns["warnings"]:
                findings.insert(0, {"type": "critical" if suspicious_patterns["risk_score"] > 30 else "warning", 
                                   "text": warning})
        
        if ai_analysis:
            ai_text = ai_analysis.lower()
            ai_adjustment = 0
            ai_severity = "info"
            
            if any(phrase in ai_text for phrase in [
                "potential scam", "likely scam", "high risk scam", "highly suspicious",
                "strong concerns about its legitimacy",
            ]):
                ai_adjustment -= 25
                ai_severity = "critical"
            elif any(phrase in ai_text for phrase in [
                "suspicious", "red flags", "concerns about", "exercise caution",
            ]):
                ai_adjustment -= 10
                ai_severity = "warning"
            elif any(phrase in ai_text for phrase in [
                "appears legitimate", "no major red flags", "no significant scam indicators",
                "overall legitimate",
            ]):
                ai_adjustment += 8
                ai_severity = "info"
            
            if ai_adjustment != 0:
                trust_score += ai_adjustment
                findings.insert(0, {
                    "type": ai_severity,
                    "text": f"AI analysis adjustment ({ai_adjustment:+}): {ai_analysis[:180]}..."
                })
        
        if malware_check["checked"]:
            findings.insert(0, {"type": "info", "text": "✅ No malware/phishing detected by Google Safe Browsing"})
        
        if user_comment_count > 0:
            if user_scam_reports > 3:
                trust_score -= 20
                findings.insert(0, {"type": "critical", "text": f"⚠️ {user_scam_reports} users reported being scammed!"})
            elif user_scam_reports > 0:
                trust_score -= 10
                findings.insert(0, {"type": "warning", "text": f"{user_scam_reports} scam report(s) from users"})
            
            if user_avg_rating >= 4:
                trust_score += 5
                findings.insert(0, {"type": "info", "text": f"Users rate this site {user_avg_rating:.1f}/5 stars ({user_comment_count} reviews)"})
            elif user_avg_rating <= 2:
                trust_score -= 10
                findings.insert(0, {"type": "warning", "text": f"Low user rating: {user_avg_rating:.1f}/5 stars ({user_comment_count} reviews)"})
        
        trust_score = max(0, min(100, trust_score))
        verdict = get_verdict(trust_score)
        scam_prob = "Low" if trust_score >= 70 else "Medium" if trust_score >= 40 else "High"
        
        if verdict == "Legit":
            recommendation = "This website appears legitimate based on our analysis."
        elif verdict == "Caution":
            recommendation = f"Exercise caution with this website. Trust score: {trust_score}/100."
        else:
            recommendation = f"⚠️ WARNING: This website shows multiple red flags. Trust score: {trust_score}/100."
        
        return {
            "url": url,
            "trustScore": trust_score,
            "verdict": verdict,
            "domainAge": domain_info["age"],
            "domainRegistered": domain_info["registered"],
            "sslStatus": "Valid SSL Certificate" if ssl_info["valid"] else "No SSL Certificate",
            "serverLocation": "Cloud Infrastructure",
            "whoisData": {
                "registrar": domain_info["registrar"],
                "owner": "Privacy Protected",
                "email": "Protected",
                "lastUpdated": datetime.now().strftime("%Y-%m-%d")
            },
            "contentAnalysis": {
                "aboutUsFound": content_info["aboutUsFound"],
                "termsOfServiceFound": content_info["termsOfServiceFound"],
                "contactInfoFound": content_info["contactInfoFound"],
                "physicalAddressFound": content_info["physicalAddressFound"],
                "teamPhotosAnalyzed": True,
                "stockImagesDetected": content_info["stockImagesDetected"]
            },
            "socialData": {
                "redditMentions": 0,
                "twitterMentions": 0,
                "trustpilotScore": 0,
                "scamAdvisorScore": trust_score
            },
            "withdrawalComplaints": 0,
            "findings": findings,
            "sentiment": {
                "positive": max(0, trust_score - 20),
                "neutral": 40,
                "negative": max(0, 80 - trust_score)
            },
            "redFlags": content_info["redFlagKeywords"],
            "ponziCalculation": None,
            "scamProbability": scam_prob,
            "recommendation": recommendation,
            "aiAnalysis": ai_analysis,
            "peopleExperience": {
                "experienceScore": trust_score,
                "userExperienceRating": "Good" if trust_score >= 70 else "Fair" if trust_score >= 40 else "Poor",
                "hasTestimonials": content_info["aboutUsFound"],
                "hasSocialProof": user_comment_count > 10,
                "hasSupport": content_info["contactInfoFound"]
            }
        }
    except Exception as e:
        print(f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)