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
import json
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


def log_analysis_to_db(
    analysis_type: str,
    url: Optional[str],
    domain: Optional[str],
    trust_score: Optional[int],
    verdict: Optional[str],
    user: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Helper to log each analysis into Supabase `analyses` table.
    Fails soft: logging errors never break the main request.
    """
    if not supabase:
        return

    try:
        payload: Dict[str, Any] = {
            "type": analysis_type,
            "url": url,
            "domain": domain,
            "trust_score": trust_score,
            "verdict": verdict,
        }

        if user and user.get("id"):
            payload["user_id"] = user["id"]

        supabase.table("analyses").insert(payload).execute()
    except Exception as e:
        # Log but do not raise – analytics should never break core flow
        print(f"Error logging analysis to Supabase: {e}")

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


def check_ssl_certificate(url: str) -> Dict[str, Any]:
    """Check if website has valid SSL certificate"""
    try:
        hostname = urlparse(url).netloc
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return {
                    "valid": True,
                    "issuer": dict(x[0] for x in cert['issuer']),
                    "expires": cert['notAfter']
                }
    except Exception as e:
        return {"valid": False, "error": str(e)}


def analyze_website_content(url: str) -> Dict[str, Any]:
    """Scrape and analyze website content for legitimacy indicators"""
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        text_content = soup.get_text().lower()
        
        # Check for key trust indicators
        has_about = 'about us' in text_content or 'about' in text_content
        has_contact = 'contact' in text_content or 'contact us' in text_content
        has_terms = 'terms' in text_content or 'terms of service' in text_content
        has_privacy = 'privacy' in text_content or 'privacy policy' in text_content
        
        # Check for images (stock photo detection would need advanced AI)
        images = soup.find_all('img')
        has_images = len(images) > 0
        
        return {
            "aboutUsFound": has_about,
            "termsOfServiceFound": has_terms,
            "contactInfoFound": has_contact,
            "privacyPolicyFound": has_privacy,
            "teamPhotosAnalyzed": has_images,
            "stockImagesDetected": False,  # Would need AI image analysis
            "totalImages": len(images)
        }
    except Exception as e:
        print(f"Content analysis error: {e}")
        return {
            "aboutUsFound": False,
            "termsOfServiceFound": False,
            "contactInfoFound": False,
            "privacyPolicyFound": False,
            "teamPhotosAnalyzed": False,
            "stockImagesDetected": False,
            "totalImages": 0
        }


def detect_scam_patterns(url: str, content: str) -> List[Dict[str, str]]:
    """Detect common scam patterns in URL and content"""
    red_flags = []
    
    # Check for suspicious TLDs
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
    if any(url.endswith(tld) for tld in suspicious_tlds):
        red_flags.append({
            "type": "warning",
            "text": "Uses suspicious top-level domain often associated with scams"
        })
    
    # Check for typosquatting indicators
    if any(char in url for char in ['1', '0']) and any(brand in url for brand in ['paypal', 'amazon', 'google', 'apple', 'microsoft']):
        red_flags.append({
            "type": "critical",
            "text": "Possible typosquatting - URL mimics legitimate brand"
        })
    
    # Check content for scam keywords
    scam_keywords = [
        'guaranteed profit', 'get rich quick', 'no risk', 'limited time offer',
        'act now', 'wire transfer', 'cryptocurrency investment', 'double your money',
        'too good to be true', 'click here now', 'congratulations you won'
    ]
    
    content_lower = content.lower()
    for keyword in scam_keywords:
        if keyword in content_lower:
            red_flags.append({
                "type": "warning",
                "text": f"Contains suspicious phrase: '{keyword}'"
            })
            break  # Only report one to avoid spam
    
    return red_flags


def check_google_safe_browsing(url: str) -> Dict[str, Any]:
    """Check URL against Google Safe Browsing API"""
    # Note: You need to set GOOGLE_SAFE_BROWSING_API_KEY in environment
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
    
    if not api_key:
        return {"checked": False, "safe": True, "threats": []}
    
    try:
        gsb_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        payload = {
            "client": {
                "clientId": "platform-analyzer",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        
        response = requests.post(gsb_url, json=payload, timeout=5)
        data = response.json()
        
        if "matches" in data:
            return {
                "checked": True,
                "safe": False,
                "threats": [match["threatType"] for match in data["matches"]]
            }
        else:
            return {"checked": True, "safe": True, "threats": []}
            
    except Exception as e:
        print(f"Google Safe Browsing check error: {e}")
        return {"checked": False, "safe": True, "threats": []}


def analyze_with_groq_ai(url: str, content: str, domain_age: str, ssl_valid: bool) -> Optional[str]:
    """Use Groq AI to analyze website legitimacy"""
    try:
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            print("GROQ_API_KEY not set, skipping AI analysis")
            return None
        
        client = Groq(api_key=api_key)
        
        prompt = f"""Analyze this website for legitimacy and potential scam indicators:

URL: {url}
Domain Age: {domain_age}
SSL Certificate: {'Valid' if ssl_valid else 'Invalid or Missing'}
Website Content Sample: {content[:3000]}

Provide a comprehensive analysis covering:

1. LEGITIMACY ASSESSMENT (2-3 sentences)
   - Overall impression of this website
   - Is this likely legitimate or a potential scam?

2. RED FLAGS (List top 3-5 concerns if any)
   - Specific warning signs you notice
   - Why each flag is concerning

3. POSITIVE INDICATORS (List 2-3 if any)
   - What suggests legitimacy
   - Professional or trustworthy elements

4. TRUST RECOMMENDATION
   - Should users trust this site?
   - What precautions should they take?

Keep response under 300 words, be direct and actionable."""

        chat_completion = client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": "You are an expert cybersecurity analyst and scam detection specialist with 15+ years of experience identifying fraudulent websites, phishing attempts, and online scams."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            model="llama-3.3-70b-versatile",
            temperature=0.3,
            max_tokens=500
        )
        
        ai_analysis = chat_completion.choices[0].message.content
        print(f"✅ AI analysis completed: {len(ai_analysis)} characters")
        return ai_analysis
        
    except Exception as e:
        print(f"Groq AI analysis error: {e}")
        return None


@app.post("/api/analyze")
async def analyze_website(request: AnalyzeRequest, authorization: Optional[str] = Header(None)):
    """Main website analysis endpoint - COMPLETE IMPLEMENTATION"""
    try:
        url = request.url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        print(f"🔍 Analyzing website: {url}")
        
        # Initialize results
        domain_info = get_domain_age(url)
        ssl_info = check_ssl_certificate(url)
        content_analysis = analyze_website_content(url)
        
        # Get page content for AI analysis
        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            response = requests.get(url, headers=headers, timeout=10)
            page_content = BeautifulSoup(response.text, 'html.parser').get_text()[:5000]
        except Exception:
            page_content = ""
        
        # Detect scam patterns
        red_flags = detect_scam_patterns(url, page_content)
        
        # Google Safe Browsing check
        gsb_result = check_google_safe_browsing(url)
        
        # Calculate base trust score
        trust_score = 70  # Start neutral
        findings = []
        
        # Domain age assessment
        age_days = domain_info.get("age_days", 0)
        if age_days > 365:
            trust_score += 15
            findings.append({"type": "info", "text": f"Domain is {domain_info['age']} old - Established presence"})
        elif age_days > 180:
            trust_score += 5
            findings.append({"type": "info", "text": f"Domain age: {domain_info['age']}"})
        elif age_days > 0:
            trust_score -= 15
            findings.append({"type": "warning", "text": f"Very new domain ({domain_info['age']}) - Exercise caution"})
        
        # SSL certificate
        if ssl_info.get("valid"):
            trust_score += 10
            findings.append({"type": "info", "text": "Valid SSL certificate detected"})
        else:
            trust_score -= 20
            findings.append({"type": "critical", "text": "No valid SSL certificate - Insecure connection"})
        
        # Content analysis
        if content_analysis["aboutUsFound"]:
            trust_score += 5
        if content_analysis["contactInfoFound"]:
            trust_score += 5
        if content_analysis["termsOfServiceFound"]:
            trust_score += 5
        
        if not content_analysis["aboutUsFound"] and not content_analysis["contactInfoFound"]:
            trust_score -= 10
            findings.append({"type": "warning", "text": "Missing 'About Us' and contact information"})
        
        # Google Safe Browsing
        if gsb_result["checked"] and not gsb_result["safe"]:
            trust_score = 0  # Immediate zero score
            findings.insert(0, {
                "type": "critical",
                "text": f"🚨 FLAGGED BY GOOGLE SAFE BROWSING: {', '.join(gsb_result['threats'])}"
            })
        
        # Add red flags
        for flag in red_flags:
            findings.append(flag)
            if flag["type"] == "critical":
                trust_score -= 20
            elif flag["type"] == "warning":
                trust_score -= 10
        
        # Ensure score bounds
        trust_score = max(0, min(100, trust_score))
        
        # AI Analysis
        ai_analysis = analyze_with_groq_ai(
            url=url,
            content=page_content,
            domain_age=domain_info["age"],
            ssl_valid=ssl_info.get("valid", False)
        )
        
        # Determine verdict
        if trust_score >= 70:
            verdict = "Legit"
            recommendation = "This website appears legitimate based on our analysis. However, always exercise caution when sharing personal information online."
        elif trust_score >= 40:
            verdict = "Caution"
            recommendation = "This website shows some concerning signs. Proceed with caution and avoid sharing sensitive information until you can verify its legitimacy."
        else:
            verdict = "Scam"
            recommendation = "⚠️ HIGH RISK: This website shows significant red flags. We strongly recommend avoiding this site and not sharing any personal or financial information."
        
        # Log to database
        try:
            user = get_user_from_token(authorization) if authorization else None
            log_analysis_to_db(
                analysis_type="website",
                url=url,
                domain=urlparse(url).netloc.replace('www.', ''),
                trust_score=trust_score,
                verdict=verdict,
                user=user
            )
        except Exception as e:
            print(f"Failed to log analysis: {e}")
        
        return {
            "url": url,
            "trustScore": trust_score,
            "verdict": verdict,
            "domainAge": domain_info["age"],
            "domainRegistered": domain_info["registered"],
            "sslStatus": "Valid SSL" if ssl_info.get("valid") else "No Valid SSL",
            "serverLocation": "Unknown",  # Would need GeoIP lookup
            "whoisData": {
                "registrar": domain_info.get("registrar", "Unknown"),
                "owner": "Private",
                "email": "Private",
                "lastUpdated": domain_info.get("registered", "Unknown")
            },
            "contentAnalysis": {
                "aboutUsFound": content_analysis["aboutUsFound"],
                "termsOfServiceFound": content_analysis["termsOfServiceFound"],
                "contactInfoFound": content_analysis["contactInfoFound"],
                "physicalAddressFound": False,
                "teamPhotosAnalyzed": content_analysis["teamPhotosAnalyzed"],
                "stockImagesDetected": content_analysis["stockImagesDetected"]
            },
            "socialData": {
                "redditMentions": 0,
                "twitterMentions": 0,
                "trustpilotScore": 0,
                "scamAdvisorScore": 0
            },
            "withdrawalComplaints": 0,
            "findings": findings,
            "sentiment": {
                "positive": 50,
                "neutral": 30,
                "negative": 20
            },
            "redFlags": [f["text"] for f in red_flags],
            "ponziCalculation": None,
            "scamProbability": f"{100 - trust_score}%" if trust_score < 50 else "Low",
            "recommendation": recommendation,
            "aiAnalysis": ai_analysis
        }
        
    except Exception as e:
        print(f"Website analysis error: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

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
            "platform": "Invalid URL",
            "trust_level": "Unknown",
            "domain": "Invalid",
        }
    except Exception:
        return {
            "is_legitimate_platform": False,
            "platform": "Invalid URL",
            "trust_level": "Unknown",
            "domain": "Invalid",
        }
def smart_extract_job_details_with_ai(job_url: str) -> Dict[str, Any]:
    """Intelligently scrape job posting and use AI to extract structured information"""
    try:
        print(f"🔍 Smart scraping job URL: {job_url}")
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(job_url, headers=headers, timeout=15)
        soup = BeautifulSoup(response.text, 'html.parser')

        full_text = soup.get_text(separator='\n', strip=True)

        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            print("⚠️ GROQ_API_KEY not set, falling back to basic scraping")
            return extract_job_details_basic(soup, full_text)

        client = Groq(api_key=api_key)

        email_domain = "not provided"
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, full_text)
        if emails:
            email_domain = emails[0].split('@')[1] if '@' in emails[0] else "not provided"

        prompt = f"""Extract job posting details from this webpage content. Return ONLY a JSON object with these exact fields:
{{
"company_name": "extracted company name or 'Unknown'",
"job_title": "extracted job title or 'Unknown'",
"salary": "extracted salary (e.g., '$80,000/year', '$5000/week') or 'Not specified'",
"recruiter_email": "extracted email or 'Not found'",
"job_description": "cleaned job description (200-500 words)"
}}
Webpage content:
{full_text[:4000]}
Return ONLY valid JSON, no other text."""
        chat_completion = client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": "You are a data extraction specialist. Extract job posting information and return ONLY valid JSON with no additional text or formatting."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            model="llama-3.3-70b-versatile",
            temperature=0.1,
            max_tokens=800
        )

        ai_response = chat_completion.choices[0].message.content.strip()

        # Strip fences if present
        if ai_response.startswith("```"):
            parts = ai_response.split("```")
            if len(parts) >= 2:
                ai_response = parts[1]
                if ai_response.startswith("json"):
                    ai_response = ai_response[4:].strip()

        try:
            extracted_data = json.loads(ai_response)
        except Exception:
            extracted_data = {}

        print(f"✅ AI extracted: Company={extracted_data.get('company_name', 'Unknown')}, Salary={extracted_data.get('salary', 'Unknown')}")

        return {
            "company_name": extracted_data.get("company_name", "Unknown"),
            "job_title": extracted_data.get("job_title", "Unknown"),
            "salary": extracted_data.get("salary", "Not specified"),
            "recruiter_email": extracted_data.get("recruiter_email", emails[0] if emails else "Not found"),
            "job_description": extracted_data.get("job_description", full_text[:2000])
        }

    except Exception as e:
        print(f"❌ Smart extraction error: {e}")
        if 'full_text' in locals():
            return extract_job_details_basic(None, full_text)
        return {
            "company_name": "Unknown",
            "job_title": "Unknown",
            "salary": "Not specified",
            "recruiter_email": "Not found",
            "job_description": ""
        }

def extract_job_details_basic(soup, text: str) -> Dict[str, Any]:
    """Fallback basic extraction without AI"""
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    emails = re.findall(email_pattern, text)
    recruiter_email = emails[0] if emails else "Not found"
    salary_pattern = r'\$[\d,]+(?:\s*(?:per|\/)\s*(?:year|month|week|hour))?'
    salaries = re.findall(salary_pattern, text, re.IGNORECASE)
    salary = salaries[0] if salaries else "Not specified"

    # Best-effort title/company extraction from HTML if soup provided
    company_name = "Unknown"
    job_title = "Unknown"
    try:
        if soup:
            # common selectors
            title_tag = soup.find(attrs={"class": re.compile(r'(job-title|title|posting-title)', re.I)}) or soup.find('h1')
            if title_tag and title_tag.get_text(strip=True):
                job_title = title_tag.get_text(strip=True)[:200]
            company_tag = soup.find(attrs={"class": re.compile(r'(company|employer|org-name)', re.I)})
            if company_tag and company_tag.get_text(strip=True):
                company_name = company_tag.get_text(strip=True)[:200]
    except Exception:
        pass

    return {
        "company_name": company_name,
        "job_title": job_title,
        "salary": salary,
        "recruiter_email": recruiter_email,
        "job_description": text[:2000]
    }

# ============================================
# JOB ANALYZER AI ENHANCEMENT
# ============================================

def analyze_job_with_ai(
    company_name: str,
    job_description: str,
    salary: str,
    recruiter_email: str,
    job_url: str
) -> Optional[str]:
    """
    Use Groq AI to analyze job posting for legitimacy and provide insights
    """
    try:
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            print("GROQ_API_KEY not set, skipping AI job analysis")
            return None

        client = Groq(api_key=api_key)

        email_domain = recruiter_email.split('@')[1] if '@' in recruiter_email else "not provided"

        prompt = f"""Analyze this job posting for legitimacy and potential red flags:

Company: {company_name or "Not specified"}
Job Description: {job_description[:2000] if job_description else "Not provided"}
Salary Offered: {salary or "Not specified"}
Recruiter Email: {recruiter_email or "Not provided"} (Domain: {email_domain})
Job URL: {job_url or "Not provided"}

Provide a comprehensive analysis covering:

1. LEGITIMACY ASSESSMENT (2-3 sentences)
   - Overall impression of this job posting
   - Is this likely a real opportunity or potential scam?

2. RED FLAGS (List top 3-5 concerns if any)
   - Specific warning signs you notice
   - Why each flag is concerning

3. POSITIVE INDICATORS (List 2-3 if any)
   - What suggests this might be legitimate
   - Professional or trustworthy elements

4. SALARY ANALYSIS
   - Is the salary reasonable for this type of role?
   - Any concerns about compensation structure?

5. RECOMMENDATIONS
   - Should the candidate proceed with this opportunity?
   - What verification steps should they take?

Keep response under 300 words, be direct and actionable."""

        chat_completion = client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": "You are an expert employment fraud investigator and HR professional specializing in identifying job scams, fake recruiters, and fraudulent employment offers. You have 15+ years of experience in recruitment fraud prevention."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            model="llama-3.3-70b-versatile",
            temperature=0.3,
            max_tokens=500
        )

        ai_analysis = chat_completion.choices[0].message.content
        print(f"✅ AI job analysis completed: {len(ai_analysis)} characters")
        return ai_analysis

    except Exception as e:
        print(f"Groq AI job analysis error: {e}")
        return None


def extract_job_insights_from_ai(ai_analysis: str) -> Dict[str, Any]:
    """
    Extract structured insights from AI analysis to adjust trust score
    """
    if not ai_analysis:
        return {
            "adjustment": 0,
            "severity": "info",
            "key_concern": None
        }

    analysis_lower = ai_analysis.lower()
    adjustment = 0
    severity = "info"
    key_concern = None

    strong_scam_phrases = [
        "this is a scam",
        "definitely a scam",
        "clear scam",
        "obvious scam",
        "highly suspicious",
        "do not proceed",
        "avoid this",
        "major red flags",
        "employment fraud",
        "money laundering"
    ]

    moderate_concern_phrases = [
        "red flags",
        "concerns about",
        "suspicious",
        "exercise caution",
        "verify carefully",
        "potential scam",
        "questionable",
        "unusual",
        "warning signs"
    ]

    positive_phrases = [
        "appears legitimate",
        "seems genuine",
        "professional",
        "no major red flags",
        "reasonable opportunity",
        "typical job posting",
        "legitimate company",
        "standard practices"
    ]

    if any(phrase in analysis_lower for phrase in strong_scam_phrases):
        adjustment = -30
        severity = "critical"
        for phrase in strong_scam_phrases:
            if phrase in analysis_lower:
                key_concern = f"AI flagged: {phrase}"
                break

    elif any(phrase in analysis_lower for phrase in moderate_concern_phrases):
        adjustment = -15
        severity = "warning"
        key_concern = "AI detected concerning patterns"

    elif any(phrase in analysis_lower for phrase in positive_phrases):
        adjustment = +10
        severity = "info"

    if "upfront" in analysis_lower and ("payment" in analysis_lower or "fee" in analysis_lower):
        adjustment -= 20
        severity = "critical"
        key_concern = "AI detected upfront payment request - SCAM INDICATOR"

    if "too good to be true" in analysis_lower:
        adjustment -= 10
        severity = "warning"
        key_concern = "AI suspects unrealistic promises"

    if "free email" in analysis_lower or "gmail" in analysis_lower or "yahoo" in analysis_lower:
        if adjustment > -10:
            adjustment -= 5

    return {
        "adjustment": adjustment,
        "severity": severity,
        "key_concern": key_concern
    }

def calculate_job_trust_score(
    email_analysis: Dict[str, Any],
    red_flags: List[Dict[str, str]],
    salary_analysis: Dict[str, Any],
    company_verification: Dict[str, Any],
    platform_analysis: Dict[str, Any],
) -> (int, List[Dict[str, str]]):
    """
    Compute a simple trust score (0-100) for a job posting and return
    a list of human-readable findings. This is intentionally conservative
    and deterministic so AI adjustments remain meaningful.
    """
    trust = 70  # base neutral score
    findings: List[Dict[str, str]] = []

    # Email analysis
    try:
        if email_analysis:
            if not email_analysis.get("is_corporate", False):
                trust -= 10
                findings.append({
                    "type": "warning",
                    "text": f"Recruiter uses free email provider ({email_analysis.get('domain','unknown')})"
                })
            elif email_analysis.get("risk","").lower() == "critical":
                trust -= 20
                findings.append({
                    "type": "critical",
                    "text": f"Recruiter email appears invalid or malformed ({email_analysis.get('domain','invalid')})"
                })
    except Exception:
        pass

    # Red flags from description
    for rf in red_flags:
        severity = rf.get("type", "warning")
        if severity == "critical":
            trust -= 30
            findings.append({"type": "critical", "text": rf.get("text", "Critical red flag detected")})
        else:
            trust -= 10
            findings.append({"type": "warning", "text": rf.get("text", "Warning flag detected")})

    # Salary analysis
    try:
        risk = (salary_analysis.get("risk") or "").lower()
        if risk == "critical":
            trust -= 20
            findings.append({"type": "critical", "text": salary_analysis.get("assessment", "Suspicious salary")})
        elif risk == "high":
            trust -= 10
            findings.append({"type": "warning", "text": salary_analysis.get("assessment", "Unusual salary")})
        elif risk == "low" and salary_analysis.get("is_reasonable", False):
            trust += 5
            findings.append({"type": "info", "text": "Salary appears reasonable"})
    except Exception:
        pass

    # Company verification
    try:
        legitimacy = int(company_verification.get("legitimacy_score", 50))
        # scale legitimacy score delta into -20..+20
        delta = (legitimacy - 50) // 2
        trust += delta
        for f in company_verification.get("findings", []):
            # map prefix to type
            t = "info"
            if f.startswith("✗") or f.startswith("⚠"):
                t = "warning"
            findings.append({"type": t, "text": f})
    except Exception:
        pass

    # Platform analysis
    try:
        plat_trust = platform_analysis.get("trust_level", "") or ""
        if plat_trust.lower() in ("very high",):
            trust += 10
            findings.append({"type": "info", "text": f"Posted on trusted platform: {platform_analysis.get('platform','Unknown')}"})
        elif plat_trust.lower() in ("high",):
            trust += 5
            findings.append({"type": "info", "text": f"Posted on reputable platform: {platform_analysis.get('platform','Unknown')}"})
        elif plat_trust.lower() in ("medium",):
            # no change, but note
            findings.append({"type": "info", "text": f"Platform: {platform_analysis.get('platform','Unknown')}"})
        else:
            # Unknown or untrusted platform
            trust -= 10
            findings.append({"type": "warning", "text": f"Unrecognized or untrusted job platform ({platform_analysis.get('domain','unknown')})"})
    except Exception:
        pass

    # Ensure bounds
    trust = max(0, min(100, int(trust)))

    # If no findings produced, add neutral note
    if not findings:
        findings.append({"type": "info", "text": "No immediate concerns detected from heuristics"})

    return trust, findings

def get_job_verdict(trust_score: int) -> str:
    """Return verdict based on trust score"""
    try:
        t = int(trust_score)
    except Exception:
        return "Unknown"
    
    if t >= 70:
        return "Likely Legitimate"
    if t >= 40:
        return "Possibly Suspicious"
    return "Likely Scam"


@app.post("/api/analyze-job")
async def analyze_job(request: JobAnalyzeRequest, authorization: Optional[str] = Header(None)):
    """Analyze job posting - WITH AUTO-SCRAPING AND AI"""
    try:
        print(f"🔍 Analyzing job posting with AI enhancement...")
        job_url = request.job_url or ""
        
        # AUTO-SCRAPE if only URL provided
        if job_url and not request.job_description:
            print("🤖 Auto-scraping job details from URL...")
            extracted = smart_extract_job_details_with_ai(job_url)
            
            job_description = request.job_description or extracted["job_description"]
            company_name = request.company_name or extracted["company_name"]
            salary = request.salary or extracted["salary"]
            recruiter_email = request.recruiter_email or extracted["recruiter_email"]
            
            print(f"✅ Extracted: {company_name}, {salary}, {recruiter_email}")
        else:
            job_description = request.job_description or ""
            company_name = request.company_name or ""
            salary = request.salary or ""
            recruiter_email = request.recruiter_email or ""

        company_website = ""

        email_analysis = analyze_email_domain(recruiter_email)
        red_flags = detect_job_red_flags(job_description, salary)
        salary_analysis = analyze_salary_reasonableness(salary, company_name)
        company_verification = verify_company_online(company_name, company_website)
        platform_analysis = analyze_job_posting_url(job_url)

        trust_score, findings = calculate_job_trust_score(
            email_analysis,
            red_flags,
            salary_analysis,
            company_verification,
            platform_analysis
        )

        print("🤖 Running AI analysis with Groq...")
        ai_analysis = analyze_job_with_ai(
            company_name=company_name,
            job_description=job_description,
            salary=salary,
            recruiter_email=recruiter_email,
            job_url=job_url
        )

        if ai_analysis:
            ai_insights = extract_job_insights_from_ai(ai_analysis)

            if ai_insights["adjustment"] != 0:
                trust_score += ai_insights["adjustment"]
                trust_score = max(0, min(100, trust_score))

                ai_finding_text = f"AI Analysis: {ai_insights.get('key_concern', 'Additional insights provided')}"
                if ai_insights["adjustment"] > 0:
                    ai_finding_text = f"AI Analysis: No major concerns detected (+{ai_insights['adjustment']} trust)"
                elif ai_insights["adjustment"] < 0:
                    ai_finding_text = f"AI Analysis: {ai_insights.get('key_concern', 'Concerns detected')} ({ai_insights['adjustment']} trust)"

                findings.insert(0, {
                    "type": ai_insights["severity"],
                    "text": ai_finding_text
                })

                print(f"🎯 AI adjustment: {ai_insights['adjustment']} points")
        else:
            print("⚠️ AI analysis not available")

        verdict = get_job_verdict(trust_score)

        if trust_score >= 70:
            risk_level = "Low Risk"
            recommendation = "This job posting appears legitimate based on our AI-enhanced analysis. However, always verify company details and never send money or sensitive information before being formally hired."
        elif trust_score >= 40:
            risk_level = "Medium Risk"
            recommendation = f"Exercise caution with this job posting (Trust: {trust_score}/100). Verify the company exists, research the recruiter on LinkedIn, and never pay upfront fees."
        else:
            risk_level = "High Risk"
            recommendation = f"⚠️ WARNING: This job posting shows significant red flags (Trust: {trust_score}/100). DO NOT send money, provide SSN/bank details, or click suspicious links."

        try:
            user = get_user_from_token(authorization) if authorization else None
            log_analysis_to_db(
                analysis_type="job",
                url=job_url or f"Job: {company_name}",
                domain=(urlparse(job_url).netloc.lower().replace("www.", "") if job_url else company_name),
                trust_score=int(trust_score),
                verdict=verdict,
                user=user,
            )
        except Exception as e:
            print(f"Failed to log job analysis: {e}")

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
            "aiAnalysis": ai_analysis,
            "aiEnhanced": ai_analysis is not None
        }
    except Exception as e:
        print(f"Job analysis error: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Job analysis failed: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    print("🚀 Starting Platform Analyzer API...")
    print("📊 Version 2.0.0")
    print("✅ All endpoints loaded successfully")
    uvicorn.run(app, host="0.0.0.0", port=8000)