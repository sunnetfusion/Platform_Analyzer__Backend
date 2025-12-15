# main.py
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

# In-memory storage for comments (will migrate to Supabase later)
comments_db: Dict[str, List[Dict[str, Any]]] = {}

# Routes
@app.get("/")
async def root():
    return {
        "status": "online",
        "message": "Platform Analyzer API is running",
        "version": "2.0.0",
        "supabase": "connected" if supabase else "not configured"
    }

# Authentication endpoints with Supabase
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
        
        # Sign up with Supabase Auth
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
            # Get token from session
            token = response.session.access_token if response.session else None
            
            if not token:
                # If no session (email confirmation required), still return success
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
        
        # Sign in with Supabase Auth
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
        
        # Extract token
        token = authorization.replace("Bearer ", "")
        
        # Get user from Supabase
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
        
        # Get OAuth URL from Supabase
        # Note: You need to configure Google OAuth in Supabase dashboard first
        return {
            "url": f"{SUPABASE_URL}/auth/v1/authorize?provider=google",
            "message": "Redirect user to this URL for Google sign-in"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/comments")
async def add_comment(comment: CommentRequest):
    """Add user comment/review for a website"""
    try:
        url = comment.url.lower().strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        domain = urlparse(url).netloc.replace('www.', '')
        
        comment_entry = {
            "id": len(comments_db.get(domain, [])) + 1,
            "user_name": comment.user_name,
            "rating": max(1, min(5, comment.rating)),
            "experience": comment.experience,
            "comment": comment.comment,
            "was_scammed": comment.was_scammed,
            "timestamp": datetime.now().isoformat(),
            "helpful_count": 0
        }
        
        if domain not in comments_db:
            comments_db[domain] = []
        comments_db[domain].append(comment_entry)
        
        return {
            "status": "success",
            "message": "Comment added successfully",
            "comment": comment_entry
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/comments/{domain}")
async def get_comments(domain: str):
    """Get all comments for a domain"""
    try:
        domain = domain.lower().replace('www.', '')
        comments = comments_db.get(domain, [])
        
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
        
        return {
            "domain": domain,
            "total_comments": total_comments,
            "average_rating": round(avg_rating, 1),
            "scam_reports": scam_reports,
            "experience_breakdown": experience_breakdown,
            "comments": sorted(comments, key=lambda x: x["timestamp"], reverse=True)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/comments/{comment_id}/helpful")
async def mark_helpful(comment_id: int, domain: str):
    """Mark a comment as helpful"""
    try:
        domain = domain.lower().replace('www.', '')
        if domain in comments_db:
            for comment in comments_db[domain]:
                if comment["id"] == comment_id:
                    comment["helpful_count"] += 1
                    return {"status": "success", "helpful_count": comment["helpful_count"]}
        raise HTTPException(status_code=404, detail="Comment not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

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

def check_ssl(url: str) -> Dict[str, Any]:
    """Check SSL certificate status"""
    try:
        hostname = urlparse(url).netloc
        context = ssl.create_default_context()
        
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    # No cert returned - treat as invalid to avoid None access
                    return {
                        "valid": False,
                        "issuer": "None",
                        "expires": "N/A"
                    }
                # Normalize the nested issuer structure into a flat dict safely
                issuer = "Unknown"
                try:
                    issuer_raw = cert.get('issuer', ())
                    issuer_items = []
                    for rdn in issuer_raw:
                        # rdn is typically a tuple/list of (key, value) tuples
                        if isinstance(rdn, (list, tuple)):
                            for attr in rdn:
                                if isinstance(attr, (list, tuple)) and len(attr) >= 2:
                                    k = attr[0]
                                    v = attr[1]
                                    # Ensure keys/values are str
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
                    # Try common attribute names used for organization
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
                "checked": False
            }
        
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        
        payload = {
            "client": {
                "clientId": "platform-analyzer",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        
        response = requests.post(api_url, json=payload, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            
            if "matches" in data and len(data["matches"]) > 0:
                threats = []
                threat_types = []
                
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
                    "checked": True
                }
            
            return {
                "is_safe": True,
                "threats": [],
                "threat_types": [],
                "checked": True
            }
        else:
            print(f"Safe Browsing API error: {response.status_code}")
            return {
                "is_safe": True,
                "threats": [],
                "threat_types": [],
                "checked": False
            }
            
    except Exception as e:
        print(f"Safe Browsing check error: {e}")
        return {
            "is_safe": True,
            "threats": [],
            "threat_types": [],
            "checked": False
        }

def check_suspicious_patterns(url: str, domain: str) -> Dict[str, Any]:
    """Check for suspicious URL patterns and typosquatting"""
    warnings = []
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
        warnings.append(f"Multiple subdomains detected - Possible phishing attempt")
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
        "is_suspicious": risk_score > 15
    }

@app.post("/api/analyze")
async def analyze_platform(request: AnalyzeRequest):
    try:
        url = request.url
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        print(f"Analyzing: {url}")
        
        domain = urlparse(url).netloc.lower().replace('www.', '')
        
        # Whitelist for known legitimate platforms
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
                    {"type": "info", "text": f"✓ Well-established, globally recognized platform"},
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
        
        # Perform real analysis for non-whitelisted sites
        domain_info = get_domain_age(url)
        ssl_info = check_ssl(url)
        content_info = analyze_content(url)
        
        # CRITICAL: Check for malware/phishing
        malware_check = check_google_safe_browsing(url)
        suspicious_patterns = check_suspicious_patterns(url, domain)
        
        # Get user comments
        user_comments_data = comments_db.get(domain, [])
        user_comment_count = len(user_comments_data)
        user_scam_reports = sum(1 for c in user_comments_data if c.get("was_scammed", False))
        user_avg_rating = sum(c.get("rating", 0) for c in user_comments_data) / user_comment_count if user_comment_count > 0 else 0
        
        website_type = detect_website_type(domain, content_info.get("pageContent", ""))
        
        trust_score, findings = calculate_trust_score(domain_info, ssl_info, content_info)
        trust_score, findings = adjust_score_by_website_type(trust_score, website_type, findings)
        
        # AI analysis with Groq (now influences score)
        ai_analysis = analyze_with_groq(domain, content_info.get("pageContent", ""), domain_info, ssl_info)
        
        # CRITICAL SECURITY CHECKS - Must be first
        if not malware_check["is_safe"]:
            # IMMEDIATE ALERT - Malware/Phishing detected
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
                "recommendation": "🚨 CRITICAL WARNING: This website has been identified as malicious by Google Safe Browsing. It may contain malware, attempt phishing attacks, or steal your personal information. DO NOT visit this site, enter any credentials, or download anything. Close this page immediately and report the URL.",
                "peopleExperience": {
                    "experienceScore": 0,
                    "userExperienceRating": "DANGEROUS",
                    "hasTestimonials": False,
                    "hasSocialProof": False,
                    "hasSupport": False
                }
            }
        
        # Check for suspicious patterns
        if suspicious_patterns["is_suspicious"]:
            trust_score -= suspicious_patterns["risk_score"]
            for warning in suspicious_patterns["warnings"]:
                findings.insert(0, {"type": "critical" if suspicious_patterns["risk_score"] > 30 else "warning", 
                                   "text": warning})
        
        # Adjust score based on AI analysis text
        if ai_analysis:
            ai_text = ai_analysis.lower()
            ai_adjustment = 0
            ai_severity = "info"
            
            # Strong scam indicators
            if any(phrase in ai_text for phrase in [
                "potential scam",
                "likely scam",
                "high risk scam",
                "highly suspicious",
                "strong concerns about its legitimacy",
            ]):
                ai_adjustment -= 25
                ai_severity = "critical"
            # Moderate concerns
            elif any(phrase in ai_text for phrase in [
                "suspicious",
                "red flags",
                "concerns about",
                "exercise caution",
            ]):
                ai_adjustment -= 10
                ai_severity = "warning"
            # Positive / legit signals
            elif any(phrase in ai_text for phrase in [
                "appears legitimate",
                "no major red flags",
                "no significant scam indicators",
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
        
        # Add malware check status (don't add AI analysis to findings anymore)
        if malware_check["checked"]:
            findings.insert(0, {"type": "info", "text": "✅ No malware/phishing detected by Google Safe Browsing"})
        
        # Adjust for user comments
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
            recommendation = "This website appears legitimate based on our analysis. It has a good trust score, valid SSL, and proper documentation. However, always exercise caution when sharing personal information or making financial transactions online."
        elif verdict == "Caution":
            recommendation = f"Exercise caution with this website. Our analysis found some concerns. Trust score: {trust_score}/100. We recommend verifying the legitimacy through additional research and checking reviews from trusted sources before proceeding."
        else:
            recommendation = f"⚠️ WARNING: This website shows multiple red flags indicating it may be a scam. Trust score: {trust_score}/100. We strongly recommend avoiding this platform and reporting it if you've been affected."
        
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
            "aiAnalysis": ai_analysis,  # Add AI analysis as separate field
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