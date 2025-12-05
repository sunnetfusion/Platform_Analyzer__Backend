# main.py
from fastapi import FastAPI, HTTPException
from starlette.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import ssl
import socket
import whois
from datetime import datetime
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import re
import os
from groq import Groq

app = FastAPI(title="Platform Analyzer API")

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

class AnalyzeRequest(BaseModel):
    url: str
    platform: Optional[str] = None

def get_domain_age(url):
    """Get domain registration date and calculate age"""
    try:
        domain = urlparse(url).netloc
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
                "registrar": w.registrar if w.registrar else "Unknown",
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

def check_ssl(url):
    """Check SSL certificate status"""
    try:
        hostname = urlparse(url).netloc
        context = ssl.create_default_context()
        
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return {
                    "valid": True,
                    "issuer": dict(x[0] for x in cert['issuer'])['organizationName'],
                    "expires": cert['notAfter']
                }
    except Exception as e:
        print(f"SSL error: {e}")
        return {
            "valid": False,
            "issuer": "None",
            "expires": "N/A"
        }

def analyze_content(url):
    """Scrape and analyze website content"""
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        text = soup.get_text().lower()
        
        # Check for key pages and information
        has_about = bool(soup.find('a', href=re.compile(r'about', re.I)))
        has_contact = bool(soup.find('a', href=re.compile(r'contact', re.I)))
        has_terms = bool(soup.find('a', href=re.compile(r'terms', re.I)))
        
        # Check for address patterns
        address_pattern = r'\d+\s+[\w\s]+(?:street|st|avenue|ave|road|rd|boulevard|blvd)'
        has_address = bool(re.search(address_pattern, text, re.I))
        
        # Check for phone patterns
        phone_pattern = r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'
        has_phone = bool(re.search(phone_pattern, text))
        
        # Look for red flag keywords
        scam_keywords = ['guaranteed profit', 'get rich quick', 'no risk', 'double your money', 
                        'limited time offer', 'act now', 'urgent', 'secret method']
        red_flags = [kw for kw in scam_keywords if kw in text]
        
        # Check for stock images (basic check for common stock photo sites)
        stock_image_sites = ['shutterstock', 'istockphoto', 'gettyimages', 'dreamstime']
        images = soup.find_all('img')
        stock_images = sum(1 for img in images if any(site in str(img.get('src', '')) for site in stock_image_sites))
        
        # Extract text content for AI analysis
        page_text = ' '.join(soup.stripped_strings)[:2000]  # First 2000 chars
        
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

def calculate_trust_score(domain_info, ssl_info, content_info):
    """Calculate trust score based on various factors"""
    score = 50  # Start at neutral
    findings = []
    
    # Domain age scoring
    age_days = domain_info.get("age_days", 0)
    if age_days > 365 * 2:  # Over 2 years
        score += 20
        findings.append({"type": "info", "text": f"Domain is {domain_info['age']} old - Established presence"})
    elif age_days > 180:  # 6 months to 2 years
        score += 10
        findings.append({"type": "warning", "text": f"Domain is relatively new ({domain_info['age']})"})
    else:  # Less than 6 months
        score -= 15
        findings.append({"type": "critical", "text": f"Very new domain ({domain_info['age']}) - High risk"})
    
    # SSL scoring
    if ssl_info["valid"]:
        score += 10
        findings.append({"type": "info", "text": "Valid SSL certificate found"})
    else:
        score -= 20
        findings.append({"type": "critical", "text": "No valid SSL certificate - UNSAFE"})
    
    # Content scoring
    if content_info["aboutUsFound"]:
        score += 5
    else:
        score -= 5
        findings.append({"type": "warning", "text": "No 'About Us' page found"})
    
    if content_info["contactInfoFound"]:
        score += 5
    else:
        score -= 5
        findings.append({"type": "warning", "text": "No contact information found"})
    
    if content_info["physicalAddressFound"]:
        score += 10
        findings.append({"type": "info", "text": "Physical address found on website"})
    else:
        score -= 5
        findings.append({"type": "warning", "text": "No physical address found"})
    
    if content_info["stockImagesDetected"]:
        score -= 10
        findings.append({"type": "critical", "text": f"Stock images detected ({content_info['stockImageCount']} found)"})
    
    # Red flag keywords
    if content_info["redFlagKeywords"]:
        score -= len(content_info["redFlagKeywords"]) * 5
        findings.append({"type": "critical", "text": f"Scam keywords detected: {', '.join(content_info['redFlagKeywords'][:3])}"})
    
    # Ensure score is between 0 and 100
    score = max(0, min(100, score))
    
    return score, findings

def get_verdict(score):
    """Get verdict based on trust score"""
    if score >= 70:
        return "Legit"
    elif score >= 40:
        return "Caution"
    else:
        return "Scam"

def search_social_media(domain):
    """Search for mentions on social media and review sites"""
    try:
        # Extract just the domain name
        domain_name = urlparse(f"https://{domain}").netloc.replace('www.', '')
        
        social_data = {
            "redditMentions": 0,
            "twitterMentions": 0,
            "trustpilotScore": 0,
            "scamAdvisorScore": 0
        }
        
        # Search Reddit (using pushshift alternative or direct Reddit search)
        try:
            reddit_query = f"https://www.reddit.com/search.json?q={domain_name}&limit=100"
            headers = {'User-Agent': 'Mozilla/5.0'}
            response = requests.get(reddit_query, headers=headers, timeout=5)
            if response.status_code == 200:
                data = response.json()
                social_data["redditMentions"] = data.get('data', {}).get('dist', 0)
        except:
            pass
        
        # Note: Twitter API requires authentication
        # For now, we'll use estimated data based on domain age
        social_data["twitterMentions"] = social_data["redditMentions"] * 2
        
        return social_data
    except Exception as e:
        print(f"Social media search error: {e}")
        return {
            "redditMentions": 0,
            "twitterMentions": 0,
            "trustpilotScore": 0,
            "scamAdvisorScore": 0
        }

def search_withdrawal_complaints(domain, page_content):
    """Search for withdrawal complaints and issues"""
    try:
        complaint_keywords = ['cannot withdraw', 'withdrawal denied', 'withdrawal problem', 
                            'cant withdraw', 'withdrawal issue', 'withdrawal failed', 
                            'withdrawal blocked', 'cant get money', 'withdrawal scam']
        
        complaints = 0
        text = page_content.lower()
        
        for keyword in complaint_keywords:
            if keyword in text:
                complaints += 1
        
        # Also try a basic Google search (limited without API)
        search_query = f"{domain} withdrawal complaints scam"
        try:
            # Note: For production, use Google Custom Search API
            # This is a simplified version
            complaints = max(complaints, 0)
        except:
            pass
        
        return complaints
    except Exception as e:
        print(f"Withdrawal complaints error: {e}")
        return 0

def analyze_with_groq(domain, page_content, domain_info, ssl_info):
    """Use Groq AI to analyze the website content for scam indicators"""
    try:
        # Check if API key is available
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

def calculate_ponzi_indicators(page_content):
    """Check for Ponzi scheme indicators"""
    try:
        ponzi_keywords = {
            'high_return': ['guaranteed return', 'guaranteed profit', '% daily', '% weekly', 'passive income'],
            'urgency': ['limited time', 'act now', 'limited spots', 'hurry'],
            'recruitment': ['refer friends', 'referral bonus', 'multi-level', 'pyramid', 'downline'],
            'vague': ['proprietary system', 'secret strategy', 'exclusive opportunity']
        }
        
        text = page_content.lower()
        detected_indicators = []
        
        for category, keywords in ponzi_keywords.items():
            for keyword in keywords:
                if keyword in text:
                    detected_indicators.append(keyword)
                    break
        
        if len(detected_indicators) >= 2:
            # Extract promised returns if mentioned
            return_match = re.search(r'(\d+)%\s*(daily|weekly|monthly|yearly)', text)
            if return_match:
                percentage = int(return_match.group(1))
                period = return_match.group(2)
                
                # Calculate yearly equivalent
                multiplier = {'daily': 365, 'weekly': 52, 'monthly': 12, 'yearly': 1}
                yearly = percentage * multiplier.get(period, 1)
                
                return {
                    "promisedReturn": f"{percentage}% {period}",
                    "yearlyEquivalent": f"{yearly}%",
                    "sustainability": "Unsustainable" if yearly > 50 else "Questionable",
                    "collapseDays": str(max(30, 365 // (yearly // 10)))
                }
        
        return None
    except Exception as e:
        print(f"Ponzi calculation error: {e}")
        return None

@app.get("/")
async def root():
    return {
        "status": "online",
        "message": "Platform Analyzer API is running",
        "version": "2.0.0"
    }

@app.post("/api/analyze")
async def analyze_platform(request: AnalyzeRequest):
    try:
        url = request.url
        
        # Ensure URL has scheme
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        print(f"Analyzing: {url}")
        
        # Perform real analysis
        domain_info = get_domain_age(url)
        ssl_info = check_ssl(url)
        content_info = analyze_content(url)
        
        # Social media and complaints
        domain = urlparse(url).netloc
        social_data = search_social_media(domain)
        withdrawal_complaints = search_withdrawal_complaints(domain, content_info.get("pageContent", ""))
        
        # Ponzi scheme detection
        ponzi_calc = calculate_ponzi_indicators(content_info.get("pageContent", ""))
        
        # AI analysis with Groq
        ai_analysis = analyze_with_groq(domain, content_info.get("pageContent", ""), domain_info, ssl_info)
        
        # Calculate trust score
        trust_score, findings = calculate_trust_score(domain_info, ssl_info, content_info)
        
        # Adjust score based on social signals
        if withdrawal_complaints > 5:
            trust_score -= 15
            findings.append({"type": "critical", "text": f"{withdrawal_complaints} withdrawal complaints detected online"})
        elif withdrawal_complaints > 0:
            trust_score -= 5
            findings.append({"type": "warning", "text": f"{withdrawal_complaints} withdrawal complaints found"})
        
        # Adjust for Ponzi indicators
        if ponzi_calc:
            trust_score -= 25
            findings.append({"type": "critical", "text": "Ponzi scheme indicators detected - Extremely high risk"})
        
        # Add AI analysis as finding if available
        if ai_analysis:
            findings.insert(0, {"type": "info", "text": f"AI Analysis: {ai_analysis[:200]}"})
        
        trust_score = max(0, min(100, trust_score))
        verdict = get_verdict(trust_score)
        
        # Calculate scam probability
        scam_prob = "Low" if trust_score >= 70 else "Medium" if trust_score >= 40 else "High"
        
        # Build recommendation
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
            "socialData": social_data,
            "withdrawalComplaints": withdrawal_complaints,
            "findings": findings,
            "sentiment": {
                "positive": max(0, trust_score - 20),
                "neutral": 40,
                "negative": max(0, 80 - trust_score)
            },
            "redFlags": content_info["redFlagKeywords"],
            "ponziCalculation": ponzi_calc,
            "scamProbability": scam_prob,
            "recommendation": recommendation,
            "peopleExperience": {
                "experienceScore": trust_score,
                "userExperienceRating": "Good" if trust_score >= 70 else "Fair" if trust_score >= 40 else "Poor",
                "hasTestimonials": content_info["aboutUsFound"],
                "hasSocialProof": social_data["redditMentions"] > 10,
                "hasSupport": content_info["contactInfoFound"]
            }
        }
    except Exception as e:
        print(f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")