# main.py
from fastapi import FastAPI, HTTPException
from starlette.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

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

@app.get("/")
async def root():
    return {
        "status": "online",
        "message": "Platform Analyzer API is running",
        "version": "1.0.0"
    }

@app.post("/api/analyze")
async def analyze_platform(request: AnalyzeRequest):
    try:
        url = request.url
        
        return {
            "url": url,
            "trustScore": 75,
            "verdict": "Caution",
            "domainAge": "2 years",
            "domainRegistered": "2022-11-15",
            "sslStatus": "Valid SSL Certificate",
            "serverLocation": "United States",
            "whoisData": {
                "registrar": "GoDaddy",
                "owner": "Private Registration",
                "email": "contact@privacy.com",
                "lastUpdated": "2024-01-15"
            },
            "contentAnalysis": {
                "aboutUsFound": True,
                "termsOfServiceFound": True,
                "contactInfoFound": False,
                "physicalAddressFound": False,
                "teamPhotosAnalyzed": True,
                "stockImagesDetected": True
            },
            "socialData": {
                "redditMentions": 15,
                "twitterMentions": 42,
                "trustpilotScore": 3.2,
                "scamAdvisorScore": 65
            },
            "withdrawalComplaints": 8,
            "findings": [
                {"type": "warning", "text": "Domain is relatively new (2 years old)"},
                {"type": "critical", "text": "Stock images detected in team section"},
                {"type": "warning", "text": "Multiple withdrawal complaints found online"},
                {"type": "info", "text": "Valid SSL certificate present"}
            ],
            "sentiment": {"positive": 30, "neutral": 40, "negative": 30},
            "redFlags": ["Recent domain registration", "Stock images used", "Withdrawal complaints"],
            "ponziCalculation": {
                "promisedReturn": "20%",
                "yearlyEquivalent": "240%",
                "sustainability": "Unsustainable",
                "collapseDays": "180"
            },
            "scamProbability": "Medium",
            "recommendation": "Exercise caution. While the platform has some legitimate features like SSL certification, there are concerning red flags including stock images in team photos and withdrawal complaints.",
            "peopleExperience": {
                "experienceScore": 65,
                "userExperienceRating": "Fair",
                "hasTestimonials": True,
                "hasSocialProof": False,
                "hasSupport": True
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))