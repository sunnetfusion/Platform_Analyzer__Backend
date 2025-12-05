# main.py
from fastapi import FastAPI, HTTPException
from starlette.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

# Define the application
app = FastAPI()

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://platform-analyzer-frontend.vercel.app",
        "https://platform-analyzer-backend.onrender.com",
        "https://*.vercel.app",
        "http://localhost:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Data models
class AnalyzeRequest(BaseModel):
    url: str
    platform: Optional[str] = None

# Routes
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
        url = request.url.lower()
        
        if "youtube.com" in url or "youtu.be" in url:
            platform = "youtube"
        elif "instagram.com" in url:
            platform = "instagram"
        elif "tiktok.com" in url:
            platform = "tiktok"
        elif "twitter.com" in url or "x.com" in url:
            platform = "twitter"
        else:
            platform = request.platform or "unknown"
        
        metrics = {
            "followers": 10000,
            "engagement_rate": 4.5,
            "avg_views": 5000,
            "total_posts": 150,
            "growth_rate": 2.3
        }
        
        return {
            "status": "success",
            "platform": platform,
            "metrics": metrics,
            "message": f"Successfully analyzed {platform} platform"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
