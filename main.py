# main.py

# 1. IMPORT NECESSARY LIBRARIES
from fastapi import FastAPI, HTTPException
from starlette.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

# 2. DEFINE THE APPLICATION OBJECT
app = FastAPI(title="Platform Analyzer API")

# 3. CONFIGURE MIDDLEWARE
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

# 4. DEFINE DATA MODELS
class AnalyzeRequest(BaseModel):
    url: str
    platform: Optional[str] = None

class AnalyzeResponse(BaseModel):
    status: str
    platform: str
    metrics: dict
    message: str

# 5. DEFINE ROUTES

@app.get("/")
async def root():
    """Root endpoint - health check"""
    return {
        "status": "online",
        "message": "Platform Analyzer API is running",
        "version": "1.0.0"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}

@app.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze_platform(request: AnalyzeRequest):
    """
    Analyze a platform URL and return metrics
    """
    try:
        # Extract platform from URL if not provided
        url = request.url.lower()
        
        if not request.platform:
            if "youtube.com" in url or "youtu.be" in url:
                platform = "youtube"
            elif "instagram.com" in url:
                platform = "instagram"
            elif "tiktok.com" in url:
                platform = "tiktok"
            elif "twitter.com" in url or "x.com" in url:
                platform = "twitter"
            else:
                platform = "unknown"
        else:
            platform = request.platform
        
        # TODO: Implement actual platform analysis logic here
        # For now, return mock data
        metrics = {
            "followers": 10000,
            "engagement_rate": 4.5,
            "avg_views": 5000,
            "total_posts": 150,
            "growth_rate": 2.3
        }
        
        return AnalyzeResponse(
            status="success",
            platform=platform,
            metrics=metrics,
            message=f"Successfully analyzed {platform} platform"
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(e)}"
        )

@app.get("/api/platforms")
async def get_supported_platforms():
    """Get list of supported platforms"""
    return {
        "platforms": [
            "youtube",
            "instagram",
            "tiktok",
            "twitter"
        ]
    }

# 6. OPTIONAL: Add startup/shutdown events
@app.on_event("startup")
async def startup_event():
    print("🚀 Platform Analyzer API starting up...")

@app.on_event("shutdown")
async def shutdown_event():
    print("👋 Platform Analyzer API shutting down...")

# This allows running with: python main.py (for local development)
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
