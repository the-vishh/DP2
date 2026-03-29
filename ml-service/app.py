"""
🚀 PHISHING DETECTION ML SERVICE - FASTAPI
==========================================

Maximum quality Python backend service for ML predictions.

Performance Targets:
- Feature extraction: <50ms
- ML inference: <5ms
- Total latency: <100ms
- Accuracy: 95%+
- Throughput: 1000 req/s
"""

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, HttpUrl, validator
import time
import sys
from pathlib import Path
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Add ml-model paths
ml_model_path = Path(__file__).parent.parent / "ml-model"
sys.path.insert(0, str(ml_model_path / "deployment"))
sys.path.insert(0, str(ml_model_path / "features"))

from model_cache import ModelCache
from production_feature_extractor import ProductionFeatureExtractor

# ============================================================================
# FASTAPI APP
# ============================================================================

app = FastAPI(
    title="Phishing Detection ML Service",
    description="High-performance ML service for real-time phishing detection",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict to specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# GLOBAL INSTANCES (Initialized once at startup)
# ============================================================================

model_cache = None
feature_extractor = None
initialization_error = None


@app.on_event("startup")
async def startup_event():
    """Initialize ML models and feature extractor on startup"""
    global model_cache, feature_extractor, initialization_error

    logger.info("Starting ML Service...")

    try:
        # Initialize model cache
        logger.info("Loading ML models...")
        start = time.time()
        model_cache = ModelCache()
        load_time = (time.time() - start) * 1000
        logger.info(
            f"Models loaded in {load_time:.0f}ms: {model_cache.get_loaded_models()}"
        )

        # Initialize feature extractor
        logger.info("Initializing feature extractor...")
        start = time.time()
        feature_extractor = ProductionFeatureExtractor(timeout=3)
        init_time = (time.time() - start) * 1000
        logger.info(f"Feature extractor ready in {init_time:.0f}ms")

        if not model_cache.get_loaded_models():
            raise RuntimeError("No trained models were loaded from ml-model/models")

        initialization_error = None
        logger.info("ML Service ready!")

    except Exception as e:
        initialization_error = str(e)
        model_cache = None
        feature_extractor = None
        logger.error("ML service startup failed: %s", e)


# ============================================================================
# REQUEST/RESPONSE MODELS
# ============================================================================


class URLCheckRequest(BaseModel):
    """Request model for URL checking"""

    url: str
    sensitivity_mode: str = "balanced"  # conservative, balanced, aggressive

    @validator("url")
    def validate_url(cls, v):
        """Validate URL format"""
        if not v or len(v) < 10:
            raise ValueError("URL must be at least 10 characters")
        if len(v) > 2000:
            raise ValueError("URL too long (max 2000 characters)")
        if not any(
            v.startswith(prefix) for prefix in ["http://", "https://", "ftp://"]
        ):
            raise ValueError("URL must start with http://, https://, or ftp://")
        return v

    @validator("sensitivity_mode")
    def validate_sensitivity(cls, v):
        """Validate sensitivity mode"""
        valid_modes = ["conservative", "balanced", "aggressive"]
        if v not in valid_modes:
            raise ValueError(
                f"sensitivity_mode must be one of: {', '.join(valid_modes)}"
            )
        return v


class URLCheckResponse(BaseModel):
    """Response model for URL checking"""

    url: str
    is_phishing: bool
    confidence: float
    threat_level: str
    sensitivity_mode: str
    threshold_used: float
    details: dict
    latency_ms: float
    model_version: str
    performance_metrics: (
        dict  # Real accuracy, feature extraction time, ML inference time
    )


# ============================================================================
# ENDPOINTS
# ============================================================================


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "Phishing Detection ML Service",
        "status": "running",
        "version": "1.0.0",
        "endpoints": {"health": "/health", "predict": "/api/predict", "docs": "/docs"},
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    if model_cache is None or feature_extractor is None:
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "message": initialization_error or "ML service not initialized",
            },
        )

    return {
        "status": "healthy",
        "mode": "ml",
        "models_loaded": model_cache.get_loaded_models(),
        "feature_extractor": "ready",
        "timestamp": time.time(),
    }


@app.post("/api/predict", response_model=URLCheckResponse)
async def predict_url(request: URLCheckRequest):
    """
    Predict if URL is phishing with dynamic sensitivity thresholds

    Sensitivity Modes:
        - conservative: 0.80 threshold (only block if 80%+ confidence)
        - balanced: 0.50 threshold (default, block if 50%+ confidence)
        - aggressive: 0.30 threshold (strict, block if 30%+ confidence)

    Returns:
        - is_phishing: bool - Whether URL is phishing (based on threshold)
        - confidence: float - Model confidence (0-1)
        - threat_level: str - SAFE, LOW, MEDIUM, HIGH, CRITICAL
        - sensitivity_mode: str - Mode used for this prediction
        - threshold_used: float - Actual threshold applied
        - details: dict - Additional information
        - latency_ms: float - Processing time
        - performance_metrics: dict - Real accuracy and timing data
    """
    start_time = time.time()

    try:
        url = request.url
        sensitivity_mode = request.sensitivity_mode

        logger.info(f"Analyzing URL (mode: {sensitivity_mode}): {url[:60]}...")

        # DYNAMIC THRESHOLDS BASED ON SENSITIVITY MODE
        SENSITIVITY_THRESHOLDS = {
            "conservative": 0.80,  # Only block if 80%+ sure (fewer false positives)
            "balanced": 0.50,  # Block if 50%+ sure (balanced approach)
            "aggressive": 0.30,  # Block if 30%+ sure (catch more threats, may have false positives)
        }

        threshold = SENSITIVITY_THRESHOLDS.get(sensitivity_mode, 0.50)
        logger.info(f"   Using threshold: {threshold} for {sensitivity_mode} mode")

        if model_cache is None or feature_extractor is None:
            raise HTTPException(
                status_code=503,
                detail="ML models are not loaded. Start service with trained models only.",
            )

        # Extract features
        feature_start = time.time()
        features = feature_extractor.extract(url)
        feature_time = (time.time() - feature_start) * 1000
        logger.info(f"   Features extracted in {feature_time:.0f}ms")

        # ML prediction
        prediction_start = time.time()
        result = model_cache.predict(features)
        prediction_time = (time.time() - prediction_start) * 1000
        logger.info(f"   ML prediction in {prediction_time:.2f}ms")

        confidence = result["confidence"]

        # ✅ USE DYNAMIC THRESHOLD INSTEAD OF HARDCODED 0.5
        is_phishing = confidence >= threshold

        logger.info(
            f"   Confidence: {confidence:.3f}, Threshold: {threshold}, Phishing: {is_phishing}"
        )

        # Determine threat level (independent of threshold)
        if confidence >= 0.9:
            threat_level = "CRITICAL"
        elif confidence >= 0.7:
            threat_level = "HIGH"
        elif confidence >= 0.5:
            threat_level = "MEDIUM"
        elif confidence >= 0.3:
            threat_level = "LOW"
        else:
            threat_level = "SAFE"

        total_latency = (time.time() - start_time) * 1000

        response = URLCheckResponse(
            url=url,
            is_phishing=is_phishing,
            confidence=float(confidence),
            threat_level=threat_level,
            sensitivity_mode=sensitivity_mode,
            threshold_used=threshold,
            details={
                "prediction": result.get("prediction", 1 if is_phishing else 0),
                "feature_extraction_ms": round(feature_time, 2),
                "ml_inference_ms": round(prediction_time, 2),
                "models_used": result.get(
                    "models_used",
                    model_cache.get_loaded_models(),
                ),
                "threshold_explanation": f"{sensitivity_mode.capitalize()} mode: blocking URLs with {int(threshold*100)}%+ confidence",
            },
            latency_ms=round(total_latency, 2),
            model_version="1.0.0",
            performance_metrics={
                "total_latency_ms": round(total_latency, 2),
                "feature_extraction_ms": round(feature_time, 2),
                "ml_inference_ms": round(prediction_time, 2),
                "feature_extraction_percent": round(
                    (feature_time / total_latency) * 100, 1
                ),
                "ml_inference_percent": round(
                    (prediction_time / total_latency) * 100, 1
                ),
                "models_count": len(model_cache.get_loaded_models()),
                "meets_performance_target": total_latency < 100,  # Target: <100ms
            },
        )

        logger.info(
            f"Result: {threat_level} (confidence: {confidence:.3f}, threshold: {threshold}) "
            f"-> {'BLOCKED' if is_phishing else 'ALLOWED'} in {total_latency:.0f}ms"
        )

        return response

    except Exception as e:
        logger.error(f"Error processing URL {request.url}: {e}")
        raise HTTPException(status_code=500, detail=f"Error analyzing URL: {str(e)}")


@app.get("/api/stats")
async def get_stats():
    """Get service statistics"""
    return {
        "models": model_cache.get_loaded_models() if model_cache else [],
        "feature_extractor": "ready" if feature_extractor else "not initialized",
        "uptime": time.time(),
    }


# ============================================================================
# ERROR HANDLERS
# ============================================================================


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler"""
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500, content={"error": "Internal server error", "message": str(exc)}
    )


# ============================================================================
# RUN SERVER
# ============================================================================

if __name__ == "__main__":
    import uvicorn

    print("=" * 80)
    print("STARTING PHISHING DETECTION ML SERVICE")
    print("=" * 80)
    print("\nService Configuration:")
    print("   Host: 0.0.0.0")
    print("   Port: 8000")
    print("   Docs: http://localhost:8000/docs")
    print("   Health: http://localhost:8000/health")
    print("\nStarting server...\n")

    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8888,
        reload=False,  # Set to True for development
        log_level="info",
        access_log=True,
    )
