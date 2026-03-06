from fastapi import FastAPI, HTTPException, Request
from contextlib import asynccontextmanager
import threading

from src.config import settings
from src.utils import initialize_logger
from src.modules.geoip import GeoIPValidator
from src.modules.bot_detection import BotDetectionValidator
from src.engine import SecurityEngine


logger = initialize_logger()

def setup_modules():
    active_modules = []

    if settings.enable_geoip:
        geoip_instance = GeoIPValidator(
                db_path=settings.geoip_db_path,
                whitelisted_countries=settings.whitelisted_set,
                default_block=settings.geoip_default_block,
                reload_interval=3600
            )
        active_modules.append(geoip_instance)
        logger.info("🛡️  GeoIP Module Enabled")

    if settings.enable_bot_detection:
        active_modules.append(
            BotDetectionValidator(user_blacklisted_bots=settings.bot_user_agents_set)
        )
        logger.info("🤖 Bot Detection Module Enabled")

    return SecurityEngine(modules=active_modules)

# Initialize the engine
security_engine = setup_modules()


@asynccontextmanager
async def lifespan(app: FastAPI):
    geoip = security_engine.geoip_module
    if settings.enable_geoip:
        if geoip:
            logger.info("Starting GeoIP background watcher...")
            geoip.load()
            thread = threading.Thread(target=geoip.watch_file, daemon=True)
            thread.start()
    yield
    if geoip and hasattr(geoip, 'close'):
        logger.info("Closing GeoIP resources...")
        geoip.close()

app = FastAPI(lifespan=lifespan)

@app.get("/")
async def authorize(request: Request):
    security_result = await security_engine.check_request(request)
    
    if security_result["decision"] == "deny":
        raise HTTPException(
            detail=f"Access Denied: {security_result['reason']}", 
            status_code=403
        )
    return {"decision": "allow", "reason": "All Security Checks Passed"}


@app.get("/health")
async def security_status():
    active = security_engine.get_active_modules()
    
    return {
        "status": "healthy" if active else "degraded",
        "total_modules": len(active),
        "active_modules": active,
        "config": {
            "geoip_enabled": settings.whitelisted_set,
            "bot_detection_enabled": settings.user_blacklisted_bots
        }
    }


@app.get("/captures")
async def captures(request: Request):
    return {
        "headers": request.headers,
        "body": request.body,
        "method": request.method,
    }
