from fastapi import FastAPI, Header
from contextlib import asynccontextmanager
import threading

from config import settings
from utils import initialize_logger
from modules.geoip import GeoIPValidator


logger = initialize_logger()
# Initialize with current environment values
geoip_service = GeoIPValidator(
    db_path=settings.geoip_db_path,
    whitelisted_countries=settings.whitelisted_set,
    default_block=settings.geoip_default_block
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Only load if the environment variable says so
    if settings.enable_geoip:
        geoip_service.load()
        # Start background watcher thread
        thread = threading.Thread(target=geoip_service.watch_file, daemon=True)
        thread.start()
        logger.info(f"GeoIP Service enabled. Whitelist: {settings.whitelisted_countries}")
    yield
    geoip_service.close()

app = FastAPI(lifespan=lifespan)

@app.get("/authz")
async def authorize(x_forwarded_for: str = Header(None)):
    if not settings.enable_geoip:
        return {"decision": "allow", "reason": "geoip validation disabled"}
    
    client_ip = x_forwarded_for.split(",")[0].strip()
    return geoip_service.validate_ip(client_ip)