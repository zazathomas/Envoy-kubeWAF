from fastapi import FastAPI, Header, HTTPException
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
    default_block=settings.geoip_default_block,
    reload_interval=3600
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    if settings.enable_geoip:
        geoip_service.load()
        thread = threading.Thread(target=geoip_service.watch_file, daemon=True)
        thread.start()
        logger.info(f"GeoIP Service enabled. Whitelist: {settings.whitelisted_countries}")
    yield
    geoip_service.close()

app = FastAPI(lifespan=lifespan)

@app.get("/")
async def authorize(x_forwarded_for: str = Header(None)):
    if not settings.enable_geoip:
        return {"decision": "allow", "reason": "geoip validation disabled"}

    if x_forwarded_for:
        client_ip = x_forwarded_for.split(",")[0].strip()
        return geoip_service.validate_ip(client_ip)
    else:
        logger.error("Client IP header not sent by Envoy")
        raise HTTPException(status_code=403,
                            detail="Client IP header missing")
