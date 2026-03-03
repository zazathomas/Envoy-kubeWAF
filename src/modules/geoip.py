import os
import time
import geoip2.database
import geoip2.errors
import ipaddress
from fastapi import HTTPException, status
from utils import initialize_logger

logger = initialize_logger()

class GeoIPValidator:
    def __init__(self, db_path: str, whitelisted_countries: set, reload_interval: int = 3600, default_block: bool = True):
        self.db_path = db_path
        self.whitelisted_countries = whitelisted_countries
        self.default_block = default_block
        self.reader = None
        self.last_mtime = 0
        self.reload_interval = reload_interval

    def load(self):
        """Initializes the reader."""
        try:
            current_mtime = os.path.getmtime(self.db_path)
            if current_mtime > self.last_mtime:
                # Open a new reader and swap
                new_reader = geoip2.database.Reader(self.db_path)
                old_reader = self.reader
                self.reader = new_reader
                self.last_mtime = current_mtime
                
                if old_reader:
                    old_reader.close()
                logger.info(f"Successfully loaded GeoIP DB (mtime: {self.last_mtime})")
        except Exception as e:
            logger.error(f"Error loading GeoIP DB: {e}")

    def watch_file(self):
        """Background loop to check for file updates every hour."""
        while True:
            self.load()
            time.sleep(self.reload_interval)

    def close(self):
        if self.reader:
            self.reader.close()

    def validate_ip(self, ip_string: str):
        if not self.reader:
            if self.default_block:
                logger.error("[DEFAULT_BLOCK] GeoIP Database missing")
                raise HTTPException(status_code=403, detail="[DEFAULT_BLOCK] GeoIP Database missing")
            logger.warning("[DEFAULT_ALLOW] GeoIP Database missing")
            return {"decision": "allow", "reason": "[DEFAULT_ALLOW] GeoIP Database missing"}


        try:
            ip_obj = ipaddress.ip_address(ip_string)
            if ip_obj.is_private:
                logger.info(f"Access Approved: Client Private IP {ip_string} Detected")

                return {"decision": "allow", "reason": "private ip"}

            response = self.reader.country(ip_string)
            country_code = response.country.iso_code

            if country_code in self.whitelisted_countries:
                logger.info(f"Access Approved: Client IP {ip_string} is whitelisted")
                return {"decision": "allow", "country": country_code}
            
            logger.info(f"Access Denied: Client IP {ip_string} is not whitelisted")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, 
                detail=f"Country {country_code} not authorized"
            )

        except geoip2.errors.AddressNotFoundError:
            if self.default_block:
                logger.info(f"Access Denied: Origin Country Client IP {ip_string} not found")
                raise HTTPException(status_code=403, detail="IP location unknown")
            logger.warning(f"[DEFAULT_ALLOW] Access Approved: Unknown Origin Country Client IP {ip_string}")