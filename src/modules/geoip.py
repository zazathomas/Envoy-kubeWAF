import os
import time
import geoip2.database
import geoip2.errors
import ipaddress
from fastapi import HTTPException, status
from utils import initialize_logger

logger = initialize_logger()

class GeoIPValidator:
    def __init__(self, db_path: str, whitelisted_countries: set, default_block: bool = True):
        self.db_path = db_path
        self.whitelisted_countries = whitelisted_countries
        self.default_block = default_block
        self.reader = None
        self.last_mtime = 0

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

    def watch_file(self, interval=3600):
        """Background loop to check for file updates every hour."""
        while True:
            self.load()
            time.sleep(interval)

    def close(self):
        if self.reader:
            self.reader.close()

    def validate_ip(self, ip_string: str):
        if not self.reader:
            if self.default_block:
                raise HTTPException(status_code=500, detail="GeoIP Service Unavailable")
            return {"decision": "allow", "reason": "database missing"}

        try:
            ip_obj = ipaddress.ip_address(ip_string)
            if ip_obj.is_private:
                return {"decision": "allow", "reason": "private ip"}

            response = self.reader.country(ip_string)
            country_code = response.country.iso_code

            if country_code in self.whitelisted_countries:
                return {"decision": "allow", "country": country_code}
            
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, 
                detail=f"Country {country_code} not authorized"
            )

        except geoip2.errors.AddressNotFoundError:
            if self.default_block:
                raise HTTPException(status_code=403, detail="IP location unknown")
            return {"decision": "allow", "reason": "default allow on unknown"}