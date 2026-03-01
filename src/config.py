import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Set

class Settings(BaseSettings):
    enable_geoip: bool = True
    geoip_default_block: bool = True
    geoip_db_path: str = "./geoip_db/GeoLite2-Country.mmdb"
    whitelisted_countries: str = "IE,GB,NG"

    @property
    def whitelisted_set(self) -> Set[str]:
        """Parses the comma-separated string into a set."""
        return {c.strip().upper() for c in self.whitelisted_countries.split(",")}

    # This tells Pydantic to check the environment first, then the .env file
    model_config = SettingsConfigDict(
        env_file=".env", 
        env_file_encoding="utf-8",
        extra="ignore" # Ignores extra variables in the .env
    )

settings = Settings()