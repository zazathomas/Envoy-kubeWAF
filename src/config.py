from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Set

class Settings(BaseSettings):
    enable_geoip: bool = True
    enable_bot_detection: bool = True
    geoip_default_block: bool = True
    geoip_db_path: str = "./geoip_db/GeoLite2-Country.mmdb"
    whitelisted_countries: str = "IE,GB,NG"
    log_level: str = "INFO"
    user_blacklisted_bots: str = "Googlebot,Bingbot,Slurp"

    @property
    def whitelisted_set(self) -> Set[str]:
        """Parses the comma-separated string into a set of country codes."""
        return {c.strip().upper() for c in self.whitelisted_countries.split(",") if c.strip()}
    
    @property
    def bot_user_agents_set(self) -> Set[str]:
        """Parses the comma-separated string into a set of User-Agent fragments."""
        return {ua.strip() for ua in self.user_blacklisted_bots.split(",") if ua.strip()}

    # This tells Pydantic to check the environment first, then the .env file
    model_config = SettingsConfigDict(
        env_file=".env", 
        env_file_encoding="utf-8",
        extra="ignore" # Ignores extra variables in the .env
    )

settings = Settings()