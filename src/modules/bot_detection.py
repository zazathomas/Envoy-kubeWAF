from fastapi import Request
import re
from src.utils import initialize_logger
from src.interfaces import BaseSecurityModule

logger = initialize_logger()

class BotDetectionValidator(BaseSecurityModule):
    def __init__(self, user_blacklisted_bots: set):
        default_bad_bots = {
            "360Spider", "80legs", "Acunetix", "AhrefsBot", "Atomic_Email_Hunter", 
            "Autoemailspider", "Baiduspider", "Barkrowler", "BlackWidow", "BLEXBot", 
            "coccocbot", "curl", "DirBuster", "DotBot", "EmailSiphon", "Exabot", 
            "Go-http-client", "java", "Jorgee", "libwww-perl", "MegaIndex", "MJ12bot", 
            "Morfeus", "Nikto", "Nmap", "PetalBot", "PHP", "python-requests", 
            "Python-urllib", "Rogerbot", "SemrushBot", "sqlmap", "Wget", "YandexBot", "ZmEu"
        }

        self.blacklist_set = default_bad_bots | user_blacklisted_bots

        if self.blacklist_set:
            pattern = "|".join(re.escape(ua) for ua in self.blacklist_set if ua)
            self.bot_pattern = re.compile(pattern, re.IGNORECASE)
        else:
            self.bot_pattern = None

    async def validate_request(self, request: Request):
        user_agent = request.headers.get("user-agent", "missing-user-agent")
        
        if user_agent == "missing-user-agent":
            logger.warning("Access Denied: Missing User Agent")
            return {"decision": "deny", "reason": "Missing User Agent"}

        if not self.bot_pattern:
            logger.info("Access Approved: No Blacklist Defined")
            return {"decision": "allow", "reason": "No blacklist defined"}

        if self.bot_pattern.search(user_agent):
            logger.warning(f"Access Denied: User-Agent '{user_agent}' is blacklisted")
            return {"decision": "deny", "reason": f"User-Agent matches a known bad bot/scraper"}

        logger.info("Access Approved: User-Agent not in blacklist")
        return {"decision": "allow", "reason": "User-Agent not in blacklist"}