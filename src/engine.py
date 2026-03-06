from typing import List
from fastapi import Request
from src.interfaces import BaseSecurityModule
from src.modules.geoip import GeoIPValidator


class SecurityEngine:
    def __init__(self, modules: List[BaseSecurityModule]):
        self.modules = modules
        self.geoip_module = next(
            (m for m in modules if isinstance(m, GeoIPValidator)), None
        )

    def get_active_modules(self) -> List[str]:
        # Returns the class names of all enabled modules
        return [getattr(m, 'name', type(m).__name__) for m in self.modules]

    async def check_request(self, request: Request):
        for module in self.modules:
            result = await module.validate_request(request)
            
            if result["decision"] == "deny":
                return result
        
        return {"decision": "allow", "reason": "All security checks passed"}