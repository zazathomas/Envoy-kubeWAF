from fastapi import Request
from typing import Dict

class BaseSecurityModule:
    """
    Abstract base class for all security modules.
    """

    async def validate_request(self, request: Request) -> Dict:
        """
        Validates a request against the module's rules.

        Args:
            request: A dictionary containing request information (headers, body, etc.).

        Returns:
            A dictionary containing the decision ("allow" or "deny"),
            a reason for the decision, and any relevant module-specific data.
            Example: {"decision": "deny", "reason": "GeoIP block", "ruleId": "GEO-123"}
        """
        raise NotImplementedError("Subclasses must implement validate_request()")