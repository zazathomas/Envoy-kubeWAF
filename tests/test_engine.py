import pytest
from unittest.mock import AsyncMock, MagicMock
from src.engine import SecurityEngine
from src.interfaces import BaseSecurityModule

# A Mock Module to simulate different security behaviors
class MockModule(BaseSecurityModule):
    def __init__(self, decision: str, reason: str, name: str = None):
        self.decision = decision
        self.reason = reason
        if name:
            self.name = name # Set an instance-specific name

    async def validate_request(self, request):
        return {"decision": self.decision, "reason": self.reason}

@pytest.mark.asyncio
async def test_engine_allows_when_all_pass():
    # Setup: Two modules that both allow
    mod1 = MockModule("allow", "Pass 1")
    mod2 = MockModule("allow", "Pass 2")
    engine = SecurityEngine(modules=[mod1, mod2])
    
    request = MagicMock()
    result = await engine.check_request(request)
    
    assert result["decision"] == "allow"
    assert result["reason"] == "All security checks passed"

@pytest.mark.asyncio
async def test_engine_short_circuits_on_deny():
    # Setup: First module denies, second should never be called
    mod1 = MockModule("deny", "Blocked by Mod 1")
    mod2 = AsyncMock(spec=BaseSecurityModule) # If called, this is a failure
    
    engine = SecurityEngine(modules=[mod1, mod2])
    
    request = MagicMock()
    result = await engine.check_request(request)
    
    # Assertions
    assert result["decision"] == "deny"
    assert result["reason"] == "Blocked by Mod 1"
    # Verify the second module was never even touched
    mod2.validate_request.assert_not_called()

@pytest.mark.asyncio
async def test_engine_fails_on_second_module():
    # Setup: First passes, second denies
    mod1 = MockModule("allow", "Pass 1")
    mod2 = MockModule("deny", "Blocked by Mod 2")
    
    engine = SecurityEngine(modules=[mod1, mod2])
    
    request = MagicMock()
    result = await engine.check_request(request)
    
    assert result["decision"] == "deny"
    assert result["reason"] == "Blocked by Mod 2"

def test_get_active_modules():
    # Setup: Check if naming logic works
    mod1 = MockModule("allow", "ok", name="GeoIPValidator")
    mod2 = MockModule("allow", "ok", name="BotValidator")
    
    engine = SecurityEngine(modules=[mod1, mod2])
    active = engine.get_active_modules()
    
    assert active == ["GeoIPValidator", "BotValidator"]
    assert len(active) == 2

@pytest.mark.asyncio
async def test_engine_with_no_modules():
    # Setup: Empty list should allow by default
    engine = SecurityEngine(modules=[])
    
    request = MagicMock()
    result = await engine.check_request(request)
    
    assert result["decision"] == "allow"