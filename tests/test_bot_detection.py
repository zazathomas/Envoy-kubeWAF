import pytest
from unittest.mock import MagicMock
from src.modules.bot_detection import BotDetectionValidator

# Helper to create mock FastAPI requests
def create_mock_request(ua_value):
    request = MagicMock()
    # Mock request.headers.get("user-agent")
    request.headers.get.side_effect = lambda key, default=None: ua_value if key == "user-agent" else default
    return request

@pytest.fixture
def validator():
    # Setup with one custom bad bot
    return BotDetectionValidator(user_blacklisted_bots={"CustomBadBot"})

@pytest.mark.asyncio
async def test_block_default_bad_bot(validator):
    # 'sqlmap' is in your default list
    request = create_mock_request("sqlmap/1.4.11#stable (http://sqlmap.org)")
    result = await validator.validate_request(request)
    
    assert result["decision"] == "deny"
    assert "known bad bot" in result["reason"]

@pytest.mark.asyncio
async def test_block_custom_bad_bot(validator):
    # 'CustomBadBot' was passed into __init__
    request = create_mock_request("Mozilla/5.0 CustomBadBot/1.0")
    result = await validator.validate_request(request)
    
    assert result["decision"] == "deny"
    assert "known bad bot" in result["reason"]

@pytest.mark.asyncio
async def test_allow_normal_browser(validator):
    # A standard Chrome user agent should pass
    chrome_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    request = create_mock_request(chrome_ua)
    result = await validator.validate_request(request)
    
    assert result["decision"] == "allow"
    assert "not in blacklist" in result["reason"]

@pytest.mark.asyncio
async def test_deny_missing_user_agent(validator):
    # Test the fallback "missing-user-agent" logic
    request = create_mock_request("missing-user-agent")
    result = await validator.validate_request(request)
    
    assert result["decision"] == "deny"
    assert "Missing User Agent" in result["reason"]

@pytest.mark.asyncio
async def test_case_insensitivity(validator):
    # Ensure 'SQLMAP' (uppercase) is still blocked
    request = create_mock_request("SQLMAP")
    result = await validator.validate_request(request)
    
    assert result["decision"] == "deny"

@pytest.mark.asyncio
async def test_empty_blacklist_allows_all():
    # Test behavior when no bots are provided and default list is somehow empty
    with pytest.MonkeyPatch.context() as m:
        # Mocking an empty pattern scenario
        v = BotDetectionValidator(user_blacklisted_bots=set())
        v.bot_pattern = None 
        
        request = create_mock_request("AnyBot")
        result = await v.validate_request(request)
        assert result["decision"] == "allow"