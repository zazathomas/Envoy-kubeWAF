import pytest
from unittest.mock import MagicMock
import geoip2.errors
from src.modules.geoip import GeoIPValidator

# Mocking the FastAPI Request object
def create_mock_request(ip_header_value):
    request = MagicMock()
    # Mock request.headers.get("x-envoy-external-address")
    request.headers.get.side_effect = lambda key, default=None: ip_header_value if key == "x-envoy-external-address" else default
    return request

@pytest.fixture
def validator():
    # Initialize with a dummy path and whitelisted countries
    return GeoIPValidator(
        db_path="dummy.mmdb", 
        whitelisted_countries={"US", "GB"},
        default_block=True
    )

@pytest.mark.asyncio
async def test_validate_request_missing_header(validator):
    request = create_mock_request("missing-header")
    result = await validator.validate_request(request)
    
    assert result["decision"] == "deny"
    assert "Missing Client IP Header" in result["reason"]

@pytest.mark.asyncio
async def test_validate_request_private_ip(validator):
    # 192.168.x.x is a private range
    request = create_mock_request("192.168.1.1")
    result = await validator.validate_request(request)
    
    assert result["decision"] == "allow"
    assert "private ip" in result["reason"]

@pytest.mark.asyncio
async def test_validate_request_whitelisted_country(validator, mocker):
    # Mock the GeoIP Reader
    mock_reader = mocker.MagicMock()
    mock_response = mocker.MagicMock()
    mock_response.country.iso_code = "US"
    mock_reader.country.return_value = mock_response
    
    validator.reader = mock_reader
    
    request = create_mock_request("8.8.8.8")
    result = await validator.validate_request(request)
    
    assert result["decision"] == "allow"
    assert "US is authorized" in result["reason"]

@pytest.mark.asyncio
async def test_validate_request_blocked_country(validator, mocker):
    mock_reader = mocker.MagicMock()
    mock_response = mocker.MagicMock()
    mock_response.country.iso_code = "CN" # Not in {US, GB}
    mock_reader.country.return_value = mock_response
    
    validator.reader = mock_reader
    
    request = create_mock_request("1.1.1.1")
    result = await validator.validate_request(request)
    
    assert result["decision"] == "deny"
    assert "CN is not authorized" in result["reason"]

@pytest.mark.asyncio
async def test_validate_request_db_missing_default_block(validator):
    validator.reader = None # DB failed to load
    validator.default_block = True
    
    request = create_mock_request("8.8.8.8")
    result = await validator.validate_request(request)
    
    assert result["decision"] == "deny"
    assert "GeoIP Database missing" in result["reason"]

@pytest.mark.asyncio
async def test_validate_request_address_not_found_handling(validator, mocker):
    mock_reader = mocker.MagicMock()
    # Simulate IP not found in MaxMind DB
    mock_reader.country.side_effect = geoip2.errors.AddressNotFoundError("IP not found")
    
    validator.reader = mock_reader
    validator.default_block = True
    
    request = create_mock_request("1.1.1.1")
    result = await validator.validate_request(request)
    
    assert result["decision"] == "deny"
    assert "Unknown Origin Country" in result["reason"]