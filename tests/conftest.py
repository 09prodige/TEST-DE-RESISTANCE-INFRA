"""Pytest fixtures for the RIG security scanner test suite."""

import pytest


@pytest.fixture
def sample_target():
    return "example.com"


@pytest.fixture
def sample_results():
    return {
        "target": "example.com",
        "modules": {
            "recon": {},
            "web": {},
            "vuln": {}
        }
    }


@pytest.fixture
def mock_dns_results():
    """Sample DNS resolution results for testing."""
    return {
        "A": ["93.184.216.34"],
        "MX": ["mail.example.com"],
        "NS": ["ns1.example.com", "ns2.example.com"],
        "TXT": ["v=spf1 include:_spf.example.com ~all"],
        "CNAME": [],
    }


@pytest.fixture
def mock_whois_results():
    """Sample WHOIS lookup results for testing."""
    return {
        "registrar": "Example Registrar Inc",
        "organization": "Example Organization",
        "country": "US",
        "creation_date": "1995-08-14T00:00:00",
        "expiration_date": "2025-08-13T00:00:00",
        "updated_date": "2024-01-01T00:00:00",
        "name_servers": ["ns1.example.com", "ns2.example.com"],
        "raw": None,
    }


@pytest.fixture
def mock_subdomain_results():
    """Sample subdomain enumeration results for testing."""
    return [
        {"subdomain": "www.example.com", "ip": "93.184.216.34", "source": "bruteforce"},
        {"subdomain": "mail.example.com", "ip": "93.184.216.35", "source": "crtsh"},
        {"subdomain": "api.example.com", "ip": "93.184.216.36", "source": "bruteforce"},
    ]


@pytest.fixture
def mock_portscan_results():
    """Sample port scan results for testing."""
    return [
        {"port": 22, "state": "open", "service": "ssh", "banner": "SSH-2.0-OpenSSH_8.9"},
        {"port": 80, "state": "open", "service": "http", "banner": "Apache/2.4.41"},
        {"port": 443, "state": "open", "service": "https", "banner": ""},
    ]
