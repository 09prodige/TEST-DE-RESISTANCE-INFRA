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
