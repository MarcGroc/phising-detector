import pytest

from src.analysis.ssl_tls_check.controller import SSLCheck

@pytest.fixture
def ssl_check_instance() -> SSLCheck:
    return SSLCheck()

@pytest.fixture
def mock_get_cert_details(mocker):
    """Mock cert details"""
    return mocker.patch("src.analysis.ssl_tls_check.controller._get_cert_details")
