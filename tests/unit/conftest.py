from unittest.mock import MagicMock

import pytest

from analysis.whois_check.controller import WhoisCheck
from src.analysis.ssl_tls_check.controller import SSLCheck

@pytest.fixture
def ssl_check_instance() -> SSLCheck:
    return SSLCheck()

@pytest.fixture
def mock_get_cert_details(mocker):
    """Mock cert details"""
    return mocker.patch("src.analysis.ssl_tls_check.controller._get_cert_details")

@pytest.fixture
def domain_info_check_instance() -> WhoisCheck:
    return WhoisCheck()

@pytest.fixture
def mock_whois(mocker) -> MagicMock:

    # Ważne: mockujemy `whois.whois` wewnątrz `asyncio.to_thread`
    # Ale łatwiej jest zmockować samą funkcję `whois.whois`
    return mocker.patch("whois.whois", autospec=True)