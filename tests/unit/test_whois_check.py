from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock

from pydantic import AnyHttpUrl

from src.scoring.constants import ImpactScore
from src.analysis.whois_check.controller import WhoisCheck


async def test_domain_check_very_young_domain(domain_info_check_instance: WhoisCheck, mock_whois: MagicMock):
    # ARRANGE
    url = AnyHttpUrl("https://very-young-domain.com")
    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)

    mock_whois_response = MagicMock()
    mock_whois_response.creation_date = thirty_days_ago
    mock_whois_response.get.return_value = "John Doe"  # Brak słów kluczowych privacy

    mock_whois.return_value = mock_whois_response

    # ACT
    result = await domain_info_check_instance.run(url)

    # ASSERT
    assert result.is_suspicious is True
    assert result.score_impact >= ImpactScore.HIGH
    assert "is very young" in result.details
    mock_whois.assert_called_once_with("very-young-domain.com")


async def test_domain_check_with_privacy_protection(domain_info_check_instance: WhoisCheck,
                                                    mock_whois: MagicMock):
    # ARRANGE
    url = AnyHttpUrl("https://private-domain.com")
    two_years_ago = datetime.now(timezone.utc) - timedelta(days=730)

    mock_whois_response = MagicMock()
    mock_whois_response.creation_date = two_years_ago
    # Kluczowy element: nazwa rejestrującego zawiera słowo "privacy"
    mock_whois_response.get.return_value = "Domains By Proxy, LLC - Domain Privacy"

    mock_whois.return_value = mock_whois_response

    # ACT
    result = await domain_info_check_instance.run(url)

    # ASSERT
    assert result.is_suspicious is True
    assert result.score_impact >= ImpactScore.MEDIUM
    assert "Registrant information is hidden" in result.details


async def test_domain_check_whois_fails(domain_info_check_instance: WhoisCheck, mock_whois: MagicMock):

    # ARRANGE
    url = AnyHttpUrl("https://failing-whois.com")
    # Konfigurujemy mocka, aby rzucał wyjątkiem przy wywołaniu
    mock_whois.side_effect = Exception("WHOIS server timeout")

    # ACT
    result = await domain_info_check_instance.run(url)

    # ASSERT
    assert result.is_suspicious is False  # Błąd lookupu to nie jest sygnał phishingu
    assert result.score_impact == ImpactScore.NO_HOSTNAME  # lub inna stała błędu
    assert "Whois check for failing-whois.com failed" in result.details


async def test_domain_check_happy_path(domain_info_check_instance: WhoisCheck, mock_whois: MagicMock):

    # ARRANGE
    url = AnyHttpUrl("https://legit-and-old.com")
    five_years_ago = datetime.now(timezone.utc) - timedelta(days=5 * 365)

    mock_whois_response = MagicMock()
    mock_whois_response.creation_date = five_years_ago
    mock_whois_response.get.return_value = "Legitimate Company Inc."

    mock_whois.return_value = mock_whois_response

    # ACT
    result = await domain_info_check_instance.run(url)

    # ASSERT
    assert result.is_suspicious is False
    assert result.score_impact == ImpactScore.ZERO
    assert result.details == "Domain info appears normal."


async def test_get_creation_date_handles_list(domain_info_check_instance: WhoisCheck):

    # ARRANGE
    now = datetime.now()
    mock_domain_info = MagicMock()
    mock_domain_info.creation_date = [now, now - timedelta(days=1)]

    # ACT
    result_date = domain_info_check_instance._get_creation_date(mock_domain_info)

    # ASSERT
    assert result_date is not None
    assert result_date.tzinfo is not None  # Sprawdza, czy jest "świadoma"
    assert result_date == now.replace(tzinfo=timezone.utc)