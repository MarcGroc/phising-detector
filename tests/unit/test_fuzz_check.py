import pytest
from pydantic import AnyHttpUrl
from src.analysis.fuzz_check.controller import FuzzDomainCheck
from src.scoring.constants import ImpactScore


@pytest.mark.asyncio
async def test_fuzz_check_highly_similar_hostname(mocker):
    """Should return high score impact, typosquattting likely"""
    # ARRANGE
    # 1. Mock brands list
    mocker.patch.object(FuzzDomainCheck, 'BRANDS', ["paypal.com", "google.com"])

    # 2. Create FuzzDomainCheck instance and test url
    checker = FuzzDomainCheck()
    suspicous_url = AnyHttpUrl("https://paypal1.com")

    # ACT
    result = await checker.run(suspicous_url)

    # ASSERT
    assert result.is_suspicious is True
    assert result.score_impact == ImpactScore.HIGH
    assert result.details.startswith(f"Hostname {suspicous_url.host} is suspiciously similar")


async def test_fuzz_check_ignore_dissimilar_hostname(mocker):
    """Should return non suspicious result"""
    # ARRANGE
    # 1. Mock brands list
    mocker.patch("utils.helpers.load_brands_list", return_value=["paypal.com", "google.com"])
    # 2. Create FuzzDomainCheck instance and test url
    checker = FuzzDomainCheck()
    safe_url = AnyHttpUrl("https://safeurl.com")

    # ACT
    result = await checker.run(safe_url)

    # ASSERT
    assert result.is_suspicious is False
    assert result.score_impact == ImpactScore.ZERO


async def test_fuzz_check_ignore_identical_hostname(mocker):
    """Should return non suspicious result, as it's not typosqyatting"""
    # ARRANGE
    # 1. Mock brands list

    mocker.patch("utils.helpers.load_brands_list", return_value=["paypal.com", "google.com"])
    # 2. Create FuzzDomainCheck instance and test url
    checker = FuzzDomainCheck()
    identical_url = AnyHttpUrl("https://paypal.com")
    # ACT
    result = await checker.run(identical_url)

    # ASSERT
    assert result.is_suspicious is False
    assert result.score_impact == ImpactScore.ZERO