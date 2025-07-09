from datetime import datetime, timezone, timedelta
from pydantic import AnyHttpUrl
from src.analysis.ssl_tls_check.controller import SSLCheck

URL_HTTP = AnyHttpUrl("http://nohttp.com/")
URL_HTTPS = AnyHttpUrl("https://nohttp.com/")


async def test_ssl_check_no_https(ssl_check_instance: SSLCheck):
    """Mark as suspicious when no https"""
    # 1. ACT
    result = await ssl_check_instance.run(URL_HTTP)
    # 2. ASSERTS
    assert result.is_suspicious is True
    assert result.score_impact > 0
    assert result.details == "Site without HTTPS"


async def test_ssl_check_fails_to_get_cert(ssl_check_instance: SSLCheck, mock_get_cert_details):
    """Should return error if unable to gey cert"""

    # 1. Mock error
    mock_get_cert_details.return_value = None
    # 2. ACT
    result = await ssl_check_instance.run(URL_HTTPS)
    # 3. ASSERT
    assert result.is_suspicious is True
    assert "Failed to retrieve SSL certificate after multiple attempts." in result.details
    mock_get_cert_details.assert_awaited_once_with(URL_HTTPS)


async def test_ssl_validate_datetime(ssl_check_instance: SSLCheck, mock_get_cert_details):
    """Should validate certificate expiration"""
    # 1. ARRANGE
    url = AnyHttpUrl(URL_HTTPS)

    # Yesterday date and 1 year prior, certs are valid for 3 months to 1 year
    yesterday_date = datetime.now(timezone.utc) - timedelta(days=1)
    mock_cert = {
        'notBefore': (yesterday_date - timedelta(days=365)).strftime('%b %d %H:%M:%S %Y GMT'),
        'notAfter': yesterday_date.strftime('%b %d %H:%M:%S %Y GMT'),
        'subject': ((('commonName', 'expired.com'),),),
        'issuer': ((('commonName', 'Some CA'),),)
    }
    mock_get_cert_details.return_value = mock_cert

    # 2. ACT
    result = await ssl_check_instance.run(url)
    # 3. ASSERT
    assert result.is_suspicious is True
    assert "Cert expired" in result.details
    assert result.score_impact > 0


async def test_ssl_check_handles_malformed_cert_dates(ssl_check_instance: SSLCheck, mock_get_cert_details):
    """
    Should detect missing or malformed date fields.
    """
    #1 ARRANGE
    url = AnyHttpUrl(URL_HTTPS)

    # Mock incorrect cert, missing dates
    mock_cert_with_missing_keys = {
        'subject': ((('commonName', 'malformed.com'),),),
        'issuer': ((('commonName', 'Some CA'),),)
    }
    mock_get_cert_details.return_value = mock_cert_with_missing_keys

    #2 ACT
    result = await ssl_check_instance.run(url)

    #3 ASSERT

    assert result.is_suspicious is True
    assert "Couldn't parse cert validity dates" in result.details


async def test_ssl_check_with_hostname_mismatch(ssl_check_instance: SSLCheck, mock_get_cert_details):
    """ Should detect that cert is issued to someone else"""
    #1 ARRANGE
    url = AnyHttpUrl(URL_HTTPS)
    valid_date = datetime.now(timezone.utc) + timedelta(days=100)

    mock_cert = {
        'notBefore': (valid_date - timedelta(days=200)).strftime('%b %d %H:%M:%S %Y GMT'),
        'notAfter': valid_date.strftime('%b %d %H:%M:%S %Y GMT'),
        'subject': ((('commonName', 'www.phishing-site.com'),),),  # Different name
        'issuer': ((('commonName', 'Some CA'),),)
    }
    mock_get_cert_details.return_value = mock_cert

    #2 ACT
    result = await ssl_check_instance.run(url)

    #3 ASSERT
    assert result.is_suspicious is True
    assert result.score_impact > 0
    assert f"Hostname {url.host} does not match cert" in result.details

async def test_ssl_check_self_sign(ssl_check_instance: SSLCheck, mock_get_cert_details):
    """Should detect self-signed cert"""
    #1 ARRANGE
    url = AnyHttpUrl(URL_HTTPS)
    # Mock self-sined cert
    valid_date = datetime.now(timezone.utc) + timedelta(days=100)

    mock_cert ={
        'notBefore': (valid_date - timedelta(days=200)).strftime('%b %d %H:%M:%S %Y GMT'),
        'notAfter': valid_date.strftime('%b %d %H:%M:%S %Y GMT'),
        'subject': ((('commonName', 'www.phishing-site.com'),),),
        'issuer': ((('commonName', 'www.phishing-site.com'),),)
    }
    mock_get_cert_details.return_value = mock_cert

    #2. ACT
    result = await ssl_check_instance.run(url)
    #3. ASSERT
    assert result.is_suspicious is True
    assert result.score_impact > 0
    assert "Cert self-signed" in result.details
async def test_ssl_check_happy_path(ssl_check_instance: SSLCheck, mock_get_cert_details):

    # ARRANGE
    url = AnyHttpUrl('https://good-site.com')
    valid_date = datetime.now(timezone.utc) + timedelta(days=100)

    mock_cert = {
        'notBefore': (valid_date - timedelta(days=200)).strftime('%b %d %H:%M:%S %Y GMT'),
        'notAfter': valid_date.strftime('%b %d %H:%M:%S %Y GMT'),
        'subject': ((('commonName', 'good-site.com'),),),
        'issuer': ((('commonName', 'Trusted CA'),),),
        'subjectAltName': (('DNS', 'good-site.com'), ('DNS', '*.good-site.com'))
    }
    mock_get_cert_details.return_value = mock_cert

    # ACT
    result = await ssl_check_instance.run(url)

    # ASSERT
    assert result.is_suspicious is False
    assert result.score_impact == 0
    assert 'Cert appears to be valid' in result.details
