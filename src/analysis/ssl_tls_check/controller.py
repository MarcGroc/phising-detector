import asyncio
import itertools
import ssl
from datetime import datetime, timezone
from typing import Optional

import httpx
from pydantic import AnyHttpUrl
from loguru import logger
from tenacity import  RetryError

from src.analysis.schema import AbstractCheck, AnalysisDetail, ValidationResult
from src.scoring.constants import ImpactScore
from utils.constants import HEADERS
from utils.helpers import create_http_retryer

__all__ = ["SSLCheck"]

async def _get_cert_details(url: AnyHttpUrl) -> Optional[dict]:
    """Instead of asyncio we'll use httpx to get cert"""
    try:
        # Async httpx client with verify SSL
        async with httpx.AsyncClient(verify=True, headers=HEADERS) as client:
            # Stream to get direct access TSL socket
            async with client.stream('GET', str(url)) as response:
                # Raise if status 400+
                response.raise_for_status()
                # If connection is secure(HTTPS) and ssl object in response
                network_stream = response.extensions["network_stream"]
                ssl_object = network_stream.get_extra_info("ssl_object")
                if ssl_object is None:
                    logger.warning(f"No SSL socket in {url}")
                    return None
                # Get cert and return it
                return ssl_object.getpeercert()

    except (ssl.SSLError, OSError, asyncio.TimeoutError) as e:
        logger.warning(f"Failed to retrieve SSL certificate {url}: {e}")
        return None


class SSLCheck(AbstractCheck):
    """Checks SSL/TLS certificate"""

    @property
    def name(self) -> str:
        return "SSL/TLS Cert Check"

    async def run(self, url: AnyHttpUrl) -> AnalysisDetail:
        # 1. If url does not contain https or hostname, mark as suspicious
        logger.info(f"Checking SSL/TLS for {url}")
        if url.scheme != 'https':
            return AnalysisDetail(check_name=self.name, is_suspicious=True, score_impact=ImpactScore.SSL_NO_HTTPS,
                                  details="Site without HTTPS")

        hostname = url.host
        if not hostname:
            return AnalysisDetail(
                check_name=self.name, is_suspicious=True, score_impact=ImpactScore.NO_HOSTNAME,
                details="Could not extract hostname from URL."
            )
        # 1.1 Try again if exception in retry_if_exception_type, then RetryError
        retryer = create_http_retryer(retry_on=(httpx.TimeoutException, httpx.ConnectError, ssl.SSLError))
        try:
            async for attempt in retryer:
                with attempt:
                    cert = await _get_cert_details(url)

        except RetryError:
            return AnalysisDetail(check_name=self.name, is_suspicious=True, score_impact=ImpactScore.SSL_FETCH_FAILED,
                                  details="Failed to retrieve SSL certificate. Site may not be using HTTPS or is down.")
        if not cert:
            return AnalysisDetail(
                check_name=self.name,
                is_suspicious=True,
                score_impact=ImpactScore.SSL_FETCH_FAILED,
                details="Failed to retrieve SSL certificate after multiple attempts."
            )
        # 2. Cert Validation tasks
        validation_tasks = [
            self._validate_datetime(cert),
            self._validate_hostname(hostname, cert),
            self._validate_issuer(cert)
        ]
        # 3. Run all tasks
        results: list[ValidationResult] = await asyncio.gather(*validation_tasks)
        # 4. Aggregate results
        total_score = sum(score.score_impact for score in results)
        details = [detail.detail for detail in results if detail.detail is not None]

        return AnalysisDetail(check_name=self.name, is_suspicious=total_score > 0,
                              score_impact=total_score,
                              details=" | ".join(details) if details else 'Cert appears to be valid')

    async def _validate_datetime(self, cert: dict) -> ValidationResult:
        """Validate datetime data in cert"""
        now = datetime.now(timezone.utc)
        try:
            # convert str to datetime with timezone
            not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
            if now < not_before:
                return ValidationResult(score_impact=ImpactScore.SSL_NOT_YET_VALID, detail="Cert not valid yet")
            if now > not_after:
                return ValidationResult(score_impact=ImpactScore.SSL_EXPIRED, detail="Cert expired")
            return ValidationResult()
        except (KeyError, ValueError):
            return ValidationResult(score_impact=ImpactScore.SSL_FETCH_FAILED,
                                    detail="Couldn't parse cert validity dates")

    async def _validate_issuer(self, cert: dict) -> ValidationResult:
        """Validate if cert is self-signed"""
        if cert.get("issuer") == cert.get("subject"):
            return ValidationResult(score_impact=ImpactScore.SSL_SELF_SIGNED, detail="Cert self-signed")
        return ValidationResult(score_impact=ImpactScore.ZERO)

    async def _validate_hostname(self, hostname: str, cert: dict) -> ValidationResult:
        """Validate certs SAN(Subject Alternative Name) and CommonName"""
        # 1. ------Generator for SAN and common names, no need to store it in memory
        san_names = (name for name_type, name in cert.get('subjectAltName', []) if
                     name_type == 'DNS')  # cert.get [] in case of missing key, there will be no error
        common_names = (name for rdn in cert.get('subject') for k, name in rdn if k == 'commonName')
        # 2. Connect both generators with itertools.chain
        all_cert_names = itertools.chain(san_names, common_names)
        # 3. if any() return match
        if not any(self._match_hostname(hostname, cert_name) for cert_name in all_cert_names):
            return ValidationResult(score_impact=ImpactScore.SSL_HOSTNAME_MISMATCH,
                                    detail=f"Hostname {hostname} does not match cert")
        return ValidationResult(score_impact=ImpactScore.ZERO)

    def _match_hostname(self, hostname: str, cert_name: str) -> bool:
        """ Check if hostname matches cert including wildcards"""
        if cert_name.startswith('*.'):
            return hostname.endswith(cert_name[1:])
        return hostname == cert_name
