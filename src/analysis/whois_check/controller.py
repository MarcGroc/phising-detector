import asyncio
from datetime import datetime, timezone
from typing import Optional

import whois
import tldextract
from loguru import logger
from pydantic import AnyHttpUrl
from src.analysis.schema import AnalysisDetail, AbstractCheck
from src.scoring.constants import ImpactScore


class WhoisCheck(AbstractCheck):
    """Whois check, analysis of whois data like domain age, location, hiding registrant data, registrant type"""
    _PRIVACY_KEYWORDS = ["privacy", "redacted", "private", "guard"]
    _DOMAIN_VERY_YOUNG = 90 # days
    _DOMAIN_LT_YEAR = 365 # days

    @property
    def name(self) -> str:
        return "Whois check"

    async def run(self, url: AnyHttpUrl) -> AnalysisDetail:
        logger.info(f"Checking WHOIS for {url}")
        hostname = url.host
        if not hostname:
            return AnalysisDetail(
                check_name=self.name, is_suspicious=True, score_impact=ImpactScore.NO_HOSTNAME,
                details="Could not extract hostname from URL."
            )
        # 1. Extract domain with tldextract
        extracted = tldextract.extract(hostname)
        domain = f"{extracted.domain}.{extracted.suffix}"

        try:
            # to_thread used to not block event loop, runs async in separate thread
            domain_info = await asyncio.to_thread(whois.whois, domain)
        except Exception as e:
            logger.warning(f"Whois check for {domain} failed with exception {e}")
            return AnalysisDetail(check_name=self.name, is_suspicious=False, score_impact=ImpactScore.NO_HOSTNAME,
                                  details=f"Whois check for {domain} failed")

        details = []
        score = 0

        #2. Check domain age
        creation_date = self._get_creation_date(domain_info)
        if creation_date:
            age_days = (datetime.now(timezone.utc) - creation_date).days
            if age_days < self._DOMAIN_VERY_YOUNG:
                score += ImpactScore.HIGH
                details.append(f" Domain: {domain} is very young {age_days} days old.")
            elif age_days < self._DOMAIN_LT_YEAR:
                score += ImpactScore.MEDIUM
                details.append(f" Domain: {domain} is relatively new registered {age_days} days ago.")
        else:
            score += ImpactScore.LOW
            details.append(f"Could not extract domain creation date from {domain}.")

        #3. Privacy check, if hidden likely suspicious
        registrant_info = str(domain_info.get("registrant_name", "")).lower()
        if any(keyword in registrant_info for keyword in self._PRIVACY_KEYWORDS):
            score += ImpactScore.MEDIUM
            details.append("Registrant information is hidden behind a privacy service.")

        return AnalysisDetail(
            check_name=self.name,
            is_suspicious=bool(details),
            score_impact=score,
            details=" | ".join(details) or "Domain info appears normal."
        )

    def _get_creation_date(self, domain_info) -> Optional[datetime]:
        """Get offset aware creation date."""
        creation_date = domain_info.creation_date
        # get first date if its list
        if isinstance(creation_date, list):
            if not creation_date:
                return None
            date = creation_date[0]
        else:
            date = creation_date
        #make sure its offset aware
        if isinstance(date, datetime):
            return date.replace(tzinfo=timezone.utc)

        return None