from loguru import logger
from pydantic import AnyHttpUrl
from thefuzz import fuzz
from analysis.schema import AnalysisDetail
from src.analysis.schema import AbstractCheck
from src.scoring.constants import ImpactScore
from utils.helpers import load_brands_list

__all__ = ["FuzzDomainCheck"]


class FuzzDomainCheck(AbstractCheck):
    """Brand impersonation, typosqautting and cybersquatting analysis"""
    BRANDS:list = load_brands_list("top-100-pl.json") # file need to stored in /utils
    __MINIMUM_RATIO:int = 90
    __EXACT_MATCH:int = 100

    @property
    def name(self) -> str:
        return "Fuzz Domain Check"

    async def run(self, url: AnyHttpUrl) -> AnalysisDetail:
        logger.info(f"Fuzz check for {url}")
        #1. Hostname from AnyHttpUrl
        hostname = url.host
        if not hostname:
            return AnalysisDetail(
                check_name=self.name, is_suspicious=True, score_impact=ImpactScore.NO_HOSTNAME,
                details="Could not extract hostname from URL."
            )
        #2. Iterate through BRANDS
        for brand in self.BRANDS:
            #3. thefuzz library checks for similarity
            ratio = fuzz.ratio(hostname, brand)
            #4. If ratio in range hostname is likely impersonated
            if self.__MINIMUM_RATIO < ratio < self.__EXACT_MATCH:
                detail = f"Hostname {hostname} is suspiciously similar to {brand} similarity {ratio}%"
                return AnalysisDetail(check_name=self.name, is_suspicious=True, score_impact=ImpactScore.HIGH,
                                      details=detail)
        return AnalysisDetail(check_name=self.name, is_suspicious=False, score_impact=ImpactScore.ZERO,
                              details=f"{hostname} doesn't look suspicious, similarity score {ratio}")

# todo add all banks, blik and other payment providers(cards), inpost all related to parcels, all markets and gov websites zus etc, zabka biedronka etc