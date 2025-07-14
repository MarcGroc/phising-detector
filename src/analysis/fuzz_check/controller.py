from loguru import logger
from pydantic import AnyHttpUrl
from thefuzz import fuzz, process
from analysis.schema import AnalysisDetail
from src.analysis.schema import AbstractCheck
from src.scoring.constants import ImpactScore
from utils.helpers import load_brands_list

__all__ = ["FuzzDomainCheck"]


class FuzzDomainCheck(AbstractCheck):
    """Brand impersonation, typosqautting and cybersquatting analysis"""
    BRANDS: list = load_brands_list("top-100-pl.json")  # file need to stored in /utils
    __TYPO_RATIO_THRESHOLD: int = 90
    __EXACT_MATCH: int = 100
    __COMBO_RATIO_THRESHOLD: int = 95
    __SUFFIX_BUFFER = 3

    @property
    def name(self) -> str:
        return "Fuzz Domain Check"

    async def run(self, url: AnyHttpUrl) -> AnalysisDetail:
        logger.info(f"Fuzz check for {url}")
        # 1. Hostname from AnyHttpUrl
        hostname = url.host
        # 1.1 Return if hostname not present
        if not hostname:
            return AnalysisDetail(
                check_name=self.name, is_suspicious=True, score_impact=ImpactScore.NO_HOSTNAME,
                details="Could not extract hostname from URL."
            )
        found_suspicion = False  # flag for stop iteration
        # 2. Iterate through BRANDS with thefuzz library
        for brand in self.BRANDS:
            # 2.1 Return trusted if exact match
            if hostname == brand:
                found_suspicion = True
                return AnalysisDetail(
                    check_name=self.name,
                    is_suspicious=False,
                    score_impact=ImpactScore.ZERO,
                    details=f"Hostname '{hostname}' is a known trusted domain."
                )
            # 2.2 First typosquatting with ratio, if hostname ratio is > 90, paypal1.com -> paypal.com,
            ratio = fuzz.ratio(hostname, brand)
            if self.__TYPO_RATIO_THRESHOLD < ratio < self.__EXACT_MATCH:
                found_suspicion = True
                detail = f"Hostname {hostname} is suspiciously similar to {brand} similarity {ratio}%"
                return AnalysisDetail(check_name=self.name, is_suspicious=True, score_impact=ImpactScore.HIGH,
                                      details=detail)

            # 2.3 Then we check typosquatting ratio for long hostname, we check for up to 3 extra characters
            # we-are-scamers-paypal1.com -> paypal.com, we-are-scamers-paypall.com -> paypal.com
            len_diff = len(hostname) - len(brand)
            if len_diff > self.__SUFFIX_BUFFER:
                hostname_suffx = hostname[-len(brand) - self.__SUFFIX_BUFFER:]
                suffix_ratio = fuzz.ratio(hostname_suffx, brand)
                if suffix_ratio > self.__TYPO_RATIO_THRESHOLD:
                    found_suspicion = True
                    detail = f" Suffix of '{hostname}' is highly similar to '{brand}', ratio {suffix_ratio}%."
                    return AnalysisDetail(check_name=self.name, score_impact=ImpactScore.CRITICAL, is_suspicious=True,
                                          details=detail)
        # 3 Then combosquatting with partial_ratio, find best matching fragment with score >=95,
        # we-are-scamers-paypal.com -> paypal.com
        if not found_suspicion:
            best_partial_match = process.extractOne(hostname, self.BRANDS, scorer=fuzz.partial_ratio,
                                                    score_cutoff=self.__COMBO_RATIO_THRESHOLD)
            if best_partial_match:
                brand, score = best_partial_match
                # Make sure to not flag exact match as combosquatting
                if hostname != brand:
                    detail = f"Hostname '{hostname}' contains a string highly similar to a known brand '{brand}' (similarity: {score}%). Possible combosquatting."
                    return AnalysisDetail(check_name=self.name, is_suspicious=True, score_impact=ImpactScore.HIGH,
                                          details=detail)

        # 4. If hostname doesn't look impersonated return score ZERO
        return AnalysisDetail(check_name=self.name, is_suspicious=False, score_impact=ImpactScore.ZERO,
                              details=f"{hostname} doesn't look suspicious, similarity score")
