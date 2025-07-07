from abc import ABC, abstractmethod

from typing import Optional
from pydantic import BaseModel, AnyHttpUrl, Field

from src.scoring.constants import ImpactScore


class AnalysisDetail(BaseModel):
    """Single task result schema"""
    check_name: str
    is_suspicious: bool
    score_impact: int
    details: dict | str


# --------Abstraction---------------
class AbstractCheck(ABC):

    @property
    @abstractmethod
    def name(self) -> str:
        """Check name e.g. Redirect Check, DNS Check etc"""
        ...

    @abstractmethod
    async def run(self, url: AnyHttpUrl) -> AnalysisDetail:
        """Main analysis runner"""
        ...


class AnalysisResponse(BaseModel):
    """Checks response schema"""
    score: int = Field(ge=0, le=200, description="The score of the analysis form 0 to 100")
    risk_level: str
    details: list[AnalysisDetail]


class ValidationResult(BaseModel):
    """Structured result of single validation"""
    score_impact: ImpactScore = ImpactScore.ZERO
    detail: Optional[str] = None
