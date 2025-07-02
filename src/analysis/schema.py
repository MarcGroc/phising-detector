from abc import ABC, abstractmethod
from pydantic import BaseModel, AnyHttpUrl, Field

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
    score: int = Field(ge=0, le=100, description="The score of the analysis form 0 to 100")
    risk_level: str
    details: list[AnalysisDetail]


