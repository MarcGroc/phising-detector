from src.analysis.schema import AnalysisDetail
from src.scoring.constants import ImpactScore, RiskLevel

def calculate_final_score(results: 'list[AnalysisDetail]') -> tuple[int, str]:
    """Calculate total score based on results from particular analysis"""

    total_score = sum(result.score_impact for result in results)

    if total_score >= ImpactScore.CRITICAL:
        risk = RiskLevel.CRITICAL
    elif total_score >= ImpactScore.HIGH:
        risk = RiskLevel.HIGH
    elif total_score >= ImpactScore.MEDIUM:
        risk = RiskLevel.MEDIUM
    elif total_score >= ImpactScore.LOW:
        risk = RiskLevel.LOW
    else:
        risk = RiskLevel.MINIMAL
    return total_score, risk