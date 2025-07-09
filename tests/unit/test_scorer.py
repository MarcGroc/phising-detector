from src.analysis.schema import AnalysisDetail
from src.scoring.constants import ImpactScore, RiskLevel
from src.scoring.scorer import calculate_final_score

VALID_SCORE = AnalysisDetail(check_name="Redirect Check", is_suspicious=False, score_impact=ImpactScore.ZERO,
                             details='test')
VALID_SCORE1 = AnalysisDetail(check_name="Redirect Check", is_suspicious=True, score_impact=ImpactScore.REDIRECTED,
                              details='test')


def test_calculate_final_score():
    result = calculate_final_score([VALID_SCORE, VALID_SCORE1])
    assert result[0] >= ImpactScore.ZERO
    assert result[1] == RiskLevel.MINIMAL
