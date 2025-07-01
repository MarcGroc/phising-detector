
def calculate_final_score(results: 'list[CheckResult]') -> tuple[int,str]:
    """Calculate total score based on results from particular analysis"""

    total_score = sum(result.score_impact for result in results)

    if total_score > 50:
        risk = "high"
    elif total_score > 20:
        risk = "Medium"
    else:
        risk = "Low"
    return total_score, risk