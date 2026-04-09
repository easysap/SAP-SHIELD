from typing import Optional
from loguru import logger
from detection.models.baseline import UserBehaviorProfile

class AnomalyScorer:
    """Calculates risk scores based on deviations from baselines."""
    
    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        self.threshold = self.config.get("anomaly_threshold", 2.0)

    def calculate_score(self, event, profile: UserBehaviorProfile) -> float:
        """Compares current event against user profile to return a 0.0-1.0 score."""
        score = 0.0
        if event.source_ip and event.source_ip not in profile.known_ips:
            score += 0.4
        if event.transaction and event.transaction not in profile.typical_transactions:
            score += 0.5
        return min(score, 1.0)
