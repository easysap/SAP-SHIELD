"""Transaction sequence analysis — detect suspicious action sequences."""

from collections import defaultdict, deque
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Optional
from loguru import logger


@dataclass
class SequenceAlert:
    """Alert from sequence analysis."""
    user: str
    pattern_name: str
    transactions: list[str]
    confidence: float
    description: str
    timestamps: list[datetime]


# Known suspicious transaction sequences
SUSPICIOUS_SEQUENCES = {
    "self_privilege_escalation": {
        "pattern": ["SU01", "PFCG"],
        "description": "User management followed by role assignment",
        "min_confidence": 0.7,
    },
    "data_exfil_sequence": {
        "pattern": ["SE16N", "SE16N", "SE16N"],
        "description": "Repeated direct table access (potential data harvesting)",
        "min_confidence": 0.6,
    },
    "cover_tracks": {
        "pattern": ["SM20", "SM21"],
        "description": "Audit and system log access (potential log review to cover tracks)",
        "min_confidence": 0.5,
    },
    "debug_and_modify": {
        "pattern": ["SE38", "SE80"],
        "description": "Program editor access (potential code injection)",
        "min_confidence": 0.7,
    },
    "user_create_and_assign": {
        "pattern": ["SU01", "SU01", "PFCG"],
        "description": "Multiple user modifications followed by role changes",
        "min_confidence": 0.8,
    },
    "payment_manipulation": {
        "pattern": ["FK01", "F110"],
        "description": "Vendor creation followed by payment run",
        "min_confidence": 0.8,
    },
}


class SequenceAnalyzer:
    """
    Analyzes sequences of transactions for suspicious patterns.

    Maintains a sliding window of recent transactions per user
    and matches against known attack patterns.
    """

    def __init__(self, config: dict = None):
        config = config or {}
        model_cfg = config.get("detection", {}).get("models", {}).get("sequence", {})

        self.window_size = model_cfg.get("window_size", 20)
        self.min_length = model_cfg.get("min_sequence_length", 3)
        self.time_window = timedelta(minutes=60)

        # Per-user sliding windows
        self._user_windows: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=self.window_size)
        )

    def analyze(self, event) -> list[SequenceAlert]:
        """Add event to window and check for suspicious sequences."""
        user = event.user
        if not event.transaction:
            return []

        self._user_windows[user].append({
            "transaction": event.transaction,
            "timestamp": event.timestamp,
            "event_id": event.event_id,
        })

        return self._check_patterns(user)

    def _check_patterns(self, user: str) -> list[SequenceAlert]:
        """Check the user's recent transaction window against known patterns."""
        alerts = []
        window = list(self._user_windows[user])

        if len(window) < self.min_length:
            return []

        recent_tcodes = [w["transaction"] for w in window]
        recent_times = [w["timestamp"] for w in window]

        for pattern_name, pattern_def in SUSPICIOUS_SEQUENCES.items():
            target = pattern_def["pattern"]
            confidence = self._match_subsequence(recent_tcodes, target)

            if confidence >= pattern_def["min_confidence"]:
                # Verify time window
                if recent_times:
                    span = max(recent_times) - min(recent_times)
                    if span <= self.time_window:
                        alerts.append(SequenceAlert(
                            user=user,
                            pattern_name=pattern_name,
                            transactions=recent_tcodes[-len(target):],
                            confidence=confidence,
                            description=pattern_def["description"],
                            timestamps=recent_times[-len(target):],
                        ))

        return alerts

    def _match_subsequence(self, window: list[str], pattern: list[str]) -> float:
        """
        Check if pattern appears as a subsequence in the window.
        Returns confidence score 0.0-1.0.
        """
        if len(pattern) > len(window):
            return 0.0

        # Exact subsequence match
        pat_idx = 0
        matches = 0
        for tcode in window:
            if pat_idx < len(pattern) and tcode == pattern[pat_idx]:
                matches += 1
                pat_idx += 1

        if pat_idx == len(pattern):
            # Full pattern matched
            return 1.0

        # Partial match score
        return matches / len(pattern) if pattern else 0.0

    def get_user_activity_diversity(self, user: str) -> float:
        """
        Calculate transaction diversity score for a user's recent window.
        High diversity can indicate transaction hopping.
        Returns 0.0-1.0.
        """
        window = list(self._user_windows.get(user, []))
        if len(window) < 3:
            return 0.0

        tcodes = [w["transaction"] for w in window]
        unique = len(set(tcodes))
        total = len(tcodes)

        return unique / total if total > 0 else 0.0
