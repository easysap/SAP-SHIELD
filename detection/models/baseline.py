"""User behavior baselining — builds statistical profiles of normal activity."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
import numpy as np
from typing import Optional
from loguru import logger


@dataclass
class UserBehaviorProfile:
    """Statistical profile of a user's normal SAP behavior."""
    user: str
    event_count: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    # Activity volume stats
    avg_events_per_hour: float = 0.0
    std_events_per_hour: float = 0.0
    avg_events_per_day: float = 0.0
    std_events_per_day: float = 0.0

    # Transaction patterns
    transaction_frequency: dict = field(default_factory=dict)  # tcode -> count
    typical_transactions: set = field(default_factory=set)

    # Time patterns
    active_hours: dict = field(default_factory=dict)  # hour -> event_count
    active_days: dict = field(default_factory=dict)    # weekday -> event_count
    avg_session_start: float = 8.0   # avg hour
    avg_session_end: float = 17.0

    # Data access patterns
    avg_record_reads: float = 0.0
    std_record_reads: float = 0.0
    max_record_reads: int = 0
    tables_accessed: set = field(default_factory=set)

    # Network
    known_ips: set = field(default_factory=set)

    def to_dict(self) -> dict:
        return {
            "user": self.user,
            "event_count": self.event_count,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "avg_events_per_hour": self.avg_events_per_hour,
            "std_events_per_hour": self.std_events_per_hour,
            "avg_events_per_day": self.avg_events_per_day,
            "std_events_per_day": self.std_events_per_day,
            "transaction_frequency": self.transaction_frequency,
            "typical_transactions": list(self.typical_transactions),
            "active_hours": self.active_hours,
            "active_days": self.active_days,
            "avg_record_reads": self.avg_record_reads,
            "std_record_reads": self.std_record_reads,
            "max_record_reads": self.max_record_reads,
            "tables_accessed": list(self.tables_accessed),
            "known_ips": list(self.known_ips),
        }


class BaselineEngine:
    """
    Builds and maintains per-user behavioral baselines.

    Uses rolling statistics to establish what 'normal' looks like
    for each user, enabling anomaly detection by deviation.
    """

    def __init__(self, config: dict = None):
        config = config or {}
        det_cfg = config.get("detection", {})
        self.baseline_days = det_cfg.get("baseline_window_days", 30)
        self.min_events = det_cfg.get("min_baseline_events", 100)
        self.profiles: dict[str, UserBehaviorProfile] = {}
        self._raw_data: dict[str, list] = defaultdict(list)

    def update(self, events: list) -> None:
        """Update baselines with new events."""
        user_events = defaultdict(list)
        for event in events:
            user_events[event.user].append(event)

        for user, evts in user_events.items():
            self._raw_data[user].extend(evts)

            # Trim to baseline window
            cutoff = datetime.now() - timedelta(days=self.baseline_days)
            self._raw_data[user] = [
                e for e in self._raw_data[user] if e.timestamp > cutoff
            ]

            self._rebuild_profile(user)

    def _rebuild_profile(self, user: str) -> None:
        """Rebuild statistical profile from raw event data."""
        events = self._raw_data.get(user, [])
        if not events:
            return

        profile = self.profiles.get(user, UserBehaviorProfile(user=user))
        profile.event_count = len(events)
        profile.first_seen = min(e.timestamp for e in events)
        profile.last_seen = max(e.timestamp for e in events)

        # Hourly event counts
        hourly_counts = defaultdict(int)
        daily_counts = defaultdict(int)

        for event in events:
            hour_key = event.timestamp.strftime("%Y-%m-%d-%H")
            day_key = event.timestamp.strftime("%Y-%m-%d")
            hourly_counts[hour_key] += 1
            daily_counts[day_key] += 1

            # Transaction frequency
            if event.transaction:
                profile.transaction_frequency[event.transaction] = (
                    profile.transaction_frequency.get(event.transaction, 0) + 1
                )

            # Active hours / days
            h = str(event.timestamp.hour)
            d = str(event.timestamp.weekday())
            profile.active_hours[h] = profile.active_hours.get(h, 0) + 1
            profile.active_days[d] = profile.active_days.get(d, 0) + 1

            # Tables
            if event.table_name:
                profile.tables_accessed.add(event.table_name)

            # IPs
            if event.source_ip:
                profile.known_ips.add(event.source_ip)

        # Volume statistics
        if hourly_counts:
            h_vals = list(hourly_counts.values())
            profile.avg_events_per_hour = float(np.mean(h_vals))
            profile.std_events_per_hour = float(np.std(h_vals))

        if daily_counts:
            d_vals = list(daily_counts.values())
            profile.avg_events_per_day = float(np.mean(d_vals))
            profile.std_events_per_day = float(np.std(d_vals))

        # Record read statistics
        reads = [e.record_count for e in events if e.record_count > 0]
        if reads:
            profile.avg_record_reads = float(np.mean(reads))
            profile.std_record_reads = float(np.std(reads))
            profile.max_record_reads = max(reads)

        # Typical transactions (top 80% by frequency)
        if profile.transaction_frequency:
            sorted_tx = sorted(
                profile.transaction_frequency.items(),
                key=lambda x: x[1],
                reverse=True,
            )
            total = sum(c for _, c in sorted_tx)
            cumulative = 0
            for tcode, count in sorted_tx:
                cumulative += count
                profile.typical_transactions.add(tcode)
                if cumulative / total >= 0.8:
                    break

        # Session hours
        active_hour_counts = [
            (int(h), c) for h, c in profile.active_hours.items()
        ]
        if active_hour_counts:
            active_hour_counts.sort(key=lambda x: x[1], reverse=True)
            top_hours = [h for h, _ in active_hour_counts[:8]]
            if top_hours:
                profile.avg_session_start = float(min(top_hours))
                profile.avg_session_end = float(max(top_hours))

        self.profiles[user] = profile

    def get_profile(self, user: str) -> Optional[UserBehaviorProfile]:
        return self.profiles.get(user)

    def is_baselined(self, user: str) -> bool:
        """Check if we have enough data to baseline this user."""
        profile = self.profiles.get(user)
        return profile is not None and profile.event_count >= self.min_events
