"""Event enrichment — adds context like sensitivity, time flags, and user metadata."""

from datetime import datetime, time
from connectors.base import SAPEvent


# Transactions that are inherently sensitive
SENSITIVE_TRANSACTIONS = {
    "SU01", "SU02", "SU10", "PFCG",      # User/role admin
    "SE16N", "SE16", "SE11",               # Table access
    "SM49", "SM69",                         # OS command execution
    "SE38", "SE80",                         # ABAP editor
    "STMS",                                 # Transport management
    "RZ10", "RZ11",                         # System profile params
    "SM59",                                 # RFC destinations
    "DBACOCKPIT",                           # Database admin
    "PA30", "PA20",                         # HR master data
    "F110",                                 # Payment runs
}

CRITICAL_TRANSACTIONS = {
    "SU01", "PFCG", "SM49", "SM69", "SE38", "STMS", "RZ10", "SM59",
}

SENSITIVE_TABLE_PREFIXES = [
    "PA0",     # HR tables
    "USR",     # User security tables
    "AGR_",    # Role tables
    "BSEG",    # Financial line items
    "KNA1",    # Customer master
    "LFA1",    # Vendor master
]


class EventEnricher:
    """
    Enriches raw SAP events with derived context fields.

    Adds:
    - Transaction sensitivity classification
    - Business hours flags
    - Table sensitivity classification
    - Derived risk indicators
    """

    def __init__(
        self,
        business_start: time = time(8, 0),
        business_end: time = time(18, 0),
        timezone: str = "UTC",
    ):
        self.business_start = business_start
        self.business_end = business_end

    def enrich(self, event: SAPEvent) -> SAPEvent:
        """Enrich a single event with derived context."""
        event.raw_data["enrichment"] = {}
        ctx = event.raw_data["enrichment"]

        # Transaction sensitivity
        ctx["transaction_sensitivity"] = self._classify_transaction(event.transaction)

        # Time-based flags
        ctx["outside_business_hours"] = self._is_outside_hours(event.timestamp)
        ctx["is_weekend"] = event.timestamp.weekday() >= 5
        ctx["hour_of_day"] = event.timestamp.hour
        ctx["day_of_week"] = event.timestamp.strftime("%A")

        # Table sensitivity
        if event.table_name:
            ctx["table_sensitivity"] = self._classify_table(event.table_name)
            if ctx["table_sensitivity"] in ("HIGH", "CRITICAL"):
                event.data_sensitivity = "HIGH"

        # Volume flags
        if event.record_count > 10000:
            ctx["high_volume"] = True
        if event.record_count > 50000:
            ctx["extreme_volume"] = True

        return event

    def _classify_transaction(self, transaction: str | None) -> str:
        if not transaction:
            return "NORMAL"
        tcode = transaction.upper().strip()
        if tcode in CRITICAL_TRANSACTIONS:
            return "CRITICAL"
        if tcode in SENSITIVE_TRANSACTIONS:
            return "HIGH"
        return "NORMAL"

    def _classify_table(self, table_name: str | None) -> str:
        if not table_name:
            return "NORMAL"
        upper = table_name.upper()
        for prefix in SENSITIVE_TABLE_PREFIXES:
            if upper.startswith(prefix):
                return "HIGH"
        return "NORMAL"

    def _is_outside_hours(self, timestamp: datetime) -> bool:
        t = timestamp.time()
        return t < self.business_start or t > self.business_end
