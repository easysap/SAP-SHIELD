from dataclasses import dataclass, field
from typing import Dict, Any
from datetime import datetime

@dataclass
class SAPEvent:
    event_id: str
    user_id: str
    timestamp: datetime
    action: str
    attributes: Dict[str, Any] = field(default_factory=dict)
