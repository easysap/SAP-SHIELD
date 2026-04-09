import yaml
import operator
from dataclasses import dataclass

# 1. The minimal logic
@dataclass
class MockEvent:
    event_type: str
    record_count: int
    raw_data: dict

# 2. Hardcoded logic to bypass file loading issues
def simple_evaluate(event):
    # This simulates your MASS_DATA_EXPORT rule
    actual_type = event.event_type
    actual_count = event.record_count
    
    print(f"--- DEBUGGING ---")
    print(f"Checking Type: {actual_type} (Expected: TABLE_READ)")
    print(f"Checking Count: {actual_count} (Expected: > 10000)")
    
    if actual_type == "TABLE_READ" and actual_count > 10000:
        return "🚨 ALERT: MATCH FOUND!"
    return "✅ Still Quiet..."

# 3. The Test
test_event = MockEvent(
    event_type="TABLE_READ", 
    record_count=50000, 
    raw_data={}
)

print(simple_evaluate(test_event))
