from detection.rules.engine import RuleEngine
from dataclasses import dataclass

# Mocking the event structure so the engine can read it
@dataclass
class MockEvent:
    event_type: str
    user: str
    transaction: str
    table_name: str
    record_count: int
    data_sensitivity: str
    source_ip: str
    raw_data: dict

# 1. Point the engine to your specific path
rules_path = "detection/rules/detection_rules.yaml"
engine = RuleEngine(rules_path=rules_path)

# 2. Create a "Suspicious" SAP event
# Scenario: An admin downloading sensitive user data outside business hours
test_event = MockEvent(
    event_type="TABLE_READ",  # Must match the list in YAML
    user="BASIS_ADMIN",
    transaction="SE16N",
    table_name="USR02",
    record_count=50000,
    data_sensitivity="HIGH",
    source_ip="10.0.0.50",
    raw_data={
        "enrichment": {
            "outside_business_hours": True,
            "extreme_volume": True,
            "transaction_sensitivity": "CRITICAL",
            "time_window_minutes": 30,
            "unique_transactions_1h": 20
        }
    }
)
# 3. Run the engine
results = engine.evaluate(test_event)

# 4. Check the output
if not results:
    print("✅ No threats detected. The engine is quiet.")
else:
    for match in results:
        print(f"🚨 ALERT: {match.rule_name} (ID: {match.rule_id})")
        print(f"   Severity: {match.severity.upper()}")
        print(f"   Risk Score: {match.final_score}")
        print(f"   Matched on: {match.matched_conditions}")
