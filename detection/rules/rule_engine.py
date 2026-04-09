"""Configurable rule-based detection engine driven by YAML rules."""

import operator
import yaml
from pathlib import Path
from typing import Optional
from dataclasses import dataclass
from loguru import logger


@dataclass
class RuleMatch:
    """Result of a rule evaluation against an event."""
    rule_id: str
    rule_name: str
    severity: str
    base_score: float
    final_score: float
    matched_conditions: list[str]
    applied_multipliers: list[str]


OPERATORS = {
    "equals": operator.eq,
    "not_equals": operator.ne,
    "greater_than": operator.gt,
    "less_than": operator.lt,
    "greater_equal": operator.ge,
    "less_equal": operator.le,
    "in": lambda val, lst: val in lst,
    "not_in": lambda val, lst: val not in lst,
    "contains": lambda val, substr: substr in str(val),
    "within": operator.le,
}


class RuleEngine:
    """
    Evaluates events against configurable YAML-defined rules.

    Rules are loaded from config/detection_rules.yaml and define
    conditions, scoring, and severity levels.
    """

    def __init__(self, rules_path: str = "config/detection_rules.yaml"):
        self.rules = []
        self._load_rules(rules_path)

    def _load_rules(self, path: str) -> None:
        """Load rules from YAML file."""
        rules_file = Path(path)
        if not rules_file.exists():
            logger.warning(f"Rules file not found: {path}")
            return

        with open(rules_file) as f:
            data = yaml.safe_load(f)

        self.rules = [r for r in data.get("rules", []) if r.get("enabled", True)]
        logger.info(f"Loaded {len(self.rules)} detection rules")

    def evaluate(self, event, context: dict = None) -> list[RuleMatch]:
        """
        Evaluate an event against all loaded rules.

        Args:
            event: SAPEvent to evaluate
            context: Additional context (enrichment data, user metadata)

        Returns:
            List of RuleMatch for all rules that matched
        """
        context = context or {}
        matches = []

        # Build evaluation context from event + enrichment
        eval_ctx = self._build_context(event, context)

        for rule in self.rules:
            match = self._evaluate_rule(rule, eval_ctx)
            if match:
                matches.append(match)

        return matches

    def _build_context(self, event, extra: dict) -> dict:
    enrichment = event.raw_data.get("enrichment", {})
    
    ctx = {
        "event_type": str(event.event_type),
        "user": event.user,
        "transaction": event.transaction or "",
        "table_name": event.table_name or "",
        "record_count": event.record_count,
        "data_sensitivity": event.data_sensitivity,
        "source_ip": event.source_ip or "",
        "time_window_minutes": enrichment.get("time_window_minutes", 0),
        "outside_business_hours": enrichment.get("outside_business_hours", False),
    }
    ctx.update(extra)
    return ctx

    def _evaluate_rule(self, rule: dict, ctx: dict) -> Optional[RuleMatch]:
        """Evaluate a single rule against context with deep logging."""
        conditions = rule.get("conditions", [])
        matched = []
        
        print(f"\n[DEBUG] Evaluating Rule: {rule.get('id')}")

        for condition in conditions:
            field = condition.get("field", "")
            op_name = condition.get("operator", "equals")
            expected = condition.get("value")
            actual = ctx.get(field)

            print(f"  - Testing '{field}': Actual({type(actual).__name__})='{actual}' {op_name} Expected({type(expected).__name__})='{expected}'")

            if actual is None:
                print(f"    ❌ FAILED: Field '{field}' is missing in context.")
                return None 

            op_func = OPERATORS.get(op_name)
            try:
                if op_func(actual, expected):
                    matched.append(f"{field} {op_name} {expected}")
                    print(f"    ✅ PASSED")
                else:
                    print(f"    ❌ FAILED: Logic returned False")
                    return None
            except Exception as e:
                print(f"    ❌ ERROR: {e}")
                return None
        
        # ... (rest of your scoring logic remains the same)

        # All conditions matched — calculate score
        scoring = rule.get("scoring", {})
        base_score = scoring.get("base_score", 0.5)
        final_score = base_score
        applied_multipliers = []

        for mult in scoring.get("multipliers", []):
            condition_str = mult.get("condition", "")
            multiply = mult.get("multiply", 1.0)

            if self._eval_multiplier_condition(condition_str, ctx):
                final_score *= multiply
                applied_multipliers.append(
                    f"{condition_str} (x{multiply})"
                )

        final_score = min(1.0, final_score)

        return RuleMatch(
            rule_id=rule.get("id", "UNKNOWN"),
            rule_name=rule.get("name", "Unknown Rule"),
            severity=rule.get("severity", "medium"),
            base_score=base_score,
            final_score=final_score,
            matched_conditions=matched,
            applied_multipliers=applied_multipliers,
        )

    def _eval_multiplier_condition(self, condition_str: str, ctx: dict) -> bool:
        """Evaluate a simple condition string like 'record_count > 50000'."""
        try:
            parts = condition_str.split()
            if len(parts) == 3:
                field, op, value = parts
                actual = ctx.get(field)
                if actual is None:
                    return False

                # Handle string comparisons
                if value.startswith("'") and value.endswith("'"):
                    value = value.strip("'")
                    return str(actual) == value

                # Boolean
                if value.lower() in ("true", "false"):
                    return bool(actual) == (value.lower() == "true")

                # Numeric
                try:
                    num_val = float(value)
                    num_actual = float(actual)
                    ops = {
                        ">": operator.gt,
                        "<": operator.lt,
                        ">=": operator.ge,
                        "<=": operator.le,
                        "==": operator.eq,
                    }
                    return ops.get(op, operator.eq)(num_actual, num_val)
                except (ValueError, TypeError):
                    return False

            # Simple key check (e.g., "outside_business_hours")
            return bool(ctx.get(condition_str, False))

        except Exception:
            return False
