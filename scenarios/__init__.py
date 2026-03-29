"""SOC-Triage-Gym scenario generators."""
from scenarios.phishing import PhishingScenario
from scenarios.lateral_movement import LateralMovementScenario
from scenarios.queue_management import QueueManagementScenario

SCENARIO_REGISTRY = {
    "phishing": PhishingScenario,
    "lateral_movement": LateralMovementScenario,
    "queue_management": QueueManagementScenario,
}

__all__ = [
    "PhishingScenario",
    "LateralMovementScenario",
    "QueueManagementScenario",
    "SCENARIO_REGISTRY",
]
