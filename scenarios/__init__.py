"""SOC-Triage-Gym scenario generators."""
from scenarios.phishing import PhishingScenario
from scenarios.lateral_movement import LateralMovementScenario
from scenarios.queue_management import QueueManagementScenario
from scenarios.insider_threat import InsiderThreatScenario

SCENARIO_REGISTRY = {
    "phishing": PhishingScenario,
    "lateral_movement": LateralMovementScenario,
    "queue_management": QueueManagementScenario,
    "insider_threat": InsiderThreatScenario,
}

__all__ = [
    "PhishingScenario",
    "LateralMovementScenario",
    "QueueManagementScenario",
    "InsiderThreatScenario",
    "SCENARIO_REGISTRY",
]
