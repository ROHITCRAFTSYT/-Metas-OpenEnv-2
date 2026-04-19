"""SOC-Triage-Gym scenario generators."""
from scenarios.phishing import PhishingScenario
from scenarios.lateral_movement import LateralMovementScenario
from scenarios.queue_management import QueueManagementScenario
from scenarios.insider_threat import InsiderThreatScenario
from scenarios.team_phishing_escalation import TeamPhishingEscalationScenario
from scenarios.team_lateral_team import TeamLateralTeamScenario

SCENARIO_REGISTRY = {
    "phishing": PhishingScenario,
    "lateral_movement": LateralMovementScenario,
    "queue_management": QueueManagementScenario,
    "insider_threat": InsiderThreatScenario,
    "team_phishing_escalation": TeamPhishingEscalationScenario,
    "team_lateral_team": TeamLateralTeamScenario,
}

__all__ = [
    "PhishingScenario",
    "LateralMovementScenario",
    "QueueManagementScenario",
    "InsiderThreatScenario",
    "TeamPhishingEscalationScenario",
    "TeamLateralTeamScenario",
    "SCENARIO_REGISTRY",
]
