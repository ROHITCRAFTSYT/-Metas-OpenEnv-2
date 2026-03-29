"""SOC-Triage-Gym graders — deterministic 0.0 to 1.0 scoring."""
from graders.phishing_grader import PhishingGrader
from graders.lateral_movement_grader import LateralMovementGrader
from graders.queue_management_grader import QueueManagementGrader

GRADER_REGISTRY = {
    "phishing": PhishingGrader,
    "lateral_movement": LateralMovementGrader,
    "queue_management": QueueManagementGrader,
}

__all__ = [
    "PhishingGrader",
    "LateralMovementGrader",
    "QueueManagementGrader",
    "GRADER_REGISTRY",
]
