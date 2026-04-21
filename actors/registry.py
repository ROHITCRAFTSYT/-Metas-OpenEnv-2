"""Actor registry that fans out step() notifications to all active actors."""
from __future__ import annotations

import random
from typing import List, Optional

from models import ActorMessage, AgentRole


class BaseActor:
    """Base class — actors override on_step() to optionally produce a message."""

    kind: str = "base"

    def __init__(self, seed: int = 0) -> None:
        self._rng = random.Random(seed)
        self._counter = 0

    def on_step(self, step: int, ctx: Optional[dict] = None) -> Optional[ActorMessage]:
        return None

    def reset(self, seed: int = 0) -> None:
        self._rng = random.Random(seed)
        self._counter = 0


class ActorRegistry:
    """Tracks active actors and collects messages per step."""

    def __init__(self, actors: Optional[List[BaseActor]] = None) -> None:
        self._actors: List[BaseActor] = list(actors or [])
        self._outbox: List[ActorMessage] = []

    def reset(self, seed: int = 0) -> None:
        self._outbox.clear()
        for i, actor in enumerate(self._actors):
            actor.reset(seed=seed + i)

    def tick(self, step: int, ctx: Optional[dict] = None) -> List[ActorMessage]:
        produced: List[ActorMessage] = []
        for actor in self._actors:
            msg = actor.on_step(step, ctx or {})
            if msg is not None:
                produced.append(msg)
                self._outbox.append(msg)
        return produced

    def inbox_for(self, role: AgentRole) -> List[ActorMessage]:
        return [m for m in self._outbox if m.to_role is None or m.to_role == role]

    def all_messages(self) -> List[ActorMessage]:
        return list(self._outbox)


def build_default_registry(seed: int = 0) -> ActorRegistry:
    """Build the standard 3-actor registry: threat-intel, compliance, end-user."""
    from actors.compliance import ComplianceOfficerActor
    from actors.end_user import EndUserReporterActor
    from actors.threat_intel import ThreatIntelFeedActor

    return ActorRegistry([
        ThreatIntelFeedActor(seed=seed),
        ComplianceOfficerActor(seed=seed + 1),
        EndUserReporterActor(seed=seed + 2),
    ])
