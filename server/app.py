"""
SOC-Triage-Gym FastAPI Application
=====================================
OpenEnv-compliant HTTP server exposing:
  POST /reset   — start new episode
  POST /step    — execute action, get observation
  GET  /state   — current episode metadata
  GET  /health  — liveness check

Thread safety: a single threading.Lock protects the SOCEnvironment instance.
FastAPI runs synchronous route handlers in a thread pool executor, so
concurrent requests are serialized by the lock.
"""

import threading
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import Body, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from models import EnvironmentState, SOCAction, SOCObservation
from server.environment import SOCEnvironment


# ---------------------------------------------------------------------------
# App state
# ---------------------------------------------------------------------------

_env: Optional[SOCEnvironment] = None
_env_lock = threading.Lock()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize environment on startup."""
    global _env
    _env = SOCEnvironment()
    yield
    # Cleanup on shutdown (nothing needed for in-memory env)


# ---------------------------------------------------------------------------
# FastAPI Application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="SOC-Triage-Gym",
    description=(
        "OpenEnv-compliant reinforcement learning environment simulating a "
        "Security Operations Center analyst. An AI agent investigates SIEM alerts "
        "by enriching threat indicators, querying log sources, correlating events, "
        "and classifying alerts with MITRE ATT&CK mapping."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class ResetRequest(BaseModel):
    """Request body for POST /reset."""
    task_id: str = "phishing"
    seed: int = 42


class StepResponse(BaseModel):
    """Extended response with info field for OpenEnv compatibility."""
    observation: SOCObservation
    reward: float
    done: bool
    info: dict = {}


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    """Liveness check — returns 200 when server is running."""
    return {"status": "ok", "version": "0.1.0", "env": "soc-triage-gym"}


@app.post("/reset", response_model=SOCObservation)
def reset(request: Optional[ResetRequest] = Body(default=None)):
    """
    Start a new episode.

    Args:
        task_id: "phishing" | "lateral_movement" | "queue_management" (default: "phishing")
        seed: RNG seed for deterministic scenario generation (default: 42)

    Returns:
        Initial SOCObservation with full alert queue.
    """
    req = request or ResetRequest()
    with _env_lock:
        try:
            obs = _env.reset(task_id=req.task_id, seed=req.seed)
            return obs
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


@app.post("/step", response_model=SOCObservation)
def step(action: SOCAction):
    """
    Execute an action in the current episode.

    The action_type field determines which other fields are relevant.
    See the SOCAction model for the full action schema.

    Returns:
        Updated SOCObservation with step reward, new results, and done flag.
    """
    with _env_lock:
        if _env._config is None:
            raise HTTPException(
                status_code=400,
                detail="No active episode. Call POST /reset first.",
            )
        try:
            obs = _env.step(action)
            return obs
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Step error: {str(e)}")


@app.get("/state", response_model=EnvironmentState)
def state():
    """
    Get current episode metadata without consuming a step.

    Returns episode_id, task_id, step_count, max_steps, done,
    cumulative_reward, alert_count, classified_count, seed.
    """
    with _env_lock:
        try:
            return _env.state()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"State error: {str(e)}")


@app.get("/")
def root():
    """Environment info endpoint."""
    return {
        "name": "soc-triage-gym",
        "version": "0.1.0",
        "description": "SOC Triage RL Environment — OpenEnv compliant",
        "tasks": ["phishing", "lateral_movement", "queue_management"],
        "endpoints": {
            "reset": "POST /reset",
            "step": "POST /step",
            "state": "GET /state",
            "health": "GET /health",
            "docs": "GET /docs",
        },
    }


# ---------------------------------------------------------------------------
# Application factory (for testing)
# ---------------------------------------------------------------------------

def create_app() -> FastAPI:
    """Return the FastAPI application instance."""
    return app
