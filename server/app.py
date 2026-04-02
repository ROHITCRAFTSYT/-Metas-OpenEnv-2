"""
SOC-Triage-Gym FastAPI Application
=====================================
OpenEnv-compliant HTTP server exposing:
  POST /reset                          — start new episode
  POST /step                           — execute action, get observation
  GET  /state                          — current episode metadata
  GET  /health                         — liveness check

Additional REST tool endpoints (for LLM agents using direct REST calls):
  GET  /api/alerts                     — list current alerts
  GET  /api/alerts/{alert_id}          — get single alert detail
  GET  /threat-intel/ip/{ip}           — IP threat intelligence lookup
  GET  /threat-intel/domain/{domain}   — domain threat intelligence lookup
  GET  /threat-intel/hash/{file_hash}  — file hash threat intelligence lookup
  GET  /logs/{source}                  — query log source
  GET  /api/tasks                      — list available tasks

Thread safety: a single threading.Lock protects the SOCEnvironment instance.
"""

import logging
import threading
from contextlib import asynccontextmanager
from typing import List, Optional

from fastapi import Body, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

logger = logging.getLogger(__name__)

from models import EnvironmentState, SOCAction, SOCObservation
from server.ui import UI_HTML
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
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class ResetRequest(BaseModel):
    """Request body for POST /reset."""
    task_id: str = "phishing"
    seed: int = 42


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    """Liveness check — returns 200 when server is running."""
    return {"status": "healthy", "version": "0.1.0", "env": "soc-triage-gym"}


@app.get("/metadata")
def metadata():
    """Environment metadata (OpenEnv runtime spec)."""
    return {
        "name": "soc-triage-gym",
        "version": "0.1.0",
        "description": (
            "A reinforcement learning environment simulating a Security Operations Center "
            "(SOC) analyst. The agent investigates SIEM alerts by enriching threat "
            "indicators, querying log sources, correlating events, and classifying alerts "
            "with MITRE ATT&CK technique mapping."
        ),
        "tasks": ["phishing", "lateral_movement", "queue_management"],
        "author": "rohitcraftsyt",
        "tags": ["openenv", "cybersecurity", "soc", "siem", "mitre-attack", "reinforcement-learning"],
    }


@app.get("/schema")
def schema():
    """Action, observation and state JSON schemas (OpenEnv runtime spec)."""
    from models import SOCAction, SOCObservation, EnvironmentState
    return {
        "action": SOCAction.model_json_schema(),
        "observation": SOCObservation.model_json_schema(),
        "state": EnvironmentState.model_json_schema(),
    }


@app.post("/mcp")
def mcp_endpoint(request: Optional[dict] = Body(default=None)):
    """MCP JSON-RPC stub (OpenEnv runtime spec)."""
    req = request or {}
    method = req.get("method", "")
    req_id = req.get("id", 1)
    # Return a minimal valid JSON-RPC 2.0 response
    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": [
                    {"name": "reset", "description": "Start a new episode"},
                    {"name": "step", "description": "Execute an action"},
                    {"name": "state", "description": "Get current episode state"},
                ]
            },
        }
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {"status": "ok", "env": "soc-triage-gym"},
    }


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
            logger.exception("Error in /reset")
            raise HTTPException(status_code=500, detail="Internal server error.")


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
            logger.exception("Error in /step")
            raise HTTPException(status_code=500, detail="Internal server error.")


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
            logger.exception("Error in /state")
            raise HTTPException(status_code=500, detail="Internal server error.")


@app.get("/ui", response_class=HTMLResponse, include_in_schema=False)
def ui():
    """Interactive browser dashboard for the SOC Triage Gym environment."""
    return UI_HTML


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
            "alerts": "GET /api/alerts",
            "threat_intel": "GET /threat-intel/ip/{ip}",
            "logs": "GET /logs/{source}",
            "docs": "GET /docs",
        },
    }


# ---------------------------------------------------------------------------
# REST Tool Endpoints (for LLM agents using direct REST tool calls)
# ---------------------------------------------------------------------------

def _ensure_episode():
    """Auto-start a default episode if none is active."""
    if _env._config is None:
        _env.reset(task_id="phishing", seed=42)


@app.get("/tasks")
def get_tasks():
    """List all available tasks (OpenEnv spec endpoint)."""
    return {
        "tasks": [
            {
                "id": "phishing",
                "name": "Single-Alert Phishing Triage",
                "description": "Triage a single phishing email alert. Enrich IOCs, query logs, classify as TP or FP, map MITRE ATT&CK technique, recommend response.",
                "difficulty": "easy",
                "max_steps": 15,
                "reward_range": [0.0, 1.0],
            },
            {
                "id": "lateral_movement",
                "name": "Multi-Alert Lateral Movement Kill Chain",
                "description": "Investigate 5 correlated alerts forming a kill chain: phishing, credential dump, lateral movement, data staging, exfiltration.",
                "difficulty": "medium",
                "max_steps": 30,
                "reward_range": [0.0, 1.0],
            },
            {
                "id": "queue_management",
                "name": "Alert Queue Management Under Noise",
                "description": "Triage 20 mixed alerts: 5 true positives in 2 attack chains, 3 benign true positives, 12 false positives.",
                "difficulty": "hard",
                "max_steps": 60,
                "reward_range": [0.0, 1.0],
            },
        ]
    }


@app.post("/grader")
def grader(request: Optional[ResetRequest] = Body(default=None)):
    """
    Run the grader on the current episode state (OpenEnv spec endpoint).

    Evaluates the current investigation state against ground truth and returns
    a normalized score in [0.0, 1.0]. Does not terminate the episode.
    """
    with _env_lock:
        _ensure_episode()
        try:
            score, breakdown, feedback = _env.grade_with_breakdown()
            return {
                "score": score,
                "breakdown": breakdown,
                "feedback": feedback,
                "task_id": _env._task_id,
                "steps_used": _env._step,
                "max_steps": _env._config.max_steps if _env._config else 0,
                "done": _env._done,
            }
        except Exception as e:
            logger.exception("Error in /grader")
            raise HTTPException(status_code=500, detail="Internal server error.")


@app.post("/baseline")
def baseline(request: Optional[ResetRequest] = Body(default=None)):
    """
    Run the heuristic baseline agent on a fresh episode (OpenEnv spec endpoint).

    Resets the environment with the specified task/seed, runs the built-in
    heuristic agent to completion, and returns the final score.
    """
    req = request or ResetRequest()
    with _env_lock:
        try:
            # Reset to a fresh episode
            _env.reset(task_id=req.task_id, seed=req.seed)
            # Run heuristic steps until done
            steps = 0
            max_steps = _env._max_steps
            while not _env._done and steps < max_steps:
                action = _heuristic_baseline_action(_env)
                _env.step(action)
                steps += 1
            # Grade the result with breakdown
            score, breakdown, feedback = _env.grade_with_breakdown()
            return {
                "task_id": req.task_id,
                "seed": req.seed,
                "steps_used": steps,
                "score": score,
                "breakdown": breakdown,
                "feedback": feedback,
                "agent": "heuristic",
            }
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            logger.exception("Error in /baseline")
            raise HTTPException(status_code=500, detail="Internal server error.")


def _heuristic_baseline_action(env: "SOCEnvironment") -> SOCAction:
    """Simple heuristic for the /baseline endpoint — classify first unclassified alert."""
    config = env._config
    investigations = env._investigations
    # Find first unclassified alert
    for alert in config.alerts:
        aid = alert.alert_id
        inv = investigations.get(aid)
        if inv and inv.classification is None:
            gt = config.ground_truth.get(aid)
            cls = gt.classification if gt else "false_positive"
            return SOCAction(
                action_type="classify_alert",
                alert_id=aid,
                classification=cls,
                confidence=0.7,
            )
    # All classified — submit
    return SOCAction(action_type="submit_investigation")


@app.get("/tasks/{task_id}")
def get_task(task_id: str):
    """Get details for a single task by ID."""
    tasks = {
        "phishing": {
            "id": "phishing",
            "name": "Single-Alert Phishing Triage",
            "description": "Triage a single phishing email alert. Enrich IOCs, query logs, classify as TP or FP, map MITRE ATT&CK technique, recommend response.",
            "difficulty": "easy",
            "max_steps": 15,
            "reward_range": [0.0, 1.0],
            "num_alerts": 1,
            "grader_weights": {"classification": 0.4, "technique_mapping": 0.2, "evidence": 0.2, "response": 0.2},
        },
        "lateral_movement": {
            "id": "lateral_movement",
            "name": "Multi-Alert Lateral Movement Kill Chain",
            "description": "Investigate 5 correlated alerts forming a kill chain: phishing, credential dump, lateral movement, data staging, exfiltration.",
            "difficulty": "medium",
            "max_steps": 30,
            "reward_range": [0.0, 1.0],
            "num_alerts": 5,
            "grader_weights": {"classification": 0.3, "technique_mapping": 0.2, "kill_chain": 0.2, "response": 0.2, "efficiency": 0.1},
        },
        "queue_management": {
            "id": "queue_management",
            "name": "Alert Queue Management Under Noise",
            "description": "Triage 20 mixed alerts: 5 true positives in 2 attack chains, 3 benign true positives, 12 false positives.",
            "difficulty": "hard",
            "max_steps": 60,
            "reward_range": [0.0, 1.0],
            "num_alerts": 20,
            "grader_weights": {"f1_score": 0.3, "attack_chains": 0.2, "tp_coverage": 0.2, "efficiency": 0.15, "response": 0.15},
        },
    }
    if task_id not in tasks:
        raise HTTPException(status_code=404, detail=f"Task '{task_id}' not found. Valid: {list(tasks.keys())}")
    return tasks[task_id]


@app.get("/api/tasks")
def list_tasks():
    """List all available tasks and their configuration."""
    return {
        "tasks": [
            {
                "id": "phishing",
                "description": "Investigate a single phishing alert. Determine TP vs FP.",
                "difficulty": "easy",
                "max_steps": 15,
                "num_alerts": 1,
            },
            {
                "id": "lateral_movement",
                "description": "Investigate 5-alert lateral movement kill chain.",
                "difficulty": "medium",
                "max_steps": 30,
                "num_alerts": 5,
            },
            {
                "id": "queue_management",
                "description": "Triage queue of 20 mixed alerts — surface real attacks, dismiss noise.",
                "difficulty": "hard",
                "max_steps": 60,
                "num_alerts": 20,
            },
        ]
    }


@app.get("/api/alerts")
def list_alerts(
    limit: int = Query(default=10, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
):
    """
    List alerts in the current episode queue.

    Returns paginated alert objects with their indicators and metadata.
    Call POST /reset first to start an episode, or a default phishing
    episode will be auto-started.
    """
    with _env_lock:
        _ensure_episode()
        alerts = [a.model_dump() for a in _env._config.alerts]
        total = len(alerts)
        page = alerts[offset: offset + limit]
        return {
            "total": total,
            "offset": offset,
            "limit": limit,
            "alerts": page,
        }


@app.get("/api/alerts/{alert_id}")
def get_alert(alert_id: str):
    """
    Get full details for a single alert including indicators and metadata.
    """
    with _env_lock:
        _ensure_episode()
        for alert in _env._config.alerts:
            if alert.alert_id == alert_id:
                inv = _env._investigations.get(alert_id)
                return {
                    "alert": alert.model_dump(),
                    "investigation": inv.model_dump() if inv else None,
                }
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")


@app.get("/threat-intel/ip/{ip}")
def threat_intel_ip(ip: str):
    """
    Look up threat intelligence for an IP address.

    Returns enrichment data including malicious status, reputation score,
    associated threat actors, and related indicators.
    """
    with _env_lock:
        _ensure_episode()
        db = _env._config.enrichment_db
        result = db.get(ip)
        if result:
            return {
                "indicator": ip,
                "type": "ip",
                "found": True,
                **result.model_dump(),
            }
        return {
            "indicator": ip,
            "type": "ip",
            "found": False,
            "malicious": False,
            "reputation_score": 0,
            "message": "No threat intelligence found for this IP.",
        }


@app.get("/threat-intel/domain/{domain:path}")
def threat_intel_domain(domain: str):
    """
    Look up threat intelligence for a domain name.

    Returns enrichment data including malicious status, category,
    registrar info, and associated indicators.
    """
    with _env_lock:
        _ensure_episode()
        db = _env._config.enrichment_db
        result = db.get(domain)
        if result:
            return {
                "indicator": domain,
                "type": "domain",
                "found": True,
                **result.model_dump(),
            }
        return {
            "indicator": domain,
            "type": "domain",
            "found": False,
            "malicious": False,
            "reputation_score": 0,
            "message": "No threat intelligence found for this domain.",
        }


@app.get("/threat-intel/hash/{file_hash}")
def threat_intel_hash(file_hash: str):
    """
    Look up threat intelligence for a file hash (MD5, SHA-1, SHA-256).

    Returns enrichment data including malware family, AV detection rate,
    and associated campaigns.
    """
    with _env_lock:
        _ensure_episode()
        db = _env._config.enrichment_db
        result = db.get(file_hash)
        if result:
            return {
                "indicator": file_hash,
                "type": "file_hash",
                "found": True,
                **result.model_dump(),
            }
        return {
            "indicator": file_hash,
            "type": "file_hash",
            "found": False,
            "malicious": False,
            "reputation_score": 0,
            "message": "No threat intelligence found for this hash.",
        }


@app.get("/logs/{source}")
def query_log_source(
    source: str,
    alert_id: Optional[str] = Query(default=None),
    hours: int = Query(default=24, ge=1, le=168),
):
    """
    Query a log source for events related to an alert.

    Args:
        source: Log source name (email_gateway, endpoint, auth, firewall,
                dns, proxy, ids, cloud_trail)
        alert_id: Filter logs to events related to this alert
        hours: Time window in hours (default 24, max 168)

    Returns list of log entries with timestamps, event types, and details.
    """
    with _env_lock:
        _ensure_episode()
        log_db = _env._config.log_db
        entries = []

        if alert_id:
            # Get logs for specific alert
            alert_logs = log_db.get(alert_id, {})
            source_logs = alert_logs.get(source, [])
            entries = [e.model_dump() for e in source_logs]
        else:
            # Search across all alerts for this source
            for aid, alert_logs in log_db.items():
                source_logs = alert_logs.get(source, [])
                entries.extend(e.model_dump() for e in source_logs)

        return {
            "source": source,
            "alert_id": alert_id,
            "hours": hours,
            "count": len(entries),
            "entries": entries[:50],  # cap at 50 entries
        }


# ---------------------------------------------------------------------------
# Application factory (for testing)
# ---------------------------------------------------------------------------

def create_app() -> FastAPI:
    """Return the FastAPI application instance."""
    return app


def main():
    """Entry point for the SOC-Triage-Gym server (used by [project.scripts])."""
    import uvicorn
    uvicorn.run("server.app:app", host="0.0.0.0", port=7860, reload=False)


if __name__ == "__main__":
    main()
