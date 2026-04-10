"""
SOC-Triage-Gym Pydantic Models
================================
All Pydantic v2 models for the SOC-Triage-Gym environment.
This module is the central contract — every other module imports from here.

Public (exposed to agent): SOCAction, SOCObservation, SOCReward, and all sub-models.
Internal (not sent to agent): GroundTruth, ScenarioConfig.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, ConfigDict


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class AlertSeverity(str, Enum):
    """Severity levels for SIEM alerts."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertClassification(str, Enum):
    """Classification outcomes for a security alert."""
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN_TRUE_POSITIVE = "benign_true_positive"
    UNCLASSIFIED = "unclassified"


class IndicatorType(str, Enum):
    """Types of threat indicators that can be enriched."""
    IP = "ip"
    DOMAIN = "domain"
    FILE_HASH = "file_hash"
    EMAIL = "email"
    URL = "url"
    USER = "user"


class LogSource(str, Enum):
    """Available SIEM log sources to query."""
    FIREWALL = "firewall"
    PROXY = "proxy"
    DNS = "dns"
    ENDPOINT = "endpoint"
    AUTH = "auth"
    EMAIL_GATEWAY = "email_gateway"
    IDS = "ids"
    CLOUD_TRAIL = "cloud_trail"


class CorrelationType(str, Enum):
    """How two alerts are correlated."""
    SOURCE_IP = "source_ip"
    DESTINATION_IP = "destination_ip"
    USER = "user"
    TECHNIQUE = "technique"
    TIME_WINDOW = "time_window"
    HOSTNAME = "hostname"
    FILE_HASH = "file_hash"
    DOMAIN = "domain"


class ResponseActionType(str, Enum):
    """Containment and response actions available to the analyst."""
    ISOLATE_ENDPOINT = "isolate_endpoint"
    DISABLE_ACCOUNT = "disable_account"
    BLOCK_IP = "block_ip"
    BLOCK_DOMAIN = "block_domain"
    QUARANTINE_FILE = "quarantine_file"
    RESET_PASSWORD = "reset_password"
    REVOKE_SESSIONS = "revoke_sessions"
    NO_ACTION = "no_action"


class ActionType(str, Enum):
    """All actions available to the SOC analyst agent."""
    ENRICH_INDICATOR = "enrich_indicator"
    QUERY_LOGS = "query_logs"
    CORRELATE_ALERTS = "correlate_alerts"
    CHECK_ASSET = "check_asset"
    CHECK_USER = "check_user"
    CLASSIFY_ALERT = "classify_alert"
    MAP_TECHNIQUE = "map_technique"
    RECOMMEND_ACTION = "recommend_action"
    ESCALATE = "escalate"
    SUBMIT_INVESTIGATION = "submit_investigation"
    NOOP = "noop"


# ---------------------------------------------------------------------------
# Observation Sub-models
# ---------------------------------------------------------------------------

class AlertMeta(BaseModel):
    """Metadata for a single SIEM alert visible to the agent."""

    model_config = ConfigDict(frozen=False)

    alert_id: str = Field(..., description="Unique alert identifier")
    title: str = Field(..., description="Human-readable alert title")
    description: str = Field(..., description="Detailed alert description")
    severity: AlertSeverity = Field(..., description="Alert severity level")
    source_system: str = Field(..., description="SIEM source system (e.g. 'Email Security', 'EDR')")
    timestamp: str = Field(..., description="ISO8601 timestamp when alert fired")
    rule_triggered: str = Field(..., description="Detection rule name that triggered this alert")
    indicators: Dict[str, List[str]] = Field(
        default_factory=dict,
        description="Threat indicators grouped by type: {ip: [...], domain: [...], file_hash: [...], email: [...], url: [...]}"
    )
    raw_log_snippet: Optional[str] = Field(None, description="Raw log excerpt that triggered the alert")
    related_alert_ids: List[str] = Field(default_factory=list, description="Alert IDs that may be related")
    classification: AlertClassification = Field(
        default=AlertClassification.UNCLASSIFIED,
        description="Current classification (starts as unclassified)"
    )


class EnrichmentResult(BaseModel):
    """Threat intelligence enrichment result for a single indicator."""

    model_config = ConfigDict(frozen=False)

    indicator: str = Field(..., description="The indicator value that was enriched")
    indicator_type: IndicatorType = Field(..., description="Type of indicator")
    malicious: bool = Field(..., description="Whether indicator is known malicious")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score 0.0-1.0")
    threat_score: int = Field(default=0, ge=0, le=100, description="Threat score 0-100")
    threat_type: Optional[str] = Field(None, description="Threat category: phishing, c2, spam, malware, etc.")
    first_seen: Optional[str] = Field(None, description="ISO8601 date first seen in threat feeds")
    last_seen: Optional[str] = Field(None, description="ISO8601 date last seen in threat feeds")
    geo_location: Optional[str] = Field(None, description="Country/region for IP indicators")
    whois_info: Optional[str] = Field(None, description="WHOIS registration summary")
    associated_malware: List[str] = Field(default_factory=list, description="Associated malware family names")
    tags: List[str] = Field(default_factory=list, description="Threat intelligence tags")
    source: str = Field(default="threat_intel", description="Threat intel source name")
    raw_data: Dict[str, Any] = Field(default_factory=dict, description="Additional raw intel data")


class LogEntry(BaseModel):
    """A single log event returned from a SIEM query."""

    model_config = ConfigDict(frozen=False)

    timestamp: str = Field(..., description="ISO8601 event timestamp")
    source: LogSource = Field(..., description="Log source system")
    event_type: str = Field(..., description="Event classification (e.g. 'email_received', 'process_created')")
    src_ip: Optional[str] = Field(None, description="Source IP address")
    dst_ip: Optional[str] = Field(None, description="Destination IP address")
    user: Optional[str] = Field(None, description="Username associated with event")
    hostname: Optional[str] = Field(None, description="Hostname where event occurred")
    action: Optional[str] = Field(None, description="Action taken (allow, block, execute, etc.)")
    severity: Optional[str] = Field(None, description="Event severity")
    details: Dict[str, Any] = Field(default_factory=dict, description="Source-specific event details")
    raw: Optional[str] = Field(None, description="Raw log line")


class CorrelatedEvent(BaseModel):
    """A correlation link found between two or more alerts."""

    model_config = ConfigDict(frozen=False)

    alert_ids: List[str] = Field(..., description="IDs of correlated alerts")
    correlation_type: CorrelationType = Field(..., description="How these alerts are correlated")
    shared_indicator: str = Field(..., description="The shared indicator value that links them")
    description: str = Field(..., description="Human-readable description of the correlation")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Correlation confidence 0.0-1.0")
    relevance_score: float = Field(default=0.5, ge=0.0, le=1.0, description="How relevant this correlation is to the investigation")


class AssetInfo(BaseModel):
    """Asset inventory information for a host."""

    model_config = ConfigDict(frozen=False)

    asset_id: str = Field(..., description="Unique asset identifier")
    hostname: str = Field(..., description="Asset hostname")
    asset_type: str = Field(..., description="Asset type: workstation, server, domain_controller, etc.")
    criticality: str = Field(..., description="Business criticality: critical, high, medium, low")
    owner: str = Field(..., description="Username of asset owner/primary user")
    department: str = Field(..., description="Owning department")
    ip_address: str = Field(..., description="Primary IP address")
    os: Optional[str] = Field(None, description="Operating system")
    patch_status: Optional[str] = Field(None, description="Patch compliance status")
    last_scan: Optional[str] = Field(None, description="ISO8601 date of last security scan")
    open_vulnerabilities: int = Field(default=0, description="Number of open CVEs")
    recent_activity_summary: str = Field(default="", description="Brief summary of recent activity")
    tags: List[str] = Field(default_factory=list, description="Asset tags")


class UserInfo(BaseModel):
    """User profile information from directory services."""

    model_config = ConfigDict(frozen=False)

    user_id: str = Field(..., description="Unique user identifier")
    username: str = Field(..., description="Login username (samaccountname)")
    display_name: str = Field(..., description="Full display name")
    email: str = Field(..., description="Email address")
    role: str = Field(..., description="Job title/role")
    department: str = Field(..., description="Department")
    access_level: str = Field(..., description="Access tier: standard, elevated, admin, service")
    is_privileged: bool = Field(default=False, description="Has privileged/admin access")
    manager: Optional[str] = Field(None, description="Manager username")
    last_login: Optional[str] = Field(None, description="ISO8601 datetime of last login")
    login_anomaly_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Anomaly score for login patterns")
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0, description="User risk score from UEBA")
    recent_actions: List[str] = Field(default_factory=list, description="Recent notable actions")


class InvestigationState(BaseModel):
    """
    Tracks all agent actions for a single alert during the episode.
    This is the primary data structure that graders evaluate.
    """

    model_config = ConfigDict(frozen=False)

    alert_id: str = Field(..., description="Alert being investigated")
    enriched_indicators: Dict[str, EnrichmentResult] = Field(
        default_factory=dict,
        description="Indicators enriched: {indicator_value: EnrichmentResult}"
    )
    queried_sources: Dict[str, List[LogEntry]] = Field(
        default_factory=dict,
        description="Log sources queried: {source_name: [LogEntry, ...]}"
    )
    correlations_found: List[CorrelatedEvent] = Field(
        default_factory=list,
        description="Correlations discovered involving this alert"
    )
    assets_looked_up: Dict[str, AssetInfo] = Field(
        default_factory=dict,
        description="Assets investigated: {hostname: AssetInfo}"
    )
    users_looked_up: Dict[str, UserInfo] = Field(
        default_factory=dict,
        description="Users investigated: {username: UserInfo}"
    )
    classification: Optional[AlertClassification] = Field(
        None, description="Agent's classification decision"
    )
    classification_confidence: float = Field(
        default=0.0, ge=0.0, le=1.0,
        description="Agent's confidence in classification"
    )
    mapped_techniques: List[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK technique IDs mapped by agent (e.g. T1566.001)"
    )
    recommended_actions: List[ResponseActionType] = Field(
        default_factory=list,
        description="Response actions recommended by agent"
    )
    escalated: bool = Field(default=False, description="Whether alert was escalated")
    escalation_severity: Optional[str] = Field(None, description="Escalation severity if escalated")
    escalation_justification: Optional[str] = Field(None, description="Reason for escalation")
    evidence_timeline: List[str] = Field(
        default_factory=list,
        description="Chronological list of evidence gathered (human-readable)"
    )
    reward_breakdown: Dict[str, float] = Field(
        default_factory=dict,
        description="Step-by-step reward contributions"
    )


# ---------------------------------------------------------------------------
# Top-level Action Model
# ---------------------------------------------------------------------------

class SOCAction(BaseModel):
    """
    Flat action model for the SOC analyst agent.
    The action_type field determines which optional fields are relevant.

    Example actions:
        {"action_type": "enrich_indicator", "indicator": "1.2.3.4", "indicator_type": "ip"}
        {"action_type": "query_logs", "log_source": "firewall", "query_alert_id": "ALT-001"}
        {"action_type": "classify_alert", "alert_id": "ALT-001", "classification": "true_positive"}
        {"action_type": "submit_investigation"}
        {"action_type": "noop"}
    """

    model_config = ConfigDict(frozen=False)

    action_type: ActionType = Field(..., description="Type of action to perform")

    # --- enrich_indicator params ---
    indicator: Optional[str] = Field(None, description="Indicator value to enrich (IP, domain, hash, email, URL)")
    indicator_type: Optional[IndicatorType] = Field(None, description="Type of indicator being enriched")

    # --- query_logs params ---
    log_source: Optional[LogSource] = Field(None, description="Log source to query")
    query_alert_id: Optional[str] = Field(None, description="Alert ID providing context for log query")
    time_window_hours: Optional[int] = Field(24, description="Time window for log query in hours (default 24)")

    # --- correlate_alerts params ---
    alert_id_a: Optional[str] = Field(None, description="First alert ID for correlation check")
    alert_id_b: Optional[str] = Field(None, description="Second alert ID for correlation check")

    # --- check_asset params ---
    hostname: Optional[str] = Field(None, description="Hostname to look up in asset inventory")

    # --- check_user params ---
    username: Optional[str] = Field(None, description="Username to look up in user directory")

    # --- classify_alert params ---
    alert_id: Optional[str] = Field(None, description="Alert ID to classify")
    classification: Optional[AlertClassification] = Field(None, description="Classification decision")
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0, description="Classification confidence 0.0-1.0")

    # --- map_technique params ---
    technique_id: Optional[str] = Field(None, description="MITRE ATT&CK technique ID (e.g. T1566.001)")

    # --- recommend_action params ---
    response_action: Optional[ResponseActionType] = Field(None, description="Recommended containment action")
    action_target: Optional[str] = Field(None, description="Target of the response action (IP, hostname, username, etc.)")

    # --- escalate params ---
    escalation_severity: Optional[str] = Field(None, description="Escalation severity: critical or high")
    justification: Optional[str] = Field(None, description="Justification for escalation")


# ---------------------------------------------------------------------------
# Top-level Observation Model
# ---------------------------------------------------------------------------

class SOCObservation(BaseModel):
    """
    Full observation returned to the agent after each step() or reset() call.
    Contains the current alert queue, investigation state, and all results
    from the most recent action.
    """

    model_config = ConfigDict(frozen=False)

    # Alert queue
    alert_queue: List[AlertMeta] = Field(
        default_factory=list,
        description="All alerts for this episode. Severity and indicators visible to agent."
    )

    # Investigation state (per-alert tracking)
    investigations: Dict[str, InvestigationState] = Field(
        default_factory=dict,
        description="Per-alert investigation state keyed by alert_id"
    )

    # Results from most recent action (populated after each step)
    enrichment_results: List[EnrichmentResult] = Field(
        default_factory=list,
        description="Threat intel results from most recent enrich_indicator action"
    )
    log_results: List[LogEntry] = Field(
        default_factory=list,
        description="Log entries from most recent query_logs action"
    )
    correlated_events: List[CorrelatedEvent] = Field(
        default_factory=list,
        description="All correlations discovered so far this episode"
    )
    asset_info: Optional[AssetInfo] = Field(None, description="Asset info from most recent check_asset action")
    user_info: Optional[UserInfo] = Field(None, description="User info from most recent check_user action")

    # Episode metadata
    investigation_budget: int = Field(..., description="Remaining steps before forced termination")
    step: int = Field(..., description="Current step number (0-indexed)")
    done: bool = Field(..., description="True when episode has ended")
    reward: float = Field(..., description="Reward earned in this step")
    cumulative_reward: float = Field(..., description="Total reward accumulated this episode")
    message: str = Field(default="", description="Human-readable status message from environment")

    # Task context
    task_id: Optional[str] = Field(None, description="Active task ID")
    episode_id: Optional[str] = Field(None, description="Unique episode identifier")

    # Final normalized task score (0,1) — populated after submit_investigation
    task_score: Optional[float] = Field(None, description="Normalized grader score in (0,1) after episode ends")


# ---------------------------------------------------------------------------
# Reward Model
# ---------------------------------------------------------------------------

class SOCReward(BaseModel):
    """Detailed reward breakdown for a single step."""

    model_config = ConfigDict(frozen=False)

    total: float = Field(..., description="Total step reward")
    enrichment_reward: float = Field(default=0.0, description="Reward from indicator enrichment")
    log_query_reward: float = Field(default=0.0, description="Reward from log queries")
    correlation_reward: float = Field(default=0.0, description="Reward from alert correlations")
    classification_reward: float = Field(default=0.0, description="Reward from classification actions")
    response_reward: float = Field(default=0.0, description="Reward from response recommendations")
    efficiency_penalty: float = Field(default=0.0, description="Penalty for inefficient actions")
    missed_tp_penalty: float = Field(default=0.0, description="Penalty for missing true positives")
    final_grader_reward: float = Field(default=0.0, description="Final grader score contribution")
    explanation: str = Field(default="", description="Human-readable explanation of reward")


# ---------------------------------------------------------------------------
# Internal Models (NOT exposed to agent)
# ---------------------------------------------------------------------------

class GroundTruth(BaseModel):
    """
    Answer key for a scenario. Stored server-side only.
    Never serialized in the Observation returned to the agent.
    """

    model_config = ConfigDict(frozen=False)

    alert_classifications: Dict[str, AlertClassification] = Field(
        default_factory=dict,
        description="Correct classification for each alert_id"
    )
    true_positive_ids: List[str] = Field(default_factory=list, description="Alert IDs that are true positives")
    false_positive_ids: List[str] = Field(default_factory=list, description="Alert IDs that are false positives")
    benign_tp_ids: List[str] = Field(default_factory=list, description="Alert IDs that are benign true positives")
    expected_techniques: Dict[str, List[str]] = Field(
        default_factory=dict,
        description="Expected MITRE ATT&CK techniques per alert_id: {alert_id: [T1566.001, ...]}"
    )
    expected_response_actions: Dict[str, List[ResponseActionType]] = Field(
        default_factory=dict,
        description="Expected response actions per alert_id"
    )
    kill_chain_order: Optional[List[str]] = Field(
        None,
        description="Ordered alert IDs forming the attack kill chain (lateral movement and queue tasks)"
    )
    relevant_log_sources: Dict[str, List[LogSource]] = Field(
        default_factory=dict,
        description="Log sources that contain relevant evidence per alert_id"
    )
    relevant_indicators: Dict[str, List[str]] = Field(
        default_factory=dict,
        description="Indicator values worth enriching per alert_id"
    )
    attack_chain_ids: List[List[str]] = Field(
        default_factory=list,
        description="For queue management: list of attack chains, each a list of related alert IDs"
    )


class ScenarioConfig(BaseModel):
    """
    Complete scenario configuration including all simulated data.
    Stored server-side and used to answer all tool queries.
    Never sent to the agent.
    """

    model_config = ConfigDict(frozen=False)

    scenario_id: str = Field(..., description="Unique scenario identifier")
    task_id: str = Field(..., description="Task this scenario belongs to")
    seed: int = Field(..., description="RNG seed used to generate this scenario")
    description: str = Field(..., description="Human-readable scenario description")
    max_steps: int = Field(..., description="Maximum steps before episode termination")
    alerts: List[AlertMeta] = Field(..., description="All alerts presented to agent")
    enrichment_db: Dict[str, EnrichmentResult] = Field(
        default_factory=dict,
        description="Threat intel database: {indicator_value: EnrichmentResult}"
    )
    log_db: Dict[str, Dict[str, List[LogEntry]]] = Field(
        default_factory=dict,
        description="Log database: {source_name: {alert_id: [LogEntry, ...]}}"
    )
    asset_db: Dict[str, AssetInfo] = Field(
        default_factory=dict,
        description="Asset inventory: {hostname: AssetInfo}"
    )
    user_db: Dict[str, UserInfo] = Field(
        default_factory=dict,
        description="User directory: {username: UserInfo}"
    )
    ground_truth: GroundTruth = Field(..., description="Answer key — never exposed to agent")


# ---------------------------------------------------------------------------
# Environment State Model
# ---------------------------------------------------------------------------

class EnvironmentState(BaseModel):
    """Current episode state returned by GET /state."""

    model_config = ConfigDict(frozen=False)

    episode_id: Optional[str] = Field(None, description="Current episode ID")
    task_id: Optional[str] = Field(None, description="Current task ID")
    step_count: int = Field(default=0, description="Steps taken so far")
    max_steps: int = Field(default=0, description="Maximum steps for this episode")
    done: bool = Field(default=False, description="Whether episode is complete")
    cumulative_reward: float = Field(default=0.0, description="Total reward so far")
    alert_count: int = Field(default=0, description="Number of alerts in queue")
    classified_count: int = Field(default=0, description="Number of alerts classified so far")
    seed: Optional[int] = Field(None, description="Scenario seed")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional episode metadata")
