from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field
from typing import Any, Callable

import httpx


SIGNUP_URL = "https://accounts.x.ai/sign-up"
DEFAULT_TOKEN_TIMEOUT = 90
DEFAULT_QUEUE_WAIT_TIMEOUT = 5.0
DEFAULT_POLL_INTERVAL = 2.0
DEFAULT_BREAKER_SECONDS = 15.0
DEFAULT_BREAKER_THRESHOLD = 2
DEFAULT_TOKEN_MAX_AGE = 110.0
DEFAULT_SOFT_PENALTY_SECONDS = 20.0
DEFAULT_PREFETCH_MIN_HEALTH_SCORE = 55
DEFAULT_DIRECT_MIN_HEALTH_SCORE = 35
DEFAULT_RECOVERING_OBSERVE_SECONDS = 10.0
DEFAULT_REINIT_TRIGGER_STREAK = 2
DEFAULT_REINIT_COOLDOWN_SECONDS = 120.0
DEFAULT_REINIT_REQUEST_TIMEOUT = 20.0
DEFAULT_REINIT_MAX_TARGETS = 2
DEFAULT_LIFECYCLE_REQUEST_TIMEOUT = 15.0
DEFAULT_DRAIN_GRACE_SECONDS = 20.0
DEFAULT_HEARTBEAT_INTERVAL_SECONDS = 25.0
DEFAULT_LEASE_TTL_SECONDS = 90.0


@dataclass
class PrefetchedToken:
    token: str
    sitekey: str
    node_url: str
    created_at: float

    def is_expired(self, max_age: float) -> bool:
        return (time.time() - self.created_at) > max_age


@dataclass
class RemoteSolverNodeState:
    url: str
    node_id: str = ""
    node_label: str = ""
    boot_id: str = ""
    started_at: float = 0.0
    init_count: int = 0
    last_init_at: float = 0.0
    last_init_reason: str = ""
    last_init_result: str = ""
    last_reinit_requested_by: str = ""
    last_reinit_source: str = ""
    last_reinit_request_at: float = 0.0
    last_reinit_finished_at: float = 0.0
    last_reinit_error: str = ""
    last_reinit_status: str = ""
    last_reinit_message: str = ""
    last_reinit_mode: str = ""
    last_reinit_trigger_summary: str = ""
    last_force_reinit_at: float = 0.0
    force_reinit_count: int = 0
    last_rebuild_browser_count: int = 0
    last_reinit_drained_indexes: list[int] = field(default_factory=list)
    reinit_in_progress: bool = False
    reinit_supported: bool = False
    reinit_cooldown_until: float = 0.0
    lifecycle_state: str = "offline"
    drain_requested_at: float = 0.0
    drain_started_at: float = 0.0
    drain_finished_at: float = 0.0
    standby_entered_at: float = 0.0
    last_task_received_at: float = 0.0
    last_task_finished_at: float = 0.0
    idle_since: float = 0.0
    idle_seconds: float = 0.0
    accepting_new_tasks: bool = False
    standby_reason: str = ""
    last_lease_at: float = 0.0
    lease_expires_at: float = 0.0
    lease_owner: str = ""
    pending_drain_reason: str = ""
    idle_soft_recycle_count: int = 0
    idle_standby_count: int = 0
    manual_drain_count: int = 0
    lease_expired_standby_count: int = 0
    standby_auto_resume: bool = True
    online: bool = False
    available_browsers: int = 0
    raw_available_browsers: int = 0
    reserved_slots: int = 0
    total_browsers: int = 0
    tracked_tasks: int = 0
    active_task_count: int = 0
    in_flight_total: int = 0
    in_flight_prefetch: int = 0
    in_flight_direct: int = 0
    consecutive_failures: int = 0
    success_count: int = 0
    fail_count: int = 0
    rejected_count: int = 0
    total_solve_time: float = 0.0
    health_score: int = 100
    health_status: str = "unknown"
    degraded_reason: str = ""
    soft_penalty_until: float = 0.0
    recovering_until: float = 0.0
    recent_timeout_count: int = 0
    recent_captcha_fail_count: int = 0
    avg_solve_time_recent: float = 0.0
    last_degraded_at: float = 0.0
    last_error: str = ""
    last_stage: str = ""
    last_message: str = ""
    last_status: str = ""
    last_http_status: int = 0
    last_seen_at: float = 0.0
    breaker_until: float = 0.0

    @property
    def avg_solve_time(self) -> float:
        if self.success_count <= 0:
            return 0.0
        return self.total_solve_time / self.success_count

    @property
    def success_rate(self) -> float:
        total = self.success_count + self.fail_count
        if total <= 0:
            return 1.0
        return self.success_count / total

    @property
    def breaker_active(self) -> bool:
        return self.breaker_until > time.time()

    @property
    def breaker_remaining(self) -> float:
        return max(self.breaker_until - time.time(), 0.0)

    @property
    def effective_capacity(self) -> int:
        return max(self.available_browsers - self.in_flight_total, 0)

    @property
    def soft_penalty_active(self) -> bool:
        return self.soft_penalty_until > time.time()

    @property
    def soft_penalty_remaining(self) -> float:
        return max(self.soft_penalty_until - time.time(), 0.0)

    @property
    def recovering_active(self) -> bool:
        return self.recovering_until > time.time()

    @property
    def recovering_remaining(self) -> float:
        return max(self.recovering_until - time.time(), 0.0)

    @property
    def reinit_cooldown_remaining(self) -> float:
        return max(self.reinit_cooldown_until - time.time(), 0.0)

    @property
    def effective_lifecycle_state(self) -> str:
        if not self.online:
            return "offline"
        if self.reinit_in_progress:
            return "reinitializing"
        state = str(self.lifecycle_state or "").strip().lower()
        if state in {"active", "draining", "standby", "reinitializing"}:
            return state
        return "active" if self.accepting_new_tasks else "standby"

    @property
    def lease_expired(self) -> bool:
        return bool(self.lease_expires_at and time.time() >= self.lease_expires_at)

    def snapshot(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "node_id": self.node_id,
            "node_label": self.node_label,
            "boot_id": self.boot_id,
            "started_at": round(self.started_at, 3) if self.started_at else 0.0,
            "init_count": self.init_count,
            "last_init_at": round(self.last_init_at, 3) if self.last_init_at else 0.0,
            "last_init_reason": self.last_init_reason,
            "last_init_result": self.last_init_result,
            "last_reinit_requested_by": self.last_reinit_requested_by,
            "last_reinit_source": self.last_reinit_source,
            "last_reinit_request_at": round(self.last_reinit_request_at, 3) if self.last_reinit_request_at else 0.0,
            "last_reinit_finished_at": round(self.last_reinit_finished_at, 3) if self.last_reinit_finished_at else 0.0,
            "last_reinit_error": self.last_reinit_error,
            "last_reinit_status": self.last_reinit_status,
            "last_reinit_message": self.last_reinit_message,
            "last_reinit_mode": self.last_reinit_mode,
            "last_reinit_trigger_summary": self.last_reinit_trigger_summary,
            "last_force_reinit_at": round(self.last_force_reinit_at, 3) if self.last_force_reinit_at else 0.0,
            "force_reinit_count": self.force_reinit_count,
            "last_rebuild_browser_count": self.last_rebuild_browser_count,
            "last_reinit_drained_indexes": list(self.last_reinit_drained_indexes),
            "reinit_in_progress": self.reinit_in_progress,
            "reinit_supported": self.reinit_supported,
            "reinit_cooldown_until": round(self.reinit_cooldown_until, 3) if self.reinit_cooldown_until else 0.0,
            "reinit_cooldown_remaining": round(self.reinit_cooldown_remaining, 3),
            "lifecycle_state": self.effective_lifecycle_state,
            "drain_requested_at": round(self.drain_requested_at, 3) if self.drain_requested_at else 0.0,
            "drain_started_at": round(self.drain_started_at, 3) if self.drain_started_at else 0.0,
            "drain_finished_at": round(self.drain_finished_at, 3) if self.drain_finished_at else 0.0,
            "standby_entered_at": round(self.standby_entered_at, 3) if self.standby_entered_at else 0.0,
            "last_task_received_at": round(self.last_task_received_at, 3) if self.last_task_received_at else 0.0,
            "last_task_finished_at": round(self.last_task_finished_at, 3) if self.last_task_finished_at else 0.0,
            "idle_since": round(self.idle_since, 3) if self.idle_since else 0.0,
            "idle_seconds": round(self.idle_seconds, 3),
            "accepting_new_tasks": self.accepting_new_tasks,
            "standby_reason": self.standby_reason,
            "last_lease_at": round(self.last_lease_at, 3) if self.last_lease_at else 0.0,
            "lease_expires_at": round(self.lease_expires_at, 3) if self.lease_expires_at else 0.0,
            "lease_owner": self.lease_owner,
            "pending_drain_reason": self.pending_drain_reason,
            "idle_soft_recycle_count": self.idle_soft_recycle_count,
            "idle_standby_count": self.idle_standby_count,
            "manual_drain_count": self.manual_drain_count,
            "lease_expired_standby_count": self.lease_expired_standby_count,
            "standby_auto_resume": self.standby_auto_resume,
            "lease_expired": self.lease_expired,
            "online": self.online,
            "available_browsers": self.available_browsers,
            "raw_available_browsers": self.raw_available_browsers,
            "reserved_slots": self.reserved_slots,
            "total_browsers": self.total_browsers,
            "tracked_tasks": self.tracked_tasks,
            "active_task_count": self.active_task_count,
            "in_flight_total": self.in_flight_total,
            "in_flight_prefetch": self.in_flight_prefetch,
            "in_flight_direct": self.in_flight_direct,
            "consecutive_failures": self.consecutive_failures,
            "success_count": self.success_count,
            "fail_count": self.fail_count,
            "rejected_count": self.rejected_count,
            "avg_solve_time": round(self.avg_solve_time, 3),
            "avg_solve_time_recent": round(self.avg_solve_time_recent, 3),
            "success_rate": round(self.success_rate, 4),
            "health_score": self.health_score,
            "health_status": self.health_status,
            "degraded_reason": self.degraded_reason,
            "soft_penalty_until": self.soft_penalty_until,
            "soft_penalty_active": self.soft_penalty_active,
            "soft_penalty_remaining": round(self.soft_penalty_remaining, 3),
            "recovering_until": self.recovering_until,
            "recovering_active": self.recovering_active,
            "recovering_remaining": round(self.recovering_remaining, 3),
            "recent_timeout_count": self.recent_timeout_count,
            "recent_captcha_fail_count": self.recent_captcha_fail_count,
            "last_degraded_at": self.last_degraded_at,
            "last_error": self.last_error,
            "last_stage": self.last_stage,
            "last_message": self.last_message,
            "last_status": self.last_status,
            "last_http_status": self.last_http_status,
            "last_seen_at": self.last_seen_at,
            "breaker_until": self.breaker_until,
            "breaker_remaining": round(self.breaker_remaining, 3),
        }


class RemoteSolverCluster:
    def __init__(
        self,
        http_client: httpx.AsyncClient,
        node_provider: Callable[[], list[str]] | None = None,
        queue_capacity: int = 0,
        queue_wait_timeout: float = DEFAULT_QUEUE_WAIT_TIMEOUT,
        token_timeout: int = DEFAULT_TOKEN_TIMEOUT,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
        token_max_age: float = DEFAULT_TOKEN_MAX_AGE,
        breaker_seconds: float = DEFAULT_BREAKER_SECONDS,
        breaker_threshold: int = DEFAULT_BREAKER_THRESHOLD,
        soft_penalty_seconds: float = DEFAULT_SOFT_PENALTY_SECONDS,
        prefetch_min_health_score: int = DEFAULT_PREFETCH_MIN_HEALTH_SCORE,
        direct_min_health_score: int = DEFAULT_DIRECT_MIN_HEALTH_SCORE,
        recovering_observe_seconds: float = DEFAULT_RECOVERING_OBSERVE_SECONDS,
        admin_token: str = "",
        reinit_enabled: bool = False,
        reinit_trigger_streak: int = DEFAULT_REINIT_TRIGGER_STREAK,
        reinit_cooldown_seconds: float = DEFAULT_REINIT_COOLDOWN_SECONDS,
        reinit_request_timeout: float = DEFAULT_REINIT_REQUEST_TIMEOUT,
        reinit_max_targets: int = DEFAULT_REINIT_MAX_TARGETS,
        reinit_allow_broadcast: bool = False,
        reinit_requested_by: str = "remote_solver_cluster",
        lifecycle_request_timeout: float = DEFAULT_LIFECYCLE_REQUEST_TIMEOUT,
        drain_grace_seconds: float = DEFAULT_DRAIN_GRACE_SECONDS,
        heartbeat_interval_seconds: float = DEFAULT_HEARTBEAT_INTERVAL_SECONDS,
        lease_ttl_seconds: float = DEFAULT_LEASE_TTL_SECONDS,
        lease_owner: str = "register-main",
    ):
        self.http_client = http_client
        self.node_provider = node_provider
        self.queue_capacity = max(int(queue_capacity or 0), 0)
        self.token_queue: asyncio.Queue[PrefetchedToken] = asyncio.Queue(maxsize=max(self.queue_capacity, 1))
        self.queue_wait_timeout = max(float(queue_wait_timeout), 0.1)
        self.token_timeout = max(int(token_timeout), 1)
        self.poll_interval = max(float(poll_interval), 0.2)
        self.token_max_age = max(float(token_max_age), 10.0)
        self.breaker_seconds = max(float(breaker_seconds), 1.0)
        self.breaker_threshold = max(int(breaker_threshold), 1)
        self.soft_penalty_seconds = max(float(soft_penalty_seconds), 1.0)
        self.prefetch_min_health_score = max(min(int(prefetch_min_health_score), 100), 0)
        self.direct_min_health_score = max(min(int(direct_min_health_score), 100), 0)
        self.recovering_observe_seconds = max(float(recovering_observe_seconds), 1.0)
        self.admin_token = str(admin_token or "").strip()
        self.reinit_enabled = bool(reinit_enabled)
        self.reinit_trigger_streak = max(int(reinit_trigger_streak), 1)
        self.reinit_cooldown_seconds = max(float(reinit_cooldown_seconds), 1.0)
        self.reinit_request_timeout = max(float(reinit_request_timeout), 3.0)
        self.reinit_max_targets = max(int(reinit_max_targets), 1)
        self.reinit_allow_broadcast = bool(reinit_allow_broadcast)
        self.reinit_requested_by = str(reinit_requested_by or "remote_solver_cluster").strip() or "remote_solver_cluster"
        self.lifecycle_request_timeout = max(float(lifecycle_request_timeout), 3.0)
        self.drain_grace_seconds = max(float(drain_grace_seconds), 0.0)
        self.heartbeat_interval_seconds = max(float(heartbeat_interval_seconds), 5.0)
        self.lease_ttl_seconds = max(float(lease_ttl_seconds), 5.0)
        self.lease_owner = str(lease_owner or "register-main").strip() or "register-main"

        self._state_lock = asyncio.Lock()
        self._cluster_reinit_lock = asyncio.Lock()
        self._prefetch_stop = asyncio.Event()
        self._prefetch_task: asyncio.Task | None = None
        self._heartbeat_stop = asyncio.Event()
        self._heartbeat_task: asyncio.Task | None = None
        self._prefetch_sitekey = ""
        self._max_queue_target = max(self.queue_capacity, 0)
        self._reserve_for_direct = 1
        self._per_node_prefetch = 1
        self._nodes: dict[str, RemoteSolverNodeState] = {}

        self.prefetch_hit_count = 0
        self.prefetch_miss_count = 0
        self.fallback_count = 0
        self.direct_success_count = 0
        self.direct_fail_count = 0
        self.last_fill_at = 0.0
        self.last_consume_at = 0.0
        self.last_queue_target = 0
        self.direct_unavailable_streak = 0
        self.direct_unavailable_since = 0.0
        self.last_direct_unavailable_at = 0.0
        self.last_direct_unavailable_summary = ""
        self.last_token_success_at = 0.0
        self.last_reinit_at = 0.0
        self.last_reinit_reason = ""
        self.last_reinit_targets: list[str] = []
        self.last_reinit_results: list[dict[str, Any]] = []
        self.last_reinit_summary = ""
        self.last_reinit_trigger_streak = 0
        self.reinit_attempt_count = 0
        self.reinit_success_count = 0
        self.reinit_fail_count = 0
        self.reinit_skip_count = 0
        self.reinit_blocked_by_config = self.reinit_enabled and not bool(self.admin_token)
        self.reinit_block_reason = "missing_admin_token" if self.reinit_blocked_by_config else ""
        self.last_reinit_skip_is_fatal = bool(self.reinit_blocked_by_config)
        self.last_reinit_skip_advice = (
            "请在注册端与远程解题端同时配置一致的 SOLVER_ADMIN_TOKEN"
            if self.reinit_blocked_by_config else ""
        )
        self.last_reinit_effective_mode = ""
        self.last_drain_summary: dict[str, Any] = {}
        self.last_resume_summary: dict[str, Any] = {}
        self.last_lease_summary: dict[str, Any] = {}

        self._reload_nodes()

    def _log(self, message: str):
        print(message)

    def _cluster_reinit_cooldown_remaining(self) -> float:
        return max((self.last_reinit_at + self.reinit_cooldown_seconds) - time.time(), 0.0)

    def _node_display_name(self, state: RemoteSolverNodeState) -> str:
        return state.node_label or state.node_id or state.url

    def _admin_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.admin_token}"} if self.admin_token else {}

    def _apply_runtime_snapshot(
        self,
        state: RemoteSolverNodeState,
        data: dict[str, Any],
        *,
        mark_online: bool,
        http_status: int,
        now: float | None = None,
    ):
        current = time.time() if now is None else now
        if mark_online:
            state.online = True
        state.node_id = str(data.get("node_id") or state.node_id or "")
        state.node_label = str(data.get("node_label") or state.node_label or state.node_id or "")
        state.boot_id = str(data.get("boot_id") or state.boot_id or "")
        state.started_at = max(float(data.get("started_at", state.started_at) or 0.0), 0.0)
        state.init_count = max(int(data.get("init_count", state.init_count) or 0), 0)
        state.last_init_at = max(float(data.get("last_init_at", state.last_init_at) or 0.0), 0.0)
        state.last_init_reason = str(data.get("last_init_reason") or state.last_init_reason or "")
        state.last_init_result = str(data.get("last_init_result") or state.last_init_result or "")
        state.last_reinit_requested_by = str(data.get("last_reinit_requested_by") or state.last_reinit_requested_by or "")
        state.last_reinit_source = str(data.get("last_reinit_source") or state.last_reinit_source or "")
        state.last_reinit_request_at = max(float(data.get("last_reinit_request_at", state.last_reinit_request_at) or 0.0), 0.0)
        state.last_reinit_finished_at = max(float(data.get("last_reinit_finished_at", state.last_reinit_finished_at) or 0.0), 0.0)
        state.last_reinit_error = str(data.get("last_reinit_error") or state.last_reinit_error or "")
        state.last_reinit_status = str(data.get("last_reinit_status") or state.last_reinit_status or "")
        state.last_reinit_message = str(data.get("last_reinit_message") or state.last_reinit_message or "")
        state.last_reinit_mode = str(data.get("last_reinit_mode") or state.last_reinit_mode or "")
        state.last_reinit_trigger_summary = str(
            data.get("last_reinit_trigger_summary") or data.get("trigger_summary") or state.last_reinit_trigger_summary or ""
        )
        state.last_force_reinit_at = max(float(data.get("last_force_reinit_at", state.last_force_reinit_at) or 0.0), 0.0)
        state.force_reinit_count = max(int(data.get("force_reinit_count", state.force_reinit_count) or 0), 0)
        state.last_rebuild_browser_count = max(int(data.get("last_rebuild_browser_count", state.last_rebuild_browser_count) or 0), 0)
        drained_indexes = data.get("last_reinit_drained_indexes", state.last_reinit_drained_indexes)
        if isinstance(drained_indexes, list):
            state.last_reinit_drained_indexes = []
            for item in drained_indexes:
                try:
                    state.last_reinit_drained_indexes.append(int(item))
                except Exception:
                    continue
        state.reinit_in_progress = bool(data.get("reinit_in_progress", state.reinit_in_progress))
        state.reinit_supported = bool(data.get("reinit_supported", state.reinit_supported))
        state.reinit_cooldown_until = max(float(data.get("reinit_cooldown_until", state.reinit_cooldown_until) or 0.0), 0.0)

        lifecycle_state = str(data.get("lifecycle_state") or state.lifecycle_state or "").strip().lower()
        if state.reinit_in_progress:
            lifecycle_state = "reinitializing"
        elif lifecycle_state not in {"active", "draining", "standby", "reinitializing", "offline"}:
            lifecycle_state = state.lifecycle_state or ("active" if state.online else "offline")
        state.lifecycle_state = lifecycle_state
        state.drain_requested_at = max(float(data.get("drain_requested_at", state.drain_requested_at) or 0.0), 0.0)
        state.drain_started_at = max(float(data.get("drain_started_at", state.drain_started_at) or 0.0), 0.0)
        state.drain_finished_at = max(float(data.get("drain_finished_at", state.drain_finished_at) or 0.0), 0.0)
        state.standby_entered_at = max(float(data.get("standby_entered_at", state.standby_entered_at) or 0.0), 0.0)
        state.last_task_received_at = max(float(data.get("last_task_received_at", state.last_task_received_at) or 0.0), 0.0)
        state.last_task_finished_at = max(float(data.get("last_task_finished_at", state.last_task_finished_at) or 0.0), 0.0)
        state.idle_since = max(float(data.get("idle_since", state.idle_since) or 0.0), 0.0)
        state.idle_seconds = round(max(float(data.get("idle_seconds", state.idle_seconds) or 0.0), 0.0), 3)
        if "accepting_new_tasks" in data:
            state.accepting_new_tasks = bool(data.get("accepting_new_tasks"))
        elif state.lifecycle_state in {"draining", "standby", "offline"}:
            state.accepting_new_tasks = False
        elif mark_online and state.lifecycle_state == "active":
            state.accepting_new_tasks = True
        state.standby_reason = str(data.get("standby_reason") or state.standby_reason or "")
        state.last_lease_at = max(float(data.get("last_lease_at", state.last_lease_at) or 0.0), 0.0)
        state.lease_expires_at = max(float(data.get("lease_expires_at", state.lease_expires_at) or 0.0), 0.0)
        state.lease_owner = str(data.get("lease_owner") or state.lease_owner or "")
        state.pending_drain_reason = str(data.get("pending_drain_reason") or state.pending_drain_reason or "")
        state.idle_soft_recycle_count = max(int(data.get("idle_soft_recycle_count", state.idle_soft_recycle_count) or 0), 0)
        state.idle_standby_count = max(int(data.get("idle_standby_count", state.idle_standby_count) or 0), 0)
        state.manual_drain_count = max(int(data.get("manual_drain_count", state.manual_drain_count) or 0), 0)
        state.lease_expired_standby_count = max(
            int(data.get("lease_expired_standby_count", state.lease_expired_standby_count) or 0),
            0,
        )
        if "standby_auto_resume" in data:
            state.standby_auto_resume = bool(data.get("standby_auto_resume"))

        state.available_browsers = max(int(data.get("available_browsers", state.available_browsers) or 0), 0)
        state.raw_available_browsers = max(int(data.get("raw_available_browsers", state.raw_available_browsers or state.available_browsers) or 0), 0)
        state.reserved_slots = max(int(data.get("reserved_slots", state.reserved_slots) or 0), 0)
        state.total_browsers = max(int(data.get("total_browsers", state.total_browsers) or 0), 0)
        state.tracked_tasks = max(int(data.get("tracked_tasks", state.tracked_tasks) or 0), 0)
        try:
            active_task_count = data.get("active_task_count", data.get("tracked_tasks", state.active_task_count))
            state.active_task_count = max(int(active_task_count or 0), 0)
        except Exception:
            pass

        health_score_raw = data.get("node_health_score")
        if health_score_raw is not None:
            health_score = int(health_score_raw or 0)
            if health_score <= 0:
                health_score = max(100 - (state.consecutive_failures * 12) - (state.recent_timeout_count * 6), 20)
            state.health_score = max(min(health_score, 100), 0)
            reported_status = str(data.get("node_health_status") or "").strip().lower()
            state.health_status = reported_status or self._derive_health_status(state.health_score, state.available_browsers)
            state.degraded_reason = str(data.get("node_degraded_reason") or state.degraded_reason or "")
            state.recent_timeout_count = max(int(data.get("recent_timeout_count", state.recent_timeout_count) or 0), 0)
            state.recent_captcha_fail_count = max(int(data.get("recent_captcha_fail_count", state.recent_captcha_fail_count) or 0), 0)
            state.avg_solve_time_recent = round(max(float(data.get("avg_solve_seconds_recent", state.avg_solve_time_recent) or 0.0), 0.0), 3)
            if state.health_status in {"warming", "recovering", "cooling"}:
                state.recovering_until = max(state.recovering_until, current + self.recovering_observe_seconds)
            elif state.health_status == "degraded":
                state.soft_penalty_until = max(state.soft_penalty_until, current + self.soft_penalty_seconds)
                state.last_degraded_at = current
        elif mark_online and state.health_status in {"unknown", "offline"}:
            state.health_status = self._derive_health_status(state.health_score, state.available_browsers)

        state.last_stage = str(data.get("stage") or data.get("last_stage") or state.last_stage or "")
        if "message" in data or "last_message" in data or "node_degraded_reason" in data:
            state.last_message = str(data.get("message") or data.get("last_message") or data.get("node_degraded_reason") or "")
        reported_status = str(data.get("status") or data.get("last_status") or "").strip().lower()
        if reported_status:
            state.last_status = reported_status
        elif not state.last_status:
            state.last_status = state.effective_lifecycle_state
        state.last_http_status = http_status
        state.last_seen_at = current

    def _response_json_dict(self, resp: httpx.Response) -> dict[str, Any]:
        try:
            data = resp.json()
        except Exception:
            data = {}
        return data if isinstance(data, dict) else {}

    def _result_type(self, ok: bool, message: str, *, skip_messages: set[str] | None = None) -> str:
        if ok:
            if skip_messages and message in skip_messages:
                return "skip"
            return "success"
        if skip_messages and message in skip_messages:
            return "skip"
        return "failed"

    async def _mark_token_success(self):
        async with self._state_lock:
            self.direct_unavailable_streak = 0
            self.direct_unavailable_since = 0.0
            self.last_token_success_at = time.time()

    async def _mark_direct_unavailable(self, summary: str) -> int:
        async with self._state_lock:
            now = time.time()
            if self.direct_unavailable_streak <= 0 or self.direct_unavailable_since <= 0:
                self.direct_unavailable_since = now
            self.direct_unavailable_streak += 1
            self.last_direct_unavailable_at = now
            self.last_direct_unavailable_summary = summary
            return self.direct_unavailable_streak

    def _is_reinit_candidate(self, state: RemoteSolverNodeState) -> bool:
        if not state.online:
            return False
        if not state.reinit_supported:
            return False
        if state.reinit_in_progress:
            return False
        if state.reinit_cooldown_remaining > 0:
            return False
        if state.health_status in {"degraded", "recovering", "cooling"}:
            return True
        if state.breaker_active or state.soft_penalty_active:
            return True
        if state.consecutive_failures > 0 or state.recent_timeout_count > 0 or state.recent_captcha_fail_count > 0:
            return True
        if state.last_status in {"failed", "timeout", "error"}:
            return True
        if state.last_status == "busy" and state.health_score < max(self.direct_min_health_score, 40):
            return True
        if state.available_browsers <= 0 and state.raw_available_browsers <= 0 and state.health_score < 75:
            return True
        return False

    def _reinit_candidate_score(self, state: RemoteSolverNodeState) -> float:
        score = 0.0
        if state.breaker_active:
            score += 60
        if state.health_status == "degraded":
            score += 50
        elif state.health_status == "recovering":
            score += 35
        elif state.health_status == "cooling":
            score += 25
        if state.soft_penalty_active:
            score += 20
        if state.available_browsers <= 0:
            score += 16
        if state.raw_available_browsers <= 0:
            score += 8
        score += state.consecutive_failures * 12
        score += state.recent_timeout_count * 10
        score += state.recent_captcha_fail_count * 4
        if state.last_status == "timeout":
            score += 20
        elif state.last_status == "error":
            score += 16
        elif state.last_status == "failed":
            score += 12
        elif state.last_status == "busy":
            score += 4
        score += max(100 - state.health_score, 0)
        return score

    def _reinit_sort_key(self, state: RemoteSolverNodeState):
        return (
            -round(self._reinit_candidate_score(state), 3),
            state.health_score,
            state.available_browsers,
            -state.consecutive_failures,
            -(state.last_seen_at or 0.0),
            state.url,
        )

    async def _select_reinit_targets(self) -> tuple[list[RemoteSolverNodeState], str]:
        async with self._state_lock:
            states = list(self._nodes.values())

        candidates = [state for state in states if self._is_reinit_candidate(state)]
        strategy = "targeted"
        if not candidates and self.reinit_allow_broadcast:
            candidates = [
                state for state in states
                if state.online and state.reinit_supported and not state.reinit_in_progress and state.reinit_cooldown_remaining <= 0
            ]
            if candidates:
                strategy = "broadcast"

        candidates.sort(key=self._reinit_sort_key)
        return candidates[: self.reinit_max_targets], strategy

    async def _request_node_reinitialize(
        self,
        node_url: str,
        trigger_reason: str,
        trigger_summary: str,
        current_streak: int,
        strategy: str,
    ) -> dict[str, Any]:
        started_at = time.time()
        requested_mode = "soft"
        allow_force = strategy == "targeted" and current_streak >= self.reinit_trigger_streak
        payload = {
            "reason": trigger_reason,
            "requested_by": self.reinit_requested_by,
            "source": "remote_solver_cluster",
            "mode": requested_mode,
            "allow_force": allow_force,
            "trigger_summary": trigger_summary[:240],
            "direct_unavailable_streak": current_streak,
        }
        try:
            resp = await self.http_client.post(
                f"{node_url}/admin/reinitialize",
                json=payload,
                headers=self._admin_headers(),
                timeout=self.reinit_request_timeout,
            )
            data = self._response_json_dict(resp)

            ok = bool(data.get("ok"))
            message = str(data.get("message") or data.get("detail") or "")
            skip_messages = {
                "reinitialize_already_running",
                "reinitialize_cooldown",
                "no_idle_browsers_to_reinitialize",
                "force_reinit_not_allowed",
                "reinitialize_delayed",
            }
            result_type = self._result_type(ok, message, skip_messages=skip_messages)

            async with self._state_lock:
                state = self._nodes.setdefault(node_url, RemoteSolverNodeState(url=node_url))
                self._apply_runtime_snapshot(state, data, mark_online=True, http_status=resp.status_code)
                state.last_reinit_requested_by = str(data.get("last_reinit_requested_by") or self.reinit_requested_by or state.last_reinit_requested_by or "")
                state.last_reinit_source = str(data.get("last_reinit_source") or "remote_solver_cluster")
                state.last_reinit_request_at = max(float(data.get("last_reinit_request_at", started_at) or started_at), 0.0)
                state.last_reinit_status = str(data.get("last_reinit_status") or result_type)
                state.last_reinit_message = str(data.get("last_reinit_message") or message or state.last_reinit_message or "")
                state.last_reinit_trigger_summary = str(
                    data.get("last_reinit_trigger_summary") or payload["trigger_summary"] or state.last_reinit_trigger_summary or ""
                )
                if result_type == "failed":
                    state.last_reinit_error = str(data.get("last_reinit_error") or message or state.last_reinit_error or "")
                    state.last_error = state.last_reinit_error
                elif "last_reinit_error" in data:
                    state.last_reinit_error = str(data.get("last_reinit_error") or "")
                    state.last_error = ""
                else:
                    state.last_reinit_error = ""
                    state.last_error = ""

                node_id = state.node_id
                node_label = state.node_label
                last_status = state.last_reinit_status
                last_message = state.last_reinit_message
                last_mode = str(data.get("effective_mode") or state.last_reinit_mode or requested_mode)
                last_rebuild_browser_count = state.last_rebuild_browser_count

            self._log(
                f"[调度] {'✅' if result_type == 'success' else ('⚠️' if result_type == 'skip' else '❌')} "
                f"节点 [{node_label or node_id or node_url}] 初始化结果: {last_status or result_type}"
                f"（mode={last_mode or requested_mode}, HTTP {resp.status_code}，{last_message or message or 'no_message'}）"
            )
            return {
                "node_url": node_url,
                "node_id": node_id,
                "node_label": node_label,
                "ok": ok,
                "accepted": bool(data.get("accepted")),
                "http_status": resp.status_code,
                "result_type": result_type,
                "message": message,
                "requested_mode": requested_mode,
                "allow_force": allow_force,
                "last_reinit_mode": state.last_reinit_mode,
                "effective_mode": last_mode,
                "last_rebuild_browser_count": last_rebuild_browser_count,
                "last_reinit_status": last_status,
                "last_reinit_message": last_message,
                "requested_at": round(started_at, 3),
                "finished_at": round(time.time(), 3),
            }
        except Exception as e:
            async with self._state_lock:
                state = self._nodes.setdefault(node_url, RemoteSolverNodeState(url=node_url))
                state.last_reinit_status = "request_exception"
                state.last_reinit_message = str(e)
                state.last_reinit_error = str(e)
                state.last_error = str(e)
                state.last_seen_at = time.time()
                node_id = state.node_id
                node_label = state.node_label

            self._log(f"[调度] ❌ 节点 [{node_label or node_id or node_url}] 软初始化请求异常: {e}")
            return {
                "node_url": node_url,
                "node_id": node_id,
                "node_label": node_label,
                "ok": False,
                "accepted": False,
                "http_status": 0,
                "result_type": "failed",
                "message": str(e),
                "last_reinit_status": "request_exception",
                "last_reinit_message": str(e),
                "requested_at": round(started_at, 3),
                "finished_at": round(time.time(), 3),
            }

    async def _maybe_trigger_targeted_reinitialize(self, trigger_reason: str, trigger_summary: str, current_streak: int):
        if not self.reinit_enabled:
            return
        if current_streak < self.reinit_trigger_streak:
            return
        if not self.admin_token:
            async with self._state_lock:
                self.reinit_skip_count += 1
                self.last_reinit_reason = "missing_admin_token"
                self.last_reinit_targets = []
                self.last_reinit_results = []
                self.last_reinit_summary = trigger_summary
                self.last_reinit_trigger_streak = current_streak
                self.reinit_blocked_by_config = True
                self.reinit_block_reason = "missing_admin_token"
                self.last_reinit_skip_is_fatal = True
                self.last_reinit_skip_advice = "请在注册端与远程解题端同时配置一致的 SOLVER_ADMIN_TOKEN"
                self.last_reinit_effective_mode = ""
            self._log("[调度] ⚠️ 已达到软初始化触发阈值，但未配置 SOLVER_ADMIN_TOKEN，跳过本轮远程软初始化")
            return

        async with self._cluster_reinit_lock:
            cooldown_remaining = 0.0
            async with self._state_lock:
                cooldown_remaining = self._cluster_reinit_cooldown_remaining()
                if cooldown_remaining > 0:
                    self.reinit_skip_count += 1
                    self.last_reinit_reason = "cluster_reinit_cooldown"
                    self.last_reinit_targets = []
                    self.last_reinit_results = []
                    self.last_reinit_summary = trigger_summary
                    self.last_reinit_trigger_streak = current_streak
                    self.reinit_blocked_by_config = False
                    self.reinit_block_reason = "cluster_reinit_cooldown"
                    self.last_reinit_skip_is_fatal = False
                    self.last_reinit_skip_advice = "等待调度器冷却结束后会自动再次尝试远程软初始化"
            if cooldown_remaining > 0:
                self._log(f"[调度] ⏱️ 软初始化仍在冷却中，剩余 {round(cooldown_remaining, 1)}s，本轮跳过")
                return

            targets, strategy = await self._select_reinit_targets()
            if not targets:
                async with self._state_lock:
                    self.reinit_skip_count += 1
                    self.last_reinit_reason = "no_reachable_reinit_targets"
                    self.last_reinit_targets = []
                    self.last_reinit_results = []
                    self.last_reinit_summary = trigger_summary
                    self.last_reinit_trigger_streak = current_streak
                    self.reinit_blocked_by_config = False
                    self.reinit_block_reason = "no_reachable_reinit_targets"
                    self.last_reinit_skip_is_fatal = False
                    self.last_reinit_skip_advice = "当前仅剩完全离线或未暴露管理接口的节点，需要平台层重启或修复节点可达性"
                self._log(
                    f"[调度] ⚠️ 已连续 {current_streak} 次无 direct 候选，但当前没有可达且支持软初始化的异常节点；"
                    "完全离线节点需交给平台层兜底"
                )
                return

            started_at = time.time()
            target_urls = [state.url for state in targets]
            async with self._state_lock:
                self.last_reinit_at = started_at
                self.last_reinit_reason = trigger_reason
                self.last_reinit_targets = target_urls
                self.last_reinit_results = []
                self.last_reinit_summary = trigger_summary
                self.last_reinit_trigger_streak = current_streak
                self.reinit_attempt_count += 1
                self.reinit_blocked_by_config = False
                self.reinit_block_reason = ""
                self.last_reinit_skip_is_fatal = False
                self.last_reinit_skip_advice = ""
                self.last_reinit_effective_mode = ""

            display_targets = ", ".join(self._node_display_name(state) for state in targets)
            self._log(
                f"[调度] 🛠️ 已连续 {current_streak} 次无 direct 候选，准备对 {len(targets)} 个"
                f"{'在线节点' if strategy == 'broadcast' else '异常节点'}执行远程初始化: {display_targets}"
            )
            results = await asyncio.gather(
                *[
                    self._request_node_reinitialize(
                        node_url=state.url,
                        trigger_reason=trigger_reason,
                        trigger_summary=trigger_summary,
                        current_streak=current_streak,
                        strategy=strategy,
                    )
                    for state in targets
                ],
                return_exceptions=True,
            )

            normalized_results: list[dict[str, Any]] = []
            success_count = 0
            fail_count = 0
            skip_count = 0
            for item in results:
                if isinstance(item, Exception):
                    fail_count += 1
                    normalized_results.append(
                        {
                            "node_url": "",
                            "node_id": "",
                            "node_label": "",
                            "ok": False,
                            "accepted": False,
                            "http_status": 0,
                            "result_type": "failed",
                            "message": str(item),
                            "last_reinit_status": "request_exception",
                            "last_reinit_message": str(item),
                            "requested_at": round(started_at, 3),
                            "finished_at": round(time.time(), 3),
                        }
                    )
                    continue
                normalized_results.append(item)
                result_type = str(item.get("result_type") or "failed")
                if result_type == "success":
                    success_count += 1
                elif result_type == "skip":
                    skip_count += 1
                else:
                    fail_count += 1

            effective_modes = {
                str(item.get("effective_mode") or item.get("last_reinit_mode") or "").strip().lower()
                for item in normalized_results
                if str(item.get("effective_mode") or item.get("last_reinit_mode") or "").strip().lower() in {"soft", "force"}
            }
            cluster_effective_mode = "force" if "force" in effective_modes else ("soft" if "soft" in effective_modes else "")

            async with self._state_lock:
                self.reinit_success_count += success_count
                self.reinit_fail_count += fail_count
                self.reinit_skip_count += skip_count
                self.last_reinit_results = normalized_results
                self.last_reinit_effective_mode = cluster_effective_mode

            self._log(
                f"[调度] 🧩 节点远程初始化完成: mode={cluster_effective_mode or 'unknown'}, "
                f"success={success_count}, skip={skip_count}, fail={fail_count}"
            )

    def _derive_health_status(self, health_score: int, available_browsers: int) -> str:
        if available_browsers <= 0:
            return "cooling"
        if health_score >= 80:
            return "healthy"
        if health_score >= 60:
            return "warming"
        if health_score >= self.direct_min_health_score:
            return "recovering"
        return "degraded"

    def _candidate_unavailable_reason(self, state: RemoteSolverNodeState, request_kind: str) -> str | None:
        lifecycle_state = state.effective_lifecycle_state
        if lifecycle_state == "offline" or not state.online:
            return "offline"
        if lifecycle_state == "reinitializing" or state.reinit_in_progress:
            return "reinitializing"
        if lifecycle_state == "draining":
            return "draining"
        if lifecycle_state == "standby" and not state.standby_auto_resume:
            return "standby"
        if not state.accepting_new_tasks and lifecycle_state != "standby":
            return "accepting_disabled"
        if state.breaker_active:
            return "breaker"
        if lifecycle_state != "standby":
            if state.available_browsers <= 0:
                return "no_available_browsers"
            if state.effective_capacity <= 0:
                return "capacity_exhausted"
        if request_kind == "prefetch" and state.in_flight_prefetch >= self._per_node_prefetch:
            return "prefetch_slot_full"
        if request_kind == "prefetch" and lifecycle_state != "standby" and state.health_status in {"degraded", "recovering", "cooling"}:
            return "prefetch_suppressed_by_health"
        if request_kind == "prefetch" and state.soft_penalty_active:
            return "soft_penalty"
        if request_kind == "prefetch" and state.health_score < self.prefetch_min_health_score:
            return "health_low"
        if request_kind == "direct" and state.health_status == "degraded" and state.health_score < self.direct_min_health_score:
            return "health_too_low"
        return None

    def _candidate_score(self, state: RemoteSolverNodeState, request_kind: str) -> float:
        lifecycle_state = state.effective_lifecycle_state
        score = float(state.health_score)
        score += min(state.effective_capacity * 8, 24)
        score += min(state.available_browsers * 4, 12)
        score += state.success_rate * 10
        if lifecycle_state == "standby":
            score -= 12 if state.standby_auto_resume else 28
        elif not state.accepting_new_tasks:
            score -= 24
        if state.lease_expired:
            score -= 8
        if state.soft_penalty_active:
            score -= 18
        if state.recovering_active:
            score -= 16 if request_kind == "prefetch" else 8
        if state.health_status == "warming":
            score -= 4
        elif state.health_status == "recovering":
            score -= 8
        elif state.health_status == "cooling":
            score -= 14
        elif state.health_status == "degraded":
            score -= 22
        solve_time = state.avg_solve_time_recent if state.avg_solve_time_recent > 0 else state.avg_solve_time
        if solve_time > 0:
            score -= min(solve_time, 25)
        score -= state.in_flight_total * 5
        score -= state.consecutive_failures * 6
        return score

    async def _build_unavailable_summary(self, request_kind: str) -> str:
        async with self._state_lock:
            states = list(self._nodes.values())
        if not states:
            return "no_nodes"
        reason_counts: dict[str, int] = {}
        for state in states:
            reason = self._candidate_unavailable_reason(state, request_kind) or "candidate"
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
        parts = [f"{reason}={count}" for reason, count in sorted(reason_counts.items()) if reason != "candidate"]
        if not parts:
            parts.append("all_candidates_filtered_after_dispatch=1")
        return ", ".join(parts)

    def _normalize_nodes(self, nodes: list[str]) -> list[str]:
        normalized = []
        seen = set()
        for raw in nodes:
            addr = str(raw or "").strip()
            if not addr:
                continue
            if not addr.startswith("http"):
                addr = f"http://{addr}"
            addr = addr.rstrip("/")
            if addr in seen:
                continue
            seen.add(addr)
            normalized.append(addr)
        return normalized

    def _reload_nodes(self):
        if not self.node_provider:
            return
        nodes = self._normalize_nodes(self.node_provider() or [])
        if not nodes:
            return
        existing = self._nodes
        self._nodes = {url: existing.get(url, RemoteSolverNodeState(url=url)) for url in nodes}

    async def refresh_nodes(self):
        self._reload_nodes()
        if not self._nodes:
            return

        tasks = [self._fetch_node_stats(url) for url in self._nodes.keys()]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _fetch_node_stats(self, node_url: str):
        now = time.time()
        try:
            resp = await self.http_client.get(f"{node_url}/stats", timeout=3)
            data = self._response_json_dict(resp)
            if resp.status_code >= 400:
                raise RuntimeError(f"HTTP {resp.status_code}: {data}")
            async with self._state_lock:
                state = self._nodes.setdefault(node_url, RemoteSolverNodeState(url=node_url))
                self._apply_runtime_snapshot(state, data, mark_online=True, http_status=resp.status_code, now=now)
                state.last_error = ""
        except Exception as e:
            async with self._state_lock:
                state = self._nodes.setdefault(node_url, RemoteSolverNodeState(url=node_url))
                state.online = False
                state.lifecycle_state = "offline"
                state.accepting_new_tasks = False
                state.available_browsers = 0
                state.raw_available_browsers = 0
                state.reserved_slots = 0
                state.total_browsers = 0
                state.tracked_tasks = 0
                state.active_task_count = 0
                state.health_score = 0
                state.health_status = "offline"
                state.degraded_reason = "stats_unreachable"
                state.last_http_status = 0
                state.last_error = str(e)
                state.last_status = "offline"
                state.last_seen_at = now

    async def _request_node_drain(
        self,
        node_url: str,
        *,
        reason: str,
        requested_by: str = "remote_solver_cluster",
        source: str = "remote_solver_cluster",
        enter_standby: bool = True,
        graceful: bool = True,
        force_reinitialize_when_idle: bool = False,
    ) -> dict[str, Any]:
        started_at = time.time()
        if not self.admin_token:
            async with self._state_lock:
                state = self._nodes.setdefault(node_url, RemoteSolverNodeState(url=node_url))
                node_id = state.node_id
                node_label = state.node_label
                lifecycle_state = state.effective_lifecycle_state
            return {
                "node_url": node_url,
                "node_id": node_id,
                "node_label": node_label,
                "ok": False,
                "accepted": False,
                "http_status": 0,
                "result_type": "failed",
                "message": "missing_admin_token",
                "lifecycle_state": lifecycle_state,
                "requested_at": round(started_at, 3),
                "finished_at": round(time.time(), 3),
            }

        payload = {
            "reason": reason,
            "requested_by": requested_by,
            "source": source,
            "enter_standby": bool(enter_standby),
            "graceful": bool(graceful),
            "force_reinitialize_when_idle": bool(force_reinitialize_when_idle),
        }
        try:
            resp = await self.http_client.post(
                f"{node_url}/admin/drain",
                json=payload,
                headers=self._admin_headers(),
                timeout=self.lifecycle_request_timeout,
            )
            data = self._response_json_dict(resp)
            ok = bool(data.get("ok"))
            message = str(data.get("message") or data.get("detail") or "")
            result_type = self._result_type(ok, message, skip_messages={"already_standby", "standby_delayed"})

            async with self._state_lock:
                state = self._nodes.setdefault(node_url, RemoteSolverNodeState(url=node_url))
                self._apply_runtime_snapshot(state, data, mark_online=True, http_status=resp.status_code)
                state.last_stage = str(data.get("stage") or state.last_stage or state.effective_lifecycle_state)
                state.last_status = str(data.get("status") or state.last_status or state.effective_lifecycle_state)
                state.last_message = str(message or state.last_message or "")
                state.last_error = "" if result_type != "failed" else (message or state.last_error)
                node_id = state.node_id
                node_label = state.node_label
                lifecycle_state = state.effective_lifecycle_state

            self._log(
                f"[调度] {'✅' if result_type == 'success' else ('⚠️' if result_type == 'skip' else '❌')} "
                f"节点 [{node_label or node_id or node_url}] 排空结果: {message or lifecycle_state or result_type}"
                f"（HTTP {resp.status_code}，state={lifecycle_state}）"
            )
            return {
                "node_url": node_url,
                "node_id": node_id,
                "node_label": node_label,
                "ok": ok,
                "accepted": bool(data.get("accepted")),
                "http_status": resp.status_code,
                "result_type": result_type,
                "message": message,
                "lifecycle_state": lifecycle_state,
                "requested_at": round(started_at, 3),
                "finished_at": round(time.time(), 3),
            }
        except Exception as e:
            async with self._state_lock:
                state = self._nodes.setdefault(node_url, RemoteSolverNodeState(url=node_url))
                state.online = False
                state.lifecycle_state = "offline"
                state.accepting_new_tasks = False
                state.last_error = str(e)
                state.last_http_status = 0
                state.last_seen_at = time.time()
                node_id = state.node_id
                node_label = state.node_label

            self._log(f"[调度] ❌ 节点 [{node_label or node_id or node_url}] 排空请求异常: {e}")
            return {
                "node_url": node_url,
                "node_id": node_id,
                "node_label": node_label,
                "ok": False,
                "accepted": False,
                "http_status": 0,
                "result_type": "failed",
                "message": str(e),
                "lifecycle_state": "offline",
                "requested_at": round(started_at, 3),
                "finished_at": round(time.time(), 3),
            }

    async def _request_node_resume(
        self,
        node_url: str,
        *,
        reason: str,
        requested_by: str = "remote_solver_cluster",
        source: str = "remote_solver_cluster",
    ) -> dict[str, Any]:
        started_at = time.time()
        if not self.admin_token:
            async with self._state_lock:
                state = self._nodes.setdefault(node_url, RemoteSolverNodeState(url=node_url))
                node_id = state.node_id
                node_label = state.node_label
                lifecycle_state = state.effective_lifecycle_state
            return {
                "node_url": node_url,
                "node_id": node_id,
                "node_label": node_label,
                "ok": False,
                "accepted": False,
                "http_status": 0,
                "result_type": "failed",
                "message": "missing_admin_token",
                "lifecycle_state": lifecycle_state,
                "requested_at": round(started_at, 3),
                "finished_at": round(time.time(), 3),
            }

        payload = {
            "reason": reason,
            "requested_by": requested_by,
            "source": source,
        }
        try:
            resp = await self.http_client.post(
                f"{node_url}/admin/resume",
                json=payload,
                headers=self._admin_headers(),
                timeout=self.lifecycle_request_timeout,
            )
            data = self._response_json_dict(resp)
            ok = bool(data.get("ok"))
            message = str(data.get("message") or data.get("detail") or "")
            result_type = self._result_type(ok, message, skip_messages={"already_active"})

            async with self._state_lock:
                state = self._nodes.setdefault(node_url, RemoteSolverNodeState(url=node_url))
                self._apply_runtime_snapshot(state, data, mark_online=True, http_status=resp.status_code)
                state.last_stage = str(data.get("stage") or state.last_stage or state.effective_lifecycle_state)
                state.last_status = str(data.get("status") or state.last_status or state.effective_lifecycle_state)
                state.last_message = str(message or state.last_message or "")
                state.last_error = "" if result_type != "failed" else (message or state.last_error)
                node_id = state.node_id
                node_label = state.node_label
                lifecycle_state = state.effective_lifecycle_state
                initialized_browsers = max(int(data.get("initialized_browsers", 0) or 0), 0)

            self._log(
                f"[调度] {'✅' if result_type == 'success' else ('⚠️' if result_type == 'skip' else '❌')} "
                f"节点 [{node_label or node_id or node_url}] 恢复结果: {message or lifecycle_state or result_type}"
                f"（HTTP {resp.status_code}，state={lifecycle_state}，initialized={initialized_browsers}）"
            )
            return {
                "node_url": node_url,
                "node_id": node_id,
                "node_label": node_label,
                "ok": ok,
                "accepted": bool(data.get("accepted")),
                "http_status": resp.status_code,
                "result_type": result_type,
                "message": message,
                "lifecycle_state": lifecycle_state,
                "initialized_browsers": initialized_browsers,
                "requested_at": round(started_at, 3),
                "finished_at": round(time.time(), 3),
            }
        except Exception as e:
            async with self._state_lock:
                state = self._nodes.setdefault(node_url, RemoteSolverNodeState(url=node_url))
                state.online = False
                state.lifecycle_state = "offline"
                state.accepting_new_tasks = False
                state.last_error = str(e)
                state.last_http_status = 0
                state.last_seen_at = time.time()
                node_id = state.node_id
                node_label = state.node_label

            self._log(f"[调度] ❌ 节点 [{node_label or node_id or node_url}] 恢复请求异常: {e}")
            return {
                "node_url": node_url,
                "node_id": node_id,
                "node_label": node_label,
                "ok": False,
                "accepted": False,
                "http_status": 0,
                "result_type": "failed",
                "message": str(e),
                "lifecycle_state": "offline",
                "initialized_browsers": 0,
                "requested_at": round(started_at, 3),
                "finished_at": round(time.time(), 3),
            }

    async def _renew_node_lease(self, node_url: str, *, reason: str = "register_heartbeat") -> dict[str, Any]:
        started_at = time.time()
        if not self.admin_token:
            async with self._state_lock:
                state = self._nodes.setdefault(node_url, RemoteSolverNodeState(url=node_url))
                node_id = state.node_id
                node_label = state.node_label
                lifecycle_state = state.effective_lifecycle_state
            return {
                "node_url": node_url,
                "node_id": node_id,
                "node_label": node_label,
                "ok": False,
                "accepted": False,
                "http_status": 0,
                "result_type": "failed",
                "message": "missing_admin_token",
                "lifecycle_state": lifecycle_state,
                "lease_owner": self.lease_owner,
                "lease_ttl_seconds": round(self.lease_ttl_seconds, 3),
                "requested_at": round(started_at, 3),
                "finished_at": round(time.time(), 3),
            }

        payload = {
            "lease_owner": self.lease_owner,
            "lease_ttl_seconds": self.lease_ttl_seconds,
            "reason": reason,
        }
        try:
            resp = await self.http_client.post(
                f"{node_url}/admin/lease",
                json=payload,
                headers=self._admin_headers(),
                timeout=self.lifecycle_request_timeout,
            )
            data = self._response_json_dict(resp)
            ok = bool(data.get("ok"))
            message = str(data.get("message") or data.get("detail") or "")
            result_type = self._result_type(ok, message)

            async with self._state_lock:
                state = self._nodes.setdefault(node_url, RemoteSolverNodeState(url=node_url))
                self._apply_runtime_snapshot(state, data, mark_online=True, http_status=resp.status_code)
                state.last_stage = str(data.get("stage") or state.last_stage or state.effective_lifecycle_state)
                state.last_status = str(data.get("status") or state.last_status or state.effective_lifecycle_state)
                state.last_message = str(message or state.last_message or "")
                state.last_error = "" if result_type != "failed" else (message or state.last_error)
                node_id = state.node_id
                node_label = state.node_label
                lifecycle_state = state.effective_lifecycle_state
                lease_ttl_seconds = round(max(float(data.get("lease_ttl_seconds", self.lease_ttl_seconds) or self.lease_ttl_seconds), 0.0), 3)

            if result_type == "failed":
                self._log(f"[调度] ❌ 节点 [{node_label or node_id or node_url}] 租约续期失败: {message or 'unknown_error'}")
            return {
                "node_url": node_url,
                "node_id": node_id,
                "node_label": node_label,
                "ok": ok,
                "accepted": bool(data.get("accepted")),
                "http_status": resp.status_code,
                "result_type": result_type,
                "message": message,
                "lifecycle_state": lifecycle_state,
                "lease_owner": str(data.get("lease_owner") or state.lease_owner or self.lease_owner),
                "lease_ttl_seconds": lease_ttl_seconds,
                "requested_at": round(started_at, 3),
                "finished_at": round(time.time(), 3),
            }
        except Exception as e:
            async with self._state_lock:
                state = self._nodes.setdefault(node_url, RemoteSolverNodeState(url=node_url))
                state.online = False
                state.lifecycle_state = "offline"
                state.accepting_new_tasks = False
                state.last_error = str(e)
                state.last_http_status = 0
                state.last_seen_at = time.time()
                node_id = state.node_id
                node_label = state.node_label

            self._log(f"[调度] ❌ 节点 [{node_label or node_id or node_url}] 租约续期异常: {e}")
            return {
                "node_url": node_url,
                "node_id": node_id,
                "node_label": node_label,
                "ok": False,
                "accepted": False,
                "http_status": 0,
                "result_type": "failed",
                "message": str(e),
                "lifecycle_state": "offline",
                "lease_owner": self.lease_owner,
                "lease_ttl_seconds": round(self.lease_ttl_seconds, 3),
                "requested_at": round(started_at, 3),
                "finished_at": round(time.time(), 3),
            }

    async def drain_all_nodes(
        self,
        *,
        reason: str = "batch_finish",
        requested_by: str = "remote_solver_cluster",
        source: str = "remote_solver_cluster",
        enter_standby: bool = True,
        graceful: bool = True,
        force_reinitialize_when_idle: bool = False,
        target_nodes: list[str] | None = None,
    ) -> dict[str, Any]:
        self._reload_nodes()
        started_at = time.time()
        target_urls = self._normalize_nodes(target_nodes or list(self._nodes.keys()))
        initial_summary = {
            "ok": False,
            "action": "drain_all_nodes",
            "message": "drain_dispatching",
            "reason": reason,
            "requested_by": requested_by,
            "source": source,
            "enter_standby": bool(enter_standby),
            "graceful": bool(graceful),
            "force_reinitialize_when_idle": bool(force_reinitialize_when_idle),
            "requested_at": round(started_at, 3),
            "finished_at": 0.0,
            "targets": list(target_urls),
            "results": [],
            "success_count": 0,
            "skip_count": 0,
            "fail_count": 0,
            "accepted_count": 0,
            "in_progress": True,
        }
        async with self._state_lock:
            self.last_drain_summary = dict(initial_summary)

        if not target_urls:
            summary = dict(initial_summary)
            summary.update({
                "ok": True,
                "message": "no_nodes_configured",
                "finished_at": round(time.time(), 3),
                "in_progress": False,
            })
            async with self._state_lock:
                self.last_drain_summary = summary
            return summary

        results = await asyncio.gather(
            *[
                self._request_node_drain(
                    node_url,
                    reason=reason,
                    requested_by=requested_by,
                    source=source,
                    enter_standby=enter_standby,
                    graceful=graceful,
                    force_reinitialize_when_idle=force_reinitialize_when_idle,
                )
                for node_url in target_urls
            ],
            return_exceptions=True,
        )

        normalized_results: list[dict[str, Any]] = []
        success_count = 0
        skip_count = 0
        fail_count = 0
        accepted_count = 0
        for item in results:
            if isinstance(item, Exception):
                fail_count += 1
                normalized_results.append(
                    {
                        "node_url": "",
                        "node_id": "",
                        "node_label": "",
                        "ok": False,
                        "accepted": False,
                        "http_status": 0,
                        "result_type": "failed",
                        "message": str(item),
                        "lifecycle_state": "offline",
                        "requested_at": round(started_at, 3),
                        "finished_at": round(time.time(), 3),
                    }
                )
                continue
            normalized_results.append(item)
            if bool(item.get("accepted")):
                accepted_count += 1
            result_type = str(item.get("result_type") or "failed")
            if result_type == "success":
                success_count += 1
            elif result_type == "skip":
                skip_count += 1
            else:
                fail_count += 1

        summary = {
            "ok": fail_count == 0,
            "action": "drain_all_nodes",
            "message": "drain_broadcast_completed" if fail_count == 0 else "drain_broadcast_partial_failure",
            "reason": reason,
            "requested_by": requested_by,
            "source": source,
            "enter_standby": bool(enter_standby),
            "graceful": bool(graceful),
            "force_reinitialize_when_idle": bool(force_reinitialize_when_idle),
            "requested_at": round(started_at, 3),
            "finished_at": round(time.time(), 3),
            "targets": list(target_urls),
            "results": normalized_results,
            "success_count": success_count,
            "skip_count": skip_count,
            "fail_count": fail_count,
            "accepted_count": accepted_count,
            "in_progress": False,
        }
        async with self._state_lock:
            self.last_drain_summary = summary

        self._log(
            f"[调度] 🧯 远程排空广播完成: success={success_count}, skip={skip_count}, fail={fail_count}, targets={len(target_urls)}"
        )
        return summary

    async def resume_all_nodes(
        self,
        *,
        reason: str = "batch_start_resume",
        requested_by: str = "remote_solver_cluster",
        source: str = "remote_solver_cluster",
        target_nodes: list[str] | None = None,
    ) -> dict[str, Any]:
        self._reload_nodes()
        started_at = time.time()
        target_urls = self._normalize_nodes(target_nodes or list(self._nodes.keys()))
        initial_summary = {
            "ok": False,
            "action": "resume_all_nodes",
            "message": "resume_dispatching",
            "reason": reason,
            "requested_by": requested_by,
            "source": source,
            "requested_at": round(started_at, 3),
            "finished_at": 0.0,
            "targets": list(target_urls),
            "results": [],
            "success_count": 0,
            "skip_count": 0,
            "fail_count": 0,
            "accepted_count": 0,
        }
        async with self._state_lock:
            self.last_resume_summary = dict(initial_summary)

        if not target_urls:
            summary = dict(initial_summary)
            summary.update({
                "ok": True,
                "message": "no_nodes_configured",
                "finished_at": round(time.time(), 3),
            })
            async with self._state_lock:
                self.last_resume_summary = summary
            return summary

        results = await asyncio.gather(
            *[
                self._request_node_resume(
                    node_url,
                    reason=reason,
                    requested_by=requested_by,
                    source=source,
                )
                for node_url in target_urls
            ],
            return_exceptions=True,
        )

        normalized_results: list[dict[str, Any]] = []
        success_count = 0
        skip_count = 0
        fail_count = 0
        accepted_count = 0
        for item in results:
            if isinstance(item, Exception):
                fail_count += 1
                normalized_results.append(
                    {
                        "node_url": "",
                        "node_id": "",
                        "node_label": "",
                        "ok": False,
                        "accepted": False,
                        "http_status": 0,
                        "result_type": "failed",
                        "message": str(item),
                        "lifecycle_state": "offline",
                        "initialized_browsers": 0,
                        "requested_at": round(started_at, 3),
                        "finished_at": round(time.time(), 3),
                    }
                )
                continue
            normalized_results.append(item)
            if bool(item.get("accepted")):
                accepted_count += 1
            result_type = str(item.get("result_type") or "failed")
            if result_type == "success":
                success_count += 1
            elif result_type == "skip":
                skip_count += 1
            else:
                fail_count += 1

        summary = {
            "ok": fail_count == 0,
            "action": "resume_all_nodes",
            "message": "resume_broadcast_completed" if fail_count == 0 else "resume_broadcast_partial_failure",
            "reason": reason,
            "requested_by": requested_by,
            "source": source,
            "requested_at": round(started_at, 3),
            "finished_at": round(time.time(), 3),
            "targets": list(target_urls),
            "results": normalized_results,
            "success_count": success_count,
            "skip_count": skip_count,
            "fail_count": fail_count,
            "accepted_count": accepted_count,
        }
        async with self._state_lock:
            self.last_resume_summary = summary

        self._log(
            f"[调度] 🔄 远程恢复广播完成: success={success_count}, skip={skip_count}, fail={fail_count}, targets={len(target_urls)}"
        )
        return summary

    async def _heartbeat_worker(self):
        while not self._heartbeat_stop.is_set():
            started_at = time.time()
            try:
                self._reload_nodes()
                async with self._state_lock:
                    target_urls = [state.url for state in self._nodes.values() if state.online]

                if not target_urls:
                    summary = {
                        "ok": True,
                        "action": "renew_all_leases",
                        "message": "no_online_nodes",
                        "reason": "register_heartbeat",
                        "requested_at": round(started_at, 3),
                        "finished_at": round(time.time(), 3),
                        "targets": [],
                        "results": [],
                        "success_count": 0,
                        "skip_count": 0,
                        "fail_count": 0,
                        "accepted_count": 0,
                        "heartbeat_running": True,
                        "interval_seconds": round(self.heartbeat_interval_seconds, 3),
                        "lease_owner": self.lease_owner,
                        "lease_ttl_seconds": round(self.lease_ttl_seconds, 3),
                    }
                else:
                    results = await asyncio.gather(
                        *[self._renew_node_lease(node_url, reason="register_heartbeat") for node_url in target_urls],
                        return_exceptions=True,
                    )
                    normalized_results: list[dict[str, Any]] = []
                    success_count = 0
                    skip_count = 0
                    fail_count = 0
                    accepted_count = 0
                    for item in results:
                        if isinstance(item, Exception):
                            fail_count += 1
                            normalized_results.append(
                                {
                                    "node_url": "",
                                    "node_id": "",
                                    "node_label": "",
                                    "ok": False,
                                    "accepted": False,
                                    "http_status": 0,
                                    "result_type": "failed",
                                    "message": str(item),
                                    "lifecycle_state": "offline",
                                    "lease_owner": self.lease_owner,
                                    "lease_ttl_seconds": round(self.lease_ttl_seconds, 3),
                                    "requested_at": round(started_at, 3),
                                    "finished_at": round(time.time(), 3),
                                }
                            )
                            continue
                        normalized_results.append(item)
                        if bool(item.get("accepted")):
                            accepted_count += 1
                        result_type = str(item.get("result_type") or "failed")
                        if result_type == "success":
                            success_count += 1
                        elif result_type == "skip":
                            skip_count += 1
                        else:
                            fail_count += 1

                    summary = {
                        "ok": fail_count == 0,
                        "action": "renew_all_leases",
                        "message": "heartbeat_cycle_completed" if fail_count == 0 else "heartbeat_cycle_partial_failure",
                        "reason": "register_heartbeat",
                        "requested_at": round(started_at, 3),
                        "finished_at": round(time.time(), 3),
                        "targets": list(target_urls),
                        "results": normalized_results,
                        "success_count": success_count,
                        "skip_count": skip_count,
                        "fail_count": fail_count,
                        "accepted_count": accepted_count,
                        "heartbeat_running": True,
                        "interval_seconds": round(self.heartbeat_interval_seconds, 3),
                        "lease_owner": self.lease_owner,
                        "lease_ttl_seconds": round(self.lease_ttl_seconds, 3),
                    }
                    if fail_count > 0:
                        self._log(
                            f"[调度] ⚠️ 租约心跳完成: success={success_count}, skip={skip_count}, fail={fail_count}, targets={len(target_urls)}"
                        )

                async with self._state_lock:
                    self.last_lease_summary = summary
            except asyncio.CancelledError:
                raise
            except Exception as e:
                summary = {
                    "ok": False,
                    "action": "renew_all_leases",
                    "message": str(e),
                    "reason": "register_heartbeat",
                    "requested_at": round(started_at, 3),
                    "finished_at": round(time.time(), 3),
                    "targets": [],
                    "results": [],
                    "success_count": 0,
                    "skip_count": 0,
                    "fail_count": 1,
                    "accepted_count": 0,
                    "heartbeat_running": True,
                    "interval_seconds": round(self.heartbeat_interval_seconds, 3),
                    "lease_owner": self.lease_owner,
                    "lease_ttl_seconds": round(self.lease_ttl_seconds, 3),
                }
                async with self._state_lock:
                    self.last_lease_summary = summary
                self._log(f"[调度] ❌ 租约心跳异常: {e}")

            try:
                await asyncio.wait_for(self._heartbeat_stop.wait(), timeout=self.heartbeat_interval_seconds)
            except asyncio.TimeoutError:
                continue

    async def heartbeat_loop(self):
        if not self.admin_token:
            async with self._state_lock:
                self.last_lease_summary = {
                    "ok": False,
                    "action": "renew_all_leases",
                    "message": "missing_admin_token",
                    "reason": "register_heartbeat",
                    "requested_at": round(time.time(), 3),
                    "finished_at": round(time.time(), 3),
                    "targets": [],
                    "results": [],
                    "success_count": 0,
                    "skip_count": 0,
                    "fail_count": 0,
                    "accepted_count": 0,
                    "heartbeat_running": False,
                    "interval_seconds": round(self.heartbeat_interval_seconds, 3),
                    "lease_owner": self.lease_owner,
                    "lease_ttl_seconds": round(self.lease_ttl_seconds, 3),
                }
            self._log("[调度] ⚠️ 未配置 SOLVER_ADMIN_TOKEN，跳过租约心跳")
            return

        self._heartbeat_stop.clear()
        if self._heartbeat_task and not self._heartbeat_task.done():
            return
        self._heartbeat_task = asyncio.create_task(self._heartbeat_worker())

    async def stop_heartbeat(self):
        self._heartbeat_stop.set()
        if self._heartbeat_task:
            try:
                await asyncio.wait_for(self._heartbeat_task, timeout=max(self.heartbeat_interval_seconds, 10.0))
            except Exception:
                self._heartbeat_task.cancel()
            self._heartbeat_task = None

        stopped_at = round(time.time(), 3)
        async with self._state_lock:
            summary = dict(self.last_lease_summary or {})
            summary.setdefault("action", "renew_all_leases")
            summary.setdefault("requested_at", 0.0)
            summary.setdefault("finished_at", 0.0)
            summary.setdefault("targets", [])
            summary.setdefault("results", [])
            summary.setdefault("success_count", 0)
            summary.setdefault("skip_count", 0)
            summary.setdefault("fail_count", 0)
            summary.setdefault("accepted_count", 0)
            summary.setdefault("lease_owner", self.lease_owner)
            summary.setdefault("lease_ttl_seconds", round(self.lease_ttl_seconds, 3))
            summary["message"] = str(summary.get("message") or "heartbeat_stopped")
            summary["heartbeat_running"] = False
            summary["interval_seconds"] = round(self.heartbeat_interval_seconds, 3)
            summary["stopped_at"] = stopped_at
            self.last_lease_summary = summary
            return dict(summary)

    async def start_prefetch(
        self,
        sitekey: str,
        max_queue_target: int | None = None,
        reserve_for_direct: int = 1,
        per_node_prefetch: int = 1,
    ):
        self._prefetch_sitekey = str(sitekey or "").strip()
        self._max_queue_target = max(int(max_queue_target if max_queue_target is not None else self.queue_capacity), 0)
        self._reserve_for_direct = max(int(reserve_for_direct), 0)
        self._per_node_prefetch = max(int(per_node_prefetch), 1)
        self._prefetch_stop.clear()
        if self._prefetch_task and not self._prefetch_task.done():
            return
        self._prefetch_task = asyncio.create_task(self._prefetch_loop())

    async def stop_prefetch(self):
        self._prefetch_stop.set()
        if self._prefetch_task:
            try:
                await asyncio.wait_for(self._prefetch_task, timeout=10)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self._prefetch_task.cancel()
            self._prefetch_task = None

    async def acquire_token(
        self,
        sitekey: str,
        queue_wait_timeout: float | None = None,
        direct_timeout: int | None = None,
        direct_attempts: int = 2,
    ) -> str | None:
        wait_timeout = self.queue_wait_timeout if queue_wait_timeout is None else max(float(queue_wait_timeout), 0.1)
        token_timeout = self.token_timeout if direct_timeout is None else max(int(direct_timeout), 1)

        token = await self._consume_prefetched_token(sitekey=sitekey, wait_timeout=wait_timeout)
        if token:
            self.prefetch_hit_count += 1
            self.last_consume_at = time.time()
            await self._mark_token_success()
            self._log(f"  ✅ 从调度器预热队列取到 Token（队列剩余: {self.token_queue.qsize()}）")
            return token

        self.prefetch_miss_count += 1
        self.fallback_count += 1
        self._log(f"  ⚠️ 调度器预热队列 {int(wait_timeout)}s 无现成 Token，回退到 direct path...")

        for attempt in range(max(int(direct_attempts), 1)):
            token = await self.acquire_direct_token(sitekey=sitekey, timeout=token_timeout)
            if token:
                self.direct_success_count += 1
                return token
            if attempt < max(int(direct_attempts), 1) - 1:
                self._log("  ⚠️ direct path 第 1 次失败，5s 后重试...")
                await asyncio.sleep(5)

        self.direct_fail_count += 1
        return None

    async def acquire_direct_token(self, sitekey: str, timeout: int | None = None) -> str | None:
        token_timeout = self.token_timeout if timeout is None else max(int(timeout), 1)
        await self.refresh_nodes()

        candidates = await self._ranked_nodes(request_kind="direct")
        if not candidates:
            summary = await self._build_unavailable_summary(request_kind="direct")
            streak = await self._mark_direct_unavailable(summary)
            self._log(f"[调度] ❌ 当前没有可用于 direct path 的 Solver 节点（{summary}，streak={streak}）")
            await self._maybe_trigger_targeted_reinitialize(
                trigger_reason="direct_path_no_candidate",
                trigger_summary=summary,
                current_streak=streak,
            )
            return None

        self._log(f"[调度] 🚀 direct path 准备从 {len(candidates)} 个候选节点中请求 Token")
        for node_url in candidates:
            reserved = await self._reserve_dispatch_slot(node_url=node_url, request_kind="direct")
            if not reserved:
                continue
            token = await self._request_token_from_node(
                node_url=node_url,
                sitekey=sitekey,
                timeout=token_timeout,
                request_kind="direct",
            )
            if token:
                return token

        return None

    async def _prefetch_loop(self):
        consecutive_fail_rounds = 0
        self._log("  [调度预热] 🚀 启动远程解题调度中心")
        while not self._prefetch_stop.is_set():
            await self.refresh_nodes()
            await self._discard_invalid_tokens(sitekey=self._prefetch_sitekey)
            queue_target = await self._compute_queue_target()
            self.last_queue_target = queue_target

            if queue_target <= 0:
                await asyncio.sleep(1.5)
                continue

            queue_gap = max(queue_target - self.token_queue.qsize(), 0)
            if queue_gap <= 0:
                await asyncio.sleep(1.0)
                continue

            candidates = await self._ranked_nodes(request_kind="prefetch")
            if not candidates:
                consecutive_fail_rounds += 1
                if consecutive_fail_rounds in {1, 3}:
                    summary = await self._build_unavailable_summary(request_kind="prefetch")
                    self._log(f"  [调度预热] ⚠️ 当前没有可用于预热的节点（{summary}）")
                await asyncio.sleep(min(max(2 ** consecutive_fail_rounds, 2), 15))
                continue

            tasks = []
            for node_url in candidates:
                if len(tasks) >= queue_gap:
                    break
                reserved = await self._reserve_dispatch_slot(node_url=node_url, request_kind="prefetch")
                if not reserved:
                    continue
                tasks.append(
                    asyncio.create_task(
                        self._request_token_from_node(
                            node_url=node_url,
                            sitekey=self._prefetch_sitekey,
                            timeout=max(self.token_timeout, 120),
                            request_kind="prefetch",
                        )
                    )
                )

            if not tasks:
                consecutive_fail_rounds += 1
                await asyncio.sleep(min(max(2 ** consecutive_fail_rounds, 2), 15))
                continue

            results = await asyncio.gather(*tasks, return_exceptions=True)
            success_count = 0
            for item in results:
                if isinstance(item, str) and item:
                    try:
                        self.token_queue.put_nowait(
                            PrefetchedToken(
                                token=item,
                                sitekey=self._prefetch_sitekey,
                                node_url="cluster",
                                created_at=time.time(),
                            )
                        )
                        success_count += 1
                        self.last_fill_at = time.time()
                        self._log(
                            f"  [调度预热] ✅ Token 已入队（队列: {self.token_queue.qsize()}/{max(self.queue_capacity, 1)}）"
                        )
                    except asyncio.QueueFull:
                        break

            if success_count > 0:
                consecutive_fail_rounds = 0
                await asyncio.sleep(1.0)
            else:
                consecutive_fail_rounds += 1
                backoff = min(max(2 ** consecutive_fail_rounds, 2), 20)
                self._log(f"  [调度预热] 💤 连续失败 {consecutive_fail_rounds} 轮，退避等待 {backoff}s...")
                await asyncio.sleep(backoff)

        self._log("  [调度预热] [成功] 调度预热协程已停止")

    async def _compute_queue_target(self) -> int:
        async with self._state_lock:
            states = list(self._nodes.values())

        prefetch_ready_states = [state for state in states if self._candidate_unavailable_reason(state, "prefetch") is None]
        direct_ready_states = [state for state in states if self._candidate_unavailable_reason(state, "direct") is None]
        total_capacity = sum(max(state.effective_capacity, 0) for state in prefetch_ready_states)
        total_browsers = sum(max(state.total_browsers, 0) for state in states if state.online)
        avg_health = (
            sum(state.health_score for state in prefetch_ready_states) / len(prefetch_ready_states)
            if prefetch_ready_states else 0.0
        )

        reserve_for_direct = self._reserve_for_direct
        if len(direct_ready_states) <= 1:
            reserve_for_direct = max(reserve_for_direct, 1)

        target = min(self._max_queue_target, max(total_capacity - reserve_for_direct, 0))
        if total_browsers <= 2 or len(prefetch_ready_states) <= 1:
            target = min(target, 1)
        elif avg_health < 75:
            target = min(target, max(len(prefetch_ready_states), 1))
        return max(target, 0)

    async def _consume_prefetched_token(self, sitekey: str, wait_timeout: float) -> str | None:
        deadline = time.time() + wait_timeout
        while time.time() < deadline:
            remaining = deadline - time.time()
            try:
                item = await asyncio.wait_for(self.token_queue.get(), timeout=max(remaining, 0.05))
            except asyncio.TimeoutError:
                return None

            if item.is_expired(self.token_max_age):
                self._log(f"  [调度预热] ♻️ 丢弃过期 Token（来源: {item.node_url}）")
                continue

            if sitekey and item.sitekey and sitekey != item.sitekey:
                self._log("  [调度预热] ♻️ 丢弃 sitekey 不匹配的旧 Token")
                continue

            return item.token

        return None

    async def _discard_invalid_tokens(self, sitekey: str):
        valid_items: list[PrefetchedToken] = []
        while not self.token_queue.empty():
            try:
                item = self.token_queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            if item.is_expired(self.token_max_age):
                continue
            if sitekey and item.sitekey and item.sitekey != sitekey:
                continue
            valid_items.append(item)

        for item in valid_items[: self.queue_capacity or len(valid_items)]:
            try:
                self.token_queue.put_nowait(item)
            except asyncio.QueueFull:
                break

    async def _ranked_nodes(self, request_kind: str) -> list[str]:
        async with self._state_lock:
            states = list(self._nodes.values())

        candidates = []
        for state in states:
            reason = self._candidate_unavailable_reason(state, request_kind)
            if reason is not None:
                continue
            candidates.append(state)

        def _sort_key(state: RemoteSolverNodeState):
            solve_time = state.avg_solve_time_recent if state.avg_solve_time_recent > 0 else (
                state.avg_solve_time if state.avg_solve_time > 0 else 9999
            )
            return (
                -round(self._candidate_score(state, request_kind), 3),
                -state.effective_capacity,
                -state.available_browsers,
                state.in_flight_total,
                solve_time,
                -state.success_rate,
            )

        random.shuffle(candidates)
        candidates.sort(key=_sort_key)
        return [state.url for state in candidates]

    async def _reserve_dispatch_slot(self, node_url: str, request_kind: str) -> bool:
        async with self._state_lock:
            state = self._nodes.get(node_url)
            if not state:
                return False
            if self._candidate_unavailable_reason(state, request_kind) is not None:
                return False

            state.in_flight_total += 1
            if request_kind == "prefetch":
                state.in_flight_prefetch += 1
            else:
                state.in_flight_direct += 1
            return True

    async def _release_dispatch_slot(self, node_url: str, request_kind: str):
        async with self._state_lock:
            state = self._nodes.get(node_url)
            if not state:
                return
            state.in_flight_total = max(state.in_flight_total - 1, 0)
            if request_kind == "prefetch":
                state.in_flight_prefetch = max(state.in_flight_prefetch - 1, 0)
            else:
                state.in_flight_direct = max(state.in_flight_direct - 1, 0)

    async def _mark_node_success(self, node_url: str, stage: str, message: str, solve_time: float):
        async with self._state_lock:
            state = self._nodes.setdefault(node_url, RemoteSolverNodeState(url=node_url))
            state.online = True
            state.last_stage = stage
            state.last_message = message
            state.last_status = "completed"
            state.last_error = ""
            state.consecutive_failures = 0
            state.success_count += 1
            state.total_solve_time += max(float(solve_time), 0.0)
            if state.avg_solve_time_recent <= 0:
                state.avg_solve_time_recent = round(max(float(solve_time), 0.0), 3)
            else:
                state.avg_solve_time_recent = round((state.avg_solve_time_recent * 0.7) + (max(float(solve_time), 0.0) * 0.3), 3)
            state.recent_timeout_count = max(state.recent_timeout_count - 1, 0)
            state.recent_captcha_fail_count = max(state.recent_captcha_fail_count - 1, 0)
            state.health_score = min(max(state.health_score + 8, 65), 100)
            state.health_status = "recovering" if state.recovering_active else ("healthy" if state.health_score >= 80 else "warming")
            if not state.soft_penalty_active or state.health_score >= 85:
                state.soft_penalty_until = 0.0
                if state.health_status == "healthy":
                    state.degraded_reason = ""
            state.last_seen_at = time.time()

    async def _mark_node_failure(
        self,
        node_url: str,
        status: str,
        stage: str,
        message: str,
        http_status: int = 0,
        trigger_breaker: bool = False,
    ):
        async with self._state_lock:
            state = self._nodes.setdefault(node_url, RemoteSolverNodeState(url=node_url))
            now = time.time()
            state.last_status = status
            state.last_stage = stage
            state.last_message = message
            state.last_error = message
            state.last_http_status = http_status
            state.fail_count += 1
            state.consecutive_failures += 1
            state.last_seen_at = now
            if status == "timeout":
                state.recent_timeout_count += 1
                state.recent_captcha_fail_count += 1
            elif status in {"failed", "error", "busy"}:
                state.recent_captcha_fail_count += 1
            penalty = 10
            if status == "busy":
                penalty = 8
            elif status == "timeout":
                penalty = 16
            elif status == "error":
                penalty = 18
            state.health_score = max(state.health_score - penalty, 0)
            state.health_status = "degraded"
            state.degraded_reason = stage or status
            state.last_degraded_at = now
            state.soft_penalty_until = max(state.soft_penalty_until, now + self.soft_penalty_seconds)
            if trigger_breaker or state.consecutive_failures >= self.breaker_threshold:
                state.breaker_until = now + self.breaker_seconds
                state.recovering_until = max(state.recovering_until, state.breaker_until + self.recovering_observe_seconds)

    async def _mark_node_rejected(self, node_url: str, status: str, stage: str, message: str, http_status: int):
        async with self._state_lock:
            state = self._nodes.setdefault(node_url, RemoteSolverNodeState(url=node_url))
            now = time.time()
            state.last_status = status
            state.last_stage = stage
            state.last_message = message
            state.last_error = message
            state.last_http_status = http_status
            state.rejected_count += 1
            state.last_seen_at = now
            state.health_score = max(state.health_score - (12 if http_status >= 500 else 6), 0)
            state.health_status = "cooling" if http_status >= 500 else "recovering"
            state.degraded_reason = stage or status
            state.last_degraded_at = now
            state.soft_penalty_until = max(state.soft_penalty_until, now + min(self.soft_penalty_seconds, 10.0))
            if http_status >= 500:
                state.breaker_until = now + min(self.breaker_seconds, 8.0)
                state.recovering_until = max(state.recovering_until, state.breaker_until + self.recovering_observe_seconds)

    async def _request_token_from_node(self, node_url: str, sitekey: str, timeout: int, request_kind: str) -> str | None:
        start = time.time()
        task_id = None
        label = "预热" if request_kind == "prefetch" else "直连"
        try:
            resp = await self.http_client.get(
                f"{node_url}/turnstile",
                params={"url": SIGNUP_URL, "sitekey": sitekey},
                timeout=5,
            )
            data = self._response_json_dict(resp)

            async with self._state_lock:
                state = self._nodes.setdefault(node_url, RemoteSolverNodeState(url=node_url))
                self._apply_runtime_snapshot(state, data, mark_online=True, http_status=resp.status_code)

            if resp.status_code >= 400:
                status = str(data.get("status") or "").strip().lower()
                stage = str(data.get("stage") or "").strip().lower()
                error_code = str(data.get("error") or "").strip().lower()
                message = str(data.get("message") or data.get("error") or data)
                lifecycle_rejection = (
                    error_code in {"solver_reinitializing", "solver_draining", "solver_standby", "solver_standby_resume_failed"}
                    or stage in {"reinitializing", "draining", "standby", "standby_waking"}
                    or status in {"draining", "standby"}
                )
                if lifecycle_rejection:
                    async with self._state_lock:
                        state = self._nodes.setdefault(node_url, RemoteSolverNodeState(url=node_url))
                        state.last_status = status or state.last_status or "busy"
                        state.last_stage = stage or state.last_stage or "rejected"
                        state.last_message = message or state.last_message
                        state.last_error = ""
                        state.last_http_status = resp.status_code
                        state.last_seen_at = time.time()
                        state.rejected_count += 1
                        lifecycle_state = state.effective_lifecycle_state
                    self._log(
                        f"[调度] ⚠️ 节点 [{node_url}] 生命周期拒绝 {label} 请求: "
                        f"HTTP {resp.status_code} {message or error_code or lifecycle_state}"
                    )
                    return None

                await self._mark_node_rejected(
                    node_url,
                    status=status or "busy",
                    stage=stage or "rejected",
                    message=message,
                    http_status=resp.status_code,
                )
                self._log(f"[调度] ⚠️ 节点 [{node_url}] 拒绝 {label} 请求: HTTP {resp.status_code} {message}")
                return None

            task_id = data.get("task_id")
            if not task_id:
                message = f"未返回 task_id: {data}"
                await self._mark_node_failure(node_url, status="failed", stage="create_task_failed", message=message, http_status=resp.status_code)
                self._log(f"[调度] ❌ 节点 [{node_url}] 创建任务失败: {message}")
                return None

            self._log(f"[调度] ✅ {label}任务已分配至节点 [{node_url}], TaskID: {task_id[:8]}...")
            elapsed = 0.0
            while elapsed < timeout:
                resp = await self.http_client.get(f"{node_url}/result", params={"task_id": task_id}, timeout=5)
                result = resp.json()
                status = str(result.get("status") or "")
                stage = str(result.get("stage") or "")
                message = str(result.get("message") or result.get("detail") or "")

                async with self._state_lock:
                    state = self._nodes.setdefault(node_url, RemoteSolverNodeState(url=node_url))
                    state.last_status = status or state.last_status
                    state.last_stage = stage or state.last_stage
                    state.last_message = message or state.last_message
                    state.last_seen_at = time.time()

                if status == "completed":
                    token = result.get("solution", {}).get("token", "")
                    if token and token != "CAPTCHA_FAIL":
                        solve_time = float(result.get("elapsed_time", round(time.time() - start, 3)))
                        await self._mark_node_success(node_url, stage=stage or "completed", message=message or "token_ready", solve_time=solve_time)
                        await self._mark_token_success()
                        self._log(f"[调度] ✅ 节点 [{node_url}] 返回 Token，耗时: {solve_time}s")
                        return token
                    await self._mark_node_failure(node_url, status="failed", stage=stage or "completed", message="返回了 CAPTCHA_FAIL")
                    return None

                if status in {"failed", "busy"}:
                    detail = message or f"阶段={stage or 'unknown'}"
                    await self._mark_node_failure(
                        node_url,
                        status=status,
                        stage=stage or status,
                        message=detail,
                        http_status=resp.status_code,
                        trigger_breaker=(status == "busy"),
                    )
                    self._log(f"[调度] ❌ 节点 [{node_url}] {label}请求失败: {detail}")
                    return None

                await asyncio.sleep(self.poll_interval)
                elapsed += self.poll_interval

            await self._mark_node_failure(
                node_url,
                status="timeout",
                stage="poll_timeout",
                message=f"{timeout}s 内未获取到 Token",
                trigger_breaker=True,
            )
            self._log(f"[调度] ❌ 节点 [{node_url}] {label}请求超时 ({timeout}s)")
            return None
        except Exception as e:
            await self._mark_node_failure(
                node_url,
                status="error",
                stage="request_exception",
                message=str(e),
                trigger_breaker=True,
            )
            self._log(f"[调度] ❌ 节点 [{node_url}] {label}请求异常: {e}")
            return None
        finally:
            await self._release_dispatch_slot(node_url=node_url, request_kind=request_kind)

    async def get_status_snapshot(self) -> dict[str, Any]:
        async with self._state_lock:
            states = list(self._nodes.values())
            node_snapshots = [state.snapshot() for state in states]
            in_flight_prefetch_total = sum(state.in_flight_prefetch for state in states)
            in_flight_prefetch_by_node = {
                state.url: state.in_flight_prefetch
                for state in states
                if state.in_flight_prefetch > 0
            }
            online_nodes = sum(1 for state in states if state.online)
            healthy_nodes = sum(1 for state in states if state.online and state.health_status == "healthy")
            degraded_nodes = sum(1 for state in states if state.online and state.health_status == "degraded")
            recovering_nodes = sum(
                1
                for state in states
                if state.online and (state.health_status in {"warming", "recovering", "cooling"} or state.recovering_active)
            )
            soft_penalty_nodes = sum(1 for state in states if state.soft_penalty_active)
            breaker_nodes = sum(1 for state in states if state.breaker_active)
            active_nodes = sum(1 for state in states if state.effective_lifecycle_state == "active")
            draining_nodes = sum(1 for state in states if state.effective_lifecycle_state == "draining")
            standby_nodes = sum(1 for state in states if state.effective_lifecycle_state == "standby")
            reinitializing_nodes = sum(1 for state in states if state.effective_lifecycle_state == "reinitializing")
            offline_nodes = sum(1 for state in states if state.effective_lifecycle_state == "offline")
            accepting_disabled_nodes = sum(1 for state in states if state.online and not state.accepting_new_tasks)
            lease_expired_nodes = sum(1 for state in states if state.online and state.lease_expired)
            busy_nodes = sum(
                1
                for state in states
                if state.online and (
                    state.effective_lifecycle_state in {"draining", "reinitializing"}
                    or (
                        state.effective_lifecycle_state != "standby"
                        and (state.available_browsers <= 0 or state.effective_capacity <= 0)
                    )
                )
            )
            direct_ready_nodes = sum(1 for state in states if self._candidate_unavailable_reason(state, "direct") is None)
            prefetch_ready_nodes = sum(1 for state in states if self._candidate_unavailable_reason(state, "prefetch") is None)
            avg_health_score = round(
                sum(state.health_score for state in states if state.online) / online_nodes,
                3,
            ) if online_nodes else 0.0
            reinit_last_failed_targets = [
                str(item.get("node_url") or item.get("node_label") or item.get("node_id") or "")
                for item in self.last_reinit_results
                if str(item.get("result_type") or "failed") not in {"success", "skip"}
                and str(item.get("node_url") or item.get("node_label") or item.get("node_id") or "")
            ]
            heartbeat_running = bool(self._heartbeat_task and not self._heartbeat_task.done())
            cluster_reinit = {
                "enabled": self.reinit_enabled,
                "admin_configured": bool(self.admin_token),
                "available": self.reinit_enabled and bool(self.admin_token),
                "blocked_by_config": self.reinit_blocked_by_config,
                "block_reason": self.reinit_block_reason,
                "last_skip_is_fatal": self.last_reinit_skip_is_fatal,
                "last_skip_advice": self.last_reinit_skip_advice,
                "last_effective_mode": self.last_reinit_effective_mode,
                "last_effective_targets": list(self.last_reinit_targets),
                "last_failed_targets": reinit_last_failed_targets,
                "trigger_streak": self.reinit_trigger_streak,
                "cooldown_seconds": round(self.reinit_cooldown_seconds, 3),
                "cooldown_remaining": round(self._cluster_reinit_cooldown_remaining(), 3),
                "request_timeout": round(self.reinit_request_timeout, 3),
                "max_targets": self.reinit_max_targets,
                "allow_broadcast": self.reinit_allow_broadcast,
                "requested_by": self.reinit_requested_by,
                "last_reinit_at": round(self.last_reinit_at, 3) if self.last_reinit_at else 0.0,
                "last_reinit_reason": self.last_reinit_reason,
                "last_reinit_targets": list(self.last_reinit_targets),
                "last_reinit_results": list(self.last_reinit_results),
                "last_reinit_summary": self.last_reinit_summary,
                "last_reinit_trigger_streak": self.last_reinit_trigger_streak,
                "attempt_count": self.reinit_attempt_count,
                "success_count": self.reinit_success_count,
                "fail_count": self.reinit_fail_count,
                "skip_count": self.reinit_skip_count,
            }
            drain_summary = dict(self.last_drain_summary or {})
            drain_summary.setdefault("ok", True)
            drain_summary.setdefault("action", "drain_all_nodes")
            drain_summary.setdefault("message", "")
            drain_summary.setdefault("reason", "")
            drain_summary.setdefault("requested_by", "")
            drain_summary.setdefault("source", "")
            drain_summary.setdefault("requested_at", 0.0)
            drain_summary.setdefault("finished_at", 0.0)
            drain_summary.setdefault("targets", [])
            drain_summary.setdefault("results", [])
            drain_summary.setdefault("success_count", 0)
            drain_summary.setdefault("skip_count", 0)
            drain_summary.setdefault("fail_count", 0)
            drain_summary.setdefault("accepted_count", 0)
            drain_summary["in_progress"] = bool(drain_summary.get("in_progress")) or draining_nodes > 0

            resume_summary = dict(self.last_resume_summary or {})
            resume_summary.setdefault("ok", True)
            resume_summary.setdefault("action", "resume_all_nodes")
            resume_summary.setdefault("message", "")
            resume_summary.setdefault("reason", "")
            resume_summary.setdefault("requested_by", "")
            resume_summary.setdefault("source", "")
            resume_summary.setdefault("requested_at", 0.0)
            resume_summary.setdefault("finished_at", 0.0)
            resume_summary.setdefault("targets", [])
            resume_summary.setdefault("results", [])
            resume_summary.setdefault("success_count", 0)
            resume_summary.setdefault("skip_count", 0)
            resume_summary.setdefault("fail_count", 0)
            resume_summary.setdefault("accepted_count", 0)

            lease_summary = dict(self.last_lease_summary or {})
            lease_summary.setdefault("ok", True)
            lease_summary.setdefault("action", "renew_all_leases")
            lease_summary.setdefault("message", "")
            lease_summary.setdefault("reason", "")
            lease_summary.setdefault("requested_at", 0.0)
            lease_summary.setdefault("finished_at", 0.0)
            lease_summary.setdefault("targets", [])
            lease_summary.setdefault("results", [])
            lease_summary.setdefault("success_count", 0)
            lease_summary.setdefault("skip_count", 0)
            lease_summary.setdefault("fail_count", 0)
            lease_summary.setdefault("accepted_count", 0)
            lease_summary["heartbeat_running"] = heartbeat_running
            lease_summary["interval_seconds"] = round(self.heartbeat_interval_seconds, 3)
            lease_summary.setdefault("lease_owner", self.lease_owner)
            lease_summary.setdefault("lease_ttl_seconds", round(self.lease_ttl_seconds, 3))

            last_drain_at = round(float(drain_summary.get("requested_at") or 0.0), 3) if drain_summary.get("requested_at") else 0.0
            last_resume_at = round(float(resume_summary.get("requested_at") or 0.0), 3) if resume_summary.get("requested_at") else 0.0
            last_lease_at = round(float(lease_summary.get("requested_at") or 0.0), 3) if lease_summary.get("requested_at") else 0.0

        return {
            "queue_target": self.last_queue_target,
            "queue_size": self.token_queue.qsize(),
            "queue_capacity": self.queue_capacity,
            "hit_count": self.prefetch_hit_count,
            "miss_count": self.prefetch_miss_count,
            "fallback_count": self.fallback_count,
            "direct_success_count": self.direct_success_count,
            "direct_fail_count": self.direct_fail_count,
            "in_flight_prefetch_total": in_flight_prefetch_total,
            "in_flight_prefetch_by_node": in_flight_prefetch_by_node,
            "last_fill_at": self.last_fill_at,
            "last_consume_at": self.last_consume_at,
            "direct_unavailable_streak": self.direct_unavailable_streak,
            "direct_last_unavailable_since": round(self.direct_unavailable_since, 3) if self.direct_unavailable_since else 0.0,
            "direct_last_unavailable_summary": self.last_direct_unavailable_summary,
            "last_direct_unavailable_at": round(self.last_direct_unavailable_at, 3) if self.last_direct_unavailable_at else 0.0,
            "last_token_success_at": round(self.last_token_success_at, 3) if self.last_token_success_at else 0.0,
            "reinit_available": cluster_reinit["available"],
            "reinit_blocked_by_config": cluster_reinit["blocked_by_config"],
            "reinit_block_reason": cluster_reinit["block_reason"],
            "reinit_last_effective_mode": cluster_reinit["last_effective_mode"],
            "reinit_last_effective_targets": list(cluster_reinit["last_effective_targets"]),
            "reinit_last_failed_targets": list(cluster_reinit["last_failed_targets"]),
            "drain_in_progress": bool(drain_summary.get("in_progress")),
            "last_drain_at": last_drain_at,
            "last_drain_reason": str(drain_summary.get("reason") or ""),
            "last_drain_targets": list(drain_summary.get("targets") or []),
            "last_drain_results": list(drain_summary.get("results") or []),
            "last_resume_at": last_resume_at,
            "last_resume_reason": str(resume_summary.get("reason") or ""),
            "last_resume_targets": list(resume_summary.get("targets") or []),
            "last_resume_results": list(resume_summary.get("results") or []),
            "last_lease_at": last_lease_at,
            "last_lease_targets": list(lease_summary.get("targets") or []),
            "last_lease_results": list(lease_summary.get("results") or []),
            "heartbeat_running": heartbeat_running,
            "heartbeat_interval_seconds": round(self.heartbeat_interval_seconds, 3),
            "reinit": cluster_reinit,
            "drain": drain_summary,
            "resume": resume_summary,
            "lease": lease_summary,
            "lifecycle": {
                "active_nodes": active_nodes,
                "draining_nodes": draining_nodes,
                "standby_nodes": standby_nodes,
                "reinitializing_nodes": reinitializing_nodes,
                "offline_nodes": offline_nodes,
                "accepting_disabled_nodes": accepting_disabled_nodes,
                "lease_expired_nodes": lease_expired_nodes,
            },
            "summary": {
                "online_nodes": online_nodes,
                "healthy_nodes": healthy_nodes,
                "degraded_nodes": degraded_nodes,
                "recovering_nodes": recovering_nodes,
                "soft_penalty_nodes": soft_penalty_nodes,
                "breaker_nodes": breaker_nodes,
                "busy_nodes": busy_nodes,
                "direct_ready_nodes": direct_ready_nodes,
                "prefetch_ready_nodes": prefetch_ready_nodes,
                "avg_health_score": avg_health_score,
                "active_nodes": active_nodes,
                "draining_nodes": draining_nodes,
                "standby_nodes": standby_nodes,
                "reinitializing_nodes": reinitializing_nodes,
                "offline_nodes": offline_nodes,
                "accepting_disabled_nodes": accepting_disabled_nodes,
                "lease_expired_nodes": lease_expired_nodes,
            },
            "nodes": node_snapshots,
        }
