"""
Grok 注册机 Web 控制台后端服务
提供 API 接口用于：统计查询、账号列表、日志读取、进程启停控制、代理池管理
"""
import os
import sys
import csv
import time
import math
import signal
import subprocess
import threading
import webbrowser
import shutil
import string
import random
import json
from collections import deque
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
import httpx
import hashlib
from fastapi import Request
from fastapi.responses import JSONResponse

from singbox_manager import (
    singbox_pm, load_user_config as load_singbox_config,
    save_user_config as save_singbox_config,
    refresh_subscription, download_singbox, SINGBOX_BIN,
    DEFAULT_LISTEN_PORT, set_manual_disabled_node,
)
from result_assets import (
    ensure_result_store,
    build_results_summary,
    get_result_preview,
    resolve_result_file,
    build_results_zip,
    archive_current_batch,
    reset_live_results,
    load_result_state,
    load_account_rows_from_path,
)

app = FastAPI(title="Grok Register Control Center")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
SOLVER_STATUS_SNAPSHOT_FILE = os.path.join(DATA_DIR, "solver_cluster_status.json")
os.makedirs(DATA_DIR, exist_ok=True)
ensure_result_store()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

@app.middleware("http")
async def verify_token_middleware(request: Request, call_next):
    path = request.url.path
    # 仅保护带 /api/ 前缀且不是登录本身的接口
    if path.startswith("/api/") and path != "/api/login":
        if ADMIN_PASSWORD:
            auth_header = request.headers.get("Authorization")
            valid_token = hashlib.sha256(ADMIN_PASSWORD.encode()).hexdigest()
            if not auth_header or not auth_header.startswith("Bearer "):
                return JSONResponse(status_code=401, content={"detail": "未授权：需要提供有效的 Administrator Token"})
            token = auth_header.split(" ")[1]
            if token != valid_token:
                return JSONResponse(status_code=401, content={"detail": "拒绝访问：Token 无效或已过期"})
    response = await call_next(request)
    return response

class LoginRequest(BaseModel):
    password: str

@app.post("/api/login")
def admin_login(req: LoginRequest):
    if not ADMIN_PASSWORD:
        return {"token": "no_auth_required", "message": "未配置管理密码，直接放行"}
    
    if req.password != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="密码错误！")
    
    token = hashlib.sha256(ADMIN_PASSWORD.encode()).hexdigest()
    return {"token": token, "message": "登录成功"}

ACCOUNTS_CSV_PATH = os.path.join(DATA_DIR, "accounts.csv")
SCRIPT_PATH = os.path.join(BASE_DIR, "grok_hybrid_register_v6.py")
SOLVER_NODES_FILE = os.path.join(BASE_DIR, "solver_nodes.txt")


def _load_account_rows() -> tuple[bool, list[str], list[list[str]]]:
    """读取 accounts.csv，兼容有表头/无表头两种格式。"""
    return load_account_rows_from_path(ACCOUNTS_CSV_PATH)



def _build_result_download_name(scope: str, filename: str) -> str:
    if scope == "current":
        batch_id = load_result_state().get("current_batch_id") or "current-batch"
        return f"{batch_id}-{filename}"
    return filename


def _read_solver_nodes() -> list[str]:
    """读取远程 Solver 节点列表：环境变量优先，其次 solver_nodes.txt；不再回退到本地 localhost。"""
    nodes: list[str] = []
    env_nodes = os.environ.get("SOLVER_NODES", "").strip()
    if env_nodes:
        for raw in env_nodes.split(","):
            line = raw.strip()
            if not line:
                continue
            if not line.startswith("http"):
                line = f"http://{line}"
            nodes.append(line.rstrip("/"))
        return nodes

    if os.path.exists(SOLVER_NODES_FILE):
        try:
            with open(SOLVER_NODES_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        if not line.startswith("http"):
                            line = f"http://{line}"
                        nodes.append(line.rstrip("/"))
        except Exception:
            pass
    return nodes


def _read_remote_solver_nodes() -> list[str]:
    """过滤掉 localhost/127.0.0.1，仅保留远程 API Solver 节点。"""
    remote_nodes: list[str] = []
    for node in _read_solver_nodes():
        lowered = node.lower()
        if "127.0.0.1" in lowered or "localhost" in lowered:
            continue
        remote_nodes.append(node)
    return remote_nodes


def _normalize_remote_solver_node(node_url: str) -> str:
    node = str(node_url or "").strip()
    if not node:
        return ""
    if not node.startswith("http"):
        node = f"http://{node}"
    node = node.rstrip("/")
    lowered = node.lower()
    if "127.0.0.1" in lowered or "localhost" in lowered:
        return ""
    return node


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value or 0)
    except Exception:
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value or 0)
    except Exception:
        return default


def _load_solver_cluster_snapshot() -> dict[str, Any]:
    if not os.path.exists(SOLVER_STATUS_SNAPSHOT_FILE):
        return {}
    try:
        with open(SOLVER_STATUS_SNAPSHOT_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception as e:
        return {"reason": f"snapshot_read_error: {e}"}


def _build_solver_node_status(
    node_url: str,
    live_data: dict[str, Any] | None = None,
    snapshot_node: dict[str, Any] | None = None,
    error: str = "",
) -> dict[str, Any]:
    live_data = live_data or {}
    snapshot_node = snapshot_node or {}

    available = _safe_int(live_data.get("available_browsers", snapshot_node.get("available_browsers", 0)))
    raw_available = _safe_int(live_data.get("raw_available_browsers", snapshot_node.get("raw_available_browsers", available)))
    reserved_slots = _safe_int(live_data.get("reserved_slots", snapshot_node.get("reserved_slots", 0)))
    total_browsers = _safe_int(live_data.get("total_browsers", snapshot_node.get("total_browsers", 0)))
    tracked_tasks = _safe_int(live_data.get("tracked_tasks", snapshot_node.get("tracked_tasks", 0)))
    solved = _safe_int(live_data.get("total_solved", snapshot_node.get("success_count", 0)))
    failed = _safe_int(live_data.get("total_failed", snapshot_node.get("fail_count", 0)))
    rejected = _safe_int(snapshot_node.get("rejected_count", 0))
    in_flight_total = _safe_int(snapshot_node.get("in_flight_total", 0))
    in_flight_prefetch = _safe_int(snapshot_node.get("in_flight_prefetch", 0))
    in_flight_direct = _safe_int(snapshot_node.get("in_flight_direct", 0))
    breaker_remaining = round(_safe_float(snapshot_node.get("breaker_remaining", 0.0)), 3)
    last_seen_at = _safe_float(snapshot_node.get("last_seen_at", 0.0))
    avg_solve_time = round(_safe_float(live_data.get("avg_solve_time", snapshot_node.get("avg_solve_time", 0.0))), 3)
    avg_solve_time_recent = round(_safe_float(live_data.get("avg_solve_seconds_recent", snapshot_node.get("avg_solve_time_recent", avg_solve_time))), 3)
    memory_mb = round(_safe_float(live_data.get("memory_mb", 0.0)), 1)

    success_attempts = solved + failed
    success_rate = round((solved / success_attempts * 100), 1) if success_attempts > 0 else round(_safe_float(snapshot_node.get("success_rate", 0.0)) * 100, 1)

    node_id = str(live_data.get("node_id") or snapshot_node.get("node_id") or "")
    node_label = str(live_data.get("node_label") or snapshot_node.get("node_label") or node_id or node_url)
    boot_id = str(live_data.get("boot_id") or snapshot_node.get("boot_id") or "")
    started_at = _safe_float(live_data.get("started_at", snapshot_node.get("started_at", 0.0)))
    uptime_seconds = round(_safe_float(live_data.get("uptime_seconds", snapshot_node.get("uptime_seconds", 0.0))), 3)
    init_count = _safe_int(live_data.get("init_count", snapshot_node.get("init_count", 0)))
    last_init_at = _safe_float(live_data.get("last_init_at", snapshot_node.get("last_init_at", 0.0)))
    last_init_reason = str(live_data.get("last_init_reason") or snapshot_node.get("last_init_reason") or "")
    last_init_result = str(live_data.get("last_init_result") or snapshot_node.get("last_init_result") or "")
    last_reinit_requested_by = str(live_data.get("last_reinit_requested_by") or snapshot_node.get("last_reinit_requested_by") or "")
    last_reinit_source = str(live_data.get("last_reinit_source") or snapshot_node.get("last_reinit_source") or "")
    last_reinit_request_at = _safe_float(live_data.get("last_reinit_request_at", snapshot_node.get("last_reinit_request_at", 0.0)))
    last_reinit_finished_at = _safe_float(live_data.get("last_reinit_finished_at", snapshot_node.get("last_reinit_finished_at", 0.0)))
    last_reinit_error = str(live_data.get("last_reinit_error") or snapshot_node.get("last_reinit_error") or "")
    last_reinit_status = str(live_data.get("last_reinit_status") or snapshot_node.get("last_reinit_status") or "")
    last_reinit_message = str(live_data.get("last_reinit_message") or snapshot_node.get("last_reinit_message") or "")
    reinit_in_progress = bool(live_data.get("reinit_in_progress", snapshot_node.get("reinit_in_progress", False)))
    reinit_supported = bool(live_data.get("reinit_supported", snapshot_node.get("reinit_supported", False)))
    reinit_cooldown_until = _safe_float(live_data.get("reinit_cooldown_until", snapshot_node.get("reinit_cooldown_until", 0.0)))
    reinit_cooldown_remaining = round(_safe_float(live_data.get("reinit_cooldown_remaining", snapshot_node.get("reinit_cooldown_remaining", 0.0))), 3)

    online = bool(live_data) and not error
    last_status = str(snapshot_node.get("last_status") or ("healthy" if online else "offline"))
    last_stage = str(snapshot_node.get("last_stage") or "")
    last_message = str(snapshot_node.get("last_message") or live_data.get("message") or "")
    last_error = str(error or snapshot_node.get("last_error") or "")
    consecutive_failures = _safe_int(snapshot_node.get("consecutive_failures", 0))
    breaker_active = breaker_remaining > 0
    effective_capacity = max(available - in_flight_total, 0)
    stale = (not online) and bool(snapshot_node)

    health_score = _safe_int(
        live_data.get("node_health_score", snapshot_node.get("health_score", 100 if online else 0)),
        100 if online else 0,
    )
    health_score = max(min(health_score, 100), 0)

    health_status = str(live_data.get("node_health_status") or snapshot_node.get("health_status") or "").strip().lower()
    if not health_status:
        if not online:
            health_status = "offline"
        elif breaker_active:
            health_status = "degraded"
        elif available <= 0 or effective_capacity <= 0:
            health_status = "cooling"
        elif health_score >= 80:
            health_status = "healthy"
        elif health_score >= 60:
            health_status = "warming"
        elif health_score > 0:
            health_status = "recovering"
        else:
            health_status = "degraded"

    degraded_reason = str(
        live_data.get("node_degraded_reason")
        or snapshot_node.get("degraded_reason")
        or last_error
        or ""
    ).strip()

    soft_penalty_remaining = round(_safe_float(snapshot_node.get("soft_penalty_remaining", 0.0)), 3)
    soft_penalty_active = bool(snapshot_node.get("soft_penalty_active")) or soft_penalty_remaining > 0
    recovering_remaining = round(_safe_float(snapshot_node.get("recovering_remaining", 0.0)), 3)
    recovering_active = bool(snapshot_node.get("recovering_active")) or recovering_remaining > 0
    recent_timeout_count = _safe_int(live_data.get("recent_timeout_count", snapshot_node.get("recent_timeout_count", 0)))
    recent_captcha_fail_count = _safe_int(live_data.get("recent_captcha_fail_count", snapshot_node.get("recent_captcha_fail_count", 0)))
    last_degraded_at = _safe_float(snapshot_node.get("last_degraded_at", 0.0))

    busy = online and (available <= 0 or effective_capacity <= 0 or last_status == "busy" or health_status == "cooling" or reinit_in_progress)
    degraded = (
        breaker_active
        or soft_penalty_active
        or consecutive_failures > 0
        or health_status in {"degraded", "recovering", "cooling"}
        or last_status in {"failed", "timeout", "offline"}
        or reinit_in_progress
    )

    if live_data and snapshot_node:
        source = "live+snapshot"
    elif live_data:
        source = "live"
    elif snapshot_node:
        source = "snapshot"
    else:
        source = "none"

    return {
        "url": node_url,
        "node_id": node_id,
        "node_label": node_label,
        "boot_id": boot_id,
        "started_at": started_at,
        "uptime_seconds": uptime_seconds,
        "source": source,
        "online": online,
        "stale": stale,
        "busy": busy,
        "degraded": degraded,
        "breaker_active": breaker_active,
        "breaker_remaining": breaker_remaining,
        "health_score": health_score,
        "health_status": health_status,
        "degraded_reason": degraded_reason,
        "soft_penalty_active": soft_penalty_active,
        "soft_penalty_remaining": soft_penalty_remaining,
        "recovering_active": recovering_active,
        "recovering_remaining": recovering_remaining,
        "recent_timeout_count": recent_timeout_count,
        "recent_captcha_fail_count": recent_captcha_fail_count,
        "available_browsers": available,
        "raw_available_browsers": raw_available,
        "effective_capacity": effective_capacity,
        "reserved_slots": reserved_slots,
        "total_browsers": total_browsers,
        "tracked_tasks": tracked_tasks,
        "solved": solved,
        "failed": failed,
        "rejected_count": rejected,
        "success_rate": success_rate,
        "memory_mb": memory_mb,
        "avg_solve_time": avg_solve_time,
        "avg_solve_time_recent": avg_solve_time_recent,
        "in_flight_total": in_flight_total,
        "in_flight_prefetch": in_flight_prefetch,
        "in_flight_direct": in_flight_direct,
        "consecutive_failures": consecutive_failures,
        "init_count": init_count,
        "last_init_at": last_init_at,
        "last_init_reason": last_init_reason,
        "last_init_result": last_init_result,
        "last_reinit_requested_by": last_reinit_requested_by,
        "last_reinit_source": last_reinit_source,
        "last_reinit_request_at": last_reinit_request_at,
        "last_reinit_finished_at": last_reinit_finished_at,
        "last_reinit_error": last_reinit_error,
        "last_reinit_status": last_reinit_status,
        "last_reinit_message": last_reinit_message,
        "reinit_in_progress": reinit_in_progress,
        "reinit_supported": reinit_supported,
        "reinit_cooldown_until": reinit_cooldown_until,
        "reinit_cooldown_remaining": reinit_cooldown_remaining,
        "last_status": last_status,
        "last_stage": last_stage,
        "last_message": last_message,
        "last_error": last_error,
        "last_http_status": _safe_int(snapshot_node.get("last_http_status", 0)),
        "last_seen_at": last_seen_at,
        "last_degraded_at": last_degraded_at,
    }


# ========== 全局进程管理器 ==========
class ProcessManager:
    """管理底层注册脚本的子进程生命周期"""
    def __init__(self):
        self.process: Optional[subprocess.Popen] = None
        self.log_buffer: deque = deque(maxlen=500)
        self.is_running: bool = False
        self.reader_thread: Optional[threading.Thread] = None
        self.current_params: Dict[str, Any] = {}
        self.success_count: int = 0
        self.fail_count: int = 0
        self.start_time: float = 0

    def start(self, count: int, concurrency: int) -> bool:
        """启动注册脚本子进程（仅使用远程 API Solver）。"""
        if self.is_running and self.process and self.process.poll() is None:
            return False  # 已经在跑了

        self.log_buffer.clear()
        self.current_params = {"count": count, "concurrency": concurrency}
        self.start_time = time.time()

        remote_nodes = _read_remote_solver_nodes()
        if not remote_nodes:
            self.log_buffer.append("[控制台] ❌ 未配置远程 API Solver 节点，无法启动注册任务。")
            self.log_buffer.append("[控制台] 请通过环境变量 SOLVER_NODES 或 solver_nodes.txt 提供至少 1 个远程节点。")
            self.is_running = False
            return False

        self.log_buffer.append(
            f"[控制台] 🌐 纯远程 API Solver 模式已启用，本次 {concurrency} 线程将使用 {len(remote_nodes)} 个远程解题节点。"
        )

        # ---- 第二步：启动注册机 ----
        global API_POOL_URL, DIRECT_SOCKS_URL, ENABLE_PROXY_POOL, PROXY_MODE
        env = os.environ.copy()
        for key in ["PROXY", "ALL_PROXY", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"]:
            env.pop(key, None)
        env["DISABLE_SYSTEM_PROXY"] = "true"
        env["PROXY_POOL_API_BASE"] = API_POOL_URL
        env["ENABLE_PROXY_POOL"] = str(ENABLE_PROXY_POOL).lower()
        env["PROXY_MODE"] = PROXY_MODE  # 注入代理模式（api_pool / direct_socks）
        env["SOLVER_NODES"] = ",".join(remote_nodes)

        runtime_proxy_mode = "direct"
        runtime_proxy_target = "直连（未配置代理）"
        runtime_proxy_detail = "DISABLE_SYSTEM_PROXY=true，子进程不会回退系统代理"

        # 直连网关模式：将 socks5 地址直接注入为全局代理
        if PROXY_MODE == "direct_socks" and ENABLE_PROXY_POOL:
            env["PROXY"] = DIRECT_SOCKS_URL
            runtime_proxy_mode = "direct_socks"
            runtime_proxy_target = DIRECT_SOCKS_URL or "未配置直连网关地址"
            runtime_proxy_detail = "注册脚本将直接使用该网关地址出站，网关内部自动轮换节点"
            self.log_buffer.append(f"[控制台] 🚀 直连网关模式: {DIRECT_SOCKS_URL}")
        elif ENABLE_PROXY_POOL:
            runtime_proxy_mode = "api_pool"
            runtime_proxy_target = API_POOL_URL or "未配置 API 节点池地址"
            runtime_proxy_detail = "注册脚本运行时会从 API 节点池轮询拉取 socks5 地址"

        # sing-box 代理模式注入
        sb_cfg = load_singbox_config()
        sb_status = singbox_pm.get_status()
        if sb_cfg.get("enabled", False) and singbox_pm.is_running:
            env["SINGBOX_ENABLED"] = "true"
            persisted_port = sb_cfg.get("listen_port", DEFAULT_LISTEN_PORT)
            config_port = sb_status.get("config_listen_port", persisted_port)
            candidate_preview_text = sb_status.get("candidate_preview_text", "暂无候选节点") or "暂无候选节点"
            candidate_preview_tags = sb_status.get("candidate_preview_tags", []) or []
            candidate_tags_text = ", ".join(
                [str(tag).strip() for tag in candidate_preview_tags if str(tag).strip()]
            )
            urltest_probe_url = sb_status.get("urltest_probe_url", "") or sb_status.get("target_url", "") or "未配置"
            env["SINGBOX_PROXY"] = f"socks5h://127.0.0.1:{config_port}"
            env["SINGBOX_CANDIDATE_PREVIEW_TEXT"] = str(candidate_preview_text)
            env["SINGBOX_CANDIDATE_COUNT"] = str(sb_status.get("available_count", 0))
            env["SINGBOX_CANDIDATE_TAGS"] = candidate_tags_text
            env["SINGBOX_URLTEST_PROBE_URL"] = str(urltest_probe_url)
            runtime_proxy_mode = "sing-box"
            runtime_proxy_target = env["SINGBOX_PROXY"]
            runtime_proxy_detail = "注册脚本接入 sing-box 本地 mixed 入口；真正远端节点由 sing-box 在候选池中自动选路"
            self.log_buffer.append(
                f"[控制台] sing-box 本地接入点已注入: socks5h://127.0.0.1:{config_port} "
                f"(persisted={persisted_port}, config={config_port}, consistent={sb_status.get('port_consistent', True)})"
            )
            self.log_buffer.append(f"[控制台] sing-box 候选池: {candidate_preview_text}")
            self.log_buffer.append(
                f"[控制台] sing-box 候选标签预览: {candidate_tags_text or '暂无候选标签'}"
            )
            self.log_buffer.append(f"[控制台] sing-box urltest 探测目标: {urltest_probe_url}")
        else:
            env["SINGBOX_ENABLED"] = "false"
            for key in [
                "SINGBOX_CANDIDATE_PREVIEW_TEXT",
                "SINGBOX_CANDIDATE_COUNT",
                "SINGBOX_CANDIDATE_TAGS",
                "SINGBOX_URLTEST_PROBE_URL",
            ]:
                env.pop(key, None)
            if env.get("PROXY"):
                runtime_proxy_mode = "explicit_proxy"
                runtime_proxy_target = env["PROXY"]
                runtime_proxy_detail = "显式代理已注入到注册脚本"
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUNBUFFERED"] = "1"

        cmd = [
            sys.executable,
            "-u",
            SCRIPT_PATH,
            "--count", str(count),
            "--concurrency", str(concurrency),
        ]

        self.log_buffer.append(f"[控制台] 启动命令: {' '.join(cmd)}")
        self.log_buffer.append(f"[控制台] 注册数量: {count}, 并发数: {concurrency}")
        self.log_buffer.append(f"[控制台] 代理接入模式: {runtime_proxy_mode}")
        self.log_buffer.append(f"[控制台] 进程代理接入点: {runtime_proxy_target}")
        self.log_buffer.append(f"[控制台] 调度诊断: {runtime_proxy_detail}")
        self.log_buffer.append("=" * 60)

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=env,
                cwd=BASE_DIR,
                bufsize=0,  # 无缓冲二进制模式，最大化实时性
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0,
            )
            self.is_running = True

            self.reader_thread = threading.Thread(target=self._read_output, daemon=True)
            self.reader_thread.start()
            return True
        except Exception as e:
            self.log_buffer.append(f"[错误] 启动失败: {str(e)}")
            self.is_running = False
            return False

    def stop(self) -> bool:
        """强制终止注册脚本子进程。"""
        if not self.process or self.process.poll() is not None:
            self.is_running = False
            return False

        self.log_buffer.append("[控制台] 收到停止信号，正在终止进程...")
        try:
            if os.name == 'nt':
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(self.process.pid)],
                    capture_output=True
                )
            else:
                os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
            self.process = None
            self.is_running = False
            self.log_buffer.append("[控制台] 注册引擎已停止。")
            return True
        except Exception as e:
            self.log_buffer.append(f"[错误] 终止进程失败: {str(e)}")
            return False

    def _read_output(self):
        """后台线程：逐块读取子进程二进制输出，手动分行实现真正的实时推送"""
        from datetime import datetime
        import os as _os
        buf = b""
        fd = self.process.stdout.fileno()
        try:
            while True:
                # 用 os.read 直接读取管道，不经过 Python IO 层缓冲
                chunk = _os.read(fd, 4096)
                if not chunk:
                    break  # EOF，子进程已关闭 stdout
                buf += chunk
                # 按换行符分割，处理完整的行
                while b"\n" in buf:
                    line_bytes, buf = buf.split(b"\n", 1)
                    line = line_bytes.decode("utf-8", errors="replace").rstrip()
                    if line:
                        ts = datetime.now().strftime("%H:%M:%S")
                        self.log_buffer.append(f"[{ts}] {line}")
                        if '[STAT] SUCCESS' in line:
                            self.success_count += 1
                        elif '[STAT] FAIL' in line:
                            self.fail_count += 1
            # 处理残留的最后一行（无换行符结尾）
            if buf:
                line = buf.decode("utf-8", errors="replace").rstrip()
                if line:
                    ts = datetime.now().strftime("%H:%M:%S")
                    self.log_buffer.append(f"[{ts}] {line}")
            self.process.stdout.close()
        except Exception:
            pass
        finally:
            elapsed = int(time.time() - self.start_time) if self.start_time > 0 else 0
            self.start_time = elapsed
            self.is_running = False
            ts = datetime.now().strftime("%H:%M:%S")
            self.log_buffer.append(f"[{ts}] [控制台] 脚本执行完毕。总耗时 {elapsed} 秒。")

    def get_status(self) -> str:
        """获取当前进程运行状态"""
        if self.process and self.process.poll() is None:
            self.is_running = True
            return "Running"
        self.is_running = False
        return "Idle"

# 全局单例
pm = ProcessManager()


# ========== 代理池通信持久化配置 ==========
PROXY_CONFIG_FILE = os.path.join(DATA_DIR, "proxy_config.json")

def load_proxy_config() -> dict:
    """加载代理配置，兼容旧版单 api_base 字段自动迁移为双地址"""
    config = {"api_pool_url": "http://127.0.0.1:8080", "direct_socks_url": "", "enable_pool": False, "proxy_mode": "api_pool"}
    if os.path.exists(PROXY_CONFIG_FILE):
        try:
            with open(PROXY_CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                config["enable_pool"] = data.get("enable_pool", config["enable_pool"])
                config["proxy_mode"] = data.get("proxy_mode", config["proxy_mode"])
                # 兼容旧版：如果存在新字段则直接用，否则从旧 api_base 迁移
                if "api_pool_url" in data:
                    config["api_pool_url"] = data["api_pool_url"]
                    config["direct_socks_url"] = data.get("direct_socks_url", "")
                elif "api_base" in data:
                    old_base = data["api_base"]
                    if config["proxy_mode"] == "direct_socks":
                        config["direct_socks_url"] = old_base
                    else:
                        config["api_pool_url"] = old_base
        except Exception:
            pass
    return config

_cfg = load_proxy_config()
API_POOL_URL = _cfg["api_pool_url"]       # API 节点池拉取地址
DIRECT_SOCKS_URL = _cfg["direct_socks_url"]  # SOCKS5/HTTP 直连网关地址
ENABLE_PROXY_POOL = _cfg["enable_pool"]
PROXY_MODE = _cfg["proxy_mode"]  # 代理模式：api_pool / direct_socks

def get_active_proxy_url() -> str:
    """根据当前模式返回对应的代理地址"""
    return DIRECT_SOCKS_URL if PROXY_MODE == "direct_socks" else API_POOL_URL

def save_proxy_config(api_pool_url: str, direct_socks_url: str, enable_pool: bool, proxy_mode: str = "api_pool"):
    try:
        with open(PROXY_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump({
                "api_pool_url": api_pool_url,
                "direct_socks_url": direct_socks_url,
                "enable_pool": enable_pool,
                "proxy_mode": proxy_mode,
            }, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"保存代理配置失败: {e}")


# ========== 请求模型 ==========
class RunRequest(BaseModel):
    count: int = 10
    concurrency: int = 5

# ========== 挂载静态文件 ==========
web_ui_path = os.path.join(BASE_DIR, "web_ui")
if not os.path.exists(web_ui_path):
    os.makedirs(web_ui_path)
app.mount("/ui", StaticFiles(directory=web_ui_path, html=True), name="web_ui")

# ========== API 路由 ==========
@app.get("/")
def read_root():
    return RedirectResponse(url="/ui/")

@app.get("/api/stats")
def get_stats() -> Dict[str, Any]:
    """获取整体统计数据"""
    total_accounts = 0
    try:
        _, _, data_rows = _load_account_rows()
        total_accounts = len(data_rows)
    except Exception:
        pass

    elapsed = 0
    if pm.start_time > 0:
        if pm.is_running:
            elapsed = int(time.time() - pm.start_time)
        else:
            elapsed = int(pm.start_time)  # 停止后保留最终时长

    return {
        "totalGenerated": total_accounts,
        "successCount": pm.success_count,
        "failCount": pm.fail_count,
        "elapsed": elapsed,
        "status": pm.get_status(),
        "params": pm.current_params,
    }

@app.post("/api/stats/reset")
def reset_stats():
    """清空计数器与实时结果文件，并开启新批次。"""
    if pm.is_running:
        raise HTTPException(status_code=409, detail="引擎运行中，禁止清空结果文件。")
    pm.success_count = 0
    pm.fail_count = 0
    reset_live_results()
    return {"message": "统计与结果文件已清空，并已开启新批次"}

@app.get("/api/accounts")
def get_accounts(limit: int = 50) -> List[Dict[str, str]]:
    """兼容旧页面：返回全量结果中的最新账号预览。"""
    try:
        return get_result_preview(scope="all", limit=limit)["items"]
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/results/summary")
def get_results_summary() -> Dict[str, Any]:
    """获取结果资产中心摘要（当前批次 + 全量结果）。"""
    return build_results_summary()


@app.get("/api/results/preview")
def get_results_preview(scope: str = "current", limit: int = 20) -> Dict[str, Any]:
    """获取结果预览列表。"""
    try:
        return get_result_preview(scope=scope, limit=limit)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/results/download")
def download_result_file(scope: str = "current", file: str = "accounts"):
    """下载单个结果文件。"""
    try:
        file_info = resolve_result_file(scope, file)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return FileResponse(
        path=file_info["path"],
        filename=_build_result_download_name(file_info["scope"], file_info["filename"]),
        media_type="application/octet-stream",
    )


@app.get("/api/results/download-zip")
def download_results_zip(scope: str = "current"):
    """打包下载指定作用域的三件套结果文件。"""
    try:
        zip_info = build_results_zip(scope)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return FileResponse(
        path=zip_info["path"],
        filename=zip_info["filename"],
        media_type="application/zip",
    )


@app.post("/api/results/archive-current")
def archive_results_current() -> Dict[str, Any]:
    """封存当前批次并开启新批次。"""
    if pm.is_running:
        raise HTTPException(status_code=409, detail="引擎运行中，禁止封存当前批次。")
    try:
        return archive_current_batch()
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/logs")
def get_logs(lines: int = 200) -> Dict[str, Any]:
    """获取实时日志（优先从子进程缓冲区获取，否则读文件）"""
    log_lines = list(pm.log_buffer)
    if not log_lines:
        # 回退：兼容两个历史日志文件名
        candidate_files = [
            os.path.join(DATA_DIR, "注册机测试日志.txt"),
            os.path.join(DATA_DIR, "v6测试日志.txt"),
        ]
        for log_file in candidate_files:
            if os.path.exists(log_file):
                try:
                    with open(log_file, 'r', encoding='utf-8', errors='replace') as f:
                        log_lines = [l.strip() for l in f.readlines()[-lines:]]
                    break
                except Exception:
                    log_lines = ["[系统] 日志文件读取失败。"]
                    break
        if not log_lines:
            log_lines = ["[系统] 等待脚本启动..."]
    return {"logs": log_lines[-lines:]}

@app.post("/api/control/run")
def control_run(req: RunRequest):
    """启动注册脚本"""
    if pm.is_running:
        raise HTTPException(status_code=409, detail="引擎已在运行中，请先停止当前任务。")
    ok = pm.start(count=req.count, concurrency=req.concurrency)
    if not ok:
        raise HTTPException(status_code=500, detail="启动失败，请检查日志。")
    return {"message": f"启动成功：注册 {req.count} 个，并发 {req.concurrency} 路", "status": "Running"}

@app.post("/api/control/stop")
def control_stop():
    """停止注册脚本"""
    ok = pm.stop()
    if not ok:
        return {"message": "当前没有运行中的任务。", "status": "Idle"}
    return {"message": "进程已终止。", "status": "Idle"}


# ========== 代理池 API 透传路由 ==========

@app.get("/api/proxy/status")
async def proxy_pool_status():
    """获取代理池状态（兼容 API 模式和直连模式），返回双地址供前端各自记忆"""
    global API_POOL_URL, DIRECT_SOCKS_URL, ENABLE_PROXY_POOL, PROXY_MODE
    # 公共字段：始终返回双地址 + 当前模式
    common = {
        "proxy_mode": PROXY_MODE,
        "api_pool_url": API_POOL_URL,
        "direct_socks_url": DIRECT_SOCKS_URL,
        "enable_pool": ENABLE_PROXY_POOL,
    }
    # 直连网关模式：不请求远端 API，直接返回静态状态
    if PROXY_MODE == "direct_socks":
        return {
            **common,
            "total": 0,
            "proxies": [],
            "active_proxy": DIRECT_SOCKS_URL if ENABLE_PROXY_POOL else "N/A",
            "active_region": "动态网关内部自动轮换",
            "last_scrape": "",
            "next_scrape": "",
        }
    # API 节点池模式：走原有远端拉取逻辑
    try:
        if not API_POOL_URL:
            return {**common, "status": "unconfigured", "total": 0, "proxies": [], "active_proxy": "N/A"}
        async with httpx.AsyncClient(timeout=3) as client:
            r = await client.get(f"{API_POOL_URL}/api/status")
            data = r.json()
            data.update(common)
            return data
    except Exception as e:
        return {**common, "error": str(e), "total": 0, "proxies": [], "active_proxy": "N/A"}

@app.post("/api/proxy/refresh")
async def proxy_pool_refresh():
    """透传触发远端代理池强制刷新"""
    global API_POOL_URL
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(f"{API_POOL_URL}/api/refresh")
            return r.json()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"远端代理池不可达: {e}")

@app.get("/api/proxy/switch")
async def proxy_pool_switch(index: Optional[int] = None):
    """透传切换代理池当前使用的节点"""
    global API_POOL_URL
    try:
        url = f"{API_POOL_URL}/api/switch"
        if index is not None:
            url += f"?index={index}"
        async with httpx.AsyncClient(timeout=3) as client:
            r = await client.get(url)
            return r.json()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"远端代理池不可达: {e}")

class ProxyConfig(BaseModel):
    api_pool_url: str = ""
    direct_socks_url: str = ""
    enable_pool: bool = False
    proxy_mode: str = "api_pool"  # api_pool / direct_socks

@app.post("/api/proxy/config")
async def config_proxy_api(config: ProxyConfig):
    """配置代理模式、双地址、开关并持久化"""
    global API_POOL_URL, DIRECT_SOCKS_URL, ENABLE_PROXY_POOL, PROXY_MODE
    # 清理尾部斜杠
    api_url = config.api_pool_url.strip().rstrip("/")
    socks_url = config.direct_socks_url.strip()
    API_POOL_URL = api_url
    DIRECT_SOCKS_URL = socks_url
    ENABLE_PROXY_POOL = config.enable_pool
    PROXY_MODE = config.proxy_mode if config.proxy_mode in ("api_pool", "direct_socks") else "api_pool"
    save_proxy_config(API_POOL_URL, DIRECT_SOCKS_URL, ENABLE_PROXY_POOL, PROXY_MODE)
    return {
        "status": "success",
        "api_pool_url": API_POOL_URL,
        "direct_socks_url": DIRECT_SOCKS_URL,
        "enable_pool": ENABLE_PROXY_POOL,
        "proxy_mode": PROXY_MODE,
    }


# ========== Solver 实时状态聚合 API ==========

def _parse_token_queue_from_logs() -> dict:
    """从注册脚本日志缓冲区中提取 Token 预热队列的最新状态（兼容旧预热与新调度器日志）"""
    import re

    queue_size = 0
    queue_cap = 0
    last_event = ""
    last_hint = ""
    log_lines = list(pm.log_buffer)

    for raw_line in reversed(log_lines):
        log_line = str(raw_line or "").strip()
        if not log_line:
            continue

        if "Token 已入队" in log_line and "队列:" in log_line:
            m = re.search(r'队列:\s*(\d+)/(\d+)', log_line)
            if m:
                queue_size = int(m.group(1))
                queue_cap = int(m.group(2))
            last_event = "token_enqueued"
            last_hint = log_line
            break

        if "队列剩余:" in log_line and "Token" in log_line:
            m = re.search(r'队列剩余:\s*(\d+)', log_line)
            if m:
                queue_size = int(m.group(1))
            last_event = "token_consumed"
            last_hint = log_line
            break

        if ("调度器预热队列" in log_line or "预热队列" in log_line) and "回退" in log_line:
            last_event = "fallback_direct"
            last_hint = log_line
            break

        if "启动远程解题调度中心" in log_line or "启动 Token 预热队列" in log_line:
            last_event = "prefetch_started"
            last_hint = log_line
            break

        if "预热协程已停止" in log_line:
            last_event = "prefetch_stopped"
            last_hint = log_line
            break

        if "连续失败" in log_line and "退避等待" in log_line:
            last_event = "prefetch_backoff"
            last_hint = log_line
            break

        if "当前没有可用于 direct path 的 Solver 节点" in log_line:
            last_event = "direct_no_candidate"
            last_hint = log_line
            break

    if queue_cap <= 0:
        for raw_line in reversed(log_lines):
            log_line = str(raw_line or "").strip()
            if "队列容量:" not in log_line and "队列:" not in log_line:
                continue
            m = re.search(r'队列容量:\s*(\d+)', log_line) or re.search(r'队列:\s*\d+/(\d+)', log_line)
            if m:
                queue_cap = int(m.group(1))
                if not last_hint:
                    last_hint = log_line
                break

    return {
        "queue_size": queue_size,
        "queue_capacity": queue_cap,
        "last_event": last_event,
        "last_hint": last_hint,
        "source": "logs",
    }


@app.get("/api/solver-status")
async def solver_status_api():
    """聚合所有 Solver 节点的实时统计，并合并注册主进程输出的调度器快照。"""
    configured_nodes = _read_remote_solver_nodes()
    snapshot = _load_solver_cluster_snapshot()
    snapshot_nodes = {
        normalized: node
        for node in snapshot.get("nodes", []) if isinstance(node, dict)
        for normalized in [_normalize_remote_solver_node(node.get("url") or "")]
        if normalized
    }

    merged_nodes: list[str] = []
    for raw in configured_nodes + snapshot.get("configured_nodes", []) + list(snapshot_nodes.keys()):
        normalized = _normalize_remote_solver_node(raw)
        if normalized and normalized not in merged_nodes:
            merged_nodes.append(normalized)

    node_statuses = []
    total_available = 0
    total_raw_available = 0
    total_reserved_slots = 0
    total_tracked_tasks = 0
    total_browsers = 0
    total_solved = 0
    total_failed = 0
    total_memory = 0.0

    snapshot_summary = snapshot.get("summary", {}) if isinstance(snapshot.get("summary", {}), dict) else {}
    snapshot_scheduler = snapshot.get("scheduler", {}) if isinstance(snapshot.get("scheduler", {}), dict) else {}
    snapshot_reinit = snapshot.get("reinit", {}) if isinstance(snapshot.get("reinit", {}), dict) else {}
    scheduler = {
        "queue_wait_timeout": round(_safe_float(snapshot_scheduler.get("queue_wait_timeout", 0.0)), 3),
        "token_timeout": _safe_int(snapshot_scheduler.get("token_timeout", 0)),
        "direct_timeout": _safe_int(snapshot_scheduler.get("direct_timeout", snapshot_scheduler.get("token_timeout", 0))),
        "direct_attempts": _safe_int(snapshot_scheduler.get("direct_attempts", 0)),
        "poll_interval": round(_safe_float(snapshot_scheduler.get("poll_interval", 0.0)), 3),
        "token_max_age": round(_safe_float(snapshot_scheduler.get("token_max_age", 0.0)), 3),
        "breaker_seconds": round(_safe_float(snapshot_scheduler.get("breaker_seconds", 0.0)), 3),
        "breaker_threshold": _safe_int(snapshot_scheduler.get("breaker_threshold", 0)),
        "soft_penalty_seconds": round(_safe_float(snapshot_scheduler.get("soft_penalty_seconds", 0.0)), 3),
        "prefetch_min_health_score": _safe_int(snapshot_scheduler.get("prefetch_min_health_score", 55), 55),
        "direct_min_health_score": _safe_int(snapshot_scheduler.get("direct_min_health_score", 35), 35),
        "recovering_observe_seconds": round(_safe_float(snapshot_scheduler.get("recovering_observe_seconds", 0.0)), 3),
        "reserve_for_direct": _safe_int(snapshot_scheduler.get("reserve_for_direct", snapshot.get("reserve_for_direct", 0))),
        "per_node_prefetch": _safe_int(snapshot_scheduler.get("per_node_prefetch", snapshot.get("per_node_prefetch", 0))),
        "max_queue_target": _safe_int(snapshot_scheduler.get("max_queue_target", snapshot.get("max_queue_target", snapshot.get("queue_capacity", 0)))),
        "queue_capacity": _safe_int(snapshot_scheduler.get("queue_capacity", snapshot.get("queue_capacity", 0))),
        "admin_configured": bool(snapshot_scheduler.get("admin_configured", snapshot_reinit.get("admin_configured", False))),
        "reinit_enabled": bool(snapshot_scheduler.get("reinit_enabled", snapshot_reinit.get("enabled", False))),
        "reinit_trigger_streak": _safe_int(snapshot_scheduler.get("reinit_trigger_streak", snapshot_reinit.get("trigger_streak", 0))),
        "reinit_cooldown_seconds": round(_safe_float(snapshot_scheduler.get("reinit_cooldown_seconds", snapshot_reinit.get("cooldown_seconds", 0.0))), 3),
        "reinit_request_timeout": round(_safe_float(snapshot_scheduler.get("reinit_request_timeout", snapshot_reinit.get("request_timeout", 0.0))), 3),
        "reinit_max_targets": _safe_int(snapshot_scheduler.get("reinit_max_targets", snapshot_reinit.get("max_targets", 0))),
        "reinit_allow_broadcast": bool(snapshot_scheduler.get("reinit_allow_broadcast", snapshot_reinit.get("allow_broadcast", False))),
        "reinit_requested_by": str(snapshot_scheduler.get("reinit_requested_by", snapshot_reinit.get("requested_by", "")) or ""),
    }

    async with httpx.AsyncClient(timeout=3, trust_env=False) as client:
        for node_url in merged_nodes:
            live_data: dict[str, Any] | None = None
            error = ""
            try:
                resp = await client.get(f"{node_url}/stats")
                if resp.status_code >= 400:
                    raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:160]}")
                raw_payload = resp.json()
                live_data = raw_payload if isinstance(raw_payload, dict) else {}
            except Exception as e:
                error = str(e)

            node_payload = _build_solver_node_status(
                node_url=node_url,
                live_data=live_data,
                snapshot_node=snapshot_nodes.get(node_url),
                error=error,
            )
            total_available += _safe_int(node_payload.get("available_browsers", 0))
            total_raw_available += _safe_int(node_payload.get("raw_available_browsers", 0))
            total_reserved_slots += _safe_int(node_payload.get("reserved_slots", 0))
            total_tracked_tasks += _safe_int(node_payload.get("tracked_tasks", 0))
            total_browsers += _safe_int(node_payload.get("total_browsers", 0))
            total_solved += _safe_int(node_payload.get("solved", 0))
            total_failed += _safe_int(node_payload.get("failed", 0))
            total_memory += _safe_float(node_payload.get("memory_mb", 0.0))
            node_statuses.append(node_payload)

    direct_min_health_score = max(_safe_int(scheduler.get("direct_min_health_score", 35), 35), 0)
    prefetch_min_health_score = max(_safe_int(scheduler.get("prefetch_min_health_score", 55), 55), 0)
    per_node_prefetch_limit = max(_safe_int(scheduler.get("per_node_prefetch", 0)), 0)

    def _node_direct_ready(item: dict[str, Any]) -> bool:
        return (
            bool(item.get("online"))
            and not bool(item.get("breaker_active"))
            and _safe_int(item.get("available_browsers", 0)) > 0
            and _safe_int(item.get("effective_capacity", 0)) > 0
            and _safe_int(item.get("health_score", 0)) >= direct_min_health_score
        )

    def _node_prefetch_ready(item: dict[str, Any]) -> bool:
        health_status = str(item.get("health_status") or "").strip().lower()
        return (
            _node_direct_ready(item)
            and not bool(item.get("soft_penalty_active"))
            and health_status not in {"degraded", "recovering", "cooling"}
            and _safe_int(item.get("health_score", 0)) >= prefetch_min_health_score
            and (per_node_prefetch_limit <= 0 or _safe_int(item.get("in_flight_prefetch", 0)) < per_node_prefetch_limit)
        )

    node_statuses.sort(key=lambda item: (
        not bool(item.get("online")),
        bool(item.get("breaker_active")),
        bool(item.get("soft_penalty_active")),
        bool(item.get("busy")),
        -_safe_int(item.get("health_score", 0)),
        item.get("url", ""),
    ))

    total_attempts = total_solved + total_failed
    success_rate = round(total_solved / total_attempts * 100, 1) if total_attempts > 0 else 0.0
    online_nodes = sum(1 for n in node_statuses if n.get("online"))
    healthy_nodes = sum(1 for n in node_statuses if n.get("online") and str(n.get("health_status") or "") == "healthy")
    recovering_nodes = sum(
        1 for n in node_statuses
        if n.get("online") and (str(n.get("health_status") or "") in {"warming", "recovering", "cooling"} or n.get("recovering_active"))
    )
    soft_penalty_nodes = sum(1 for n in node_statuses if n.get("soft_penalty_active"))
    breaker_nodes = sum(1 for n in node_statuses if n.get("breaker_active"))
    busy_nodes = sum(1 for n in node_statuses if n.get("busy"))
    degraded_nodes = sum(1 for n in node_statuses if n.get("degraded"))
    reinitializing_nodes = sum(1 for n in node_statuses if n.get("reinit_in_progress"))
    direct_ready_nodes = sum(1 for n in node_statuses if _node_direct_ready(n))
    prefetch_ready_nodes = sum(1 for n in node_statuses if _node_prefetch_ready(n))
    online_health_scores = [_safe_int(n.get("health_score", 0)) for n in node_statuses if n.get("online")]
    avg_health_score = round(sum(online_health_scores) / len(online_health_scores), 3) if online_health_scores else 0.0

    log_queue = _parse_token_queue_from_logs()
    snapshot_updated_at = _safe_float(snapshot.get("updated_at", 0.0))
    token_queue = {
        "source": "snapshot" if snapshot else log_queue.get("source", "logs"),
        "running": bool(snapshot.get("running")) if snapshot else bool(pm.is_running and log_queue.get("last_event") != "prefetch_stopped"),
        "reason": str(snapshot.get("reason") or ""),
        "queue_target": _safe_int(snapshot.get("queue_target", 0)),
        "queue_size": _safe_int(snapshot.get("queue_size", log_queue.get("queue_size", 0))),
        "queue_capacity": _safe_int(snapshot.get("queue_capacity", log_queue.get("queue_capacity", scheduler.get("queue_capacity", 0)))),
        "hit_count": _safe_int(snapshot.get("hit_count", 0)),
        "miss_count": _safe_int(snapshot.get("miss_count", 0)),
        "fallback_count": _safe_int(snapshot.get("fallback_count", 0)),
        "direct_success_count": _safe_int(snapshot.get("direct_success_count", 0)),
        "direct_fail_count": _safe_int(snapshot.get("direct_fail_count", 0)),
        "direct_unavailable_streak": _safe_int(snapshot.get("direct_unavailable_streak", 0)),
        "last_direct_unavailable_at": _safe_float(snapshot.get("last_direct_unavailable_at", 0.0)),
        "last_direct_unavailable_summary": str(snapshot.get("last_direct_unavailable_summary") or ""),
        "last_token_success_at": _safe_float(snapshot.get("last_token_success_at", 0.0)),
        "in_flight_prefetch_total": _safe_int(snapshot.get("in_flight_prefetch_total", 0)),
        "in_flight_prefetch_by_node": snapshot.get("in_flight_prefetch_by_node", {}) if isinstance(snapshot.get("in_flight_prefetch_by_node", {}), dict) else {},
        "last_fill_at": _safe_float(snapshot.get("last_fill_at", 0.0)),
        "last_consume_at": _safe_float(snapshot.get("last_consume_at", 0.0)),
        "last_event": str(log_queue.get("last_event") or ("snapshot_only" if snapshot else "")),
        "last_hint": str(log_queue.get("last_hint") or snapshot.get("reason") or ""),
        "updated_at": snapshot_updated_at,
        "freshness_sec": round(max(time.time() - snapshot_updated_at, 0), 1) if snapshot_updated_at > 0 else None,
        "reserve_for_direct": _safe_int(snapshot.get("reserve_for_direct", scheduler.get("reserve_for_direct", 0))),
        "per_node_prefetch": _safe_int(snapshot.get("per_node_prefetch", scheduler.get("per_node_prefetch", 0))),
        "max_queue_target": _safe_int(snapshot.get("max_queue_target", scheduler.get("max_queue_target", snapshot.get("queue_capacity", 0)))),
        "prefetch_sitekey": str(snapshot.get("prefetch_sitekey") or ""),
        "snapshot_available": bool(snapshot),
    }
    if token_queue["queue_target"] <= 0:
        token_queue["queue_target"] = max(token_queue["queue_capacity"] - token_queue["reserve_for_direct"], 0)

    reinit = {
        "enabled": bool(snapshot_reinit.get("enabled", scheduler.get("reinit_enabled", False))),
        "admin_configured": bool(snapshot_reinit.get("admin_configured", scheduler.get("admin_configured", False))),
        "trigger_streak": _safe_int(snapshot_reinit.get("trigger_streak", scheduler.get("reinit_trigger_streak", 0))),
        "cooldown_seconds": round(_safe_float(snapshot_reinit.get("cooldown_seconds", scheduler.get("reinit_cooldown_seconds", 0.0))), 3),
        "cooldown_remaining": round(_safe_float(snapshot_reinit.get("cooldown_remaining", 0.0)), 3),
        "request_timeout": round(_safe_float(snapshot_reinit.get("request_timeout", scheduler.get("reinit_request_timeout", 0.0))), 3),
        "max_targets": _safe_int(snapshot_reinit.get("max_targets", scheduler.get("reinit_max_targets", 0))),
        "allow_broadcast": bool(snapshot_reinit.get("allow_broadcast", scheduler.get("reinit_allow_broadcast", False))),
        "requested_by": str(snapshot_reinit.get("requested_by", scheduler.get("reinit_requested_by", "")) or ""),
        "last_reinit_at": _safe_float(snapshot_reinit.get("last_reinit_at", 0.0)),
        "last_reinit_reason": str(snapshot_reinit.get("last_reinit_reason") or ""),
        "last_reinit_targets": snapshot_reinit.get("last_reinit_targets", []) if isinstance(snapshot_reinit.get("last_reinit_targets", []), list) else [],
        "last_reinit_results": snapshot_reinit.get("last_reinit_results", []) if isinstance(snapshot_reinit.get("last_reinit_results", []), list) else [],
        "last_reinit_summary": str(snapshot_reinit.get("last_reinit_summary") or ""),
        "last_reinit_trigger_streak": _safe_int(snapshot_reinit.get("last_reinit_trigger_streak", 0)),
        "attempt_count": _safe_int(snapshot_reinit.get("attempt_count", 0)),
        "success_count": _safe_int(snapshot_reinit.get("success_count", 0)),
        "fail_count": _safe_int(snapshot_reinit.get("fail_count", 0)),
        "skip_count": _safe_int(snapshot_reinit.get("skip_count", 0)),
    }

    summary = {
        "total_nodes": len(merged_nodes),
        "online_nodes": online_nodes,
        "healthy_nodes": _safe_int(snapshot_summary.get("healthy_nodes", healthy_nodes)),
        "degraded_nodes": _safe_int(snapshot_summary.get("degraded_nodes", degraded_nodes)),
        "recovering_nodes": _safe_int(snapshot_summary.get("recovering_nodes", recovering_nodes)),
        "soft_penalty_nodes": _safe_int(snapshot_summary.get("soft_penalty_nodes", soft_penalty_nodes)),
        "breaker_nodes": _safe_int(snapshot_summary.get("breaker_nodes", breaker_nodes)),
        "busy_nodes": _safe_int(snapshot_summary.get("busy_nodes", busy_nodes)),
        "reinitializing_nodes": reinitializing_nodes,
        "direct_ready_nodes": _safe_int(snapshot_summary.get("direct_ready_nodes", direct_ready_nodes)),
        "prefetch_ready_nodes": _safe_int(snapshot_summary.get("prefetch_ready_nodes", prefetch_ready_nodes)),
        "avg_health_score": round(_safe_float(snapshot_summary.get("avg_health_score", avg_health_score)), 3),
        "available_browsers": total_available,
        "raw_available_browsers": total_raw_available,
        "reserved_slots": total_reserved_slots,
        "tracked_tasks": total_tracked_tasks,
        "total_browsers": total_browsers,
        "total_solved": total_solved,
        "total_failed": total_failed,
        "success_rate": success_rate,
        "total_memory_mb": round(total_memory, 1),
    }

    return {
        "mode": "remote_api_only",
        "source": "remote_api_snapshot",
        "configured": len(merged_nodes) > 0,
        "configured_nodes": merged_nodes,
        "running": bool(token_queue.get("running")),
        "reason": token_queue.get("reason", ""),
        "updated_at": snapshot_updated_at,
        "nodes": node_statuses,
        "summary": summary,
        "token_queue": token_queue,
        "scheduler": scheduler,
        "reinit": reinit,
    }


# ========== sing-box 代理池 API ==========

class SingBoxConfigModel(BaseModel):
    subscribe_url: str = ""
    listen_port: int = DEFAULT_LISTEN_PORT
    enabled: bool = False


class SingBoxNodeToggleModel(BaseModel):
    tag: str = ""
    type: str = ""
    server: str = ""
    server_port: str | int = ""


@app.get("/api/singbox/status")
async def singbox_status():
    """获取 sing-box 运行状态"""
    status = singbox_pm.get_status()
    status.update(singbox_pm.get_log_tail())
    return status

@app.post("/api/singbox/config")
async def config_singbox(config: SingBoxConfigModel):
    """保存 sing-box 配置（订阅链接、端口、开关）"""
    save_singbox_config(
        subscribe_url=config.subscribe_url,
        listen_port=config.listen_port,
        enabled=config.enabled,
    )
    return {"status": "success", **config.dict()}

@app.get("/api/singbox/config")
async def get_singbox_config():
    """读取 sing-box 配置"""
    return load_singbox_config()


def _refresh_singbox_after_toggle() -> dict | None:
    cfg = load_singbox_config()
    url = cfg.get("subscribe_url", "")
    if not url:
        return None
    port = cfg.get("listen_port", DEFAULT_LISTEN_PORT)
    result = refresh_subscription(url, port)
    if result.get("success") and cfg.get("enabled", False):
        singbox_pm.stop()
        time.sleep(1)
        start_result = singbox_pm.start()
        result["restart"] = start_result
    return result


@app.post("/api/singbox/node/disable")
async def singbox_disable_node(node: SingBoxNodeToggleModel):
    try:
        result = set_manual_disabled_node(
            tag=node.tag,
            node_type=node.type,
            server=node.server,
            server_port=node.server_port,
            disabled=True,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    refresh_result = _refresh_singbox_after_toggle()
    message = result["message"]
    if refresh_result:
        message = f"{message}；{refresh_result.get('message', '已刷新订阅')}"
    else:
        message = f"{message}；尚未配置订阅链接，改动会在下次刷新时生效"
    return {
        **result,
        "message": message,
        "refresh": refresh_result,
    }


@app.post("/api/singbox/node/enable")
async def singbox_enable_node(node: SingBoxNodeToggleModel):
    try:
        result = set_manual_disabled_node(
            tag=node.tag,
            node_type=node.type,
            server=node.server,
            server_port=node.server_port,
            disabled=False,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    refresh_result = _refresh_singbox_after_toggle()
    message = result["message"]
    if refresh_result:
        message = f"{message}；{refresh_result.get('message', '已刷新订阅')}"
    else:
        message = f"{message}；尚未配置订阅链接，改动会在下次刷新时生效"
    return {
        **result,
        "message": message,
        "refresh": refresh_result,
    }


@app.post("/api/singbox/refresh")
async def singbox_refresh():
    """刷新订阅：拉取节点 → 生成配置 → 重启 sing-box"""
    cfg = load_singbox_config()
    url = cfg.get("subscribe_url", "")
    if not url:
        raise HTTPException(status_code=400, detail="未配置订阅链接")
    port = cfg.get("listen_port", DEFAULT_LISTEN_PORT)
    result = refresh_subscription(url, port)
    if result["success"] and cfg.get("enabled", False):
        # 刷新成功且已启用 → 自动重启 sing-box
        singbox_pm.stop()
        import time; time.sleep(1)
        start_result = singbox_pm.start()
        result["restart"] = start_result
    return result

@app.post("/api/singbox/start")
async def singbox_start():
    """启动 sing-box"""
    return singbox_pm.start()

@app.post("/api/singbox/stop")
async def singbox_stop():
    """停止 sing-box"""
    return singbox_pm.stop()

@app.post("/api/singbox/download")
async def singbox_download():
    """自动下载 sing-box 二进制文件"""
    return download_singbox()


# ========== 生命周期事件 ==========

@app.on_event("startup")
async def on_startup():
    """Web 服务启动生命周期钩子"""
    pass

@app.on_event("shutdown")
async def on_shutdown():
    """Web 服务关闭时，自动终止注册机与 sing-box。"""
    pm.stop()
    singbox_pm.stop()


def _open_browser():
    """延迟 1.5 秒后自动打开浏览器"""
    import time
    time.sleep(1.5)
    webbrowser.open("http://127.0.0.1:8000/ui/")

if __name__ == "__main__":
    print("=" * 50)
    print("  Grok Control Center - Web Server")
    print("  [网络] 代理池: socks5-proxy-main (自动启动)")
    print("  控制面板: http://127.0.0.1:8000/ui/")
    print("=" * 50)
    # 后台线程延迟打开浏览器
    threading.Thread(target=_open_browser, daemon=True).start()
    uvicorn.run(app, host="127.0.0.1", port=8000)
