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
from fastapi.responses import RedirectResponse
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

app = FastAPI(title="Grok Register Control Center")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

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


def _load_account_rows() -> tuple[bool, list[list[str]], list[str]]:
    """读取 accounts.csv，兼容有表头/无表头两种格式。"""
    if not os.path.exists(ACCOUNTS_CSV_PATH):
        return False, [], []

    with open(ACCOUNTS_CSV_PATH, 'r', encoding='utf-8') as f:
        rows = [r for r in csv.reader(f) if any(cell.strip() for cell in r)]

    if not rows:
        return False, [], []

    first_row = rows[0]
    has_header = any("email" in str(cell).lower() for cell in first_row)
    data_rows = rows[1:] if has_header else rows
    return has_header, first_row if has_header else [], data_rows


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
    """清空全部统计（成功/失败计数器 + CSV 账号记录）"""
    pm.success_count = 0
    pm.fail_count = 0
    # 清空 accounts.csv：有表头则保留表头，无表头则清空为 0 字节
    if os.path.exists(ACCOUNTS_CSV_PATH):
        try:
            has_header, header, _ = _load_account_rows()
            with open(ACCOUNTS_CSV_PATH, 'w', encoding='utf-8') as f:
                if has_header and header:
                    f.write(",".join(header) + '\n')
        except Exception:
            pass
    return {"message": "统计已清空"}

@app.get("/api/accounts")
def get_accounts(limit: int = 50) -> List[Dict[str, str]]:
    """获取最新生成的账号列表（兼容无表头 CSV + Pydantic v2 严格校验）"""
    accounts = []
    if not os.path.exists(ACCOUNTS_CSV_PATH):
        return accounts
    # 默认列名：当 CSV 缺少表头时自动赋予
    DEFAULT_FIELDS = ["email", "password", "cookie", "token"]
    try:
        with open(ACCOUNTS_CSV_PATH, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            rows = [r for r in reader if any(cell.strip() for cell in r)]
            if not rows:
                return accounts
            # 智能检测表头：第一行若包含 "email" 则视为表头，否则全是数据
            first_row = rows[0]
            if any("email" in cell.lower() for cell in first_row):
                header = first_row
                data_rows = rows[1:]
            else:
                header = DEFAULT_FIELDS[:len(first_row)]
                data_rows = rows
            for row in data_rows:
                item = {}
                for i, field in enumerate(header):
                    key = str(field).strip() if field else f"col_{i}"
                    item[key] = row[i] if i < len(row) else ""
                accounts.append(item)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"读取账号文件失败: {e}")
    accounts.reverse()
    return accounts[:limit]

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
    """从注册脚本日志缓冲区中提取 Token 预热队列的最新状态"""
    queue_size = 0
    queue_cap = 0
    last_event = ""
    for log_line in reversed(list(pm.log_buffer)):
        # 匹配 "[预热] ✅ Token 已入队（队列: 1/4）"
        if "已入队" in log_line and "队列:" in log_line:
            import re
            m = re.search(r'队列:\s*(\d+)/(\d+)', log_line)
            if m:
                queue_size = int(m.group(1))
                queue_cap = int(m.group(2))
                last_event = "token_enqueued"
                break
        # 匹配 "从预热队列取到 Token（队列剩余: 0）"
        elif "队列剩余:" in log_line:
            import re
            m = re.search(r'队列剩余:\s*(\d+)', log_line)
            if m:
                queue_size = int(m.group(1))
                last_event = "token_consumed"
                break
        # 匹配 "预热队列 15s 无现成 Token，回退到直接请求"
        elif "预热队列" in log_line and "回退" in log_line:
            last_event = "fallback_direct"
            break
        # 匹配 "预热协程已停止"
        elif "预热协程已停止" in log_line:
            last_event = "prefetch_stopped"
            break
        # 匹配 "⚡ 总并发上限: 1（1 节点 × 1 并发/节点），队列容量: 4"
        elif "队列容量:" in log_line:
            import re
            m = re.search(r'队列容量:\s*(\d+)', log_line)
            if m:
                queue_cap = int(m.group(1))
    return {"queue_size": queue_size, "queue_capacity": queue_cap, "last_event": last_event}


@app.get("/api/solver-status")
async def solver_status_api():
    """聚合所有 Solver 节点的解题统计 + Token 预热队列状态"""
    nodes = _read_remote_solver_nodes()
    node_statuses = []
    total_available = 0
    total_browsers = 0
    total_solved = 0
    total_failed = 0
    total_memory = 0.0

    async with httpx.AsyncClient(timeout=3, trust_env=False) as client:
        for node_url in nodes:
            try:
                resp = await client.get(f"{node_url}/stats")
                if resp.status_code == 200:
                    data = resp.json()
                    avail = data.get("available_browsers", 0)
                    total = data.get("total_browsers", 0)
                    solved = data.get("total_solved", 0)
                    failed = data.get("total_failed", 0)
                    mem = data.get("memory_mb", 0)
                    total_available += avail
                    total_browsers += total
                    total_solved += solved
                    total_failed += failed
                    total_memory += mem
                    node_statuses.append({
                        "url": node_url,
                        "online": True,
                        "available_browsers": avail,
                        "total_browsers": total,
                        "solved": solved,
                        "failed": failed,
                        "memory_mb": mem,
                        "avg_solve_time": data.get("avg_solve_time", 0),
                    })
                else:
                    node_statuses.append({"url": node_url, "online": False})
            except Exception:
                node_statuses.append({"url": node_url, "online": False})

    # 计算整体成功率
    total_attempts = total_solved + total_failed
    success_rate = round(total_solved / total_attempts * 100, 1) if total_attempts > 0 else 0

    # 从日志解析 Token 预热队列状态
    token_queue = _parse_token_queue_from_logs()

    return {
        "mode": "remote_api_only",
        "configured": len(nodes) > 0,
        "nodes": node_statuses,
        "summary": {
            "total_nodes": len(nodes),
            "online_nodes": sum(1 for n in node_statuses if n.get("online")),
            "available_browsers": total_available,
            "total_browsers": total_browsers,
            "total_solved": total_solved,
            "total_failed": total_failed,
            "success_rate": success_rate,
            "total_memory_mb": round(total_memory, 1),
        },
        "token_queue": token_queue,
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
