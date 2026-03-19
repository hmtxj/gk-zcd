"""
=== Grok 混合模式自动注册机 V6 ===

全异步架构（asyncio），支持 N 路并发注册。

架构设计：
  - AsyncGrokGRPCClient → curl_cffi.requests.AsyncSession（TLS 指纹伪装，绕 Cloudflare）
  - AsyncFreemailClient → httpx.AsyncClient（自建 Freemail 临时邮箱，高并发无限制）
  - Turnstile Solver → httpx.AsyncClient（本地服务无需 TLS 伪装）
  - register_one_async() 全异步主链路，按 V5 正确顺序：先注册再解题
  - batch_register(count, concurrency) 并发调度
  - asyncio.Lock 保护 accounts.csv / key.txt 持久化写入
  - asyncio.Semaphore 并发流量钳制

严禁修改 turnstile_server/ 和 turnstile_solver.py。
"""
import struct
import re
import json
import random
import string
import os
import sys
import asyncio
from urllib.parse import unquote
import httpx
from curl_cffi.requests import AsyncSession as CurlAsyncSession

from turnstile_solver import get_turnstile_token_async, get_solver_nodes
from action_id_fetcher import fetch_action_id

import urllib.request

# ========== 自动探测系统代理 ==========
def get_system_proxy() -> str:
    """自动获取 Windows/Linux 系统的全局代理配置"""
    try:
        # 1. 优先尝试 urllib 原生读取（支持 Windows 注册表）
        proxies = urllib.request.getproxies()
        # 往往返回形如 {"http": "http://127.0.0.1:7890", "https": "https://127.0.0.1:7890"}
        # 也可能是 {"no": ... } 或空字典
        if "http" in proxies and str(proxies["http"]).strip():
            # 若梯子不支持 socks5 协议可能报错，这里直接返回原始探测到的 http 代理地址
            return str(proxies["http"]).strip()
        elif "https" in proxies and str(proxies["https"]).strip():
             return str(proxies["https"]).strip()
        
        # 2. 从环境变量读取
        for k in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"]:
            value = os.environ.get(k, "").strip()
            if value:
                # 如果环境变量自带协议头，直接用
                return value
                
    except Exception:
        pass
    
    return "" # 没有检测到，返回空字符串，代表直连


def should_bypass_system_proxy() -> bool:
    """是否显式禁止回退到系统代理（Web 控制面板启动时需保持代理来源可控）"""
    flag = os.environ.get("DISABLE_SYSTEM_PROXY", "").strip().lower()
    if flag in {"1", "true", "yes", "on"}:
        return True

    # Web 控制面板会注入这组环境变量；此时若未显式传入 PROXY，就应当视为真正直连，
    # 不能再偷偷回退到系统代理，否则 UI 展示与子进程实际流量会不一致。
    return any(key in os.environ for key in ("PROXY_POOL_API_BASE", "ENABLE_PROXY_POOL", "PROXY_MODE", "SINGBOX_ENABLED"))


def resolve_default_proxy() -> str:
    """解析当前进程应使用的默认代理。"""
    if "PROXY" in os.environ:
        return os.environ.get("PROXY", "").strip()

    if should_bypass_system_proxy():
        return ""

    return (get_system_proxy() or "").strip()


# ========== 全局配置 ==========

PROXY = resolve_default_proxy()  # 优先读取显式注入；Web 控制面板未指定代理时强制直连；CLI 才回退系统代理
ENABLE_PROXY_POOL = os.environ.get("ENABLE_PROXY_POOL", "false").lower() == "true" # [全局开关] 是否启用远端代理池动态分发
PROXY_POOL_API = "http://127.0.0.1:8080"  # Go 代理池 Status API 地址
PROXY_MODE = os.environ.get("PROXY_MODE", "api_pool")  # 代理模式：api_pool（节点池轮询）/ direct_socks（直连网关）
# sing-box 代理模式（由 web_server 注入环境变量）
SINGBOX_ENABLED = os.environ.get("SINGBOX_ENABLED", "false").lower() == "true"
SINGBOX_PROXY = os.environ.get("SINGBOX_PROXY", "socks5h://127.0.0.1:2080")
BASE = "https://accounts.x.ai"
SINGBOX_CANDIDATE_PREVIEW_TEXT = os.environ.get("SINGBOX_CANDIDATE_PREVIEW_TEXT", "").strip()
SINGBOX_CANDIDATE_COUNT = os.environ.get("SINGBOX_CANDIDATE_COUNT", "").strip()
SINGBOX_CANDIDATE_TAGS = [
    item.strip()
    for item in os.environ.get("SINGBOX_CANDIDATE_TAGS", "").split(",")
    if item.strip()
]
SINGBOX_URLTEST_PROBE_URL = (
    os.environ.get("SINGBOX_URLTEST_PROBE_URL", f"{BASE}/sign-up?redirect=grok-com").strip()
    or f"{BASE}/sign-up?redirect=grok-com"
)
SERVICE = "auth_mgmt.AuthManagement"
# im-mail 优化版 配置
IM_MAIL_API_BASE = os.environ.get("IM_MAIL_API_BASE", "http://127.0.0.1:3000")
IM_MAIL_AUTH_TOKEN = os.environ.get("IM_MAIL_AUTH_TOKEN", "")
# 回退默认值（深度扫描失败时使用，需定期手动更新）
DEFAULT_ACTION_ID = "7f182bc67c733403fbbfefe029b24a790a57b09877"
DEFAULT_SITE_KEY = "0x4AAAAAAAhr9JGVDZbrZOo0"

# 持久化文件路径（以脚本所在目录为基准，运行时数据写入 data/ 子目录）
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(SCRIPT_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)
ACCOUNTS_CSV = os.path.join(DATA_DIR, "accounts.csv")
KEY_TXT = os.path.join(DATA_DIR, "key.txt")
NSFW_FAIL_TXT = os.path.join(DATA_DIR, "未开启nsfw.txt")

# 并发控制全局锁与信号灯（在 batch_register 中初始化）
file_lock: asyncio.Lock | None = None
semaphore: asyncio.Semaphore | None = None
# Token 预热队列（在 batch_register 中初始化）
token_queue: asyncio.Queue | None = None
_prefetch_stop: asyncio.Event | None = None

# ========== 全局 Action ID 缓存（避免重复扫描） ==========
_GLOBAL_ACTION_CACHE = {
    "action_id": None,
    "sitekey": None,
    "last_update": 0,
    "lock": None,  # 在 batch_register 中初始化为 asyncio.Lock()
}
STEP0_TIMEOUT_ABORT_THRESHOLD = 2
_RUNTIME_NETWORK_STATE = {
    "preflight_ok": None,
    "preflight_detail": "",
    "step0_timeout_count": 0,
    "last_error": "",
    "abort_reason": "",
    "lock": None,  # 在 batch_register 中初始化为 asyncio.Lock()
}
_batch_abort: asyncio.Event | None = None


async def get_cached_action_id(session: CurlAsyncSession) -> tuple[str, str]:
    """
    全局缓存的 Action ID 获取器（单例模式，懒加载）
    
    首次调用时执行深度扫描，后续调用直接返回缓存。
    如果扫描失败，回退到 DEFAULT_ACTION_ID。
    
    返回: (action_id, sitekey)
    """
    global _GLOBAL_ACTION_CACHE
    
    async with _GLOBAL_ACTION_CACHE["lock"]:
        # 如果缓存有效，直接返回
        if _GLOBAL_ACTION_CACHE["action_id"]:
            return _GLOBAL_ACTION_CACHE["action_id"], _GLOBAL_ACTION_CACHE["sitekey"]
        
        # 首次启动或缓存失效，执行一次深度扫描
        print("  [搜索] [全局缓存] 首次启动，执行 Action ID 深度扫描...")
        import time
        start = time.time()
        
        try:
            scanned_aid, scanned_sk = await fetch_action_id(session, verbose=True)
            
            if scanned_aid:
                _GLOBAL_ACTION_CACHE["action_id"] = scanned_aid
                _GLOBAL_ACTION_CACHE["sitekey"] = scanned_sk or DEFAULT_SITE_KEY
                _GLOBAL_ACTION_CACHE["last_update"] = time.time()
                elapsed = round(time.time() - start, 2)
                print(f"  [成功] [全局缓存] Action ID 已缓存: {scanned_aid[:20]}... (耗时 {elapsed}s)")
                print(f"  [成功] [全局缓存] Sitekey: {_GLOBAL_ACTION_CACHE['sitekey']}")
            else:
                # 回退到默认值
                _GLOBAL_ACTION_CACHE["action_id"] = DEFAULT_ACTION_ID
                _GLOBAL_ACTION_CACHE["sitekey"] = DEFAULT_SITE_KEY
                print(f"  [警告] [全局缓存] 扫描失败，使用默认值: {DEFAULT_ACTION_ID[:20]}...")
        except Exception as e:
            # 异常时也回退到默认值
            _GLOBAL_ACTION_CACHE["action_id"] = DEFAULT_ACTION_ID
            _GLOBAL_ACTION_CACHE["sitekey"] = DEFAULT_SITE_KEY
            print(f"  [警告] [全局缓存] 扫描异常 ({e})，使用默认值")
        
        return _GLOBAL_ACTION_CACHE["action_id"], _GLOBAL_ACTION_CACHE["sitekey"]


def invalidate_action_cache():
    """清空 Action ID 缓存，触发下次重新扫描"""
    global _GLOBAL_ACTION_CACHE
    _GLOBAL_ACTION_CACHE["action_id"] = None
    _GLOBAL_ACTION_CACHE["sitekey"] = None
    _GLOBAL_ACTION_CACHE["last_update"] = 0
    print("  🔄 [全局缓存] Action ID 缓存已清空")


# curl_cffi 浏览器指纹池（与 V5 一致）
CHROME_PROFILES = [
    {"impersonate": "chrome110", "version": "110.0.0.0"},
    {"impersonate": "chrome119", "version": "119.0.0.0"},
    {"impersonate": "chrome120", "version": "120.0.0.0"},
    {"impersonate": "chrome124", "version": "124.0.0.0"},
    {"impersonate": "edge99",  "version": "99.0.1150.36"},
    {"impersonate": "edge101", "version": "101.0.1210.47"},
]


def _build_singbox_candidate_summary() -> str:
    preview_text = SINGBOX_CANDIDATE_PREVIEW_TEXT or "暂无候选节点"
    if SINGBOX_CANDIDATE_TAGS:
        preview_text = f"{preview_text}；标签预览: {', '.join(SINGBOX_CANDIDATE_TAGS)}"
    if SINGBOX_CANDIDATE_COUNT:
        preview_text = f"{preview_text}；available_count={SINGBOX_CANDIDATE_COUNT}"
    return preview_text



def get_runtime_proxy_snapshot() -> tuple[str, str, str]:
    """返回当前进程视角下的代理接入模式、接入点与调度说明。"""
    if SINGBOX_ENABLED:
        return (
            "sing-box",
            SINGBOX_PROXY,
            f"注册请求先进入 sing-box 本地 mixed 入口，再由 sing-box 在远端候选池自动选路；候选池：{_build_singbox_candidate_summary()}；urltest 目标：{SINGBOX_URLTEST_PROBE_URL}",
        )

    if ENABLE_PROXY_POOL and PROXY_MODE == "direct_socks":
        proxy_target = PROXY or "未配置直连网关地址"
        return (
            "direct_socks",
            proxy_target,
            "直连网关模式已启用，网关内部负责自动轮换节点",
        )

    if ENABLE_PROXY_POOL:
        api_base = os.environ.get("PROXY_POOL_API_BASE", PROXY_POOL_API).rstrip("/")
        return (
            "api_pool",
            api_base or "未配置 API 节点池地址",
            "启动后将从 API 节点池轮询分配 socks5 节点",
        )

    if PROXY:
        return (
            "explicit_proxy",
            PROXY,
            "当前进程使用显式注入的代理地址",
        )

    return (
        "direct",
        "直连（未配置代理）",
        "未启用 sing-box / 代理池，且已禁用系统代理回退",
    )


def build_curl_session_kwargs(impersonate: str, proxy_addr: str = "") -> dict:
    """统一构造 curl_cffi 会话参数。"""
    kwargs = {
        "impersonate": impersonate,
        "trust_env": False,
    }
    if proxy_addr:
        kwargs["proxies"] = {"https": proxy_addr, "http": proxy_addr}
    return kwargs


def is_timeout_like(message: str) -> bool:
    """判断异常文本是否属于典型超时。"""
    lowered = (message or "").lower()
    return any(marker in lowered for marker in ("curl: (28)", "timed out", "timeout"))


async def note_step0_result(success: bool, detail: str = "") -> bool:
    """记录 Step 0 结果；连续超时达到阈值时触发批量熔断。"""
    global _RUNTIME_NETWORK_STATE, _batch_abort, _prefetch_stop

    lock = _RUNTIME_NETWORK_STATE.get("lock")
    if not lock:
        return False

    async with lock:
        if success:
            _RUNTIME_NETWORK_STATE["step0_timeout_count"] = 0
            _RUNTIME_NETWORK_STATE["last_error"] = ""
            return False

        _RUNTIME_NETWORK_STATE["last_error"] = detail
        if not is_timeout_like(detail):
            return False

        _RUNTIME_NETWORK_STATE["step0_timeout_count"] += 1
        timeout_count = _RUNTIME_NETWORK_STATE["step0_timeout_count"]
        if timeout_count < STEP0_TIMEOUT_ABORT_THRESHOLD:
            return False
        if _batch_abort is not None and _batch_abort.is_set():
            return False

        reason = f"Step 0 连续超时达到 {timeout_count} 次，当前代理出口疑似不可用于 x.ai"
        _RUNTIME_NETWORK_STATE["abort_reason"] = reason
        if _batch_abort is not None:
            _batch_abort.set()
        if _prefetch_stop is not None:
            _prefetch_stop.set()
        return True


async def preflight_signup_healthcheck(proxy_addr: str = "") -> tuple[bool, dict]:
    """在正式批量注册前，预检当前出口是否可访问 x.ai sign-up。"""
    probe_client = AsyncGrokGRPCClient()
    probe_url = f"{BASE}/sign-up?redirect=grok-com"
    result = {
        "ok": False,
        "status_code": 0,
        "reason": "",
        "preview": "",
        "proxy": proxy_addr or "",
    }
    try:
        async with CurlAsyncSession(**build_curl_session_kwargs(probe_client.profile["impersonate"], proxy_addr)) as session:
            resp = await session.get(
                probe_url,
                headers={
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Referer": BASE,
                    "User-Agent": probe_client.user_agent,
                },
                timeout=15,
            )
            result["status_code"] = resp.status_code
            preview = resp.text[:200].replace("\n", " ").replace("\r", " ")
            result["preview"] = preview
            if resp.status_code != 200:
                result["reason"] = f"HTTP {resp.status_code}"
                return False, result
            if "Attention Required" in preview or "cf-challenge-running" in resp.text:
                result["reason"] = "命中 Cloudflare Challenge"
                return False, result
            result["ok"] = True
            result["reason"] = f"HTTP {resp.status_code}，sign-up 页面可达"
            return True, result
    except Exception as e:
        result["reason"] = str(e)
        return False, result


# ========== 代理池管理器（从 Go socks5-pool API 动态拉取节点） ==========

class ProxyManager:
    """从 Go 代理池的 HTTP API 拉取存活节点，轮询分配给每个并发线程"""

    def __init__(self, fallback_proxy: str = PROXY):
        self.api_base = None  # 延迟赋值，从 web_server 的全局变量读取
        self.fallback_proxy = fallback_proxy
        self.proxies: list[str] = []  # 存活的代理地址列表
        self._index = 0  # 轮询游标

    async def refresh(self, http_client: httpx.AsyncClient) -> int:
        """从代理池 API 拉取最新存活节点列表，返回可用数量"""
        try:
            # 读取主进程安全注入的环境变量
            self.api_base = os.environ.get("PROXY_POOL_API_BASE", "").rstrip("/")
            
            if not self.api_base:
                print("  ⚠️ 远端代理池未配置，使用默认全局降级代理")
                return 0
                
            r = await http_client.get(f"{self.api_base}/api/status", timeout=5)
            data = r.json()
            alive = [p["addr"] for p in data.get("proxies", [])]
            if alive:
                self.proxies = alive
                self._index = 0
                print(f"  🌍 代理池刷新成功: {len(alive)} 个存活节点")
            else:
                print(f"  ⚠️ 代理池配置了但返回 0 个节点，使用默认代理")
        except Exception as e:
            print(f"  ⚠️ 代理池 API {self.api_base} 不可达 ({e})，回退到默认代理: {self.fallback_proxy}")
        return len(self.proxies)

    def allocate(self) -> str:
        """轮询分配一个代理地址（socks5://ip:port 格式）"""
        if not self.proxies:
            return self.fallback_proxy
        addr = self.proxies[self._index % len(self.proxies)]
        self._index += 1
        # 代理池返回的是 ip:port，需要包装为 socks5:// 协议
        return f"socks5://{addr}"

    @property
    def pool_size(self) -> int:
        return len(self.proxies)


# ========== Protobuf 编解码（纯计算，无需异步） ==========

def encode_varint(value: int) -> bytes:
    r = []
    while value > 0x7F:
        r.append((value & 0x7F) | 0x80)
        value >>= 7
    r.append(value & 0x7F)
    return bytes(r)


def decode_varint(data: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while pos < len(data):
        b = data[pos]
        result |= (b & 0x7F) << shift
        pos += 1
        if not (b & 0x80):
            break
        shift += 7
    return result, pos


def encode_string_field(fn: int, val: str) -> bytes:
    tag = (fn << 3) | 2
    enc = val.encode("utf-8")
    return bytes([tag]) + encode_varint(len(enc)) + enc


def encode_bytes_field(fn: int, val: bytes) -> bytes:
    tag = (fn << 3) | 2
    return bytes([tag]) + encode_varint(len(val)) + val


def encode_int_field(fn: int, val: int) -> bytes:
    tag = (fn << 3) | 0
    return bytes([tag]) + encode_varint(val)


def decode_protobuf(data: bytes) -> list:
    fields = []
    pos = 0
    while pos < len(data):
        tag, pos = decode_varint(data, pos)
        field_number = tag >> 3
        wire_type = tag & 0x07
        if wire_type == 0:
            value, pos = decode_varint(data, pos)
            fields.append((field_number, "varint", value))
        elif wire_type == 1:
            value = struct.unpack("<d", data[pos:pos+8])[0]
            pos += 8
            fields.append((field_number, "64bit", value))
        elif wire_type == 2:
            length, pos = decode_varint(data, pos)
            value = data[pos:pos+length]
            pos += length
            try:
                str_val = value.decode("utf-8")
                if all(c.isprintable() or c in '\r\n\t' for c in str_val):
                    fields.append((field_number, "string", str_val))
                else:
                    try:
                        nested = decode_protobuf(value)
                        fields.append((field_number, "message", nested)) if nested else fields.append((field_number, "bytes", value.hex()))
                    except:
                        fields.append((field_number, "bytes", value.hex()))
            except:
                try:
                    nested = decode_protobuf(value)
                    fields.append((field_number, "message", nested)) if nested else fields.append((field_number, "bytes", value.hex()))
                except:
                    fields.append((field_number, "bytes", value.hex()))
        elif wire_type == 5:
            value = struct.unpack("<f", data[pos:pos+4])[0]
            pos += 4
            fields.append((field_number, "32bit_float", value))
        else:
            break
    return fields


def wrap_grpc_frame(payload: bytes) -> bytes:
    return struct.pack(">BI", 0, len(payload)) + payload


def parse_grpc_response(content: bytes) -> tuple[int, bytes, dict]:
    pos = 0
    message = b""
    trailers = {}
    while pos < len(content):
        if pos + 5 > len(content):
            break
        flag = content[pos]
        length = struct.unpack(">I", content[pos+1:pos+5])[0]
        pos += 5
        if flag == 0:
            message = content[pos:pos+length]
        elif flag == 0x80:
            trailer_text = content[pos:pos+length].decode("utf-8", errors="replace")
            for line in trailer_text.strip().split("\r\n"):
                if ":" in line:
                    k, v = line.split(":", 1)
                    trailers[k.strip()] = v.strip()
        pos += length
    grpc_status = int(trailers.get("grpc-status", "-1"))
    return grpc_status, message, trailers


# ========== 异步 im-mail 邮箱客户端 ==========

from im_mail_client import AsyncImMailClient


# ========== 异步 x.ai gRPC-Web 客户端（curl_cffi TLS 指纹伪装） ==========

class AsyncGrokGRPCClient:
    """x.ai gRPC-Web 异步客户端（curl_cffi.AsyncSession 做 TLS 指纹伪装）"""

    def __init__(self):
        # 随机选择浏览器指纹（与 V5 一致）
        self.profile = random.choice(CHROME_PROFILES)
        ver = self.profile["version"]
        self.user_agent = (
            f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            f"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver} Safari/537.36"
        )
        self.last_init_error = ""
        print(f"  [环境] 浏览器指纹: {self.profile['impersonate']} (Chrome/{ver})")

    async def _call(self, session: CurlAsyncSession, method: str, proto: bytes) -> tuple[int, bytes]:
        """发起 gRPC-Web 异步调用"""
        url = f"{BASE}/{SERVICE}/{method}"
        r = await session.post(
            url,
            data=wrap_grpc_frame(proto),
            headers={
                "Content-Type": "application/grpc-web+proto",
                "Accept": "application/grpc-web+proto",
                "Origin": BASE,
                "Referer": f"{BASE}/sign-up?redirect=grok-com",
                "X-Grpc-Web": "1",
                "X-User-Agent": "connect-es/2.1.1",
                "User-Agent": self.user_agent,
            },
            timeout=20,
        )
        grpc_status, message, trailers = parse_grpc_response(r.content)

        # 某些网关/边缘节点会把 gRPC trailer 暴露到 HTTP Header，避免误判为 -1
        if grpc_status == -1 and r.headers.get("grpc-status") is not None:
            try:
                grpc_status = int(r.headers.get("grpc-status", "-1"))
            except ValueError:
                grpc_status = -1

        grpc_msg = trailers.get("grpc-message", "") or r.headers.get("grpc-message", "")

        icon = "[成功]" if grpc_status == 0 else "[失败]"
        print(f"  {icon} [{method}] HTTP: {r.status_code}  gRPC-status: {grpc_status}")
        if grpc_msg:
            print(f"     gRPC-message: {unquote(grpc_msg)}")
        if grpc_status == -1 or r.status_code >= 400:
            content_type = r.headers.get("content-type", "")
            body_preview = r.text[:300].replace("\n", " ").replace("\r", " ")
            print(f"     Content-Type: {content_type}")
            if body_preview:
                print(f"     响应预览: {body_preview}")
        if message:
            fields = decode_protobuf(message)
            print(f"     返回字段: {fields}")

        return grpc_status, message

    async def init_session(self, session: CurlAsyncSession, task_tag: str = "") -> tuple[bool, str, str]:
        """预热连接 + 从全局缓存获取 Action ID（只有首次会触发扫描）"""
        print(f"\n{task_tag} [Step 0] 初始化会话...")
        self.last_init_error = ""

        # 真实访问 sign-up 页面，为当前会话建立 Cloudflare / Session Cookie
        warmup_url = f"{BASE}/sign-up?redirect=grok-com"
        try:
            warm_resp = await session.get(
                warmup_url,
                headers={
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Referer": BASE,
                    "User-Agent": self.user_agent,
                },
                timeout=20,
            )
            html_preview = warm_resp.text[:200]
            if warm_resp.status_code != 200:
                self.last_init_error = f"HTTP {warm_resp.status_code}"
                print(f"{task_tag} ❌ sign-up 预热失败: HTTP {warm_resp.status_code}")
                if html_preview:
                    print(f"{task_tag} 预热响应预览: {html_preview.replace(chr(10), ' ').replace(chr(13), ' ')}")
                return False, "", ""
            if "Attention Required" in html_preview or "cf-challenge-running" in warm_resp.text:
                self.last_init_error = "命中 Cloudflare Challenge"
                print(f"{task_tag} ❌ sign-up 预热命中 Cloudflare Challenge")
                return False, "", ""
            print(f"{task_tag} ✅ sign-up 预热成功，当前 Cookie 数: {len(session.cookies.jar)}")
        except Exception as e:
            self.last_init_error = str(e)
            print(f"{task_tag} ❌ sign-up 预热异常: {e}")
            return False, "", ""

        # 从全局缓存获取（只有第一个任务会触发深度扫描）
        action_id, sitekey = await get_cached_action_id(session)

        print(f"{task_tag} ℹ️ 初始化完成 (Action ID: {action_id[:20]}...)")
        return True, action_id, sitekey

    async def send_code(self, session: CurlAsyncSession, email: str) -> bool:
        """发送验证码"""
        print(f"\n[Step 2] 发送验证码 → {email}")
        proto = encode_string_field(1, email)
        status, _ = await self._call(session, "CreateEmailValidationCode", proto)
        return status == 0

    async def verify_code(self, session: CurlAsyncSession, email: str, code: str) -> tuple[bool, str]:
        """校验验证码"""
        print(f"\n[Step 4] 校验验证码: {email} / {code}")
        proto = encode_string_field(1, email) + encode_string_field(2, code)
        status, msg = await self._call(session, "VerifyEmailValidationCode", proto)
        token = ""
        if msg:
            fields = decode_protobuf(msg)
            for fn, wt, val in fields:
                if wt == "string" and len(str(val)) > 10:
                    token = str(val)
        return status == 0, token

    async def create_user_via_action(self, session: CurlAsyncSession,
                                     email: str, password: str, code: str,
                                     turnstile_token: str,
                                     action_id: str = DEFAULT_ACTION_ID,
                                     first: str = "", last: str = "") -> tuple[bool, dict]:
        """通过 Server Action 创建用户（需要 Turnstile token）"""
        if not first:
            first = random.choice(string.ascii_uppercase) + "".join(random.choices(string.ascii_lowercase, k=3))
        if not last:
            last = random.choice(string.ascii_uppercase) + "".join(random.choices(string.ascii_lowercase, k=4))

        print(f"\n[Step 6] 创建用户: {email} ({first} {last})")

        payload = [{
            "emailValidationCode": code,
            "createUserAndSessionRequest": {
                "email": email,
                "givenName": first,
                "familyName": last,
                "clearTextPassword": password,
                "tosAcceptedVersion": 1,
            },
            "turnstileToken": turnstile_token,
            "promptOnDuplicateEmail": True,
        }]

        state_tree = (
            "%5B%22%22%2C%7B%22children%22%3A%5B%22(app)%22%2C%7B%22children%22%3A"
            "%5B%22(auth)%22%2C%7B%22children%22%3A%5B%22sign-up%22%2C%7B%22children"
            "%22%3A%5B%22__PAGE__%22%2C%7B%7D%2C%22%2Fsign-up%22%2C%22refresh%22%5D"
            "%7D%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%2Ctrue%5D"
        )

        r = await session.post(
            f"{BASE}/sign-up",
            json=payload,
            headers={
                "Content-Type": "text/plain;charset=UTF-8",
                "Next-Action": action_id,
                "Next-Router-State-Tree": state_tree,
                "Origin": BASE,
                "Referer": f"{BASE}/sign-up",
                "Accept": "text/x-component",
            },
            timeout=20,
        )

        print(f"  HTTP: {r.status_code}")
        resp_text = r.text[:600]
        print(f"  响应: {resp_text}")

        result = {
            "http_status": r.status_code,
            "response": r.text[:1000],
            "cookies": {c.name: c.value for c in session.cookies.jar},
        }

        # 从响应中提取 set-cookie URL 并跟随获取 SSO token
        if r.status_code == 200:
            match = re.search(r'(https://[^"\s]+set-cookie\?q=[^:"\s]+)1:', r.text)
            if match:
                verify_url = match.group(1)
                print(f"  🔗 跟随 set-cookie URL: {verify_url[:80]}...")
                try:
                    await session.get(verify_url, allow_redirects=True)
                except Exception:
                    print(f"  ⚠️ set-cookie 跟随失败，尝试备用方案...")
                    for domain in ["grok.com", "x.ai"]:
                        domain_match = re.search(r'https://[^/]+', verify_url)
                        if domain_match:
                            alt_url = verify_url.replace(
                                domain_match.group(0),
                                f"https://auth.{domain}"
                            )
                            try:
                                await session.get(alt_url, allow_redirects=True)
                                if session.cookies.get("sso"):
                                    print(f"  ✅ 备用域名 {domain} 成功!")
                                    break
                            except:
                                continue

                sso = session.cookies.get("sso")
                sso_rw = session.cookies.get("sso-rw")
                if sso:
                    print(f"  🍪 SSO Token 获取成功!")
                    result["sso"] = sso
                    result["sso_rw"] = sso_rw or ""
                else:
                    print(f"  ⚠️ 未获取到 SSO Token")

        success = r.status_code == 200 and "error" not in resp_text.lower()

        if not success and "error" in resp_text.lower():
            for line in resp_text.split("\n"):
                if "error" in line.lower():
                    print(f"  ⚠️ 错误: {line.strip()[:200]}")
                    # 检测 Action ID 过期错误（常见错误信息包含 "action" 或 "invalid" 等关键词）
                    if any(keyword in line.lower() for keyword in ["action", "invalid", "expired", "not found"]):
                        print(f"  🔄 检测到可能的 Action ID 过期，清空缓存以便下次重新扫描")
                        invalidate_action_cache()
                    break

        return success, result

    async def enable_nsfw_unhinged(self, session: CurlAsyncSession, sso_token: str) -> tuple[bool, str]:
        """异步开启 NSFW/Unhinged（复用注册 session 的 TLS 握手和 Cloudflare Cookie）"""
        # 将 SSO Token 注入 session 的 Cookie jar（保留已有的 __cf_bm 等 Cloudflare Cookie）
        session.cookies.set("sso", sso_token)
        session.cookies.set("sso-rw", sso_token)

        # Protobuf: field 1 (nsfw) = true, field 2 (unhinged) = true
        proto = bytes([0x08, 0x01, 0x10, 0x01])

        # 复用 _call 一样的请求模式（使用 BASE 域名 accounts.x.ai，不手动设 cookie header）
        url = f"{BASE}/{SERVICE}/UpdateUserFeatureControls"
        try:
            resp = await session.post(
                url,
                data=wrap_grpc_frame(proto),
                headers={
                    "Content-Type": "application/grpc-web+proto",
                    "Accept": "application/grpc-web+proto",
                    "Origin": BASE,
                    "Referer": f"{BASE}/",
                    "X-Grpc-Web": "1",
                    "X-User-Agent": "connect-es/2.1.1",
                    "User-Agent": self.user_agent,
                },
                timeout=30,
            )
            if resp.status_code == 200:
                grpc_status, message, trailers = parse_grpc_response(resp.content)
                if grpc_status == 0:
                    return True, "NSFW/Unhinged 开启成功"
                grpc_msg = trailers.get("grpc-message", "")
                return False, f"gRPC {grpc_status}: {grpc_msg}"
            return False, f"HTTP {resp.status_code}"
        except Exception as e:
            return False, str(e)[:80]


# ========== 随机密码 ==========

def gen_password() -> str:
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    pw = (
        random.choice(string.ascii_uppercase)
        + random.choice(string.ascii_lowercase)
        + random.choice(string.digits)
        + random.choice("!@#$%^&*()")
        + "".join(random.choices(chars, k=12))
    )
    pw_list = list(pw)
    random.shuffle(pw_list)
    return "".join(pw_list)


def build_code_candidates(code: str) -> list[str]:
    ambiguous_map = {
        "0": ("O",),
        "O": ("0",),
        "1": ("I", "L"),
        "I": ("1", "L"),
        "L": ("1", "I"),
        "5": ("S",),
        "S": ("5",),
        "2": ("Z",),
        "Z": ("2",),
        "6": ("G",),
        "G": ("6",),
        "8": ("B",),
        "B": ("8",),
    }
    compact = re.sub(r"[\s\u00A0\u2009\u202F]+", "", str(code or "")).upper()
    candidates: list[str] = []
    seen: set[str] = set()

    def _add(candidate: str):
        normalized = (candidate or "").strip().upper()
        if not normalized or normalized in seen:
            return
        seen.add(normalized)
        candidates.append(normalized)

    _add(compact)
    if "-" in compact:
        _add(compact.replace("-", ""))

    for idx, ch in enumerate(compact):
        for replacement in ambiguous_map.get(ch, ()):
            mutated = compact[:idx] + replacement + compact[idx + 1:]
            _add(mutated)
            if "-" in mutated:
                _add(mutated.replace("-", ""))
        if len(candidates) >= 10:
            break

    return candidates or [compact]


# ========== Turnstile Token 预热队列（多节点集群模式） ==========

async def _check_solver_has_free_browser(http_client: httpx.AsyncClient, nodes: list[str]) -> int:
    """查询所有 Solver 节点的空闲浏览器总数，返回 0 则表示全忙"""
    total_free = 0
    for node in nodes:
        try:
            resp = await http_client.get(f"{node}/", timeout=3)
            info = resp.json()
            total_free += info.get("available_browsers", 0)
        except Exception:
            pass
    return total_free


async def _prefetch_tokens(http_client: httpx.AsyncClient, sitekey: str,
                           max_concurrent: int = 5, queue_cap: int = 10):
    """
    后台预热协程：持续向 Solver 集群申请 Turnstile Token 并缓存到队列。
    根据 solver_nodes.txt 中的节点数量自动调整并发上限。
    每次调用 get_turnstile_token_async 时，它会随机选择一个节点派发，
    实现对多节点的自然负载均衡。

    资源保护：预热前检查 Solver 是否有空闲浏览器，避免占满全部资源
    导致注册任务的直接请求也无法获取浏览器（资源饥饿）。
    """
    global token_queue, _prefetch_stop

    # 读取集群节点数，动态计算实际并发上限
    solver_nodes = get_solver_nodes()
    node_count = len(solver_nodes)
    # 每个节点允许 max_concurrent 个并发任务，总并发 = 节点数 × 单节点并发
    # 但不超过队列容量，避免过度预热导致 Token 过期
    effective_concurrent = min(max_concurrent * node_count, queue_cap)

    sem = asyncio.Semaphore(effective_concurrent)
    consecutive_fails = 0
    MAX_BACKOFF = 60
    # 首次失败至少退避 5 秒，避免疯狂重试霸占浏览器
    MIN_BACKOFF = 5

    async def _fetch_one():
        """单次解题并放入队列（自动选择最优节点）"""
        async with sem:
            if _prefetch_stop.is_set():
                return False
            try:
                token = await get_turnstile_token_async(
                    client=None, timeout=120, sitekey=sitekey
                )
                if token:
                    await token_queue.put(token)
                    print(f"  [预热] ✅ Token 已入队（队列: {token_queue.qsize()}/{queue_cap}）")
                    return True
                else:
                    print(f"  [预热] ⚠️ 本次解题未拿到 Token，继续")
                    return False
            except Exception as e:
                print(f"  [预热] ⚠️ 解题异常: {e}")
                return False

    print(f"  [预热] 🚀 启动 Token 预热队列")
    print(f"  [预热] 📡 检测到 {node_count} 个 Solver 节点:")
    for i, n in enumerate(solver_nodes):
        print(f"  [预热]   {i+1}. {n}")
    print(f"  [预热] ⚡ 总并发上限: {effective_concurrent}（{node_count} 节点 × {max_concurrent} 并发/节点），队列容量: {queue_cap}")

    while not _prefetch_stop.is_set():
        # 队列接近满时暂停发起新请求，避免 Token 过期
        if token_queue.qsize() >= queue_cap - 1:
            await asyncio.sleep(2)
            continue

        # 资源保护：检查 Solver 是否有空闲浏览器
        free_browsers = await _check_solver_has_free_browser(http_client, solver_nodes)
        if free_browsers <= 1:
            # 空闲浏览器 ≤1：预热完全让步，把资源留给注册任务的直接请求
            await asyncio.sleep(3)
            continue

        # 预热并发数不超过空闲浏览器减 1（始终预留 1 个给注册直接请求）
        max_prefetch = free_browsers - 1
        slots = queue_cap - token_queue.qsize()
        batch = min(slots, effective_concurrent, max_prefetch)
        tasks = [asyncio.create_task(_fetch_one()) for _ in range(batch)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        success_count = sum(1 for r in results if r is True)

        if success_count > 0:
            consecutive_fails = 0
        else:
            consecutive_fails += 1

        if consecutive_fails > 0:
            backoff = min(max(MIN_BACKOFF, 2 ** consecutive_fails), MAX_BACKOFF)
            print(f"  [预热] 💤 连续失败 {consecutive_fails} 轮，退避等待 {backoff}s...")
            await asyncio.sleep(backoff)
        else:
            await asyncio.sleep(1)

    print(f"  [预热] [成功] 预热协程已停止")


# ========== 持久化写入（加锁保护） ==========

async def save_account(account: dict):
    """将注册结果写入 accounts.csv / key.txt / 未开启nsfw.txt"""
    global file_lock
    async with file_lock:
        sso = account.get("sso", "")
        sso_rw = account.get("sso_rw", "")
        await asyncio.to_thread(
            _append_file, ACCOUNTS_CSV,
            f"\n{account['email']},{account['password']},{sso},{sso_rw}"
        )
        print(f"  ✅ 已保存到 accounts.csv")

        if sso and account.get("nsfw_enabled"):
            await asyncio.to_thread(_append_file, KEY_TXT, f"{sso}\n")
            print(f"  🔑 SSO Token 已追加到 key.txt（NSFW 已开启）")
        elif sso:
            await asyncio.to_thread(_append_file, NSFW_FAIL_TXT, f"{sso}\n")
            print(f"  ⚠️ NSFW 未开启，SSO Token 已保存到 未开启nsfw.txt")
        else:
            print(f"  ⚠️ 未获取到 SSO Token")


def _append_file(path: str, content: str):
    with open(path, "a", encoding="utf-8") as f:
        f.write(content)


# ========== 单次注册主链路（全异步，V5 正确顺序） ==========

async def register_one_async(task_id: int, http_client: httpx.AsyncClient,
                              sem: asyncio.Semaphore,
                              proxy_addr: str = "") -> dict | None:
    """
    执行一次完整的异步注册。
    流程顺序：
      Step 0: 初始化会话 + 动态扫描（curl_cffi）
      Step 1: 创建 im-mail 临时邮箱（httpx → im-mail API）
      Step 2: 发送验证码（curl_cffi gRPC）
      Step 3: 等待验证码（httpx 轮询 im-mail API）
      Step 4: 校验验证码（curl_cffi gRPC）
      Step 5: 获取 Turnstile Token（httpx → 本地 Solver）
      Step 6: 创建用户（curl_cffi Server Action）
      Step 7: 开启 NSFW（curl_cffi gRPC）
    """
    # 使用传入的独立代理地址，回退到全局默认
    px = proxy_addr or PROXY
    async with sem:
        tag = f"[任务 #{task_id}]"
        if _batch_abort is not None and _batch_abort.is_set():
            reason = _RUNTIME_NETWORK_STATE.get("abort_reason") or "批量任务已熔断"
            print(f"{tag} ⏭️ 已跳过：{reason}")
            return None

        px_text = px or "直连（无代理）"
        print(f"\n{'=' * 60}")
        print(f"{tag} === Grok 异步注册机 V6 - 开始 ===")
        print(f"  🌐 分配代理: {px_text}")
        print(f"{'=' * 60}")

        # 初始化 gRPC 客户端（curl_cffi TLS 伪装）
        grpc = AsyncGrokGRPCClient()
        mail = AsyncImMailClient(api_base=IM_MAIL_API_BASE, api_auth_token=IM_MAIL_AUTH_TOKEN, client=http_client)

        # 每个任务创建独立的 curl_cffi session（隔离 cookie 和代理）
        async with CurlAsyncSession(**build_curl_session_kwargs(grpc.profile["impersonate"], px)) as curl_session:

            # Step 0: 初始化会话 + 动态扫描
            ok, action_id, sitekey = await grpc.init_session(curl_session, task_tag=tag)
            if ok:
                await note_step0_result(True)
            if not ok:
                circuit_opened = await note_step0_result(False, grpc.last_init_error)
                if circuit_opened:
                    print(f"{tag} ⛔ 已触发批量熔断：{_RUNTIME_NETWORK_STATE.get('abort_reason', '')}")
                    if grpc.last_init_error:
                        print(f"{tag} ⛔ 最近 Step 0 异常: {grpc.last_init_error}")
                print(f"{tag} ❌ 会话初始化失败")
                print(f"{tag} [STAT] FAIL")
                return None

            # Step 1: 创建 im-mail 临时邮箱
            print(f"\n{tag} [Step 1] 创建 im-mail 临时邮箱...")
            try:
                email = await mail.create_mailbox()
            except Exception as e:
                print(f"{tag} ❌ 创建邮箱失败: {e}")
                print(f"{tag} [STAT] FAIL")
                return None

            password = gen_password()
            print(f"  📧 邮箱: {email}")
            print(f"  🔒 密码: {password}")

            # Step 2: 发送验证码
            if not await grpc.send_code(curl_session, email):
                print(f"{tag} ❌ 发送验证码失败")
                print(f"{tag} [STAT] FAIL")
                return None

            # Step 3+5 并行：等待验证码 + 同时获取 Turnstile Token
            print(f"\n{tag} [Step 3+5] 等待验证码 + 同时获取 Turnstile Token...")

            async def _get_token_parallel():
                """并行获取 Turnstile Token（优先队列，回退直接请求，带重试）"""
                t = None
                if token_queue is not None:
                    try:
                        # 只等 15 秒，快速回退到直接请求，避免被预热队列阻塞
                        t = await asyncio.wait_for(token_queue.get(), timeout=15)
                        print(f"  ✅ 从预热队列取到 Token（队列剩余: {token_queue.qsize()}）")
                    except asyncio.TimeoutError:
                        print(f"  ⚠️ 预热队列 15s 无现成 Token，回退到直接请求...")
                if not t:
                    # 直接请求，最多尝试 2 次（Solver 有概率失败）
                    for attempt in range(2):
                        t = await get_turnstile_token_async(
                            client=http_client, timeout=90, sitekey=sitekey
                        )
                        if t:
                            break
                        if attempt == 0:
                            print(f"  ⚠️ 直接请求第 1 次失败，5s 后重试...")
                            await asyncio.sleep(5)
                return t

            # 同时启动两个任务
            code_task = asyncio.create_task(mail.wait_for_code(timeout=120))
            token_task = asyncio.create_task(_get_token_parallel())

            # 等待验证码
            raw_code = await code_task
            if not raw_code:
                # 验证码失败，取消 token 任务
                if not token_task.done():
                    token_task.cancel()
                print(f"{tag} [失败] 获取验证码失败")
                print(f"{tag} [STAT] FAIL")
                return None
            compact_code = re.sub(r"[\s\u00A0\u2009\u202F]+", "", str(raw_code or "")).upper()
            if re.fullmatch(r"[\d-]+", compact_code):
                clean_code = re.sub(r"\D+", "", compact_code)
            else:
                clean_code = compact_code
            code_candidates = build_code_candidates(clean_code)
            verify_attempts = code_candidates
            preview_candidates = ", ".join(verify_attempts[:6])
            if len(code_candidates) > 6:
                preview_candidates += ", ..."
            print(f"  [验证码] 原始验证码: {raw_code} → 候选提交值: {preview_candidates}")

            # Step 4: 校验验证码
            ok = False
            verify_token = ""
            total_attempts = len(verify_attempts)
            for attempt, candidate in enumerate(verify_attempts, 1):
                clean_code = candidate
                if attempt > 1:
                    wait_s = 2 if attempt == 2 else 1
                    print(f"  [验证码] 重试候选 #{attempt}/{total_attempts}: {clean_code}（等待 {wait_s}s）")
                    await asyncio.sleep(wait_s)
                ok, verify_token = await grpc.verify_code(curl_session, email, clean_code)
                if ok:
                    break
            if not ok:
                if not token_task.done():
                    token_task.cancel()
                print(f"{tag} ❌ 验证码校验失败")
                print(f"{tag} [STAT] FAIL")
                return None
            if verify_token:
                print(f"  [通行证] Verify Token: {verify_token[:50]}...")

            # 等待 Turnstile Token（如果还没完成）
            turnstile_token = await token_task
            if not turnstile_token:
                print(f"{tag} ❌ Turnstile Token 获取失败")
                print(f"{tag} [STAT] FAIL")
                return None
            print(f"  ✅ Turnstile Token: {turnstile_token[:50]}...")

            # Step 6: 创建用户
            ok, result = await grpc.create_user_via_action(
                session=curl_session,
                email=email,
                password=password,
                code=clean_code,
                turnstile_token=turnstile_token,
                action_id=action_id,
            )

            if not ok:
                print(f"{tag} ❌ 用户创建失败")
                print(f"   详情: {result}")
                print(f"{tag} [STAT] FAIL")
                return None

            print(f"\n{'=' * 60}")
            print(f"{tag} [成功] 注册成功！")
            print(f"{'=' * 60}")

            # Step 7: 自动开启 NSFW/Unhinged（复用同一个 curl_session，避免重复握手）
            sso = result.get("sso", "")
            nsfw_enabled = False
            if sso:
                print(f"\n{tag} [Step 7] 🔓 自动开启 NSFW/Unhinged...")
                nsfw_ok, nsfw_msg = await grpc.enable_nsfw_unhinged(curl_session, sso)
                if nsfw_ok:
                    print(f"  ✅ {nsfw_msg}")
                    nsfw_enabled = True
                else:
                    print(f"  ⚠️ NSFW 开启失败: {nsfw_msg}（不影响注册结果）")
            else:
                print(f"\n  ⚠️ 无 SSO Token，跳过 NSFW/Unhinged 自动开启")

        account = {
            "email": email,
            "password": password,
            "code": raw_code,
            "nsfw_enabled": nsfw_enabled,
            **result,
        }

        # 持久化写入（加锁）
        await save_account(account)

        print(f"\n{tag} 📋 账号信息:")
        print(json.dumps(account, indent=2, default=str))
        print(f"{tag} [STAT] SUCCESS")
        return account


# ========== 并发批量注册入口 ==========

async def batch_register(count: int = 1, concurrency: int = 5):
    """并发批量注册主入口（含 Token 预热队列 + 代理池动态分配 + Action ID 全局缓存）"""
    global file_lock, semaphore, token_queue, _prefetch_stop, _GLOBAL_ACTION_CACHE, _RUNTIME_NETWORK_STATE, _batch_abort

    print("\n" + "=" * 60)
    print(f"  [启动] Grok 异步注册机 V6 - 批量模式")
    print(f"  📊 注册数量: {count}  并发数: {concurrency}")
    print("=" * 60)

    results = []

    # 初始化全局锁（包括 Action ID 缓存锁）
    file_lock = asyncio.Lock()
    semaphore = asyncio.Semaphore(concurrency)
    _GLOBAL_ACTION_CACHE["lock"] = asyncio.Lock()
    _RUNTIME_NETWORK_STATE["lock"] = asyncio.Lock()
    _RUNTIME_NETWORK_STATE["preflight_ok"] = None
    _RUNTIME_NETWORK_STATE["preflight_detail"] = ""
    _RUNTIME_NETWORK_STATE["step0_timeout_count"] = 0
    _RUNTIME_NETWORK_STATE["last_error"] = ""
    _RUNTIME_NETWORK_STATE["abort_reason"] = ""
    _batch_abort = asyncio.Event()
    # 预热队列容量 = 并发数 * 2，给予充足缓冲
    queue_cap = concurrency * 2
    token_queue = asyncio.Queue(maxsize=queue_cap)
    _prefetch_stop = asyncio.Event()

    # httpx 用于 Freemail 和 Turnstile Solver（无需 TLS 伪装）
    async with httpx.AsyncClient(
        timeout=30,
        follow_redirects=True,
        trust_env=False,
    ) as http_client:

        # 代理模式选择：sing-box > 直连网关 > API 节点池 > 裸跑
        proxy_mgr = ProxyManager(fallback_proxy=PROXY)
        if SINGBOX_ENABLED:
            print(f"  🎵 [sing-box 模式] 本地接入点: {SINGBOX_PROXY}（真正远端节点由 sing-box 自动选路）")
            print(f"  🎯 [sing-box 候选池] {_build_singbox_candidate_summary()}")
            print(f"  🧪 [sing-box urltest] 目标: {SINGBOX_URLTEST_PROBE_URL}")
            # 覆盖 fallback，让所有任务都走 sing-box
            proxy_mgr.fallback_proxy = SINGBOX_PROXY
        elif ENABLE_PROXY_POOL and PROXY_MODE == "direct_socks":
            # 直连网关模式：PROXY 已由 web_server 注入为 socks5://xxx 地址
            proxy_mgr.fallback_proxy = PROXY
            print(f"  🚀 [直连网关模式] 代理: {PROXY}（网关内部自动并发轮换 IP）")
        elif ENABLE_PROXY_POOL:
            pool_size = await proxy_mgr.refresh(http_client)
            if pool_size > 0:
                print(f"  🌍 代理池就绪: {pool_size} 个节点可用，将为 {concurrency} 个并发线程轮询分配")
            else:
                p_text = PROXY if PROXY else "🎯 真正的本机直飞 (无代理)"
                print(f"  ⚠️ 代理池不可用，全部任务回退使用本机代理: {p_text}")
        else:
            p_text = PROXY if PROXY else "🎯 真正的本机直飞 (无代理)"
            print(f"  ⚙️ [全局开关] 已关闭远端调度，当前引擎使用: {p_text}")

        runtime_mode, runtime_target, runtime_detail = get_runtime_proxy_snapshot()
        print(f"  🌐 [代理接入] 模式: {runtime_mode}")
        print(f"  🌐 [代理接入] 接入点: {runtime_target}")
        print(f"  🧭 [调度说明] {runtime_detail}")

        preflight_proxy = proxy_mgr.allocate()
        if SINGBOX_ENABLED:
            print("  🔀 [sing-box 说明] 本次预检仍先连接本地 sing-box 入口，具体远端节点由 sing-box 当次自动选路")
        print(f"  🩺 [预检] 正在检测 x.ai sign-up 可达性...")
        preflight_ok, preflight_info = await preflight_signup_healthcheck(preflight_proxy)
        _RUNTIME_NETWORK_STATE["preflight_ok"] = preflight_ok
        _RUNTIME_NETWORK_STATE["preflight_detail"] = preflight_info.get("reason", "")

        if not preflight_ok:
            _RUNTIME_NETWORK_STATE["abort_reason"] = f"x.ai 前置健康检查失败：{preflight_info.get('reason', '未知错误')}"
            _batch_abort.set()
            print(f"  ❌ [预检] {_RUNTIME_NETWORK_STATE['abort_reason']}")
            if preflight_info.get("status_code"):
                print(f"  ❌ [预检] 响应状态码: {preflight_info['status_code']}")
            if preflight_info.get("preview"):
                print(f"  ❌ [预检] 页面预览: {preflight_info['preview']}")
        else:
            print(f"  ✅ [预检] {preflight_info.get('reason', 'x.ai sign-up 页面可达')}")

            # 先预热一次 Action ID / Sitekey 共享缓存，避免 Token 预热仍使用过期默认 sitekey
            initial_sitekey = DEFAULT_SITE_KEY
            try:
                warmup_grpc = AsyncGrokGRPCClient()
                warmup_proxy = proxy_mgr.allocate()
                async with CurlAsyncSession(**build_curl_session_kwargs(warmup_grpc.profile["impersonate"], warmup_proxy)) as warmup_session:
                    _, initial_sitekey = await get_cached_action_id(warmup_session)
                    print(f"  🔥 预热 Sitekey: {initial_sitekey}")
            except Exception as e:
                initial_sitekey = DEFAULT_SITE_KEY
                print(f"  ⚠️ 预热获取 Sitekey 失败 ({e})，回退默认 Sitekey")

            # 启动 Token 预热协程（后台持续运行，自动感知集群节点数）
            # max_concurrent 代表每个节点的并发上限，预热协程内部会乘以节点数
            # 每节点只允许 1 个预热并发，避免占满浏览器导致注册任务饥饿
            per_node_concurrent = 1
            prefetch_task = asyncio.create_task(
                _prefetch_tokens(http_client, initial_sitekey,
                                 max_concurrent=per_node_concurrent, queue_cap=queue_cap)
            )

            # 创建并发注册任务，每个任务分配独立代理 IP
            tasks = [
                asyncio.create_task(
                    register_one_async(i + 1, http_client, semaphore,
                                       proxy_addr=proxy_mgr.allocate())
                )
                for i in range(count)
            ]

            results = await asyncio.gather(*tasks, return_exceptions=True)

            # 注册全部完成，停止预热协程
            _prefetch_stop.set()
            try:
                await asyncio.wait_for(prefetch_task, timeout=10)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                prefetch_task.cancel()

    # 统计结果
    success = sum(1 for r in results if isinstance(r, dict))
    failed = count - success
    errors = [r for r in results if isinstance(r, Exception)]

    print("\n" + "=" * 60)
    print(f"  📊 批量注册完成！")
    print(f"  ✅ 成功: {success}/{count}")
    print(f"  ❌ 失败: {failed}/{count}")
    if _RUNTIME_NETWORK_STATE.get("abort_reason"):
        print(f"  ⛔ 中止原因: {_RUNTIME_NETWORK_STATE['abort_reason']}")
    if _RUNTIME_NETWORK_STATE.get("last_error"):
        print(f"  🧾 最近 Step 0 异常: {_RUNTIME_NETWORK_STATE['last_error']}")
    if errors:
        print(f"  ⚠️ 异常详情:")
        for e in errors:
            print(f"     - {type(e).__name__}: {e}")
    print("=" * 60)


# ========== 入口 ==========

def main():
    global IM_MAIL_API_BASE, IM_MAIL_AUTH_TOKEN, PROXY
    # 强制 stdout 直写模式：每次 print() 立即穿透缓冲层写入管道，避免日志积攒
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(write_through=True)
    import argparse
    parser = argparse.ArgumentParser(description="Grok 异步注册机 V6")
    parser.add_argument("--count", "-n", type=int, default=1, help="注册数量（默认 1）")
    parser.add_argument("--concurrency", "-c", type=int, default=5, help="并发数（默认 5）")
    parser.add_argument("--proxy", "-p", type=str, default=None,
                        help="代理地址（如 socks5h://127.0.0.1:1080 或 http://127.0.0.1:7890）")
    parser.add_argument("--im-mail-api-base", type=str, default=None,
                        help="im-mail API 地址（默认读取 IM_MAIL_API_BASE 或 http://127.0.0.1:3000）")
    parser.add_argument("--im-mail-auth-token", type=str, default=None,
                        help="im-mail API 鉴权 Token（可选，默认读取 IM_MAIL_AUTH_TOKEN）")
    args = parser.parse_args()

    # 命令行参数覆盖全局默认值
    if args.proxy:
        PROXY = args.proxy
    if args.im_mail_api_base:
        IM_MAIL_API_BASE = args.im_mail_api_base.rstrip("/")
    if args.im_mail_auth_token is not None:
        IM_MAIL_AUTH_TOKEN = args.im_mail_auth_token.strip()

    proxy_mode_text, proxy_target_text, proxy_detail_text = get_runtime_proxy_snapshot()
    token_text = f"{IM_MAIL_AUTH_TOKEN[:8]}..." if IM_MAIL_AUTH_TOKEN else "未配置（若接口无需鉴权可忽略）"

    print("\n" + "=" * 60)
    print("  🚀 Grok 混合模式注册机 V6 - 全异步引擎")
    print("  📦 依赖: asyncio + curl_cffi(gRPC) + httpx(im-mail/solver)")
    print("  📬 邮箱: im-mail 兼容接口")
    print(f"  🌐 代理模式: {proxy_mode_text}")
    print(f"  🌐 进程代理接入点: {proxy_target_text}")
    print(f"  🧭 调度说明: {proxy_detail_text}")
    if SINGBOX_ENABLED:
        print(f"  🎯 sing-box 候选池: {_build_singbox_candidate_summary()}")
        print(f"  🧪 sing-box urltest 目标: {SINGBOX_URLTEST_PROBE_URL}")
    print(f"  📮 im-mail API: {IM_MAIL_API_BASE}")
    print(f"  🔑 im-mail Token: {token_text}")
    print("  🔒 并发保护: Semaphore + Lock")
    print("=" * 60)

    asyncio.run(batch_register(count=args.count, concurrency=args.concurrency))


if __name__ == "__main__":
    main()
