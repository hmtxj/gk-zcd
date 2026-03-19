"""
sing-box 代理网关管理模块

职责：
  1. 从 sublinkPro 订阅链接拉取节点（Base64 编码的协议 URI 列表）
  2. 解析 vmess/vless/ss/trojan 协议 URI 为 sing-box outbound JSON
  3. 生成完整的 sing-box 配置文件（mixed inbound + urltest 负载均衡）
  4. 管理 sing-box 进程的启动/停止/重启
"""

import os
import sys
import json
import base64
import signal
import socket
import subprocess
import platform
import zipfile
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, unquote
from typing import Optional

import httpx

# 模块常量
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(SCRIPT_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)
SINGBOX_DIR = os.path.join(SCRIPT_DIR, "singbox")
SINGBOX_CONFIG_PATH = os.path.join(DATA_DIR, "singbox_config.json")
SINGBOX_PERSIST_PATH = os.path.join(DATA_DIR, "singbox_user_config.json")
SINGBOX_STDOUT_LOG = os.path.join(DATA_DIR, "singbox_stdout.log")
SINGBOX_STDERR_LOG = os.path.join(DATA_DIR, "singbox_stderr.log")

# sing-box 可执行文件路径（根据系统自动选择）
SINGBOX_BIN = os.path.join(SINGBOX_DIR, "sing-box.exe" if os.name == "nt" else "sing-box")

# 默认本地代理端口（避开常用的 1080）
DEFAULT_LISTEN_PORT = 2080
XAI_SIGNUP_URL = "https://accounts.x.ai/sign-up?redirect=grok-com"
URLTEST_PROBE_URL = XAI_SIGNUP_URL
CANDIDATE_PREVIEW_LIMIT = 6
DIAGNOSTIC_AVAILABLE_BASIS = "tcp_connectivity_only"
DIAGNOSTIC_AVAILABLE_LABEL = "仅 TCP 快速探测"
DIAGNOSTIC_WARNING = "当前“快速探测可用”仅代表 TCP 建连成功，不代表已验证可访问 accounts.x.ai"
REGION_FILTER_MODE = "exclude_hk_tw_cn"
REGION_FILTER_LABEL = "排除港/台/国内节点"
REGION_FILTER_WARNING = "检测到港/台/国内线路对 accounts.x.ai / 美国站点可用性较差，订阅刷新时将按标签排除这些节点，避免继续混入 sing-box 可用池"
BLOCKED_REGION_KEYWORDS = (
    "香港", "hk", "hong kong",
    "台湾", "tw", "taiwan", "台北", "新北",
    "中国", "cn", "china", "国内", "内地",
)


def _build_default_diagnostics() -> dict:
    return {
        "total_uris": 0,
        "parse_failed_count": 0,
        "quick_probe_failed_count": 0,
        "region_excluded_count": 0,
        "manual_disabled_count": 0,
        "parse_failed_nodes": [],
        "quick_probe_failed_nodes": [],
        "region_excluded_nodes": [],
        "manual_disabled_nodes": [],
        "availability_basis": DIAGNOSTIC_AVAILABLE_BASIS,
        "availability_basis_label": DIAGNOSTIC_AVAILABLE_LABEL,
        "xai_probe_enabled": False,
        "target_url": XAI_SIGNUP_URL,
        "urltest_probe_url": URLTEST_PROBE_URL,
        "candidate_preview_tags": [],
        "candidate_preview_text": "暂无候选节点",
        "diagnostic_warning": DIAGNOSTIC_WARNING,
        "region_filter_enabled": True,
        "region_filter_mode": REGION_FILTER_MODE,
        "region_filter_label": REGION_FILTER_LABEL,
        "region_filter_warning": REGION_FILTER_WARNING,
    }


# ========== 订阅解析器 ==========

def fetch_subscription(url: str, timeout: int = 15) -> list[str]:
    """
    从 sublinkPro 订阅链接拉取节点列表。
    sublinkPro 通常返回 Base64 编码的多行协议 URI。
    也支持直接返回明文 URI 列表。
    """
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        r = client.get(url)
        r.raise_for_status()
        raw = r.text.strip()

    # 尝试 Base64 解码
    lines = _try_decode_base64(raw)
    if not lines:
        # 明文格式，直接按行分割
        lines = [l.strip() for l in raw.splitlines() if l.strip()]

    # 过滤出支持的协议
    supported = ("vmess://", "vless://", "ss://", "trojan://", "hysteria2://", "hy2://")
    return [l for l in lines if any(l.startswith(s) for s in supported)]


def _try_decode_base64(text: str) -> list[str]:
    """尝试 Base64 解码，失败返回空列表"""
    try:
        # 补齐 padding
        padded = text + "=" * (-len(text) % 4)
        decoded = base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")
        lines = [l.strip() for l in decoded.splitlines() if l.strip()]
        # 验证至少一行是合法协议 URI
        if any(l.startswith(("vmess://", "vless://", "ss://", "trojan://")) for l in lines):
            return lines
    except Exception:
        pass
    return []


# ========== 协议 URI → sing-box outbound 转换 ==========

def parse_uri_to_outbound(uri: str, index: int) -> Optional[dict]:
    """将代理协议 URI 转为 sing-box outbound 配置字典"""
    outbound, error = parse_uri_to_outbound_with_error(uri, index)
    if error:
        print(f"  ⚠️ 解析失败 [{uri[:40]}...]: {error}")
    return outbound


def parse_uri_to_outbound_with_error(uri: str, index: int) -> tuple[Optional[dict], str]:
    """将协议 URI 转为 outbound，并保留失败原因供诊断使用。"""
    try:
        if uri.startswith("vmess://"):
            outbound = _parse_vmess(uri, index)
        elif uri.startswith("vless://"):
            outbound = _parse_vless(uri, index)
        elif uri.startswith("ss://"):
            outbound = _parse_shadowsocks(uri, index)
        elif uri.startswith("trojan://"):
            outbound = _parse_trojan(uri, index)
        elif uri.startswith(("hysteria2://", "hy2://")):
            outbound = _parse_hysteria2(uri, index)
        else:
            return None, "不支持的协议类型"

        if not outbound:
            return None, "解析器返回空结果"
        return outbound, ""
    except Exception as e:
        reason = str(e).strip() or e.__class__.__name__
        return None, reason


def _parse_vmess(uri: str, index: int) -> Optional[dict]:
    """解析 vmess://base64(JSON) 格式"""
    raw = uri[len("vmess://"):]
    padded = raw + "=" * (-len(raw) % 4)
    data = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))

    tag = data.get("ps", f"vmess-{index}")
    outbound = {
        "type": "vmess",
        "tag": _sanitize_tag(tag, index),
        "server": data["add"],
        "server_port": int(data["port"]),
        "uuid": data["id"],
        "alter_id": int(data.get("aid", 0)),
        "security": data.get("scy", "auto"),
    }

    # TLS 配置
    tls_val = str(data.get("tls", ""))
    if tls_val == "tls":
        outbound["tls"] = {
            "enabled": True,
            "server_name": data.get("sni", data.get("host", data["add"])),
            "insecure": True,
        }

    # 传输层配置
    net = data.get("net", "tcp")
    if net == "ws":
        outbound["transport"] = {
            "type": "ws",
            "path": data.get("path", "/"),
            "headers": {"Host": data.get("host", data["add"])},
        }
    elif net == "grpc":
        outbound["transport"] = {
            "type": "grpc",
            "service_name": data.get("path", ""),
        }
    elif net == "h2":
        outbound["transport"] = {
            "type": "http",
            "host": [data.get("host", data["add"])],
            "path": data.get("path", "/"),
        }

    return outbound


def _parse_vless(uri: str, index: int) -> Optional[dict]:
    """解析 vless://uuid@server:port?params#name 格式"""
    parsed = urlparse(uri)
    params = parse_qs(parsed.query)
    tag = unquote(parsed.fragment) if parsed.fragment else f"vless-{index}"

    outbound = {
        "type": "vless",
        "tag": _sanitize_tag(tag, index),
        "server": parsed.hostname,
        "server_port": parsed.port,
        "uuid": parsed.username,
    }

    # flow（XTLS）
    flow = _get_param(params, "flow")
    if flow:
        outbound["flow"] = flow

    # TLS 配置
    security = _get_param(params, "security", "none")
    if security in ("tls", "reality"):
        tls_cfg = {
            "enabled": True,
            "server_name": _get_param(params, "sni", parsed.hostname),
            "insecure": True,
        }
        if security == "reality":
            tls_cfg["reality"] = {
                "enabled": True,
                "public_key": _get_param(params, "pbk", ""),
                "short_id": _get_param(params, "sid", ""),
            }
            # Reality 不安全跳过验证
            tls_cfg["insecure"] = False
        fp = _get_param(params, "fp")
        if fp:
            tls_cfg["utls"] = {"enabled": True, "fingerprint": fp}

        alpn = _get_param(params, "alpn")
        if alpn:
            tls_cfg["alpn"] = alpn.split(",")

        outbound["tls"] = tls_cfg

    # 传输层
    transport_type = _get_param(params, "type", "tcp")
    _attach_transport(outbound, transport_type, params, parsed.hostname)

    return outbound


def _parse_shadowsocks(uri: str, index: int) -> Optional[dict]:
    """
    解析 ss:// 格式（支持两种变体）：
    - SIP002: ss://base64(method:password)@server:port#name
    - 旧格式: ss://base64(method:password@server:port)#name
    """
    raw = uri[len("ss://"):]
    tag_part = ""
    if "#" in raw:
        raw, tag_part = raw.rsplit("#", 1)
    tag = unquote(tag_part) if tag_part else f"ss-{index}"

    # SIP002 格式（有 @ 分隔服务器信息）
    if "@" in raw:
        user_part, server_part = raw.rsplit("@", 1)
        # 解码 userinfo
        try:
            padded = user_part + "=" * (-len(user_part) % 4)
            decoded = base64.urlsafe_b64decode(padded).decode("utf-8")
            method, password = decoded.split(":", 1)
        except Exception:
            # 直接是 method:password 明文
            method, password = user_part.split(":", 1)
        # 解析服务器
        if ":" in server_part:
            host, port_str = server_part.rsplit(":", 1)
            port = int(port_str.split("?")[0].split("/")[0])
        else:
            return None
    else:
        # 旧格式：整体 Base64
        try:
            padded = raw + "=" * (-len(raw) % 4)
            decoded = base64.urlsafe_b64decode(padded).decode("utf-8")
            method_pw, server_part = decoded.rsplit("@", 1)
            method, password = method_pw.split(":", 1)
            host, port_str = server_part.rsplit(":", 1)
            port = int(port_str)
        except Exception:
            return None

    return {
        "type": "shadowsocks",
        "tag": _sanitize_tag(tag, index),
        "server": host,
        "server_port": port,
        "method": method,
        "password": password,
    }


def _parse_trojan(uri: str, index: int) -> Optional[dict]:
    """解析 trojan://password@server:port?params#name 格式"""
    parsed = urlparse(uri)
    params = parse_qs(parsed.query)
    tag = unquote(parsed.fragment) if parsed.fragment else f"trojan-{index}"

    outbound = {
        "type": "trojan",
        "tag": _sanitize_tag(tag, index),
        "server": parsed.hostname,
        "server_port": parsed.port,
        "password": unquote(parsed.username) if parsed.username else "",
        "tls": {
            "enabled": True,
            "server_name": _get_param(params, "sni", parsed.hostname),
            "insecure": True,
        },
    }

    # 传输层
    transport_type = _get_param(params, "type", "tcp")
    _attach_transport(outbound, transport_type, params, parsed.hostname)

    return outbound


def _parse_hysteria2(uri: str, index: int) -> Optional[dict]:
    """解析 hysteria2://password@server:port?params#name 格式"""
    parsed = urlparse(uri)
    params = parse_qs(parsed.query)
    tag = unquote(parsed.fragment) if parsed.fragment else f"hy2-{index}"

    return {
        "type": "hysteria2",
        "tag": _sanitize_tag(tag, index),
        "server": parsed.hostname,
        "server_port": parsed.port,
        "password": unquote(parsed.username) if parsed.username else "",
        "tls": {
            "enabled": True,
            "server_name": _get_param(params, "sni", parsed.hostname),
            "insecure": True,
        },
    }


# ========== 辅助函数 ==========

def _get_param(params: dict, key: str, default: str = "") -> str:
    """从 parse_qs 结果中取单个参数值"""
    vals = params.get(key, [])
    return vals[0] if vals else default


def _sanitize_tag(tag: str, index: int) -> str:
    """清理 tag，去除不安全字符，保证唯一性"""
    # 去除前后空白和特殊字符
    tag = tag.strip()
    if not tag:
        return f"node-{index}"
    # 截断过长的 tag
    if len(tag) > 50:
        tag = tag[:50]
    # 追加索引确保唯一
    return f"{tag}_{index}"


def _attach_transport(outbound: dict, transport_type: str, params: dict, hostname: str):
    """为 outbound 附加传输层配置"""
    if transport_type == "ws":
        outbound["transport"] = {
            "type": "ws",
            "path": _get_param(params, "path", "/"),
            "headers": {"Host": _get_param(params, "host", hostname)},
        }
    elif transport_type == "grpc":
        outbound["transport"] = {
            "type": "grpc",
            "service_name": _get_param(params, "serviceName", ""),
        }
    elif transport_type == "h2":
        outbound["transport"] = {
            "type": "http",
            "host": [_get_param(params, "host", hostname)],
            "path": _get_param(params, "path", "/"),
        }


# ========== sing-box 配置文件生成 ==========

def _format_exception_reason(exc: Exception) -> str:
    text = str(exc).strip()
    return text or exc.__class__.__name__



def _probe_single_outbound_detail(outbound: dict, timeout: float = 1.8) -> dict:
    """返回单个节点 TCP 快速探测结果与失败原因。"""
    server = outbound.get("server")
    port = outbound.get("server_port")
    result = {
        "ok": False,
        "reason": "",
        "server": server or "",
        "server_port": port or "",
    }
    if not server or not port:
        result["reason"] = "缺少 server / server_port"
        return result
    try:
        port = int(port)
        with socket.create_connection((server, port), timeout=timeout):
            result["ok"] = True
            result["reason"] = "TCP 连接成功"
            result["server_port"] = port
            return result
    except TimeoutError:
        result["reason"] = f"TCP 连接超时（{timeout:.1f}s）"
    except OSError as e:
        result["reason"] = _format_exception_reason(e)
    except Exception as e:
        result["reason"] = _format_exception_reason(e)
    return result



def _probe_single_outbound(outbound: dict, timeout: float = 1.8) -> bool:
    """快速探测单个节点的 TCP 连通性，仅用于预过滤明显不可达节点。"""
    return _probe_single_outbound_detail(outbound, timeout=timeout)["ok"]


def generate_config(outbounds: list[dict], listen_port: int = DEFAULT_LISTEN_PORT) -> dict:
    """
    生成完整的 sing-box 配置文件 JSON。
    - mixed inbound: 暴露 socks5+http 代理接口
    - urltest outbound: 自动测速负载均衡
    """
    # 所有代理节点的 tag 列表
    node_tags = [o["tag"] for o in outbounds]

    config = {
        "log": {
            "level": "warn",
            "timestamp": True,
        },
        "inbounds": [
            {
                "type": "mixed",
                "tag": "proxy-in",
                "listen": "127.0.0.1",
                "listen_port": listen_port,
            }
        ],
        "outbounds": [
            # urltest 自动测速轮换（核心：实现 IP 轮换）
            {
                "type": "urltest",
                "tag": "auto",
                "outbounds": node_tags,
                "url": URLTEST_PROBE_URL,
                "interval": "3m",
                "tolerance": 100,
                "interrupt_exist_connections": True,
            },
            # 直连出口
            {"type": "direct", "tag": "direct"},
            # 阻断
            {"type": "block", "tag": "block"},
        ] + outbounds,  # 附加所有代理节点
        "route": {
            "final": "auto",
        },
    }
    return config


# ========== 用户配置持久化 ==========

def load_user_config() -> dict:
    """读取持久化的用户配置（订阅链接、端口等）"""
    config = {
        "subscribe_url": "",
        "listen_port": DEFAULT_LISTEN_PORT,
        "enabled": False,
        "parsed_count": 0,
        "available_count": 0,
        "last_refresh_message": "",
        "parsed_nodes": [],
        "available_nodes": [],
        "manual_disabled_keys": [],
        **_build_default_diagnostics(),
    }
    if os.path.exists(SINGBOX_PERSIST_PATH):
        try:
            with open(SINGBOX_PERSIST_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                config.update(data)
                if data.get("region_filter_mode") == "exclude_us":
                    config["region_excluded_count"] = 0
                    config["region_excluded_nodes"] = []
                    config["last_refresh_message"] = "检测到旧版“排除美国节点”策略残留，请重新刷新订阅以按新规则排除港/台/国内节点"
                config["region_filter_enabled"] = True
                config["region_filter_mode"] = REGION_FILTER_MODE
                config["region_filter_label"] = REGION_FILTER_LABEL
                config["region_filter_warning"] = REGION_FILTER_WARNING
        except Exception:
            pass
    return config


def save_user_config(subscribe_url: str, listen_port: int, enabled: bool):
    """持久化用户配置"""
    try:
        existing = load_user_config()
        existing.update({
            "subscribe_url": subscribe_url,
            "listen_port": listen_port,
            "enabled": enabled,
        })
        with open(SINGBOX_PERSIST_PATH, "w", encoding="utf-8") as f:
            json.dump(existing, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"[sing-box] 保存配置失败: {e}")


def _build_node_key(node: dict) -> str:
    if not isinstance(node, dict):
        return ""
    node_type = str(node.get("type", "") or "").strip().lower()
    tag = str(node.get("tag", "") or "").strip()
    server = str(node.get("server", "") or "").strip().lower()
    server_port = str(node.get("server_port", "") or "").strip()
    if not any((node_type, tag, server, server_port)):
        return ""
    return "|".join([node_type, tag, server, server_port])



def _serialize_node(outbound: dict, reason: str = "", uri_preview: str = "") -> dict:
    row = {
        "tag": outbound.get("tag", ""),
        "type": outbound.get("type", ""),
        "server": outbound.get("server", ""),
        "server_port": outbound.get("server_port", ""),
    }
    row["node_key"] = _build_node_key(row)
    if reason:
        row["reason"] = reason
    if uri_preview:
        row["uri_preview"] = uri_preview
    return row



def _normalize_manual_disabled_nodes(nodes: list[dict] | None) -> list[dict]:
    normalized = {}
    for item in nodes or []:
        if not isinstance(item, dict):
            continue
        summary = _serialize_node(item, reason=item.get("reason", "已手动禁用"))
        node_key = summary.get("node_key", "")
        if not node_key:
            continue
        normalized[node_key] = summary
    return sorted(normalized.values(), key=lambda x: x.get("tag", ""))



def _get_manual_disabled_state(user_cfg: dict | None = None) -> tuple[set[str], list[dict]]:
    config = user_cfg if isinstance(user_cfg, dict) else load_user_config()
    manual_disabled_nodes = _normalize_manual_disabled_nodes(config.get("manual_disabled_nodes", []))
    manual_disabled_keys = {
        str(key).strip()
        for key in (config.get("manual_disabled_keys", []) or [])
        if str(key).strip()
    }
    if not manual_disabled_keys:
        manual_disabled_keys = {
            node.get("node_key", "")
            for node in manual_disabled_nodes
            if node.get("node_key", "")
        }
    return manual_disabled_keys, manual_disabled_nodes



def _split_manually_disabled_outbounds(outbounds: list[dict], manual_disabled_keys: set[str]) -> tuple[list[dict], list[dict]]:
    normalized_keys = {str(key).strip() for key in (manual_disabled_keys or set()) if str(key).strip()}
    allowed = []
    excluded = []
    for outbound in outbounds:
        node_key = _build_node_key(outbound)
        if node_key and node_key in normalized_keys:
            excluded.append(outbound)
        else:
            allowed.append(outbound)
    return allowed, excluded



def _is_blocked_region_tag(tag: str) -> bool:
    normalized = f" {str(tag or '').strip().lower()} "
    if not normalized.strip():
        return False
    for keyword in BLOCKED_REGION_KEYWORDS:
        key = keyword.lower()
        if any(ord(ch) > 127 for ch in key):
            if key in normalized:
                return True
            continue
        if len(key) <= 3:
            compact = normalized.replace("|", " ").replace("/", " ").replace("-", " ").replace("_", " ")
            tokens = compact.split()
            if key in tokens:
                return True
            continue
        if key in normalized:
            return True
    return False



def _split_region_filtered_outbounds(outbounds: list[dict]) -> tuple[list[dict], list[dict]]:
    allowed = []
    excluded = []
    for outbound in outbounds:
        if _is_blocked_region_tag(outbound.get("tag", "")):
            excluded.append(outbound)
        else:
            allowed.append(outbound)
    return allowed, excluded



def _serialize_uri_failure(uri: str, index: int, reason: str) -> dict:
    uri_preview = uri if len(uri) <= 120 else uri[:117] + "..."
    protocol = uri.split("://", 1)[0].lower() if "://" in uri else "unknown"
    return {
        "tag": f"parse-failed-{index + 1}",
        "type": protocol,
        "server": "",
        "server_port": "",
        "reason": reason or "解析失败",
        "uri_preview": uri_preview,
    }



def _serialize_nodes(outbounds: list[dict]) -> list[dict]:
    """提取适合前端展示的节点摘要。"""
    return [_serialize_node(ob) for ob in outbounds]



def _build_candidate_preview(nodes: list[dict] | None, limit: int = CANDIDATE_PREVIEW_LIMIT) -> tuple[list[str], str]:
    preview_limit = max(1, int(limit or CANDIDATE_PREVIEW_LIMIT))
    tags = []
    seen = set()
    for node in nodes or []:
        if not isinstance(node, dict):
            continue
        tag = str(node.get("tag", "") or "").strip()
        if not tag or tag in seen:
            continue
        seen.add(tag)
        tags.append(tag)

    preview_tags = tags[:preview_limit]
    if not tags:
        return [], "暂无候选节点"

    suffix = " ..." if len(tags) > len(preview_tags) else ""
    return preview_tags, f"{len(tags)} 个候选节点：{', '.join(preview_tags)}{suffix}"



def _build_refresh_diagnostics(
    total_uris: int = 0,
    parse_failed_nodes: list[dict] | None = None,
    quick_probe_failed_nodes: list[dict] | None = None,
    region_excluded_nodes: list[dict] | None = None,
    manual_disabled_nodes: list[dict] | None = None,
) -> dict:
    diagnostics = _build_default_diagnostics()
    diagnostics.update({
        "total_uris": total_uris,
        "parse_failed_count": len(parse_failed_nodes or []),
        "quick_probe_failed_count": len(quick_probe_failed_nodes or []),
        "region_excluded_count": len(region_excluded_nodes or []),
        "manual_disabled_count": len(manual_disabled_nodes or []),
        "parse_failed_nodes": parse_failed_nodes or [],
        "quick_probe_failed_nodes": quick_probe_failed_nodes or [],
        "region_excluded_nodes": region_excluded_nodes or [],
        "manual_disabled_nodes": manual_disabled_nodes or [],
    })
    return diagnostics



def save_refresh_stats(
    parsed_count: int,
    available_count: int,
    message: str,
    parsed_nodes: list[dict] | None = None,
    available_nodes: list[dict] | None = None,
    diagnostics: dict | None = None,
):
    """持久化最近一次订阅刷新结果，供 UI 展示解析数/可用数与诊断详情。"""
    try:
        existing = load_user_config()
        manual_disabled_keys, manual_disabled_nodes = _get_manual_disabled_state(existing)
        candidate_preview_tags, candidate_preview_text = _build_candidate_preview(available_nodes or [])
        existing.update(_build_default_diagnostics())
        existing.update({
            "parsed_count": parsed_count,
            "available_count": available_count,
            "last_refresh_message": message,
            "parsed_nodes": parsed_nodes or [],
            "available_nodes": available_nodes or [],
            "manual_disabled_keys": sorted(manual_disabled_keys),
            "manual_disabled_nodes": manual_disabled_nodes,
            "manual_disabled_count": len(manual_disabled_nodes),
            "urltest_probe_url": URLTEST_PROBE_URL,
            "candidate_preview_tags": candidate_preview_tags,
            "candidate_preview_text": candidate_preview_text,
        })
        if diagnostics:
            existing.update(diagnostics)
        with open(SINGBOX_PERSIST_PATH, "w", encoding="utf-8") as f:
            json.dump(existing, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"[sing-box] 保存刷新统计失败: {e}")



def set_manual_disabled_node(
    tag: str,
    node_type: str = "",
    server: str = "",
    server_port: str | int = "",
    disabled: bool = True,
) -> dict:
    candidate = {
        "tag": tag or "",
        "type": node_type or "",
        "server": server or "",
        "server_port": server_port or "",
    }
    node_key = _build_node_key(candidate)
    if not node_key:
        raise ValueError("节点标识不能为空")

    existing = load_user_config()
    manual_disabled_keys, manual_disabled_nodes = _get_manual_disabled_state(existing)
    manual_disabled_map = {
        node.get("node_key", ""): node
        for node in manual_disabled_nodes
        if node.get("node_key", "")
    }
    node_label = candidate["tag"] or f"{candidate['server']}:{candidate['server_port']}".strip(":") or node_key

    if disabled:
        manual_disabled_keys.add(node_key)
        manual_disabled_map[node_key] = _serialize_node(candidate, reason="已手动禁用")
        message = f"已手动禁用节点：{node_label}"
    else:
        manual_disabled_keys.discard(node_key)
        manual_disabled_map.pop(node_key, None)
        message = f"已恢复节点：{node_label}"

    existing["manual_disabled_keys"] = sorted(manual_disabled_keys)
    existing["manual_disabled_nodes"] = sorted(manual_disabled_map.values(), key=lambda x: x.get("tag", ""))
    existing["manual_disabled_count"] = len(existing["manual_disabled_nodes"])

    with open(SINGBOX_PERSIST_PATH, "w", encoding="utf-8") as f:
        json.dump(existing, f, ensure_ascii=False, indent=2)

    return {
        "success": True,
        "message": message,
        "node_key": node_key,
        "manual_disabled_count": existing["manual_disabled_count"],
        "manual_disabled_nodes": existing["manual_disabled_nodes"],
    }



def load_runtime_config() -> dict:
    """读取当前生效的 sing-box 配置文件。"""
    if not os.path.exists(SINGBOX_CONFIG_PATH):
        return {}
    try:
        with open(SINGBOX_CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}



def get_config_inbound_port() -> int:
    """从 sing-box 实际配置文件读取 mixed inbound 端口。"""
    cfg = load_runtime_config()
    for inbound in cfg.get("inbounds", []):
        if inbound.get("tag") == "proxy-in" or inbound.get("type") == "mixed":
            try:
                return int(inbound.get("listen_port", DEFAULT_LISTEN_PORT))
            except Exception:
                return DEFAULT_LISTEN_PORT
    return DEFAULT_LISTEN_PORT


# ========== 完整订阅刷新流程 ==========

def refresh_subscription(subscribe_url: str, listen_port: int = DEFAULT_LISTEN_PORT) -> dict:
    """
    完整订阅刷新流程：拉取 → 解析 → 生成配置 → 写入文件。
    返回结果摘要 dict。
    """
    # 拉取节点 URI 列表
    user_cfg = load_user_config()
    _, persisted_manual_disabled_nodes = _get_manual_disabled_state(user_cfg)
    uris = fetch_subscription(subscribe_url)
    total_uris = len(uris)
    if not uris:
        diagnostics = _build_refresh_diagnostics(
            total_uris=0,
            manual_disabled_nodes=persisted_manual_disabled_nodes,
        )
        save_refresh_stats(0, 0, "订阅链接返回 0 个节点", [], [], diagnostics=diagnostics)
        return {
            "success": False,
            "message": "订阅链接返回 0 个节点",
            "node_count": 0,
            "parsed_count": 0,
            "available_count": 0,
            "config_path": SINGBOX_CONFIG_PATH,
            **diagnostics,
        }

    # 解析为 sing-box outbound，并记录失败原因
    parsed_outbounds = []
    parse_failed_nodes = []
    for i, uri in enumerate(uris):
        ob, error = parse_uri_to_outbound_with_error(uri, i)
        if ob:
            parsed_outbounds.append(ob)
        else:
            parse_failed_nodes.append(_serialize_uri_failure(uri, i, error or "解析器返回空结果"))

    parsed_count = len(parsed_outbounds)
    region_allowed_outbounds, region_excluded_outbounds = _split_region_filtered_outbounds(parsed_outbounds)
    region_excluded_nodes = [
        _serialize_node(ob, reason=f"地区策略已排除：{REGION_FILTER_LABEL}")
        for ob in region_excluded_outbounds
    ]
    manual_disabled_keys, persisted_manual_disabled_nodes = _get_manual_disabled_state(user_cfg)
    manual_allowed_outbounds, manual_disabled_outbounds = _split_manually_disabled_outbounds(
        region_allowed_outbounds,
        manual_disabled_keys,
    )
    manual_disabled_map = {
        node.get("node_key", ""): node
        for node in persisted_manual_disabled_nodes
        if node.get("node_key", "")
    }
    for ob in manual_disabled_outbounds:
        summary = _serialize_node(ob, reason="已手动禁用")
        node_key = summary.get("node_key", "")
        if node_key:
            manual_disabled_map[node_key] = summary
    manual_disabled_nodes = sorted(manual_disabled_map.values(), key=lambda x: x.get("tag", ""))
    manual_disabled_hit_count = len(manual_disabled_outbounds)

    diagnostics = _build_refresh_diagnostics(
        total_uris=total_uris,
        parse_failed_nodes=parse_failed_nodes,
        region_excluded_nodes=region_excluded_nodes,
        manual_disabled_nodes=manual_disabled_nodes,
    )
    if not parsed_outbounds:
        message = f"拉取到 {total_uris} 个 URI，但全部解析失败"
        save_refresh_stats(0, 0, message, [], [], diagnostics=diagnostics)
        return {
            "success": False,
            "message": message,
            "node_count": 0,
            "parsed_count": 0,
            "available_count": 0,
            "config_path": SINGBOX_CONFIG_PATH,
            **diagnostics,
        }

    if not manual_allowed_outbounds:
        message = (
            f"成功解析 {parsed_count} / {total_uris} 个节点，"
            f"地区策略排除 {diagnostics['region_excluded_count']} 个，"
            f"手动禁用命中 {manual_disabled_hit_count} 个，"
            f"剩余候选为 0"
        )
        save_refresh_stats(
            parsed_count,
            0,
            message,
            _serialize_nodes(parsed_outbounds),
            [],
            diagnostics=diagnostics,
        )
        return {
            "success": False,
            "message": message,
            "node_count": 0,
            "parsed_count": parsed_count,
            "available_count": 0,
            "config_path": SINGBOX_CONFIG_PATH,
            "listen_port": listen_port,
            **diagnostics,
        }

    # 并发探测 TCP 连通性，过滤明显不可用节点，并保留失败原因
    available_outbounds = []
    quick_probe_failed_nodes = []
    with ThreadPoolExecutor(max_workers=min(32, max(8, len(manual_allowed_outbounds)))) as executor:
        future_map = {executor.submit(_probe_single_outbound_detail, ob): ob for ob in manual_allowed_outbounds}
        for future in as_completed(future_map):
            ob = future_map[future]
            try:
                probe_result = future.result()
            except Exception as e:
                probe_result = {"ok": False, "reason": _format_exception_reason(e)}
            if probe_result.get("ok"):
                available_outbounds.append(ob)
            else:
                quick_probe_failed_nodes.append(
                    _serialize_node(ob, reason=probe_result.get("reason", "TCP 快速探测失败"))
                )

    available_outbounds.sort(key=lambda x: x.get("tag", ""))
    quick_probe_failed_nodes.sort(key=lambda x: x.get("tag", ""))
    region_excluded_nodes.sort(key=lambda x: x.get("tag", ""))
    manual_disabled_nodes.sort(key=lambda x: x.get("tag", ""))
    available_count = len(available_outbounds)
    diagnostics = _build_refresh_diagnostics(
        total_uris=total_uris,
        parse_failed_nodes=parse_failed_nodes,
        quick_probe_failed_nodes=quick_probe_failed_nodes,
        region_excluded_nodes=region_excluded_nodes,
        manual_disabled_nodes=manual_disabled_nodes,
    )
    if not available_outbounds:
        message = (
            f"成功解析 {parsed_count} / {total_uris} 个节点，"
            f"地区策略排除 {diagnostics['region_excluded_count']} 个，"
            f"手动禁用命中 {manual_disabled_hit_count} 个，"
            f"解析失败 {diagnostics['parse_failed_count']} 个，"
            f"TCP 快速探测后 0 个可用"
        )
        save_refresh_stats(
            parsed_count,
            0,
            message,
            _serialize_nodes(parsed_outbounds),
            [],
            diagnostics=diagnostics,
        )
        return {
            "success": False,
            "message": message,
            "node_count": 0,
            "parsed_count": parsed_count,
            "available_count": 0,
            "config_path": SINGBOX_CONFIG_PATH,
            "listen_port": listen_port,
            **diagnostics,
        }

    # 生成配置
    config = generate_config(available_outbounds, listen_port)

    # 写入文件
    with open(SINGBOX_CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)

    message = (
        f"成功解析 {parsed_count} / {total_uris} 个节点，"
        f"地区策略排除 {diagnostics['region_excluded_count']} 个，"
        f"手动禁用命中 {manual_disabled_hit_count} 个，"
        f"TCP 快速探测通过 {available_count} 个，"
        f"解析失败 {diagnostics['parse_failed_count']} 个，"
        f"探测失败 {diagnostics['quick_probe_failed_count']} 个"
    )
    save_refresh_stats(
        parsed_count,
        available_count,
        message,
        _serialize_nodes(parsed_outbounds),
        _serialize_nodes(available_outbounds),
        diagnostics=diagnostics,
    )
    return {
        "success": True,
        "message": message,
        "node_count": available_count,
        "parsed_count": parsed_count,
        "available_count": available_count,
        "config_path": SINGBOX_CONFIG_PATH,
        "listen_port": listen_port,
        **diagnostics,
    }


# ========== sing-box 进程管理器 ==========

class SingBoxProcessManager:
    """sing-box 进程的生命周期管理器"""

    def __init__(self):
        self.process: Optional[subprocess.Popen] = None
        self.is_running: bool = False
        self.node_count: int = 0
        self.last_message: str = ""

    def start(self) -> dict:
        """启动 sing-box 进程"""
        # 检查可执行文件存在
        if not os.path.exists(SINGBOX_BIN):
            self.last_message = f"sing-box 可执行文件不存在: {SINGBOX_BIN}，请先下载并放到 singbox/ 目录"
            return {
                "success": False,
                "message": self.last_message,
            }

        # 检查配置文件存在
        if not os.path.exists(SINGBOX_CONFIG_PATH):
            self.last_message = "配置文件不存在，请先刷新订阅"
            return {
                "success": False,
                "message": self.last_message,
            }

        # 如果已经在运行，先停止
        if self.is_running and self.process and self.process.poll() is None:
            self.stop()

        # 检查端口是否被占用：以实际配置文件中的 inbound 端口为准
        user_cfg = load_user_config()
        persisted_port = user_cfg.get("listen_port", DEFAULT_LISTEN_PORT)
        config_port = get_config_inbound_port()
        port = config_port
        self._kill_on_port(port)

        cmd = [SINGBOX_BIN, "run", "-c", SINGBOX_CONFIG_PATH]

        try:
            stdout_f = open(SINGBOX_STDOUT_LOG, "ab")
            stderr_f = open(SINGBOX_STDERR_LOG, "ab")
            self.process = subprocess.Popen(
                cmd,
                stdout=stdout_f,
                stderr=stderr_f,
                cwd=SINGBOX_DIR,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
            )
            stdout_f.close()
            stderr_f.close()

            import time
            time.sleep(1.2)
            if self.process.poll() is not None:
                self.is_running = False
                self.last_message = f"sing-box 进程启动后立即退出，退出码: {self.process.poll()}"
                stderr_tail = self._read_log_tail(SINGBOX_STDERR_LOG)
                stdout_tail = self._read_log_tail(SINGBOX_STDOUT_LOG)
                detail = stderr_tail or stdout_tail
                if detail:
                    self.last_message += f"；日志: {detail}"
                return {"success": False, "message": self.last_message}

            if not self._wait_port_ready(port, timeout=6):
                self.is_running = False
                self.last_message = f"sing-box 进程已启动，但端口 127.0.0.1:{port} 未就绪"
                stderr_tail = self._read_log_tail(SINGBOX_STDERR_LOG)
                stdout_tail = self._read_log_tail(SINGBOX_STDOUT_LOG)
                detail = stderr_tail or stdout_tail
                if detail:
                    self.last_message += f"；日志: {detail}"
                try:
                    self.stop()
                except Exception:
                    pass
                return {"success": False, "message": self.last_message}

            self.is_running = True

            # 读取配置中的节点数
            try:
                with open(SINGBOX_CONFIG_PATH, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                    # 统计非系统类型的 outbound 数量
                    sys_types = {"urltest", "selector", "direct", "block", "dns"}
                    self.node_count = sum(
                        1 for o in cfg.get("outbounds", [])
                        if o.get("type") not in sys_types
                    )
            except Exception:
                pass

            self.last_message = (
                f"sing-box 已启动，监听 127.0.0.1:{port}，{self.node_count} 个节点"
                f"（持久化端口={persisted_port}，配置端口={config_port}）"
            )
            return {
                "success": True,
                "message": self.last_message,
            }
        except Exception as e:
            self.is_running = False
            self.last_message = f"启动失败: {e}"
            return {"success": False, "message": self.last_message}

    def stop(self) -> dict:
        """停止 sing-box 进程"""
        if not self.process or self.process.poll() is not None:
            self.is_running = False
            self.last_message = "sing-box 未在运行"
            return {"success": False, "message": self.last_message}

        try:
            if os.name == "nt":
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(self.process.pid)],
                    capture_output=True,
                )
            else:
                os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
            self.process = None
            self.is_running = False
            self.last_message = "sing-box 已停止"
            return {"success": True, "message": self.last_message}
        except Exception as e:
            self.last_message = f"停止失败: {e}"
            return {"success": False, "message": self.last_message}

    def get_status(self) -> dict:
        """获取当前 sing-box 运行状态"""
        if self.process and self.process.poll() is None:
            self.is_running = True
        else:
            self.is_running = False

        user_cfg = load_user_config()
        available_count = user_cfg.get("available_count", 0)
        parsed_count = user_cfg.get("parsed_count", 0)
        _, manual_disabled_nodes = _get_manual_disabled_state(user_cfg)
        candidate_preview_tags, candidate_preview_text = _build_candidate_preview(user_cfg.get("available_nodes", []))
        diagnostics = _build_default_diagnostics()
        diagnostics.update({
            "total_uris": user_cfg.get("total_uris", 0),
            "parse_failed_count": user_cfg.get("parse_failed_count", 0),
            "quick_probe_failed_count": user_cfg.get("quick_probe_failed_count", 0),
            "region_excluded_count": user_cfg.get("region_excluded_count", 0),
            "manual_disabled_count": len(manual_disabled_nodes),
            "parse_failed_nodes": user_cfg.get("parse_failed_nodes", []),
            "quick_probe_failed_nodes": user_cfg.get("quick_probe_failed_nodes", []),
            "region_excluded_nodes": user_cfg.get("region_excluded_nodes", []),
            "manual_disabled_nodes": manual_disabled_nodes,
            "availability_basis": user_cfg.get("availability_basis", DIAGNOSTIC_AVAILABLE_BASIS),
            "availability_basis_label": user_cfg.get("availability_basis_label", DIAGNOSTIC_AVAILABLE_LABEL),
            "xai_probe_enabled": user_cfg.get("xai_probe_enabled", False),
            "target_url": user_cfg.get("target_url", XAI_SIGNUP_URL),
            "urltest_probe_url": user_cfg.get("urltest_probe_url", URLTEST_PROBE_URL) or URLTEST_PROBE_URL,
            "candidate_preview_tags": user_cfg.get("candidate_preview_tags", candidate_preview_tags) or candidate_preview_tags,
            "candidate_preview_text": user_cfg.get("candidate_preview_text", candidate_preview_text) or candidate_preview_text,
            "diagnostic_warning": user_cfg.get("diagnostic_warning", DIAGNOSTIC_WARNING),
            "region_filter_enabled": user_cfg.get("region_filter_enabled", True),
            "region_filter_mode": user_cfg.get("region_filter_mode", REGION_FILTER_MODE),
            "region_filter_label": user_cfg.get("region_filter_label", REGION_FILTER_LABEL),
            "region_filter_warning": user_cfg.get("region_filter_warning", REGION_FILTER_WARNING),
        })
        persisted_port = user_cfg.get("listen_port", DEFAULT_LISTEN_PORT)
        config_port = get_config_inbound_port()
        return {
            "running": self.is_running,
            "node_count": self.node_count or available_count,
            "parsed_count": parsed_count,
            "available_count": available_count,
            "listen_port": persisted_port,
            "persisted_listen_port": persisted_port,
            "config_listen_port": config_port,
            "port_consistent": persisted_port == config_port,
            "parsed_nodes": user_cfg.get("parsed_nodes", []),
            "available_nodes": user_cfg.get("available_nodes", []),
            "last_refresh_message": user_cfg.get("last_refresh_message", ""),
            **diagnostics,
            "subscribe_url": user_cfg.get("subscribe_url", ""),
            "enabled": user_cfg.get("enabled", False),
            "bin_exists": os.path.exists(SINGBOX_BIN),
            "config_exists": os.path.exists(SINGBOX_CONFIG_PATH),
            "config_path": SINGBOX_CONFIG_PATH,
            "stdout_log": SINGBOX_STDOUT_LOG,
            "stderr_log": SINGBOX_STDERR_LOG,
            "last_message": self.last_message or user_cfg.get("last_refresh_message", ""),
        }

    def get_log_tail(self) -> dict:
        stdout_tail = self._read_log_tail(SINGBOX_STDOUT_LOG)
        stderr_tail = self._read_log_tail(SINGBOX_STDERR_LOG)
        return {
            "stdout_log_tail": stdout_tail,
            "stderr_log_tail": stderr_tail,
            "stdout": stdout_tail,
            "stderr": stderr_tail,
        }

    def _read_log_tail(self, path: str, max_bytes: int = 4000) -> str:
        try:
            if not os.path.exists(path):
                return ""
            with open(path, "rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(max(0, size - max_bytes))
                data = f.read().decode("utf-8", errors="replace")
                return data.strip()[-1500:]
        except Exception:
            return ""

    def _wait_port_ready(self, port: int, timeout: float = 6) -> bool:
        import socket
        import time

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    if s.connect_ex(("127.0.0.1", port)) == 0:
                        return True
            except Exception:
                pass
            time.sleep(0.25)
        return False

    def _kill_on_port(self, port: int):
        """检测并杀掉占用指定端口的进程"""
        import socket
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    print(f"[sing-box] 端口 {port} 被占用，正在清理...")
                    if os.name == "nt":
                        try:
                            out = subprocess.check_output(
                                f'netstat -ano | findstr ":{port}" | findstr "LISTENING"',
                                shell=True, text=True,
                            )
                            for line in out.strip().split("\n"):
                                parts = line.split()
                                if parts:
                                    pid = parts[-1]
                                    subprocess.run(["taskkill", "/F", "/T", "/PID", pid], capture_output=True)
                        except Exception:
                            pass
                    import time
                    time.sleep(1)
        except Exception:
            pass


# ========== sing-box 二进制自动下载 ==========

def download_singbox(target_version: str = "1.11.7") -> dict:
    """
    自动下载 sing-box 二进制文件到 singbox/ 目录。
    支持 Windows amd64 和 Linux amd64。
    """
    # 确保目录存在
    os.makedirs(SINGBOX_DIR, exist_ok=True)

    if os.path.exists(SINGBOX_BIN):
        return {"success": True, "message": "sing-box 已存在，跳过下载"}

    system = platform.system().lower()
    arch = platform.machine().lower()

    # 映射架构名
    if arch in ("x86_64", "amd64"):
        arch_name = "amd64"
    elif arch in ("aarch64", "arm64"):
        arch_name = "arm64"
    else:
        return {"success": False, "message": f"不支持的架构: {arch}"}

    if system == "windows":
        suffix = "windows-" + arch_name
        ext = ".zip"
    elif system == "linux":
        suffix = "linux-" + arch_name
        ext = ".tar.gz"
    elif system == "darwin":
        suffix = "darwin-" + arch_name
        ext = ".tar.gz"
    else:
        return {"success": False, "message": f"不支持的系统: {system}"}

    filename = f"sing-box-{target_version}-{suffix}"
    url = f"https://github.com/SagerNet/sing-box/releases/download/v{target_version}/{filename}{ext}"

    print(f"[sing-box] 正在下载: {url}")
    download_path = os.path.join(SINGBOX_DIR, f"{filename}{ext}")

    try:
        with httpx.Client(timeout=120, follow_redirects=True) as client:
            with client.stream("GET", url) as r:
                r.raise_for_status()
                with open(download_path, "wb") as f:
                    for chunk in r.iter_bytes(chunk_size=8192):
                        f.write(chunk)

        # 解压
        if ext == ".zip":
            with zipfile.ZipFile(download_path, "r") as zf:
                zf.extractall(SINGBOX_DIR)
        else:
            import tarfile
            with tarfile.open(download_path, "r:gz") as tf:
                tf.extractall(SINGBOX_DIR)

        # 移动二进制文件到 singbox/ 根目录
        inner_dir = os.path.join(SINGBOX_DIR, filename)
        bin_name = "sing-box.exe" if system == "windows" else "sing-box"
        inner_bin = os.path.join(inner_dir, bin_name)
        if os.path.exists(inner_bin):
            shutil.move(inner_bin, SINGBOX_BIN)

        # 清理解压残留
        if os.path.exists(inner_dir):
            shutil.rmtree(inner_dir, ignore_errors=True)
        if os.path.exists(download_path):
            os.remove(download_path)

        # Linux/macOS 设置可执行权限
        if system != "windows":
            os.chmod(SINGBOX_BIN, 0o755)

        return {"success": True, "message": f"sing-box v{target_version} 下载完成"}

    except Exception as e:
        return {"success": False, "message": f"下载失败: {e}"}


# ========== 全局单例 ==========
singbox_pm = SingBoxProcessManager()
