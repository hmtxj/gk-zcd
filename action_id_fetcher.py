"""
Action ID 自动获取模块

从 accounts.x.ai/sign-up 页面的 JS chunk 文件中，
自动提取最新的 Server Action ID 和 Turnstile sitekey。

Next.js 通过 createServerReference() 在 JS chunk 中注册 Server Action，
注册用的 Action ID 所在 chunk 会同时包含 createUser、turnstile 等关键词。

用法：
  命令行一键获取：  python action_id_fetcher.py
  代码中异步调用：  action_id, sitekey = await fetch_action_id(session)
  代码中同步调用：  action_id, sitekey = fetch_action_id_sync()
"""
import sys
import io
import re
import os
import asyncio

# Windows 控制台 UTF-8 兼容
if sys.platform == "win32" and hasattr(sys.stdout, "buffer"):
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
    except Exception:
        pass

from curl_cffi.requests import AsyncSession as CurlAsyncSession
from curl_cffi.requests import Session as CurlSession

BASE = "https://accounts.x.ai"

# 注册用 chunk 必须包含的关键词（至少匹配 2 个才认定为注册 chunk）
_SIGNUP_KEYWORDS = [
    "createUser",
    "emailValidationCode",
    "turnstile",
    "clearTextPassword",
    "createUserAndSession",
]

# 从 createServerReference 调用中提取 Action ID
# JS 压缩后格式可能是 createServerReference)("hex_id" 或 createServerReference("hex_id"
_RE_SERVER_REF = re.compile(r'createServerReference\)?\(\s*"([a-f0-9]{40,64})"')

# 提取 sitekey（Cloudflare Turnstile 格式：0x4AAAAAAA 开头）
_RE_SITEKEY = re.compile(r'(0x4[Aa]{6,}[a-zA-Z0-9]+)')

# 提取页面中引用的 JS chunk 路径
_RE_SCRIPT_SRC = re.compile(r'<script[^>]+src="([^"]*/_next/static/chunks/[^"]+)"')


def _pick_signup_action(chunks_data: list[tuple[str, str]]) -> tuple[str, str]:
    """
    从多个 JS chunk 的 (url, content) 列表中，
    找到注册用 chunk 并返回 (action_id, sitekey)。
    
    策略：包含注册关键词最多的 chunk → 取其中的 Action ID
    """
    best_action_id = ""
    best_sitekey = ""
    best_score = 0

    for url, js_content in chunks_data:
        js_lower = js_content.lower()
        
        # 计算与注册相关的关键词命中数
        score = sum(1 for kw in _SIGNUP_KEYWORDS if kw.lower() in js_lower)
        if score < 2:
            continue  # 命中不足 2 个，不是注册 chunk

        # 提取 Action ID
        action_ids = _RE_SERVER_REF.findall(js_content)
        if not action_ids:
            continue

        # 提取 sitekey
        sitekeys = _RE_SITEKEY.findall(js_content)

        if score > best_score:
            best_score = score
            best_action_id = action_ids[0]
            best_sitekey = sitekeys[0] if sitekeys else ""

    return best_action_id, best_sitekey


async def fetch_action_id(
    session: CurlAsyncSession | None = None,
    impersonate: str = "chrome120",
    verbose: bool = True,
) -> tuple[str, str]:
    """
    异步获取最新的注册 Action ID 和 sitekey。
    
    返回 (action_id, sitekey)，获取失败则返回空字符串。
    """
    own_session = session is None
    if own_session:
        session = CurlAsyncSession(impersonate=impersonate)

    try:
        # 第一步：获取 sign-up 页面 HTML
        if verbose:
            print("  🔍 [深度扫描] 正在获取 sign-up 页面...")
        r = await session.get(f"{BASE}/sign-up", timeout=15)
        if r.status_code != 200:
            if verbose:
                print(f"  ⚠️ [深度扫描] 页面返回 HTTP {r.status_code}")
            return "", ""
        
        html = r.text

        # 检测 Cloudflare 拦截
        if "Attention Required" in html or "cf-challenge-running" in html:
            if verbose:
                print("  ⚠️ [深度扫描] 检测到 Cloudflare Challenge，页面被拦截")
                print(f"  📄 响应前 300 字符: {html[:300]}")
            return "", ""

        # 第二步：提取所有 JS chunk URL
        script_srcs = _RE_SCRIPT_SRC.findall(html)
        if verbose:
            print(f"  📦 [深度扫描] 发现 {len(script_srcs)} 个 JS chunk 文件")

        if not script_srcs:
            if verbose:
                print("  ⚠️ [深度扫描] 未找到任何 JS chunk 文件")
            return "", ""

        # 第三步：并发请求所有 JS chunk
        chunks_data = []

        async def _fetch_chunk(src: str):
            url = src if src.startswith("http") else f"{BASE}{src}"
            try:
                cr = await session.get(url, timeout=10)
                return (src, cr.text)
            except Exception:
                return (src, "")

        tasks = [_fetch_chunk(src) for src in script_srcs]
        results = await asyncio.gather(*tasks)
        chunks_data = [(src, text) for src, text in results if text]

        if verbose:
            print(f"  📥 [深度扫描] 成功下载 {len(chunks_data)}/{len(script_srcs)} 个 chunk")

        # 第四步：从 chunk 中提取注册 Action ID
        action_id, sitekey = _pick_signup_action(chunks_data)

        if verbose:
            if action_id:
                print(f"  🔑 [深度扫描] Action ID: {action_id}")
            else:
                print("  ❌ [深度扫描] 未找到注册用 Action ID")
            if sitekey:
                print(f"  🔑 [深度扫描] sitekey: {sitekey}")

        return action_id, sitekey

    except Exception as e:
        if verbose:
            print(f"  ❌ [深度扫描] 异常: {e}")
        return "", ""
    finally:
        if own_session:
            await session.close()


def fetch_action_id_sync(impersonate: str = "chrome120", verbose: bool = True) -> tuple[str, str]:
    """
    同步获取最新的注册 Action ID 和 sitekey（内部启动事件循环）。
    """
    with CurlSession(impersonate=impersonate) as session:
        if verbose:
            print("🔍 [深度扫描] 正在获取 sign-up 页面...")
        r = session.get(f"{BASE}/sign-up", timeout=15)
        if r.status_code != 200:
            if verbose:
                print(f"⚠️ [深度扫描] 页面返回 HTTP {r.status_code}")
            return "", ""
        
        html = r.text

        if "Attention Required" in html or "cf-challenge-running" in html:
            if verbose:
                print("⚠️ [深度扫描] 检测到 Cloudflare Challenge")
            return "", ""

        script_srcs = _RE_SCRIPT_SRC.findall(html)
        if verbose:
            print(f"📦 [深度扫描] 发现 {len(script_srcs)} 个 JS chunk 文件")

        chunks_data = []
        for src in script_srcs:
            url = src if src.startswith("http") else f"{BASE}{src}"
            try:
                cr = session.get(url, timeout=10)
                chunks_data.append((src, cr.text))
            except Exception:
                continue

        if verbose:
            print(f"📥 [深度扫描] 成功下载 {len(chunks_data)}/{len(script_srcs)} 个 chunk")

        action_id, sitekey = _pick_signup_action(chunks_data)

        if verbose:
            if action_id:
                print(f"🔑 [深度扫描] Action ID: {action_id}")
            else:
                print("❌ [深度扫描] 未找到注册用 Action ID")
            if sitekey:
                print(f"🔑 [深度扫描] sitekey: {sitekey}")

        return action_id, sitekey


# ========== 命令行一键调用 ==========
if __name__ == "__main__":
    print("=" * 60)
    print(" Action ID 自动获取工具")
    print("=" * 60)
    print()
    
    action_id, sitekey = fetch_action_id_sync()
    
    print()
    print("=" * 60)
    if action_id:
        print(f"✅ 注册用 Action ID: {action_id}")
    else:
        print("❌ 未能获取 Action ID")
    if sitekey:
        print(f"✅ Turnstile sitekey:  {sitekey}")
    else:
        print("⚠️ 未找到 sitekey（使用默认值即可）")
    print("=" * 60)
