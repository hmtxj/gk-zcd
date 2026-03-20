"""
Cloudflare Turnstile Token 异步获取器

调用本地 Turnstile Solver 服务获取 token。
支持同步和异步两种调用方式。

API 流程:
  1. GET /turnstile?url=<url>&sitekey=<sitekey>  → 创建解题任务，返回 task_id
  2. 轮询 GET /result?task_id=<task_id>           → 等待 token 返回
"""
import asyncio
import httpx

import os
import random

# 默认 x.ai 注册页的 Turnstile 配置
SIGNUP_URL = "https://accounts.x.ai/sign-up"
SITE_KEY = "0x4AAAAAAAhr9JGVDZbrZOo0"
# 最大等待时间
DEFAULT_TIMEOUT = 90

# 节点配置中心文件（优先读取环境变量，其次本地文件；纯远程模式不再默认回退 localhost）
SOLVER_NODES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "solver_nodes.txt")


def get_solver_nodes() -> list[str]:
    """读取可用的远程 Solver 节点列表（优先级：环境变量 > 文件）。"""
    nodes = []

    # 优先从环境变量读取（云端部署场景，逗号分隔多个节点）
    env_nodes = os.environ.get("SOLVER_NODES", "").strip()
    if env_nodes:
        for raw in env_nodes.split(","):
            addr = raw.strip()
            if not addr:
                continue
            if not addr.startswith("http"):
                addr = f"http://{addr}"
            nodes.append(addr.rstrip("/"))
        if nodes:
            print(f"[Turnstile] 从环境变量 SOLVER_NODES 读取到 {len(nodes)} 个节点")
            return nodes

    # 其次从本地配置文件读取
    if os.path.exists(SOLVER_NODES_FILE):
        try:
            with open(SOLVER_NODES_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        if not line.startswith("http"):
                            line = f"http://{line}"
                        nodes.append(line.rstrip("/"))
        except Exception as e:
            print(f"[Turnstile] 读取 solver_nodes.txt 失败: {e}")

    remote_nodes = [n for n in nodes if "127.0.0.1" not in n.lower() and "localhost" not in n.lower()]
    if len(remote_nodes) != len(nodes):
        print(f"[Turnstile] 已过滤 {len(nodes) - len(remote_nodes)} 个本地节点，仅保留远程 Solver")
    return remote_nodes

async def get_turnstile_token_async(
    client: httpx.AsyncClient | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    sitekey: str | None = None,
    # 保留 solver_url 参数为了向后兼容，但默认使用 None，优先从配置文件加载
    solver_url: str | None = None,
) -> str | None:
    """
    异步获取 Turnstile token。

    参数:
        client: 复用的 httpx.AsyncClient（为空时临时创建）
        timeout: 超时秒数
        sitekey: 动态 sitekey（为空时使用默认值）
        solver_url: Solver 服务地址

    返回:
        Turnstile token 字符串，失败返回 None
    """
    use_sitekey = sitekey or SITE_KEY
    own_client = client is None
    if own_client:
        client = httpx.AsyncClient(timeout=10)

    # 1. 获取并选择 Solver 节点 (支持集群/多台机器)
    nodes = get_solver_nodes() if not solver_url else [solver_url.rstrip("/")]
    if not solver_url:
        nodes = [n for n in nodes if "127.0.0.1" not in n.lower() and "localhost" not in n.lower()]
    if not nodes:
        print("[Turnstile] ❌ 未配置任何远程 Solver 节点，请设置 SOLVER_NODES 或 solver_nodes.txt")
        return None

    # 随机打乱节点列表，实现基础的负载均衡
    random.shuffle(nodes)
    
    selected_node = None
    task_id = None
    
    print(f"[Turnstile] 即将从 {len(nodes)} 个节点中分配解题任务...")

    # 2. 遍历节点池，尝试创建任务 (Failover 容灾机制)
    for target_url in nodes:
        try:
            # 健康检查与建立任务可以在一次请求完成（如果 Solver 创建任务接口很快）
            # 或者先检查健康状态，这取决于 Solver 集群的网络质量
            health = await client.get(f"{target_url}/", timeout=3)
            info = health.json()
            available = max(int(info.get("available_browsers", 0) or 0), 0)
            total = info.get("total_browsers", "?")
            print(f"[Turnstile] 节点 [{target_url}] 在线，可用浏览器: {available}/{total}")

            if available <= 0:
                print(f"[Turnstile] ⏭️ 节点 [{target_url}] 当前无空闲浏览器，跳过派单")
                continue

            # 尝试在选定的节点上创建解题任务
            resp = await client.get(f"{target_url}/turnstile", params={
                "url": SIGNUP_URL,
                "sitekey": use_sitekey,
            }, timeout=5)

            data = resp.json()
            task_id = data.get("task_id")

            if resp.status_code >= 400:
                print(f"[Turnstile] ⚠️ 节点 [{target_url}] 拒绝接单: HTTP {resp.status_code} {data}")
                continue

            if task_id:
                selected_node = target_url
                print(f"[Turnstile] ✅ 任务已分配至节点 [{selected_node}], TaskID: {task_id[:8]}...")
                break # 成功分配，跳出重试循环
            else:
                print(f"[Turnstile] ⚠️ 节点 [{target_url}] 拒绝/无法创建任务: {data}")
                
        except Exception as e:
            print(f"[Turnstile] ❌ 节点 [{target_url}] 宕机或超时: {e}")
            continue # 自动切换下一个节点

    if not selected_node or not task_id:
        print(f"[Turnstile] ❌ 所有 {len(nodes)} 个 Solver 节点均不可用或任务创建彻底失败！")
        return None

    try:
        # 3. 异步轮询等待结果 (定向到被分配的节点)
        print(f"[Turnstile] 在节点 [{selected_node}] 等待解题结果（最多 {timeout}s）...")
        elapsed = 0
        poll_interval = 2

        while elapsed < timeout:
            try:
                resp = await client.get(f"{selected_node}/result", params={
                    "task_id": task_id
                }, timeout=5)
                result = resp.json()
                status = result.get("status", "")
                stage = result.get("stage", "")
                message = result.get("message") or result.get("detail") or ""

                if status == "completed":
                    token = result.get("solution", {}).get("token", "")
                    if token and token != "CAPTCHA_FAIL":
                        solve_time = result.get("elapsed_time", round(elapsed, 1))
                        print(f"[Turnstile] ✅ 成功从 [{selected_node}] 获取 Token! 长度: {len(token)}, 耗时: {solve_time}s")
                        return token
                    else:
                        print(f"[Turnstile] ❌ 节点 [{selected_node}] 返回了失败的 Token")
                        return None

                if status in {"failed", "busy"}:
                    detail_text = ""
                    if stage:
                        detail_text += f" 阶段={stage}"
                    if message:
                        detail_text += f" 原因={message}"
                    print(f"[Turnstile] ❌ 节点 [{selected_node}] 宣布解题失败。{detail_text}".rstrip())
                    return None

                if int(elapsed) % 10 == 0:
                    stage_text = f", 阶段={stage}" if stage else ""
                    msg_text = f", 信息={message}" if message else ""
                    print(f"[Turnstile] ⏳ 节点 [{selected_node}] 运算中... ({int(elapsed)}s / {timeout}s{stage_text}{msg_text})")

            except Exception as e:
                print(f"[Turnstile] ⚠️ 轮询节点 [{selected_node}] 时遇到网络波动: {e}")

            await asyncio.sleep(poll_interval)
            elapsed += poll_interval

        print(f"[Turnstile] ❌ 从节点 [{selected_node}] 获取 Token 超时 ({timeout}s)")
        return None

    finally:
        if own_client:
            await client.aclose()


# 同步兼容wrapper（供旧代码调用）
def get_turnstile_token(proxy: str | None = None, timeout: int = DEFAULT_TIMEOUT, sitekey: str | None = None) -> str | None:
    """同步版本（兼容旧代码）"""
    return asyncio.run(get_turnstile_token_async(timeout=timeout, sitekey=sitekey))


# ========== 独立运行测试 ==========
if __name__ == "__main__":
    print("=" * 50)
    print("Turnstile Token 获取器 - 独立测试（集群/异步模式）")
    
    nodes = get_solver_nodes()
    print(f"当前加载了 {len(nodes)} 个远程 Solver 节点:")
    for i, n in enumerate(nodes):
        print(f"  {i+1}. {n}")
    print("=" * 50)

    async def _test():
        token = await get_turnstile_token_async()
        if token:
            print(f"\n🎉 Token: {token[:80]}...")
            print(f"   长度: {len(token)}")
        else:
            print("\n❌ 获取失败")

    asyncio.run(_test())
