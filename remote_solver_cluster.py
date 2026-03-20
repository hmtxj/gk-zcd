from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass
from typing import Any, Callable

import httpx


SIGNUP_URL = "https://accounts.x.ai/sign-up"
DEFAULT_TOKEN_TIMEOUT = 90
DEFAULT_QUEUE_WAIT_TIMEOUT = 5.0
DEFAULT_POLL_INTERVAL = 2.0
DEFAULT_BREAKER_SECONDS = 15.0
DEFAULT_BREAKER_THRESHOLD = 2
DEFAULT_TOKEN_MAX_AGE = 110.0


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
    online: bool = False
    available_browsers: int = 0
    raw_available_browsers: int = 0
    reserved_slots: int = 0
    total_browsers: int = 0
    tracked_tasks: int = 0
    in_flight_total: int = 0
    in_flight_prefetch: int = 0
    in_flight_direct: int = 0
    consecutive_failures: int = 0
    success_count: int = 0
    fail_count: int = 0
    rejected_count: int = 0
    total_solve_time: float = 0.0
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

    def snapshot(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "online": self.online,
            "available_browsers": self.available_browsers,
            "raw_available_browsers": self.raw_available_browsers,
            "reserved_slots": self.reserved_slots,
            "total_browsers": self.total_browsers,
            "tracked_tasks": self.tracked_tasks,
            "in_flight_total": self.in_flight_total,
            "in_flight_prefetch": self.in_flight_prefetch,
            "in_flight_direct": self.in_flight_direct,
            "consecutive_failures": self.consecutive_failures,
            "success_count": self.success_count,
            "fail_count": self.fail_count,
            "rejected_count": self.rejected_count,
            "avg_solve_time": round(self.avg_solve_time, 3),
            "success_rate": round(self.success_rate, 4),
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

        self._state_lock = asyncio.Lock()
        self._prefetch_stop = asyncio.Event()
        self._prefetch_task: asyncio.Task | None = None
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

        self._reload_nodes()

    def _log(self, message: str):
        print(message)

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
            data = resp.json()
            if resp.status_code >= 400:
                raise RuntimeError(f"HTTP {resp.status_code}: {data}")
            async with self._state_lock:
                state = self._nodes.setdefault(node_url, RemoteSolverNodeState(url=node_url))
                state.online = True
                state.available_browsers = max(int(data.get("available_browsers", 0) or 0), 0)
                state.raw_available_browsers = max(int(data.get("raw_available_browsers", state.available_browsers) or 0), 0)
                state.reserved_slots = max(int(data.get("reserved_slots", 0) or 0), 0)
                state.total_browsers = max(int(data.get("total_browsers", 0) or 0), 0)
                state.tracked_tasks = max(int(data.get("tracked_tasks", 0) or 0), 0)
                state.last_stage = str(data.get("last_stage") or state.last_stage or "")
                state.last_message = str(data.get("message") or state.last_message or "")
                state.last_status = "healthy"
                state.last_http_status = resp.status_code
                state.last_seen_at = now
                state.last_error = ""
        except Exception as e:
            async with self._state_lock:
                state = self._nodes.setdefault(node_url, RemoteSolverNodeState(url=node_url))
                state.online = False
                state.available_browsers = 0
                state.last_http_status = 0
                state.last_error = str(e)
                state.last_status = "offline"
                state.last_seen_at = now

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
            self._log("[调度] ❌ 当前没有可用于 direct path 的 Solver 节点")
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
            total_capacity = sum(max(state.available_browsers - state.in_flight_total, 0) for state in states if state.online and not state.breaker_active)
            total_browsers = sum(max(state.total_browsers, 0) for state in states if state.online)

        target = min(self._max_queue_target, max(total_capacity - self._reserve_for_direct, 0))
        if total_browsers <= 2:
            target = min(target, 1)
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
            if not state.online:
                continue
            if state.breaker_active:
                continue
            if state.available_browsers <= 0:
                continue
            if request_kind == "prefetch" and state.in_flight_prefetch >= self._per_node_prefetch:
                continue
            if state.effective_capacity <= 0:
                continue
            candidates.append(state)

        random.shuffle(candidates)
        candidates.sort(
            key=lambda state: (
                -state.effective_capacity,
                -state.available_browsers,
                state.in_flight_total,
                -state.success_rate,
                state.avg_solve_time if state.avg_solve_time > 0 else 9999,
            )
        )
        return [state.url for state in candidates]

    async def _reserve_dispatch_slot(self, node_url: str, request_kind: str) -> bool:
        async with self._state_lock:
            state = self._nodes.get(node_url)
            if not state:
                return False
            if not state.online or state.breaker_active:
                return False
            if state.available_browsers <= 0:
                return False
            if state.effective_capacity <= 0:
                return False
            if request_kind == "prefetch" and state.in_flight_prefetch >= self._per_node_prefetch:
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
            state.last_status = status
            state.last_stage = stage
            state.last_message = message
            state.last_error = message
            state.last_http_status = http_status
            state.fail_count += 1
            state.consecutive_failures += 1
            state.last_seen_at = time.time()
            if trigger_breaker or state.consecutive_failures >= self.breaker_threshold:
                state.breaker_until = time.time() + self.breaker_seconds

    async def _mark_node_rejected(self, node_url: str, status: str, stage: str, message: str, http_status: int):
        async with self._state_lock:
            state = self._nodes.setdefault(node_url, RemoteSolverNodeState(url=node_url))
            state.last_status = status
            state.last_stage = stage
            state.last_message = message
            state.last_error = message
            state.last_http_status = http_status
            state.rejected_count += 1
            state.last_seen_at = time.time()
            if http_status >= 500:
                state.breaker_until = time.time() + min(self.breaker_seconds, 8.0)

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
            data = resp.json()
            if resp.status_code >= 400:
                message = str(data.get("message") or data.get("error") or data)
                await self._mark_node_rejected(node_url, status="busy", stage="rejected", message=message, http_status=resp.status_code)
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
            node_snapshots = [state.snapshot() for state in self._nodes.values()]
            in_flight_prefetch_total = sum(state.in_flight_prefetch for state in self._nodes.values())
            in_flight_prefetch_by_node = {
                state.url: state.in_flight_prefetch
                for state in self._nodes.values()
                if state.in_flight_prefetch > 0
            }

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
            "nodes": node_snapshots,
        }
