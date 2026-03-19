"""
内置 im-mail 兼容客户端。

用于替代历史上放在仓库外部目录中的 `im_mail_client` 模块，
保持与现有调用方式兼容：
- `AsyncImMailClient(api_base, api_auth_token, client)`
- `await create_mailbox()`
- `await wait_for_code(timeout=120)`

实现策略：
1. 兼容多种常见 REST 路径风格；
2. 优先从现有 im-mail API 创建邮箱；
3. 若本地 im-mail 服务不可用，则自动回退到 mail.tm 创建真实收件箱；
4. 轮询多种消息/验证码接口，并从 JSON/文本中提取 6 位验证码；
5. 所有在线后备都失败时，最后才回退为本地生成 catch-all 邮箱地址。
"""

from __future__ import annotations

import asyncio
import html
import json
import os
import random
import re
import string
import time
from typing import Any
from urllib.parse import quote_plus

import httpx


def _safe_terminal_text(message: Any) -> str:
    text = str(message)
    stream = getattr(__import__("sys"), "stdout", None)
    encoding = getattr(stream, "encoding", None) or "utf-8"
    try:
        text.encode(encoding)
        return text
    except Exception:
        try:
            return text.encode(encoding, errors="replace").decode(encoding, errors="replace")
        except Exception:
            return text.encode("ascii", errors="replace").decode("ascii", errors="replace")


def _safe_print(message: Any):
    print(_safe_terminal_text(message))


_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_CODE_TOKEN_RE = r"(?:\d{3}[-\s\u00A0\u2009\u202F]?\d{3}|[A-Za-z0-9]{3}-[A-Za-z0-9]{3})"
_MAILTM_ALNUM_CODE_RE = re.compile(r"(?i)\b([A-Z0-9]{3}-[A-Z0-9]{3})\b")
_CODE_PATTERNS = [
    re.compile(r"\b(\d{3}-\d{3})\b"),
    re.compile(r"\b(\d{6})\b"),
    re.compile(r"(?i)\b([A-Z0-9]{3}-[A-Z0-9]{3})\b"),
]
_CODE_CONTEXT_PATTERNS = [
    re.compile(
        rf"(?is)(?:verification\s*(?:code|pin|otp)|verify\s*code|one[-\s]?time\s*(?:password|passcode|code)|security\s*code|login\s*code|confirmation\s*code|验证码|驗證碼|校验码|校驗码|动态码|动态密码)\D{{0,40}}({_CODE_TOKEN_RE})"
    ),
    re.compile(
        rf"(?is)\b({_CODE_TOKEN_RE})\b\D{{0,40}}(?:is\s+your\s+(?:verification\s*code|pin|otp|security\s*code|login\s*code|confirmation\s*code)|xAI\s+confirmation\s+code|(?:用于|作为).{{0,12}}(?:验证码|校验码|驗證碼|验证码))"
    ),
]
_STYLE_BLOCK_RE = re.compile(r"(?is)<style\b.*?>.*?</style>")
_SCRIPT_BLOCK_RE = re.compile(r"(?is)<script\b.*?>.*?</script>")
_HTML_TAG_RE = re.compile(r"(?is)<[^>]+>")
_HEX_COLOR_RE = re.compile(r"(?i)#(?:[0-9a-f]{6}|[0-9a-f]{3})\b")
_DOMAIN_RE = re.compile(r"(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}")
_FALLBACK_DOMAIN = "hmtxj.de5.net"
_DEFAULT_MAILTM_BASE = "https://api.mail.tm"


def _random_local_part(prefix: str = "") -> str:
    k = random.randint(9, 12)
    return prefix + "".join(random.choices(string.ascii_lowercase + string.digits, k=k))


def _random_secret(length: int = 18) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choices(alphabet, k=length))





def _deep_find_by_keys(data: Any, keys: set[str]) -> Any:
    if isinstance(data, dict):
        for key, value in data.items():
            if str(key).strip().lower() in keys and value not in (None, "", [], {}):
                return value
        for value in data.values():
            found = _deep_find_by_keys(value, keys)
            if found not in (None, "", [], {}):
                return found
    elif isinstance(data, (list, tuple, set)):
        for item in data:
            found = _deep_find_by_keys(item, keys)
            if found not in (None, "", [], {}):
                return found
    return None


def _deep_collect_by_keys(data: Any, keys: set[str]) -> list[Any]:
    results: list[Any] = []
    if isinstance(data, dict):
        for key, value in data.items():
            if str(key).strip().lower() in keys and value not in (None, "", [], {}):
                results.append(value)
            results.extend(_deep_collect_by_keys(value, keys))
    elif isinstance(data, (list, tuple, set)):
        for item in data:
            results.extend(_deep_collect_by_keys(item, keys))
    return results


def _deep_iter_strings(data: Any):
    if data is None:
        return
    if isinstance(data, str):
        yield data
        return
    if isinstance(data, bytes):
        yield data.decode("utf-8", errors="replace")
        return
    if isinstance(data, dict):
        for value in data.values():
            yield from _deep_iter_strings(value)
        return
    if isinstance(data, (list, tuple, set)):
        for item in data:
            yield from _deep_iter_strings(item)
        return
    yield str(data)


def _extract_email_from_payload(payload: Any, fallback_email: str) -> str:
    email_candidate = _deep_find_by_keys(
        payload,
        {"email", "address", "mail", "mailbox", "inbox", "alias"},
    )
    if isinstance(email_candidate, str):
        match = _EMAIL_RE.search(email_candidate)
        if match:
            return match.group(0)

    flat_text = "\n".join(_deep_iter_strings(payload))
    match = _EMAIL_RE.search(flat_text)
    if match:
        return match.group(0)

    return fallback_email


def _extract_mailbox_id(payload: Any) -> str:
    mailbox_id = _deep_find_by_keys(
        payload,
        {"mailbox_id", "mailboxid", "inbox_id", "inboxid", "id"},
    )
    if mailbox_id in (None, "", [], {}):
        return ""
    return str(mailbox_id).strip()


def _normalize_code(code: str) -> str:
    compact = re.sub(r"[\s\u00A0\u2009\u202F]+", "", str(code or "")).upper()
    return compact.replace("-", "").strip()


def _strip_markup_noise(text: str) -> str:
    cleaned = _STYLE_BLOCK_RE.sub(" ", text)
    cleaned = _SCRIPT_BLOCK_RE.sub(" ", cleaned)
    cleaned = _HEX_COLOR_RE.sub(" ", cleaned)
    if "<" in cleaned and ">" in cleaned:
        cleaned = _HTML_TAG_RE.sub(" ", cleaned)
        cleaned = html.unescape(cleaned)
    return re.sub(r"\s+", " ", cleaned).strip()


def _extract_code_from_text(text: str, *, require_context: bool) -> str:
    if not text:
        return ""

    cleaned = _strip_markup_noise(text)

    for pattern in _CODE_CONTEXT_PATTERNS:
        match = pattern.search(cleaned)
        if match:
            return _normalize_code(match.group(1))

    if require_context:
        return ""

    for pattern in _CODE_PATTERNS:
        match = pattern.search(cleaned)
        if match:
            code = match.group(1)
            if code and not re.search(rf"#{re.escape(code)}\b", text, re.IGNORECASE):
                return _normalize_code(code)

    return ""


def _extract_code_from_payload(payload: Any) -> str:
    code_candidate = _deep_find_by_keys(
        payload,
        {
            "code",
            "otp",
            "pin",
            "verification_code",
            "verificationcode",
            "verify_code",
            "verifycode",
        },
    )
    if code_candidate not in (None, "", [], {}):
        code = _extract_code_from_text(str(code_candidate).strip(), require_context=False)
        if code:
            return code

    is_scalar_payload = isinstance(payload, (str, bytes, int, float))
    if is_scalar_payload:
        code = _extract_code_from_text(str(payload), require_context=False)
        if code:
            return code

    for text in _deep_iter_strings(payload):
        code = _extract_code_from_text(text, require_context=True)
        if code:
            return code

    try:
        flat_text = json.dumps(payload, ensure_ascii=False)
    except Exception:
        flat_text = str(payload)

    return _extract_code_from_text(flat_text, require_context=not is_scalar_payload)


def _preview_text(text: Any, limit: int = 160) -> str:
    normalized = re.sub(r"\s+", " ", _strip_markup_noise(str(text or ""))).strip()
    if len(normalized) <= limit:
        return normalized
    return normalized[: max(0, limit - 3)] + "..."


def _mailtm_sender_text(payload: Any) -> str:
    if isinstance(payload, dict):
        for key in ("from", "sender"):
            candidate = payload.get(key)
            if candidate not in (None, "", [], {}):
                text = " | ".join(_deep_iter_strings(candidate))
                preview = _preview_text(text, limit=120)
                if preview:
                    return preview
    candidate = _deep_find_by_keys(payload, {"from", "sender"})
    return _preview_text(candidate, limit=120)


def _extract_code_from_mailtm_payload(payload: Any) -> str:
    code = _extract_code_from_payload(payload)
    if code:
        return code

    subject_values = _deep_collect_by_keys(payload, {"subject", "intro"})
    body_values = _deep_collect_by_keys(payload, {"text", "html", "htmlastext", "htmlastxt", "textashtml"})
    sender_text = _mailtm_sender_text(payload)
    subject_text = "\n".join(
        text
        for candidate in subject_values
        for text in _deep_iter_strings(candidate)
    )
    trusted_context = bool(
        re.search(
            r"(?i)(x\.ai|\bgrok\b|verification|verify|otp|pin|security\s*code|login\s*code|confirmation\s*code|validate\s+your\s+email|验证码|校验码|驗證碼)",
            f"{sender_text}\n{subject_text}",
        )
    )

    for candidate in subject_values:
        for text in _deep_iter_strings(candidate):
            code = _extract_code_from_text(text, require_context=False)
            if code:
                return code
            if trusted_context:
                match = _MAILTM_ALNUM_CODE_RE.search(_strip_markup_noise(text).upper())
                if match:
                    return _normalize_code(match.group(1))

    for candidate in body_values:
        for text in _deep_iter_strings(candidate):
            code = _extract_code_from_text(text, require_context=not trusted_context)
            if code:
                return code
            if trusted_context:
                match = _MAILTM_ALNUM_CODE_RE.search(_strip_markup_noise(text).upper())
                if match:
                    return _normalize_code(match.group(1))

    return ""


def _summarize_mailtm_message(payload: Any) -> dict[str, str]:
    return {
        "id": _extract_mailbox_id(payload),
        "from": _mailtm_sender_text(payload),
        "subject": _preview_text(_deep_find_by_keys(payload, {"subject"}), limit=120),
        "intro": _preview_text(_deep_find_by_keys(payload, {"intro", "text"}), limit=160),
    }


def _sanitize_debug_filename(text: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", text or "").strip("._")
    return cleaned or "mailtm"


def _dump_mailtm_debug_snapshot(
    email: str,
    list_payload: Any,
    message_summaries: list[dict[str, str]],
    detail_payloads: dict[str, Any],
) -> str:
    try:
        stamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"mailtm_debug_{_sanitize_debug_filename(email)}_{stamp}.json"
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
        snapshot = {
            "email": email,
            "generated_at": stamp,
            "message_summaries": message_summaries,
            "list_payload": list_payload,
            "detail_payloads": detail_payloads,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, ensure_ascii=False, indent=2)
        return os.path.basename(path)
    except Exception:
        return ""


def _extract_error_detail(payload: Any) -> str:
    detail = _deep_find_by_keys(
        payload,
        {"detail", "message", "error", "description", "title"},
    )
    if detail in (None, "", [], {}):
        return ""
    if isinstance(detail, (dict, list, tuple, set)):
        try:
            return json.dumps(detail, ensure_ascii=False)
        except Exception:
            return str(detail)
    return str(detail).strip()


def _extract_domains_from_payload(payload: Any) -> list[str]:
    domains: list[str] = []
    seen: set[str] = set()

    for candidate in _deep_collect_by_keys(payload, {"domain", "domains", "name"}):
        values = candidate if isinstance(candidate, (list, tuple, set)) else [candidate]
        for value in values:
            if not isinstance(value, str):
                continue
            domain = value.strip().lower().lstrip("@")
            if not domain or "@" in domain or domain.startswith("http"):
                continue
            if _DOMAIN_RE.fullmatch(domain) and domain not in seen:
                seen.add(domain)
                domains.append(domain)

    if domains:
        return domains

    for text in _deep_iter_strings(payload):
        for match in _DOMAIN_RE.finditer(text.lower()):
            domain = match.group(0).lstrip("@")
            if "@" in domain or domain in seen:
                continue
            seen.add(domain)
            domains.append(domain)

    return domains


def _extract_message_items(payload: Any) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("hydra:member", "messages", "items", "data", "results"):
            value = payload.get(key)
            if isinstance(value, list):
                return value
        for value in payload.values():
            if isinstance(value, list) and value:
                return value
    return []


class AsyncImMailClient:
    """兼容多种临时邮箱 API 风格的异步客户端。"""

    def __init__(
        self,
        api_base: str,
        api_auth_token: str = "",
        client: httpx.AsyncClient | None = None,
        proxy: str | None = None,
    ):
        self.api_base = (api_base or "http://127.0.0.1:3000").rstrip("/")
        self.api_auth_token = (api_auth_token or "").strip()
        self.proxy = (proxy or "").strip()
        self.client = client or httpx.AsyncClient(
            timeout=30,
            follow_redirects=True,
            proxy=self.proxy or None,
        )
        self._own_client = client is None
        self.email = ""
        self.mailbox_id = ""
        self.provider = "im_mail"
        self.mailtm_base = os.environ.get("MAILTM_API_BASE", _DEFAULT_MAILTM_BASE).rstrip("/")
        self._mailtm_token = ""
        self._mailtm_password = ""
        self._mailtm_account_id = ""
        self._mailtm_seen_message_ids: set[str] = set()
        self.im_mail_jwt_token = ""

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/json, text/plain, */*",
            "User-Agent": "grok-im-mail-client/1.0",
        }
        if self.im_mail_jwt_token:
            headers["Authorization"] = f"Bearer {self.im_mail_jwt_token}"
            if self.api_auth_token:
                headers["X-Auth-Token"] = self.api_auth_token
                headers["X-API-Key"] = self.api_auth_token
        elif self.api_auth_token:
            headers["Authorization"] = f"Bearer {self.api_auth_token}"
            headers["X-Auth-Token"] = self.api_auth_token
            headers["X-API-Key"] = self.api_auth_token
        return headers

    def _mailtm_headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/json, text/plain, */*",
            "User-Agent": "grok-im-mail-client/1.0",
        }
        if self._mailtm_token:
            headers["Authorization"] = f"Bearer {self._mailtm_token}"
        return headers

    async def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        headers = kwargs.pop("headers", {})
        merged_headers = self._headers()
        merged_headers.update(headers)
        url = path if path.startswith("http://") or path.startswith("https://") else f"{self.api_base}{path}"
        return await self.client.request(method, url, headers=merged_headers, **kwargs)

    async def _request_mailtm(self, method: str, path: str, **kwargs) -> httpx.Response:
        headers = kwargs.pop("headers", {})
        merged_headers = self._mailtm_headers()
        merged_headers.update(headers)
        url = path if path.startswith("http://") or path.startswith("https://") else f"{self.mailtm_base}{path}"
        return await self.client.request(method, url, headers=merged_headers, **kwargs)

    @staticmethod
    def _read_payload(response: httpx.Response) -> Any:
        content_type = response.headers.get("content-type", "").lower()
        if "json" in content_type:
            try:
                return response.json()
            except Exception:
                pass
        try:
            return response.json()
        except Exception:
            return response.text

    async def get_domains(self) -> list[str]:
        last_error: Exception | None = None
        for path in (
            "/api/domains",
            "/domains",
            "/api/v1/domains",
        ):
            try:
                response = await self._request("GET", path, timeout=10)
            except httpx.RequestError as exc:
                last_error = exc
                continue

            if response.status_code in (401, 403):
                raise RuntimeError("im-mail API 鉴权失败，请检查 IM_MAIL_AUTH_TOKEN")
            if response.status_code in (404, 405):
                continue
            if not response.is_success:
                data = self._read_payload(response)
                detail = _extract_error_detail(data)
                suffix = f": {detail}" if detail else ""
                last_error = RuntimeError(f"域名接口返回 HTTP {response.status_code}{suffix}")
                continue

            data = self._read_payload(response)
            domains = _extract_domains_from_payload(data)
            if domains:
                return domains
            last_error = RuntimeError("im-mail 未返回可用域名")

        raise RuntimeError(f"im-mail 域名接口不可用：{last_error or '未知错误'}")

    async def _fetch_mailtm_domains(self) -> list[str]:
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                response = await self._request_mailtm("GET", "/domains?page=1", timeout=20)
            except httpx.RequestError as exc:
                last_error = exc
                if attempt < 2:
                    await asyncio.sleep(attempt + 1)
                continue

            data = self._read_payload(response)
            if response.status_code == 429:
                last_error = RuntimeError(_extract_error_detail(data) or "mail.tm 域名接口触发限流 (HTTP 429)")
            elif not response.is_success:
                detail = _extract_error_detail(data)
                suffix = f": {detail}" if detail else ""
                last_error = RuntimeError(f"mail.tm 域名接口返回 HTTP {response.status_code}{suffix}")
            else:
                domains = _extract_domains_from_payload(data)
                if domains:
                    return domains
                last_error = RuntimeError("mail.tm 未返回可用域名")

            if attempt < 2:
                await asyncio.sleep(attempt + 1)

        raise RuntimeError(f"mail.tm 域名接口不可用：{last_error or '未知错误'}")

    async def _create_mailbox_via_mailtm(self) -> str:
        domains = await self._fetch_mailtm_domains()
        last_error: Exception | None = None
        candidate_domains = domains[: min(5, len(domains))] or domains

        for _ in range(6):
            local_part = _random_local_part("mt")
            password = _random_secret()
            for domain in candidate_domains:
                address = f"{local_part}@{domain}"
                try:
                    response = await self._request_mailtm(
                        "POST",
                        "/accounts",
                        json={"address": address, "password": password},
                        timeout=20,
                    )
                except httpx.RequestError as exc:
                    last_error = exc
                    continue

                data = self._read_payload(response)
                if response.status_code == 429:
                    raise RuntimeError(_extract_error_detail(data) or "mail.tm 创建邮箱触发限流 (HTTP 429)")
                if response.status_code in (400, 409, 422):
                    last_error = RuntimeError(_extract_error_detail(data) or f"mail.tm 拒绝地址 {address}")
                    continue
                if not response.is_success:
                    detail = _extract_error_detail(data)
                    suffix = f": {detail}" if detail else ""
                    last_error = RuntimeError(f"mail.tm 创建邮箱返回 HTTP {response.status_code}{suffix}")
                    continue

                try:
                    token_resp = await self._request_mailtm(
                        "POST",
                        "/token",
                        json={"address": address, "password": password},
                        timeout=20,
                    )
                except httpx.RequestError as exc:
                    last_error = exc
                    continue

                token_data = self._read_payload(token_resp)
                if token_resp.status_code == 429:
                    raise RuntimeError(_extract_error_detail(token_data) or "mail.tm 获取 Token 触发限流 (HTTP 429)")
                if not token_resp.is_success:
                    detail = _extract_error_detail(token_data)
                    suffix = f": {detail}" if detail else ""
                    last_error = RuntimeError(f"mail.tm 获取 Token 返回 HTTP {token_resp.status_code}{suffix}")
                    continue

                token = _deep_find_by_keys(token_data, {"token", "access_token", "jwt"})
                if not token:
                    last_error = RuntimeError("mail.tm 未返回登录 Token")
                    continue

                self.provider = "mailtm"
                self.email = address
                self.mailbox_id = _extract_mailbox_id(data) or address
                self._mailtm_account_id = _extract_mailbox_id(data)
                self._mailtm_password = password
                self._mailtm_token = str(token).strip()
                self._mailtm_seen_message_ids.clear()
                return self.email

            await asyncio.sleep(1)

        raise RuntimeError(f"mail.tm 后备邮箱创建失败：{last_error or '未知错误'}")

    async def create_mailbox(self) -> str:
        self.provider = "im_mail"
        self.email = ""
        self.mailbox_id = ""
        self.im_mail_jwt_token = ""
        self._mailtm_token = ""
        self._mailtm_password = ""
        self._mailtm_account_id = ""
        self._mailtm_seen_message_ids.clear()

        env_domain = os.environ.get("IM_MAIL_DOMAIN", "").strip().lstrip("@")
        if env_domain:
            target_domain = env_domain
        else:
            try:
                domains = await self.get_domains()
                if domains:
                    target_domain = random.choice(domains)
                    _safe_print(f"  [mail] 🎲 未指定环境域名配置，已自动为您随机选中服务端返回的防风控域名: {target_domain}")
                else:
                    target_domain = _FALLBACK_DOMAIN
            except Exception:
                target_domain = _FALLBACK_DOMAIN

        local_part = _random_local_part()
        desired_email = f"{local_part}@{target_domain}"
        payload = {
            "email": desired_email,
            "address": desired_email,
            "local_part": local_part,
            "localPart": local_part,
            "name": local_part,
            "domain": target_domain,
        }
        candidates = [
            ("POST", "/api/mailboxes", {"json": payload}),
            ("POST", "/mailboxes", {"json": payload}),
            ("POST", "/api/v1/mailboxes", {"json": payload}),
            ("POST", "/api/inboxes", {"json": payload}),
            ("POST", "/inboxes", {"json": payload}),
            ("POST", "/api/mailbox/create", {"json": payload}),
            ("POST", "/mailbox/create", {"json": payload}),
            ("GET", f"/api/mailbox/new?email={quote_plus(desired_email)}", {}),
            ("GET", f"/mailbox/new?email={quote_plus(desired_email)}", {}),
        ]

        last_error: Exception | None = None
        for method, path, kwargs in candidates:
            try:
                response = await self._request(method, path, timeout=20, **kwargs)
            except httpx.RequestError as exc:
                last_error = exc
                continue

            if response.status_code in (401, 403):
                raise RuntimeError("im-mail API 鉴权失败，请检查 IM_MAIL_AUTH_TOKEN")
            if response.status_code in (404, 405):
                continue
            if not response.is_success:
                last_error = RuntimeError(f"创建邮箱接口返回 HTTP {response.status_code}")
                continue

            data = self._read_payload(response)
            self.provider = "im_mail"
            self.email = _extract_email_from_payload(data, desired_email)
            self.mailbox_id = _extract_mailbox_id(data)
            token_candidate = _deep_find_by_keys(data, {"token", "jwt", "access_token"})
            if token_candidate:
                self.im_mail_jwt_token = str(token_candidate).strip()
            return self.email

        try:
            email = await self._create_mailbox_via_mailtm()
            _safe_print(f"  [mail] im-mail API 不可用，已切换到 mail.tm 后备邮箱: {email}")
            return email
        except Exception as fallback_exc:
            if last_error is None:
                last_error = fallback_exc
            else:
                last_error = RuntimeError(f"{last_error}；mail.tm 后备失败：{fallback_exc}")

        # 历史版本客户端位于仓库外部目录，当前仓库缺失时至少保证主流程可继续运行。
        # 仅当在线后备邮箱也不可用时，才回退为本地生成 catch-all 地址模式。
        self.provider = "generated"
        self.email = desired_email
        self.mailbox_id = self.mailbox_id or desired_email
        if last_error:
            _safe_print(f"  [mail] 临时邮箱后备全部失败，退回 catch-all 地址模式: {last_error}")

        if last_error and not self.api_base:
            raise RuntimeError(f"im-mail API 未配置: {last_error}")
        return self.email

    def _message_poll_candidates(self, remaining_timeout: int) -> list[tuple[str, str]]:
        encoded_email = quote_plus(self.email)
        candidates: list[tuple[str, str]] = []

        if self.im_mail_jwt_token:
            candidates.extend(
                [
                    ("GET", "/api/emails?limit=5"),
                    ("GET", "/emails?limit=5"),
                ]
            )

        if self.mailbox_id:
            mailbox_id = quote_plus(self.mailbox_id)
            candidates.extend(
                [
                    ("GET", f"/api/mailboxes/{mailbox_id}/messages"),
                    ("GET", f"/mailboxes/{mailbox_id}/messages"),
                    ("GET", f"/api/v1/mailboxes/{mailbox_id}/messages"),
                    ("GET", f"/api/inboxes/{mailbox_id}/messages"),
                    ("GET", f"/inboxes/{mailbox_id}/messages"),
                    ("GET", f"/api/mailbox/{mailbox_id}"),
                    ("GET", f"/mailbox/{mailbox_id}"),
                ]
            )

        candidates.extend(
            [
                ("GET", f"/api/messages?email={encoded_email}"),
                ("GET", f"/messages?email={encoded_email}"),
                ("GET", f"/api/v1/messages?email={encoded_email}"),
                ("GET", f"/api/mailbox/messages?email={encoded_email}"),
                ("GET", f"/mailbox/messages?email={encoded_email}"),
                ("GET", f"/api/wait_for_code?email={encoded_email}&timeout={remaining_timeout}"),
                ("GET", f"/wait_for_code?email={encoded_email}&timeout={remaining_timeout}"),
            ]
        )
        return candidates

    async def _wait_for_code_mailtm(self, timeout: int = 120) -> str:
        if not self.email or not self._mailtm_token:
            raise RuntimeError("mail.tm 邮箱尚未准备完成")

        try:
            timeout = max(timeout, int((os.environ.get("MAILTM_WAIT_TIMEOUT", "180") or "180").strip()))
        except Exception:
            timeout = max(timeout, 180)

        deadline = time.monotonic() + timeout
        last_error: Exception | None = None
        last_list_payload: Any = None
        last_detail_payloads: dict[str, Any] = {}
        last_message_summaries: list[dict[str, str]] = []
        last_logged_signature = ""

        while time.monotonic() < deadline:
            remaining = max(1, int(deadline - time.monotonic()))
            try:
                response = await self._request_mailtm("GET", "/messages?page=1", timeout=min(20, max(5, remaining)))
            except httpx.RequestError as exc:
                last_error = exc
                await asyncio.sleep(3)
                continue

            data = self._read_payload(response)
            last_list_payload = data
            if response.status_code == 401:
                raise RuntimeError("mail.tm Token 已失效，请重新创建邮箱")
            if response.status_code == 429:
                last_error = RuntimeError(_extract_error_detail(data) or "mail.tm 拉信触发限流 (HTTP 429)")
                await asyncio.sleep(5)
                continue
            if not response.is_success:
                detail = _extract_error_detail(data)
                suffix = f": {detail}" if detail else ""
                last_error = RuntimeError(f"mail.tm 消息接口返回 HTTP {response.status_code}{suffix}")
                await asyncio.sleep(3)
                continue

            items = _extract_message_items(data)
            current_signature = f"{len(items)}:" + "|".join(_extract_mailbox_id(item) for item in items[:5])
            if current_signature != last_logged_signature:
                last_message_summaries = [_summarize_mailtm_message(item) for item in items[:5]]
                _safe_print(f"  [mail.tm] 当前邮件数: {len(items)}")
                for idx, summary in enumerate(last_message_summaries, 1):
                    _safe_print(
                        f"  [mail.tm] #{idx} from={summary['from'] or '-'} subject={summary['subject'] or '-'} intro={summary['intro'] or '-'}"
                    )
                last_logged_signature = current_signature

            for item in items:
                code = _extract_code_from_mailtm_payload(item)
                if code:
                    _safe_print(f"  [mail.tm] 已在邮件列表摘要中命中验证码: {code}")
                    return code

                message_id = _extract_mailbox_id(item)
                if not message_id:
                    continue

                try:
                    detail_resp = await self._request_mailtm(
                        "GET",
                        f"/messages/{quote_plus(message_id)}",
                        timeout=min(20, max(5, remaining)),
                    )
                except httpx.RequestError as exc:
                    last_error = exc
                    continue

                detail_data = self._read_payload(detail_resp)
                last_detail_payloads[message_id] = detail_data
                if len(last_detail_payloads) > 5:
                    oldest_key = next(iter(last_detail_payloads))
                    last_detail_payloads.pop(oldest_key, None)
                if detail_resp.status_code == 429:
                    last_error = RuntimeError(_extract_error_detail(detail_data) or "mail.tm 读取邮件详情触发限流 (HTTP 429)")
                    continue
                if not detail_resp.is_success:
                    detail = _extract_error_detail(detail_data)
                    suffix = f": {detail}" if detail else ""
                    last_error = RuntimeError(f"mail.tm 邮件详情接口返回 HTTP {detail_resp.status_code}{suffix}")
                    continue

                self._mailtm_seen_message_ids.add(message_id)
                code = _extract_code_from_mailtm_payload(detail_data)
                if code:
                    summary = _summarize_mailtm_message(detail_data)
                    _safe_print(
                        f"  [mail.tm] 已命中验证码邮件: subject={summary['subject'] or '-'} from={summary['from'] or '-'}"
                    )
                    return code

            await asyncio.sleep(3)

        snapshot_name = _dump_mailtm_debug_snapshot(
            self.email,
            last_list_payload,
            last_message_summaries,
            last_detail_payloads,
        )
        if snapshot_name:
            _safe_print(f"  [mail.tm] 等待超时，已导出调试快照: {snapshot_name}")
        if last_error:
            raise RuntimeError(f"等待验证码失败：{last_error}")
        return ""

    async def wait_for_code(self, timeout: int = 120) -> str:
        if not self.email:
            raise RuntimeError("邮箱尚未创建，无法等待验证码")

        if self.provider == "mailtm":
            return await self._wait_for_code_mailtm(timeout)

        deadline = time.monotonic() + timeout
        last_error: Exception | None = None
        saw_success_response = False

        while time.monotonic() < deadline:
            remaining = max(1, int(deadline - time.monotonic()))
            for method, path in self._message_poll_candidates(remaining):
                try:
                    response = await self._request(method, path, timeout=min(20, max(5, remaining)))
                except httpx.RequestError as exc:
                    last_error = exc
                    continue

                if response.status_code in (401, 403):
                    raise RuntimeError("im-mail API 鉴权失败，请检查 IM_MAIL_AUTH_TOKEN")
                if response.status_code in (404, 405):
                    continue
                if not response.is_success:
                    last_error = RuntimeError(f"验证码接口返回 HTTP {response.status_code}")
                    continue

                saw_success_response = True
                data = self._read_payload(response)
                code = _extract_code_from_payload(data)
                if code:
                    return code

            await asyncio.sleep(3)

        if last_error and not saw_success_response:
            raise RuntimeError(f"等待验证码失败：{last_error}")
        return ""

    async def aclose(self):
        if self._own_client:
            await self.client.aclose()
