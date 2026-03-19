from __future__ import annotations

import csv
import json
import os
import random
import shutil
import string
import time
import zipfile
from datetime import datetime
from typing import Any

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
BATCHES_DIR = os.path.join(DATA_DIR, "batches")
CURRENT_BATCH_DIR = os.path.join(BATCHES_DIR, "current")
EXPORTS_DIR = os.path.join(DATA_DIR, "exports")
RESULT_STATE_PATH = os.path.join(DATA_DIR, "result_state.json")

ACCOUNTS_CSV_PATH = os.path.join(DATA_DIR, "accounts.csv")
KEY_TXT_PATH = os.path.join(DATA_DIR, "key.txt")
NSFW_FAIL_TXT_PATH = os.path.join(DATA_DIR, "未开启nsfw.txt")

CURRENT_ACCOUNTS_CSV_PATH = os.path.join(CURRENT_BATCH_DIR, "accounts.csv")
CURRENT_KEY_TXT_PATH = os.path.join(CURRENT_BATCH_DIR, "key.txt")
CURRENT_NSFW_FAIL_TXT_PATH = os.path.join(CURRENT_BATCH_DIR, "未开启nsfw.txt")

RESULT_FILE_SPECS: dict[str, dict[str, str]] = {
    "accounts": {
        "label": "账号总表",
        "filename": "accounts.csv",
        "kind": "csv",
        "all": ACCOUNTS_CSV_PATH,
        "current": CURRENT_ACCOUNTS_CSV_PATH,
    },
    "key": {
        "label": "NSFW 已开启 Token",
        "filename": "key.txt",
        "kind": "text",
        "all": KEY_TXT_PATH,
        "current": CURRENT_KEY_TXT_PATH,
    },
    "nsfw_fail": {
        "label": "NSFW 未开启 Token",
        "filename": "未开启nsfw.txt",
        "kind": "text",
        "all": NSFW_FAIL_TXT_PATH,
        "current": CURRENT_NSFW_FAIL_TXT_PATH,
    },
}

VALID_SCOPES = {"current", "all"}


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _format_ts(ts: float | int | None) -> str:
    if not ts:
        return ""
    return datetime.fromtimestamp(float(ts)).astimezone().isoformat(timespec="seconds")


def _random_suffix(length: int = 4) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choices(alphabet, k=length))


def generate_batch_id() -> str:
    return f"batch-{time.strftime('%Y%m%d-%H%M%S')}-{_random_suffix()}"


def _touch_file(path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        with open(path, "a", encoding="utf-8"):
            pass


def _write_json(path: str, payload: dict[str, Any]):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def _clear_file(path: str, preserve_header: bool = False):
    header_line = ""
    if preserve_header and path.endswith(".csv"):
        has_header, header, _ = load_account_rows_from_path(path)
        if has_header and header:
            header_line = ",".join(header) + "\n"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        if header_line:
            f.write(header_line)


def _default_result_state() -> dict[str, Any]:
    return {
        "current_batch_id": generate_batch_id(),
        "current_batch_started_at": _now_iso(),
        "last_archive_batch_id": "",
        "last_archive_at": "",
    }


def ensure_result_store(migrate_legacy: bool = True) -> dict[str, Any]:
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(BATCHES_DIR, exist_ok=True)
    os.makedirs(CURRENT_BATCH_DIR, exist_ok=True)
    os.makedirs(EXPORTS_DIR, exist_ok=True)

    state_exists = os.path.exists(RESULT_STATE_PATH)
    state: dict[str, Any] = {}
    if state_exists:
        try:
            with open(RESULT_STATE_PATH, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                state = loaded
        except Exception:
            state = {}

    if not state:
        state = _default_result_state()
        state_exists = False

    changed = False
    if not state.get("current_batch_id"):
        state["current_batch_id"] = generate_batch_id()
        changed = True
    if not state.get("current_batch_started_at"):
        state["current_batch_started_at"] = _now_iso()
        changed = True
    if "last_archive_batch_id" not in state:
        state["last_archive_batch_id"] = ""
        changed = True
    if "last_archive_at" not in state:
        state["last_archive_at"] = ""
        changed = True

    for spec in RESULT_FILE_SPECS.values():
        _touch_file(spec["all"])
        _touch_file(spec["current"])

    if migrate_legacy and not state_exists:
        current_has_content = any(
            os.path.exists(spec["current"]) and os.path.getsize(spec["current"]) > 0
            for spec in RESULT_FILE_SPECS.values()
        )
        legacy_has_content = any(
            os.path.exists(spec["all"]) and os.path.getsize(spec["all"]) > 0
            for spec in RESULT_FILE_SPECS.values()
        )
        if legacy_has_content and not current_has_content:
            for spec in RESULT_FILE_SPECS.values():
                if os.path.exists(spec["all"]) and os.path.getsize(spec["all"]) > 0:
                    shutil.copy2(spec["all"], spec["current"])
            changed = True

    if changed or not os.path.exists(RESULT_STATE_PATH):
        _write_json(RESULT_STATE_PATH, state)
    return state


def load_result_state() -> dict[str, Any]:
    return ensure_result_store(migrate_legacy=True)


def save_result_state(state: dict[str, Any]) -> dict[str, Any]:
    ensure_result_store(migrate_legacy=False)
    _write_json(RESULT_STATE_PATH, state)
    return state


def start_new_batch(archived_batch_id: str = "", archived_at: str = "") -> dict[str, Any]:
    state = load_result_state()
    if archived_batch_id:
        state["last_archive_batch_id"] = archived_batch_id
    if archived_at:
        state["last_archive_at"] = archived_at
    state["current_batch_id"] = generate_batch_id()
    state["current_batch_started_at"] = _now_iso()
    for spec in RESULT_FILE_SPECS.values():
        _clear_file(spec["current"], preserve_header=True)
    return save_result_state(state)


def reset_live_results() -> dict[str, Any]:
    ensure_result_store(migrate_legacy=False)
    for spec in RESULT_FILE_SPECS.values():
        _clear_file(spec["all"], preserve_header=True)
        _clear_file(spec["current"], preserve_header=True)
    return start_new_batch()


def load_account_rows_from_path(path: str) -> tuple[bool, list[str], list[list[str]]]:
    if not os.path.exists(path):
        return False, [], []

    with open(path, "r", encoding="utf-8") as f:
        rows = [r for r in csv.reader(f) if any(cell.strip() for cell in r)]

    if not rows:
        return False, [], []

    first_row = rows[0]
    has_header = any("email" in str(cell).lower() for cell in first_row)
    data_rows = rows[1:] if has_header else rows
    return has_header, first_row if has_header else [], data_rows


def _load_text_rows(path: str) -> list[str]:
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return [line.strip() for line in f.readlines() if line.strip()]


def _normalize_scope(scope: str) -> str:
    normalized = (scope or "current").strip().lower()
    if normalized not in VALID_SCOPES:
        raise ValueError("scope 仅支持 current 或 all")
    return normalized


def _normalize_file_key(file_key: str) -> str:
    normalized = (file_key or "accounts").strip().lower()
    if normalized not in RESULT_FILE_SPECS:
        raise ValueError("file 仅支持 accounts / key / nsfw_fail")
    return normalized


def _normalize_limit(limit: int) -> int:
    try:
        value = int(limit)
    except Exception:
        value = 20
    return max(1, min(200, value))


def resolve_result_file(scope: str, file_key: str) -> dict[str, str]:
    ensure_result_store(migrate_legacy=True)
    normalized_scope = _normalize_scope(scope)
    normalized_file_key = _normalize_file_key(file_key)
    spec = RESULT_FILE_SPECS[normalized_file_key]
    return {
        "scope": normalized_scope,
        "key": normalized_file_key,
        "label": spec["label"],
        "filename": spec["filename"],
        "kind": spec["kind"],
        "path": spec[normalized_scope],
    }


def _count_records(file_key: str, path: str) -> int:
    if RESULT_FILE_SPECS[file_key]["kind"] == "csv":
        return len(load_account_rows_from_path(path)[2])
    return len(_load_text_rows(path))


def _build_file_entry(scope: str, file_key: str) -> dict[str, Any]:
    entry = resolve_result_file(scope, file_key)
    path = entry["path"]
    exists = os.path.exists(path)
    size = os.path.getsize(path) if exists else 0
    mtime = os.path.getmtime(path) if exists else 0.0
    entry.update(
        {
            "exists": exists,
            "size": size,
            "records": _count_records(file_key, path),
            "updated_at": _format_ts(mtime),
            "mtime": mtime,
        }
    )
    return entry


def _build_scope_summary(scope: str, state: dict[str, Any] | None = None) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    normalized_scope = _normalize_scope(scope)
    state = state or load_result_state()
    files = [_build_file_entry(normalized_scope, key) for key in RESULT_FILE_SPECS]
    latest_mtime = max((float(item.get("mtime", 0) or 0) for item in files), default=0.0)
    summary = {
        "scope": normalized_scope,
        "batch_id": state.get("current_batch_id", "") if normalized_scope == "current" else "",
        "started_at": state.get("current_batch_started_at", "") if normalized_scope == "current" else "",
        "accounts_count": next((item["records"] for item in files if item["key"] == "accounts"), 0),
        "key_count": next((item["records"] for item in files if item["key"] == "key"), 0),
        "nsfw_fail_count": next((item["records"] for item in files if item["key"] == "nsfw_fail"), 0),
        "updated_at": _format_ts(latest_mtime),
        "total_records": sum(int(item.get("records", 0) or 0) for item in files),
        "has_content": any((int(item.get("records", 0) or 0) > 0) or (int(item.get("size", 0) or 0) > 0) for item in files),
    }
    for item in files:
        item.pop("mtime", None)
    return summary, files


def build_results_summary() -> dict[str, Any]:
    state = load_result_state()
    current_summary, current_files = _build_scope_summary("current", state)
    all_summary, all_files = _build_scope_summary("all", state)
    return {
        "state": state,
        "current_batch": current_summary,
        "all_time": all_summary,
        "downloads": {
            "current": current_files,
            "all": all_files,
        },
        "actions": {
            "can_archive_current": current_summary["has_content"],
        },
    }


def get_result_preview(scope: str = "current", limit: int = 20) -> dict[str, Any]:
    normalized_scope = _normalize_scope(scope)
    normalized_limit = _normalize_limit(limit)
    path = resolve_result_file(normalized_scope, "accounts")["path"]
    accounts: list[dict[str, str]] = []
    has_header, header, data_rows = load_account_rows_from_path(path)
    if data_rows:
        default_fields = ["email", "password", "cookie", "token"]
        fields = header if has_header and header else default_fields[: len(data_rows[0])]
        for row in data_rows:
            item: dict[str, str] = {}
            for index, field in enumerate(fields):
                key = str(field).strip() if field else f"col_{index}"
                item[key] = row[index] if index < len(row) else ""
            accounts.append(item)
    accounts.reverse()
    return {
        "scope": normalized_scope,
        "limit": normalized_limit,
        "items": accounts[:normalized_limit],
    }


def build_results_zip(scope: str, output_path: str = "") -> dict[str, str]:
    state = load_result_state()
    normalized_scope = _normalize_scope(scope)
    summary, files = _build_scope_summary(normalized_scope, state)
    root_folder = state.get("current_batch_id", "current-batch") if normalized_scope == "current" else "all-results"
    if not output_path:
        default_name = f"{root_folder}.zip" if normalized_scope == "current" else "all-results.zip"
        output_path = os.path.join(EXPORTS_DIR, default_name)

    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for item in files:
            if not os.path.exists(item["path"]):
                _touch_file(item["path"])
            zf.write(item["path"], arcname=os.path.join(root_folder, item["filename"]))

    return {
        "scope": normalized_scope,
        "path": output_path,
        "filename": os.path.basename(output_path),
        "batch_id": summary.get("batch_id", ""),
    }


def archive_current_batch() -> dict[str, Any]:
    state = load_result_state()
    current_summary, current_files = _build_scope_summary("current", state)
    if not current_summary["has_content"]:
        raise ValueError("当前批次暂无可封存结果")

    archive_batch_id = state.get("current_batch_id") or generate_batch_id()
    archive_dir = os.path.join(BATCHES_DIR, archive_batch_id)
    if os.path.exists(archive_dir):
        archive_batch_id = f"{archive_batch_id}-{_random_suffix()}"
        archive_dir = os.path.join(BATCHES_DIR, archive_batch_id)
    os.makedirs(archive_dir, exist_ok=True)

    for item in current_files:
        src = item["path"]
        dst = os.path.join(archive_dir, item["filename"])
        if os.path.exists(src):
            shutil.copy2(src, dst)
        else:
            _touch_file(dst)

    zip_path = os.path.join(EXPORTS_DIR, f"{archive_batch_id}.zip")
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for item in current_files:
            src = item["path"]
            if not os.path.exists(src):
                _touch_file(src)
            zf.write(src, arcname=os.path.join(archive_batch_id, item["filename"]))

    archived_at = _now_iso()
    new_state = start_new_batch(archived_batch_id=archive_batch_id, archived_at=archived_at)
    return {
        "archived_batch_id": archive_batch_id,
        "archived_at": archived_at,
        "archive_dir": archive_dir,
        "zip_path": zip_path,
        "state": new_state,
    }
