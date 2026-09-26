"""跨审计复核标记：指纹计算、失效时间规范化与审计结果附着。

复核标记针对「冲突/告警条目」而非某一次审计：指纹由
**祖先节点 id + 被依赖节点 id + 双方规范化许可证 token** 构成，
因此同一份依赖关系在任意历史审计中重现时都会命中同一条复核记录；
任一节点许可证变化都会改变指纹，旧标记自动不再匹配（条目回到待复核）。

指纹采用带版本前缀的「定长前缀 + JSON 四元组」编码（v2）：先写 4 字节
小端长度再写 UTF-8 JSON 文本，字段边界由长度前缀而非分隔符承担，故节点
id / 许可证 token 内含 ``|`` 等字符时不会发生跨字段串用（旧 v1 直接以
``|`` 拼接五个字段，``a@1|b@1`` / ``c@1`` 与 ``a@1`` / ``b@1|c@1``
会得到同一指纹）。

标记的存储、取代（supersede）、撤销、过期判定与旧指纹迁移见
``database.py``；本模块只负责指纹计算与把当前有效标记附着到审计结果上
（纯内存操作，不改写已持久化的审计 JSON，因此原始冲突、严重程度与
两次审计对比完全不受影响）。
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from . import database

# 条目复核状态
PENDING = "pending"    # 待复核：无有效标记（从未标记 / 许可证变更 / 过期 / 撤销）
REVIEWED = "reviewed"  # 已复核：存在指纹一致且未过期、未撤销的最新标记

# 指纹版本：v1 为旧的 "|" 拼接（存在字段边界串用问题）；
# v2 改为保留字段边界的定长前缀编码。
FINGERPRINT_VERSION = "v2"
_DATE_ONLY = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _encode_parts(parts: Tuple[str, str, str, str]) -> bytes:
    """把四字段编码为保留字段边界的字节串：4 字节小端长度 + UTF-8 JSON。

    JSON 对每个字符串整体转义，长度前缀给出整体边界，分隔/引号等字符
    全部作为字段内容存在，无法跨字段重组。
    """
    payload = json.dumps(list(parts), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return FINGERPRINT_VERSION.encode("ascii") + struct.pack("<I", len(payload)) + payload


def conflict_fingerprint(
    ancestor: str,
    node: str,
    ancestor_license_token: str,
    node_license_token: str,
) -> str:
    """由祖先节点、被依赖节点与双方规范化许可证 token 计算稳定指纹。

    编码保留四字段边界：任一字段内含 ``|``、引号等字符都不会与其他
    字段切分方式混淆，故不同四字段身份必得不同指纹。
    """
    raw = _encode_parts((ancestor, node, ancestor_license_token, node_license_token))
    return hashlib.sha256(raw).hexdigest()


def _node_tokens(result: Dict[str, Any]) -> Dict[str, str]:
    return {
        str(n.get("id")): str(n.get("license") or "")
        for n in result.get("nodes") or []
    }


def fingerprint_parts(
    result: Dict[str, Any],
    conflict: Dict[str, Any],
    tokens: Optional[Dict[str, str]] = None,
) -> Tuple[str, str, str, str]:
    """取冲突条目的指纹四要素（许可证一律用规范化 token，缺失时回退展示文本）。"""
    if tokens is None:
        tokens = _node_tokens(result)
    ancestor = str(conflict.get("ancestor") or "")
    node = str(conflict.get("node") or "")
    ancestor_token = tokens.get(ancestor) or str(conflict.get("ancestor_license") or "")
    node_token = tokens.get(node) or str(conflict.get("node_license") or "")
    return ancestor, node, ancestor_token, node_token


def fingerprint_for_conflict(
    result: Dict[str, Any],
    conflict: Dict[str, Any],
    tokens: Optional[Dict[str, str]] = None,
) -> str:
    return conflict_fingerprint(*fingerprint_parts(result, conflict, tokens))


def normalize_expires_at(raw: str) -> str:
    """把用户输入的失效时间规范化为 UTC ISO 秒级字符串。

    支持 ``2026-12-31``（按当日 23:59:59 UTC）、ISO 8601 日期时间
    （可带时区偏移或 ``Z``；不带时区按 UTC 处理）。
    """
    text = (raw or "").strip()
    if not text:
        raise ValueError("失效时间不能为空。")
    if _DATE_ONLY.match(text):
        day = datetime.strptime(text, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        dt = day + timedelta(hours=23, minutes=59, seconds=59)
    else:
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("失效时间格式无法解析：%r，请使用 ISO 8601。" % raw)
        dt = parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def attach_reviews(result: Dict[str, Any]) -> Dict[str, Any]:
    """把当前有效复核标记附着到审计结果的每条冲突上（就地修改并返回）。

    每条冲突新增 ``review`` 字段（``state`` 为 reviewed/pending），
    并在 ``summary.review`` 中给出已复核/待复核计数。指纹不一致、
    已过期或已撤销的标记不会被附着，条目自然回到待复核。
    """
    conflicts: List[Dict[str, Any]] = result.get("conflicts") or []
    tokens = _node_tokens(result)
    # 指纹 -> 四字段身份：读取标记时按指纹 + 四字段双重核对，
    # 即便指纹列残留旧编码的串用值，也不会把标记附到另一条身份上。
    identities: Dict[str, Tuple[str, str, str, str]] = {}
    fingerprints: List[str] = []
    for conflict in conflicts:
        parts = fingerprint_parts(result, conflict, tokens)
        fingerprint = conflict_fingerprint(*parts)
        fingerprints.append(fingerprint)
        identities.setdefault(fingerprint, parts)
    marks = database.active_review_map(identities)

    reviewed = 0
    for conflict, fingerprint in zip(conflicts, fingerprints):
        mark = marks.get(fingerprint)
        if mark is not None:
            conflict["review"] = {
                "state": REVIEWED,
                "fingerprint": fingerprint,
                "review_id": mark["id"],
                "note": mark["note"],
                "created_at": mark["created_at"],
                "expires_at": mark["expires_at"],
            }
            reviewed += 1
        else:
            conflict["review"] = {"state": PENDING, "fingerprint": fingerprint}

    summary = result.setdefault("summary", {})
    summary["review"] = {"reviewed": reviewed, "pending": len(conflicts) - reviewed}
    return result
