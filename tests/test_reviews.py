"""跨审计复核标记的自测（无测试框架依赖）：python -m tests.test_reviews

使用独立临时 SQLite 库，不触碰 ./data；只依赖 analyzer/compare/database/reviews，
无需安装 fastapi 即可运行。
"""

from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

from app import analyzer, compare as compare_mod, database, reviews

# 隔离的临时数据库（database.connect 在调用时读取 DB_PATH，运行时替换即可）
_TMP_DIR = tempfile.mkdtemp(prefix="reviews-test-")
database.DB_PATH = Path(_TMP_DIR) / "test.db"
database.init_db()


def _check(name: str, condition: bool, detail: str = "") -> None:
    if not condition:
        raise AssertionError("%s %s" % (name, detail))
    print("ok -", name)


def _conflict_manifest(app_license: str = "GPL-3.0", lib_license: str = "Proprietary"):
    return {
        "name": "review-demo",
        "packages": [
            {"name": "app", "version": "1", "license": app_license,
             "dependencies": ["lib@1"]},
            {"name": "lib", "version": "1", "license": lib_license},
        ],
    }


def _save_audit(**kwargs) -> dict:
    result = analyzer.analyze_manifest(_conflict_manifest(**kwargs))
    audit_id = database.save_audit(result, result["manifest_name"])
    result["audit_id"] = audit_id
    return result


def _only_conflict(result: dict) -> dict:
    _check("exactly one conflict", len(result["conflicts"]) == 1, str(result["conflicts"]))
    return result["conflicts"][0]


def _boundary_manifest(ancestor_name: str, node_name: str) -> dict:
    """两包 manifest：祖先包名/被依赖包名可含竖线（GPL-2.0 -> Apache-2.0 硬冲突）。"""
    return {
        "name": "boundary-demo",
        "packages": [
            {"name": ancestor_name, "version": "1", "license": "GPL-2.0",
             "dependencies": ["%s@1" % node_name]},
            {"name": node_name, "version": "1", "license": "Apache-2.0"},
        ],
    }


def _save_boundary_audit(ancestor_name: str, node_name: str) -> dict:
    result = analyzer.analyze_manifest(_boundary_manifest(ancestor_name, node_name))
    _check("boundary manifest parsed", result["status"] != "error", str(result.get("error")))
    audit_id = database.save_audit(result, result["manifest_name"])
    result["audit_id"] = audit_id
    return result


def _legacy_fingerprint_v1(ancestor: str, node: str, a_tok: str, n_tok: str) -> str:
    """迁移前 v1 竖线拼接指纹（仅测试用，模拟旧库记录）。"""
    return hashlib.sha256(
        "|".join(["v1", ancestor, node, a_tok, n_tok]).encode("utf-8")
    ).hexdigest()


def test_fingerprint() -> None:
    fp1 = reviews.conflict_fingerprint("app@1", "lib@1", "GPL-3.0", "Proprietary")
    fp2 = reviews.conflict_fingerprint("app@1", "lib@1", "GPL-3.0", "Proprietary")
    _check("fingerprint deterministic", fp1 == fp2)
    _check("fingerprint is sha256 hex", len(fp1) == 64 and all(c in "0123456789abcdef" for c in fp1))
    _check(
        "ancestor license change alters fingerprint",
        reviews.conflict_fingerprint("app@1", "lib@1", "GPL-2.0", "Proprietary") != fp1,
    )
    _check(
        "node license change alters fingerprint",
        reviews.conflict_fingerprint("app@1", "lib@1", "GPL-3.0", "MIT") != fp1,
    )
    _check(
        "node id change alters fingerprint",
        reviews.conflict_fingerprint("app@1", "lib@2", "GPL-3.0", "Proprietary") != fp1,
    )


def test_fingerprint_field_boundary() -> None:
    # 任务案例：祖先/依赖为 a@1|b@1、c@1 与 a@1、b@1|c@1，双方许可证同为
    # GPL-2.0、Apache-2.0 —— v1 竖线拼接会撞指纹，v2 边界保留编码必须区分
    fp_a = reviews.conflict_fingerprint("a@1|b@1", "c@1", "GPL-2.0", "Apache-2.0")
    fp_b = reviews.conflict_fingerprint("a@1", "b@1|c@1", "GPL-2.0", "Apache-2.0")
    legacy_a = _legacy_fingerprint_v1("a@1|b@1", "c@1", "GPL-2.0", "Apache-2.0")
    legacy_b = _legacy_fingerprint_v1("a@1", "b@1|c@1", "GPL-2.0", "Apache-2.0")
    _check("legacy v1 collides (bug repro)", legacy_a == legacy_b)
    _check("v2 keeps field boundary", fp_a != fp_b)
    _check("v2 differs from legacy", fp_a != legacy_a and fp_b != legacy_b)
    _check(
        "payload keeps boundary",
        reviews.fingerprint_payload("a@1|b@1", "c@1", "GPL-2.0", "Apache-2.0")
        != reviews.fingerprint_payload("a@1", "b@1|c@1", "GPL-2.0", "Apache-2.0"),
    )


def test_pipe_fields_no_cross_review() -> None:
    # 端到端：两条四字段不同但 v1 会撞指纹的冲突，复核第一条不得让第二条误显已复核
    result_a = _save_boundary_audit("a@1|b", "c")    # 祖先 a@1|b@1 -> 被依赖 c@1
    result_b = _save_boundary_audit("a", "b@1|c")    # 祖先 a@1 -> 被依赖 b@1|c@1
    conflict_a = _only_conflict(result_a)
    conflict_b = _only_conflict(result_b)
    _check("ancestor keeps pipe", conflict_a["ancestor"] == "a@1|b@1", conflict_a["ancestor"])
    _check("node keeps pipe", conflict_b["node"] == "b@1|c@1", conflict_b["node"])
    fp_a = reviews.fingerprint_for_conflict(result_a, conflict_a)
    fp_b = reviews.fingerprint_for_conflict(result_b, conflict_b)
    _check("four-field identity separated", fp_a != fp_b)

    record = database.save_review(
        fingerprint=fp_a,
        ancestor=conflict_a["ancestor"],
        node=conflict_a["node"],
        ancestor_license="GPL-2.0",
        node_license="Apache-2.0",
        note="只复核 a@1|b@1 -> c@1",
    )
    attached_a = reviews.attach_reviews(dict(result_a))
    attached_b = reviews.attach_reviews(dict(result_b))
    _check("first conflict reviewed", attached_a["conflicts"][0]["review"]["state"] == reviews.REVIEWED)
    _check(
        "second conflict NOT cross-marked",
        attached_b["conflicts"][0]["review"]["state"] == reviews.PENDING,
    )
    _check(
        "second summary stays pending",
        attached_b["summary"]["review"] == {"reviewed": 0, "pending": 1},
    )

    # 同一关系跨审计仍复用标记：与第一条四字段相同的新审计自动带出同一标记
    again_a = _save_boundary_audit("a@1|b", "c")
    _check("different audit id", again_a["audit_id"] != result_a["audit_id"])
    attached_again = reviews.attach_reviews(dict(again_a))
    review = attached_again["conflicts"][0]["review"]
    _check("same relation reuses mark cross-audit", review["state"] == reviews.REVIEWED)
    _check("same review id reused", review["review_id"] == record["id"])


def test_normalize_expires_at() -> None:
    _check(
        "date only means end of day UTC",
        reviews.normalize_expires_at("2026-12-31") == "2026-12-31T23:59:59+00:00",
    )
    _check(
        "Z suffix normalized",
        reviews.normalize_expires_at("2026-12-31T10:00:00Z") == "2026-12-31T10:00:00+00:00",
    )
    _check(
        "offset converted to UTC",
        reviews.normalize_expires_at("2026-12-31T18:00:00+08:00") == "2026-12-31T10:00:00+00:00",
    )
    _check(
        "naive datetime treated as UTC",
        reviews.normalize_expires_at("2026-12-31T10:00:00") == "2026-12-31T10:00:00+00:00",
    )
    for bad in ("", "not-a-date", "2026-13-40"):
        try:
            reviews.normalize_expires_at(bad)
        except ValueError:
            continue
        raise AssertionError("invalid expires_at accepted: %r" % bad)
    print("ok - invalid expires_at rejected")


def test_mark_and_cross_audit_attach() -> None:
    first = _save_audit()
    conflict = _only_conflict(first)

    attached = reviews.attach_reviews(dict(first))
    _check("fresh audit pending", attached["conflicts"][0]["review"]["state"] == reviews.PENDING)
    _check("summary counts pending", attached["summary"]["review"] == {"reviewed": 0, "pending": 1})

    fingerprint = reviews.fingerprint_for_conflict(first, conflict)
    record = database.save_review(
        fingerprint=fingerprint,
        ancestor=conflict["ancestor"],
        node=conflict["node"],
        ancestor_license="GPL-3.0",
        node_license="Proprietary",
        note="法务已确认允许组合分发",
    )
    _check("record active", record["state"] == database.REVIEW_ACTIVE, str(record))
    _check("record keeps note", record["note"] == "法务已确认允许组合分发")
    _check("record no expiry", record["expires_at"] is None)

    attached = reviews.attach_reviews(dict(first))
    review = attached["conflicts"][0]["review"]
    _check("marked conflict reviewed", review["state"] == reviews.REVIEWED)
    _check("review carries note", review["note"] == "法务已确认允许组合分发")
    _check("review carries id", review["review_id"] == record["id"])
    _check("summary counts reviewed", attached["summary"]["review"] == {"reviewed": 1, "pending": 0})

    # 跨审计：同一依赖关系在新审计中重现，指纹一致 -> 自动带出同一标记
    second = _save_audit()
    _check("different audit id", second["audit_id"] != first["audit_id"])
    attached_second = reviews.attach_reviews(dict(second))
    _check(
        "cross-audit attach",
        attached_second["conflicts"][0]["review"]["state"] == reviews.REVIEWED,
    )
    _check(
        "cross-audit same review id",
        attached_second["conflicts"][0]["review"]["review_id"] == record["id"],
    )


def test_license_change_returns_pending() -> None:
    _save_audit()  # 确保上一条标记存在（GPL-3.0 -> Proprietary）
    changed = _save_audit(app_license="GPL-2.0")  # 祖先许可证变化 -> 指纹变化
    conflict = _only_conflict(changed)
    _check("still a hard conflict", conflict["severity"] == "error")
    attached = reviews.attach_reviews(dict(changed))
    _check(
        "license change back to pending",
        attached["conflicts"][0]["review"]["state"] == reviews.PENDING,
    )


def test_expiry_returns_pending() -> None:
    result = _save_audit()
    conflict = _only_conflict(result)
    fingerprint = reviews.fingerprint_for_conflict(result, conflict)
    record = database.save_review(
        fingerprint=fingerprint,
        ancestor=conflict["ancestor"],
        node=conflict["node"],
        ancestor_license="GPL-3.0",
        node_license="Proprietary",
        note="过期标记",
        expires_at="2020-01-01T00:00:00+00:00",
    )
    _check("stored record computed expired", record["state"] == database.REVIEW_EXPIRED)
    attached = reviews.attach_reviews(dict(result))
    _check(
        "expired mark not attached",
        attached["conflicts"][0]["review"]["state"] == reviews.PENDING,
    )
    expired = database.list_reviews(state=database.REVIEW_EXPIRED, fingerprint=fingerprint)
    _check("expired listed by state", any(r["id"] == record["id"] for r in expired))
    active = database.list_reviews(state=database.REVIEW_ACTIVE, fingerprint=fingerprint)
    _check("expired not in active list", all(r["id"] != record["id"] for r in active))


def test_revoke_returns_pending() -> None:
    result = _save_audit()
    conflict = _only_conflict(result)
    fingerprint = reviews.fingerprint_for_conflict(result, conflict)
    record = database.save_review(
        fingerprint=fingerprint,
        ancestor=conflict["ancestor"],
        node=conflict["node"],
        ancestor_license="GPL-3.0",
        node_license="Proprietary",
        note="将被撤销",
    )
    revoked = database.revoke_review(record["id"])
    _check("revoke returns record", revoked is not None and revoked["id"] == record["id"])
    _check("state revoked", revoked["state"] == database.REVIEW_REVOKED, str(revoked))
    _check("revoked_at set", bool(revoked["revoked_at"]))
    attached = reviews.attach_reviews(dict(result))
    _check(
        "revoked mark not attached",
        attached["conflicts"][0]["review"]["state"] == reviews.PENDING,
    )
    _check("revoke missing id", database.revoke_review(999999) is None)
    kept = database.get_review(record["id"])
    _check("revoked record kept", kept is not None and kept["state"] == database.REVIEW_REVOKED)


def test_latest_mark_supersedes() -> None:
    result = _save_audit()
    conflict = _only_conflict(result)
    fingerprint = reviews.fingerprint_for_conflict(result, conflict)
    first = database.save_review(
        fingerprint=fingerprint, ancestor=conflict["ancestor"], node=conflict["node"],
        ancestor_license="GPL-3.0", node_license="Proprietary", note="第一次复核",
    )
    second = database.save_review(
        fingerprint=fingerprint, ancestor=conflict["ancestor"], node=conflict["node"],
        ancestor_license="GPL-3.0", node_license="Proprietary", note="第二次复核",
    )
    _check(
        "old mark superseded",
        database.get_review(first["id"])["state"] == database.REVIEW_SUPERSEDED,
    )
    _check("new mark active", database.get_review(second["id"])["state"] == database.REVIEW_ACTIVE)
    marks = database.active_review_map([fingerprint])
    _check("only latest valid mark", marks[fingerprint]["id"] == second["id"])
    attached = reviews.attach_reviews(dict(result))
    _check("attached note is latest", attached["conflicts"][0]["review"]["note"] == "第二次复核")
    history = database.list_reviews(fingerprint=fingerprint)
    _check("history kept", len(history) >= 2, str(len(history)))


def test_stored_result_and_compare_untouched() -> None:
    base = _save_audit()
    target = _save_audit(app_license="GPL-2.0")
    # 给 base 的冲突打上标记，确认持久化内容与对比不受影响
    conflict = _only_conflict(base)
    database.save_review(
        fingerprint=reviews.fingerprint_for_conflict(base, conflict),
        ancestor=conflict["ancestor"], node=conflict["node"],
        ancestor_license="GPL-3.0", node_license="Proprietary", note="不应影响对比",
    )
    stored = database.get_audit(base["audit_id"])
    _check(
        "stored conflicts carry no review field",
        all("review" not in c for c in stored["conflicts"]),
    )
    _check("stored summary has no review key", "review" not in stored["summary"])

    diff = compare_mod.compare_audits(
        database.get_audit(base["audit_id"]), database.get_audit(target["audit_id"])
    )
    _check("compare still read only", diff["read_only"] is True)
    _check("severity flip detected", len(diff["changed"]) == 1, str(diff["changed"]))
    finding = diff["changed"][0]
    _check(
        "severity preserved on both sides",
        finding["severity_base"] == "error" and finding["severity_target"] == "error",
    )
    _check("license change flagged", "ancestor_license" in finding["fields_changed"])
    _check(
        "no review leakage into compare",
        all("review" not in (f.get("base") or {}) and "review" not in (f.get("target") or {})
            for bucket in (diff["added"], diff["removed"], diff["changed"]) for f in bucket),
    )


def test_migrate_review_fingerprints() -> None:
    # 模拟旧库：直接写入一条 v1 竖线拼接指纹的标记（用含竖线的包名，
    # 正是旧编码会撞指纹的那类记录；四字段与其他测试互不相同）
    result = _save_boundary_audit("mig|app", "mig|lib")
    conflict = _only_conflict(result)
    ancestor, node = conflict["ancestor"], conflict["node"]
    legacy_fp = _legacy_fingerprint_v1(ancestor, node, "GPL-2.0", "Apache-2.0")
    new_fp = reviews.conflict_fingerprint(ancestor, node, "GPL-2.0", "Apache-2.0")
    _check("legacy differs from v2", legacy_fp != new_fp)
    record = database.save_review(
        fingerprint=legacy_fp,
        ancestor=ancestor,
        node=node,
        ancestor_license="GPL-2.0",
        node_license="Apache-2.0",
        note="旧库标记",
    )
    # 迁移前：v1 指纹与当前计算不一致，标记附着不上
    attached = reviews.attach_reviews(dict(result))
    _check(
        "legacy mark not attached before migration",
        attached["conflicts"][0]["review"]["state"] == reviews.PENDING,
    )

    migrated = database.migrate_review_fingerprints()
    _check("migration reports update", migrated >= 1, str(migrated))
    after = database.get_review(record["id"])
    _check("record id preserved", after["id"] == record["id"])
    _check("fingerprint recomputed", after["fingerprint"] == new_fp)
    _check("note preserved", after["note"] == "旧库标记")
    _check("created_at preserved", after["created_at"] == record["created_at"])
    _check("status preserved", after["state"] == database.REVIEW_ACTIVE)

    # 迁移后：新指纹命中，标记重新附着；持久化的审计 JSON 不被改写
    attached = reviews.attach_reviews(dict(result))
    review = attached["conflicts"][0]["review"]
    _check("migrated mark attaches", review["state"] == reviews.REVIEWED)
    _check("migrated mark id", review["review_id"] == record["id"])
    stored = database.get_audit(result["audit_id"])
    _check(
        "stored audit json untouched",
        all("review" not in c for c in stored["conflicts"]) and "review" not in stored["summary"],
    )

    # 幂等：再次迁移不再改动任何记录
    _check("migration idempotent", database.migrate_review_fingerprints() == 0)


def test_migration_keeps_terminal_states() -> None:
    # 旧库中已 被取代 / 已撤销 / 已过期 的记录：迁移只重算指纹，绝不恢复状态
    result = _save_boundary_audit("term|app", "term|lib")  # 四字段与其他测试错开
    conflict = _only_conflict(result)
    ancestor, node = conflict["ancestor"], conflict["node"]
    legacy_fp = _legacy_fingerprint_v1(ancestor, node, "GPL-2.0", "Apache-2.0")
    new_fp = reviews.conflict_fingerprint(ancestor, node, "GPL-2.0", "Apache-2.0")

    superseded = database.save_review(
        fingerprint=legacy_fp, ancestor=ancestor, node=node,
        ancestor_license="GPL-2.0", node_license="Apache-2.0", note="将被取代",
    )
    revoked = database.save_review(
        fingerprint=legacy_fp, ancestor=ancestor, node=node,
        ancestor_license="GPL-2.0", node_license="Apache-2.0", note="将被撤销",
    )
    revoked = database.revoke_review(revoked["id"])
    expired = database.save_review(
        fingerprint=legacy_fp, ancestor=ancestor, node=node,
        ancestor_license="GPL-2.0", node_license="Apache-2.0", note="已过期",
        expires_at="2020-01-01T00:00:00+00:00",
    )
    _check("setup superseded", database.get_review(superseded["id"])["state"] == database.REVIEW_SUPERSEDED)
    _check("setup revoked", database.get_review(revoked["id"])["state"] == database.REVIEW_REVOKED)
    _check("setup expired", database.get_review(expired["id"])["state"] == database.REVIEW_EXPIRED)

    database.migrate_review_fingerprints()

    gone_superseded = database.get_review(superseded["id"])
    gone_revoked = database.get_review(revoked["id"])
    gone_expired = database.get_review(expired["id"])
    _check("superseded fingerprint migrated", gone_superseded["fingerprint"] == new_fp)
    _check("revoked fingerprint migrated", gone_revoked["fingerprint"] == new_fp)
    _check("expired fingerprint migrated", gone_expired["fingerprint"] == new_fp)
    _check("superseded not restored", gone_superseded["state"] == database.REVIEW_SUPERSEDED)
    _check("revoked not restored", gone_revoked["state"] == database.REVIEW_REVOKED)
    _check("revoked_at preserved", bool(gone_revoked["revoked_at"])
           and gone_revoked["revoked_at"] == revoked["revoked_at"])
    _check("expired still expired", gone_expired["state"] == database.REVIEW_EXPIRED)
    _check("expires_at preserved", gone_expired["expires_at"] == "2020-01-01T00:00:00+00:00")

    # 三条终态记录都不得附着到条目上
    attached = reviews.attach_reviews(dict(result))
    _check(
        "terminal marks never attach",
        attached["conflicts"][0]["review"]["state"] == reviews.PENDING,
    )


def main() -> None:
    test_fingerprint()
    test_fingerprint_field_boundary()
    test_pipe_fields_no_cross_review()
    test_normalize_expires_at()
    test_mark_and_cross_audit_attach()
    test_license_change_returns_pending()
    test_expiry_returns_pending()
    test_revoke_returns_pending()
    test_latest_mark_supersedes()
    test_stored_result_and_compare_untouched()
    test_migrate_review_fingerprints()
    test_migration_keeps_terminal_states()
    print("\nall review tests passed.")


if __name__ == "__main__":
    main()
