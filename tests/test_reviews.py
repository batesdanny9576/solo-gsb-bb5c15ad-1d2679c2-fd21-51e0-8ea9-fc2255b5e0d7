"""跨审计复核标记的自测（无测试框架依赖）：python -m tests.test_reviews

使用独立临时 SQLite 库，不触碰 ./data；只依赖 analyzer/compare/database/reviews，
无需安装 fastapi 即可运行。
"""

from __future__ import annotations

import hashlib
import sqlite3
import tempfile
from pathlib import Path

from app import analyzer, compare as compare_mod, database, reviews

# 隔离的临时数据库（database.connect 在调用时读取 DB_PATH，运行时替换即可）
_TMP_DIR = tempfile.mkdtemp(prefix="reviews-test-")
database.DB_PATH = Path(_TMP_DIR) / "test.db"
database.init_db()


# 旧版 v1 指纹算法（"|" 直接拼接五字段，存在字段边界串用），仅用于构造历史数据
def _v1_fingerprint(ancestor: str, node: str, anc_lic: str, node_lic: str) -> str:
    raw = "|".join(["v1", ancestor, node, anc_lic, node_lic])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


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
    # 字段边界隔离：竖线跨字段重组不得得到同一指纹（v1 会碰撞的两组身份）
    boundary_a = ("a@1|b@1", "c@1", "GPL-2.0", "Apache-2.0")
    boundary_b = ("a@1", "b@1|c@1", "GPL-2.0", "Apache-2.0")
    _check(
        "pipe boundary split does not collide",
        reviews.conflict_fingerprint(*boundary_a)
        != reviews.conflict_fingerprint(*boundary_b),
    )
    _check(
        "pipe inside license token keeps boundary",
        reviews.conflict_fingerprint("a", "b", "x|y", "z")
        != reviews.conflict_fingerprint("a", "b", "x", "y|z"),
    )
    _check("fingerprint carries v2 version tag", reviews.FINGERPRINT_VERSION == "v2")


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


def _boundary_manifest() -> dict:
    # 同一份审计内含两条四字段身份不同、旧 v1 指纹却相同的冲突：
    # C001: a@1 -> b@1|c@1；C002: a@1|b@1 -> c@1（许可证同为 GPL-2.0/Apache-2.0）
    return {
        "name": "boundary-demo",
        "packages": [
            {"name": "a", "version": "1", "license": "GPL-2.0",
             "dependencies": ["b@1|c@1"]},
            {"name": "b@1|c", "version": "1", "license": "Apache-2.0"},
            {"name": "a@1|b", "version": "1", "license": "GPL-2.0",
             "dependencies": ["c@1"]},
            {"name": "c", "version": "1", "license": "Apache-2.0"},
        ],
    }


def test_boundary_identities_isolated() -> None:
    identity_a = ("a@1", "b@1|c@1", "GPL-2.0", "Apache-2.0")
    identity_b = ("a@1|b@1", "c@1", "GPL-2.0", "Apache-2.0")
    # 旧 v1 确实碰撞，新 v2 不碰撞（回归前提）
    _check(
        "legacy v1 collides (bug premise)",
        _v1_fingerprint(*identity_a) == _v1_fingerprint(*identity_b),
    )
    fp_a = reviews.conflict_fingerprint(*identity_a)
    fp_b = reviews.conflict_fingerprint(*identity_b)
    _check("v2 fingerprints distinct", fp_a != fp_b)

    result = analyzer.analyze_manifest(_boundary_manifest())
    audit_id = database.save_audit(result, result["manifest_name"])
    result["audit_id"] = audit_id
    conflicts = {c["node"]: c for c in result["conflicts"]}
    c_a = conflicts["b@1|c@1"]
    c_b = conflicts["c@1"]
    _check("both boundary conflicts present",
           c_a["ancestor"] == "a@1" and c_b["ancestor"] == "a@1|b@1")

    # 只复核第一条（a@1 -> b@1|c@1）
    record = database.save_review(
        fingerprint=fp_a, ancestor=identity_a[0], node=identity_a[1],
        ancestor_license=identity_a[2], node_license=identity_a[3],
        note="只确认第一条关系",
    )
    attached = reviews.attach_reviews(database.get_audit(audit_id))
    by_node = {c["node"]: c["review"] for c in attached["conflicts"]}
    _check(
        "first conflict reviewed",
        by_node["b@1|c@1"]["state"] == reviews.REVIEWED
        and by_node["b@1|c@1"]["review_id"] == record["id"],
    )
    _check(
        "second conflict stays pending (no cross-wiring)",
        by_node["c@1"]["state"] == reviews.PENDING,
        str(by_node["c@1"]),
    )
    _check(
        "summary counts isolated",
        attached["summary"]["review"] == {"reviewed": 1, "pending": 1},
    )

    # 复核第二条不会取代第一条（取代按四字段身份隔离）
    record_b = database.save_review(
        fingerprint=fp_b, ancestor=identity_b[0], node=identity_b[1],
        ancestor_license=identity_b[2], node_license=identity_b[3],
        note="确认第二条关系",
    )
    _check(
        "first mark not superseded by second identity",
        database.get_review(record["id"])["state"] == database.REVIEW_ACTIVE,
    )
    attached = reviews.attach_reviews(database.get_audit(audit_id))
    by_node = {c["node"]: c["review"] for c in attached["conflicts"]}
    _check("both reviewed independently",
           by_node["b@1|c@1"]["state"] == reviews.REVIEWED
           and by_node["c@1"]["state"] == reviews.REVIEWED
           and by_node["b@1|c@1"]["review_id"] == record["id"]
           and by_node["c@1"]["review_id"] == record_b["id"])

    # 同一关系跨审计仍复用同一条标记
    again_id = database.save_audit(
        analyzer.analyze_manifest(_boundary_manifest()), _boundary_manifest()
    )
    _check("second audit created", again_id != audit_id)
    attached = reviews.attach_reviews(database.get_audit(again_id))
    by_node = {c["node"]: c["review"] for c in attached["conflicts"]}
    _check(
        "same relation reuses mark across audits",
        by_node["b@1|c@1"]["review_id"] == record["id"]
        and by_node["c@1"]["review_id"] == record_b["id"],
    )

    # 防御纵深：即使指纹列被改成与另一身份查询相同的值（旧串用残留/碰撞），
    # 读取仍按四字段身份拒绝错配。此时数据库中 B 的标记指纹即 fp_b，
    # 用 A 的四字段身份去查 fp_b 必须命不中。
    guarded = database.active_review_map({fp_b: identity_a})
    _check("read rejects fingerprint row with mismatched identity", fp_b not in guarded)
    # 正确身份仍正常命中
    guarded = database.active_review_map({fp_b: identity_b, fp_a: identity_a})
    _check("read accepts exact identity",
           guarded[fp_b]["id"] == record_b["id"] and guarded[fp_a]["id"] == record["id"])
    # 纯指纹序列调用方（兼容路径）仍可用
    _check("plain fingerprint iterable still supported", fp_b in database.active_review_map([fp_b]))


def test_legacy_v1_fingerprint_migration() -> None:
    """启动迁移：旧库 v1 串用指纹按四字段重算，保留全部历史属性，可重复执行。"""
    legacy_dir = tempfile.mkdtemp(prefix="reviews-legacy-")
    legacy_db = Path(legacy_dir) / "legacy.db"

    identity_a = ("a@1", "b@1|c@1", "GPL-2.0", "Apache-2.0")
    identity_b = ("a@1|b@1", "c@1", "GPL-2.0", "Apache-2.0")
    colliding = _v1_fingerprint(*identity_a)
    _check("fixture uses colliding v1 fingerprint", colliding == _v1_fingerprint(*identity_b))

    # 手工建一个“升级前”的库：schema 不含 schema_meta，reviews 内含各状态记录
    conn = sqlite3.connect(legacy_db)
    conn.execute(
        """
        CREATE TABLE reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT, fingerprint TEXT NOT NULL,
            ancestor TEXT NOT NULL, node TEXT NOT NULL,
            ancestor_license TEXT NOT NULL, node_license TEXT NOT NULL,
            note TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'active',
            expires_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
            revoked_at TEXT)
        """
    )
    rows = [
        # id=1: active，身份 A（旧串用指纹）
        (colliding, *identity_a, "有效备注", database.REVIEW_ACTIVE, None,
         "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00", None),
        # id=2: superseded，身份 B（同一旧指纹）
        (colliding, *identity_b, "被取代备注", database.REVIEW_SUPERSEDED, None,
         "2026-01-02T00:00:00+00:00", "2026-01-03T00:00:00+00:00", None),
        # id=3: revoked
        (colliding, *identity_b, "已撤销备注", database.REVIEW_REVOKED, None,
         "2026-01-04T00:00:00+00:00", "2026-01-05T00:00:00+00:00",
         "2026-01-05T00:00:00+00:00"),
        # id=4: active 但已过期
        (colliding, *identity_a, "过期备注", database.REVIEW_ACTIVE,
         "2020-01-01T00:00:00+00:00", "2026-01-06T00:00:00+00:00",
         "2026-01-06T00:00:00+00:00", None),
    ]
    conn.executemany(
        """
        INSERT INTO reviews
            (fingerprint, ancestor, node, ancestor_license, node_license,
             note, status, expires_at, created_at, updated_at, revoked_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    conn.commit()
    conn.close()

    saved_db_path = database.DB_PATH
    try:
        database.DB_PATH = legacy_db
        database.init_db()  # 建表 + 同一事务内迁移

        fp_a = reviews.conflict_fingerprint(*identity_a)
        fp_b = reviews.conflict_fingerprint(*identity_b)
        r1, r2, r3, r4 = (database.get_review(i) for i in (1, 2, 3, 4))
        _check("active record recomputed to own fingerprint", r1["fingerprint"] == fp_a)
        _check("superseded record recomputed separately", r2["fingerprint"] == fp_b
               and fp_a != fp_b)
        _check("revoked record recomputed", r3["fingerprint"] == fp_b)
        _check("expired record recomputed", r4["fingerprint"] == fp_a)

        # id / 备注 / 时间 / 状态全部保留
        _check("id note times status preserved for active",
               r1["id"] == 1 and r1["note"] == "有效备注"
               and r1["created_at"] == "2026-01-01T00:00:00+00:00"
               and r1["updated_at"] == "2026-01-01T00:00:00+00:00"
               and r1["state"] == database.REVIEW_ACTIVE and r1["revoked_at"] is None)
        _check("superseded stays superseded",
               r2["state"] == database.REVIEW_SUPERSEDED
               and r2["note"] == "被取代备注")
        _check("revoked not restored",
               r3["state"] == database.REVIEW_REVOKED
               and r3["revoked_at"] == "2026-01-05T00:00:00+00:00")
        _check("expired not restored", r4["state"] == database.REVIEW_EXPIRED)

        # 读取按隔离后的指纹各归各：身份 A 命中 #1，身份 B 无有效标记
        marks = database.active_review_map({fp_a: identity_a, fp_b: identity_b})
        _check("identity A attaches only its own mark",
               marks.get(fp_a, {}).get("id") == 1 and fp_b not in marks)

        # 迁移可重复执行：再启动一次不改动任何指纹
        with database.connect() as conn:
            before = conn.execute(
                "SELECT id, fingerprint FROM reviews ORDER BY id"
            ).fetchall()
        database.init_db()
        with database.connect() as conn:
            after = conn.execute(
                "SELECT id, fingerprint FROM reviews ORDER BY id"
            ).fetchall()
        _check("migration idempotent on restart",
               [tuple(r) for r in before] == [tuple(r) for r in after])
    finally:
        database.DB_PATH = saved_db_path


def main() -> None:
    test_fingerprint()
    test_normalize_expires_at()
    test_mark_and_cross_audit_attach()
    test_license_change_returns_pending()
    test_expiry_returns_pending()
    test_revoke_returns_pending()
    test_latest_mark_supersedes()
    test_boundary_identities_isolated()
    test_legacy_v1_fingerprint_migration()
    test_stored_result_and_compare_untouched()
    print("\nall review tests passed.")


if __name__ == "__main__":
    main()
