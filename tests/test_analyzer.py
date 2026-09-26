"""核心分析逻辑的轻量自测（无测试框架依赖）：python -m tests.test_analyzer"""

from __future__ import annotations

from app import analyzer, licenses


def _check(name: str, condition: bool, detail: str = "") -> None:
    if not condition:
        raise AssertionError("%s %s" % (name, detail))
    print("ok -", name)


def test_normalization() -> None:
    cases = {
        "MIT": ("MIT", True),
        "mit license": ("MIT", True),
        "Apache 2.0": ("Apache-2.0", True),
        "gplv3": ("GPL-3.0", True),
        "lgplv2": ("LGPL-2.1", True),
        "BSD3": ("BSD-3-Clause", True),
        "CC0": ("CC0-1.0", True),
        "GPL-3.0-or-later": ("GPL-3.0", True),
        "commercial": ("Proprietary", True),
        "OFL-1.1": ("ofl-1.1", False),
    }
    for raw, (token, known) in cases.items():
        _, got_token, got_known = licenses.normalize_license(raw)
        _check("normalize %r" % raw, got_token == token and got_known == known)


def test_matrix_rules() -> None:
    expectations = [
        ("MIT", "GPL-3.0", licenses.OK),
        ("GPL-2.0", "Apache-2.0", licenses.CONFLICT),
        ("GPL-3.0", "Proprietary", licenses.CONFLICT),
        ("Proprietary", "MIT", licenses.OK),
        ("Proprietary", "LGPL-3.0", licenses.WARNING),
        ("Proprietary", "GPL-2.0", licenses.CONFLICT),
        ("MPL-2.0", "GPL-2.0", licenses.CONFLICT),
        ("MPL-2.0", "GPL-3.0", licenses.OK),
        ("AGPL-3.0", "Proprietary", licenses.CONFLICT),
        ("MIT", "Proprietary", licenses.WARNING),
        ("MIT", "weird-license", licenses.WARNING),
    ]
    for parent, dep, want in expectations:
        got, reason = licenses.compatibility(parent, dep)
        _check("compat %s->%s == %s (%s)" % (parent, dep, got, reason), got == want)


def test_transitive_and_shortest_path() -> None:
    manifest = {
        "name": "t",
        "packages": [
            {"name": "app", "version": "1", "license": "GPL-3.0",
             "dependencies": ["mid@1"]},
            {"name": "mid", "version": "1", "license": "MIT",
             "dependencies": ["leaf@1"]},
            {"name": "leaf", "version": "1", "license": "Proprietary"},
        ],
        "edges": [{"source": "app@1", "target": "leaf@1"}],
    }
    result = analyzer.analyze_manifest(manifest)
    direct = [
        c for c in result["conflicts"]
        if c["ancestor"] == "app@1" and c["node"] == "leaf@1"
    ]
    _check("one app->leaf conflict", len(direct) == 1)
    _check(
        "shortest path uses direct edge",
        direct[0]["distance"] == 1 and direct[0]["path"] == ["app@1", "leaf@1"],
        str(direct[0]["path"]),
    )
    leaf = next(n for n in result["nodes"] if n["id"] == "leaf@1")
    sources = {c["from"] for c in leaf["constraints"]}
    _check("leaf constrained by app", "app@1" in sources, str(sources))


def test_cycle_safe() -> None:
    manifest = {
        "packages": [
            {"name": "a", "version": "1", "license": "MIT", "dependencies": ["b@1"]},
            {"name": "b", "version": "1", "license": "MIT", "dependencies": ["a@1"]},
        ]
    }
    result = analyzer.analyze_manifest(manifest)
    _check("cycle does not crash", result["status"] == "clean")
    _check("cycle keeps 2 edges", result["summary"]["edges"] == 2)


def test_unresolved_and_filter() -> None:
    manifest = {
        "packages": [
            {"name": "app", "version": "1", "license": "MIT",
             "dependencies": ["ghost", "lib"]},
            {"name": "lib", "version": "1", "license": "MIT"},
            {"name": "lib", "version": "2", "license": "GPL-3.0"},
        ]
    }
    result = analyzer.analyze_manifest(manifest)
    refs = {u["reference"] for u in result["unresolved"]}
    _check("unknown + ambiguous refs unresolved", refs == {"ghost", "lib"}, str(refs))
    filtered = analyzer.filter_result(result, "lib")
    _check("filter keeps only lib nodes", {n["id"] for n in filtered["nodes"]} == {"lib@1", "lib@2"})


def test_inline_dependency_registration_order() -> None:
    """包内 dependencies：内联包先统一登记，解析结果与书写顺序无关。

    packages 已声明 lib@1，包内 dependencies 同时出现无版本引用 "lib" 与
    带许可证的内联 lib@2 时：无版本引用应进入未解析并提示 name@version 消歧，
    显式版本仍建立依赖边；调换 dependencies / packages 顺序结果不变。
    """
    inline = {"name": "lib", "version": "2", "license": "GPL-3.0"}

    def build(deps, pkg_order):
        pkgs = {
            "lib": {"name": "lib", "version": "1", "license": "MIT"},
            "app": {"name": "app", "version": "1", "license": "MIT",
                    "dependencies": deps},
        }
        return {"name": "repro", "packages": [pkgs[key] for key in pkg_order]}

    signatures = []
    for deps in (["lib", inline], [inline, "lib"]):
        for pkg_order in (("lib", "app"), ("app", "lib")):
            result = analyzer.analyze_manifest(build(deps, pkg_order))
            signatures.append((
                sorted((e["source"], e["target"]) for e in result["edges"]),
                sorted((u["source"], u["reference"], u["reason"]) for u in result["unresolved"]),
                sorted(n["id"] for n in result["nodes"]),
                sorted(result["warnings"]),
            ))
    _check(
        "resolution independent of declaration order",
        all(sig == signatures[0] for sig in signatures),
        str(signatures),
    )
    edges, unresolved, nodes, _ = signatures[0]
    _check("explicit version edge kept", edges == [("app@1", "lib@2")], str(edges))
    _check(
        "version-less ref unresolved with disambiguation hint",
        unresolved == [("app@1", "lib", "存在多个版本：lib@1, lib@2，请用 name@version 消歧")],
        str(unresolved),
    )
    _check("inline package registered as node", nodes == ["app@1", "lib@1", "lib@2"], str(nodes))


def test_inline_dependency_unique_name_still_resolves() -> None:
    """内联包预登记后，名字唯一的无版本引用仍可自动解析（含跨包引用）。"""
    manifest = {
        "packages": [
            {"name": "app", "version": "1", "license": "MIT",
             "dependencies": [{"name": "util", "version": "2", "license": "Apache-2.0"}]},
            {"name": "other", "version": "1", "license": "MIT",
             "dependencies": ["util"]},
        ]
    }
    result = analyzer.analyze_manifest(manifest)
    edges = sorted((e["source"], e["target"]) for e in result["edges"])
    _check(
        "unique inline name resolves from any package",
        edges == [("app@1", "util@2"), ("other@1", "util@2")],
        str(edges),
    )
    _check("no unresolved refs", result["unresolved"] == [], str(result["unresolved"]))


def _build_chain(n: int, license_of) -> dict:
    packages = []
    for i in range(n):
        packages.append({
            "name": "pkg-%03d" % i,
            "version": "1.0.0",
            "license": license_of(i),
            "dependencies": (["pkg-%03d@1.0.0" % (i + 1)] if i + 1 < n else []),
        })
    return {"name": "chain", "packages": packages}


def test_long_chain_constraint_distances() -> None:
    """长链（无冲突）：每项传递约束的 distance 等于链上最短跳数。"""
    n = 60
    result = analyzer.analyze_manifest(_build_chain(n, lambda i: "GPL-3.0"))
    _check("long chain stays clean", result["status"] == "clean", result["status"])
    _check("long chain has no conflicts", result["conflicts"] == [])
    nodes = {node["id"]: node for node in result["nodes"]}
    for i in range(n):
        node = nodes["pkg-%03d@1.0.0" % i]
        distances = [c["distance"] for c in node["constraints"]]
        sources = [c["from"] for c in node["constraints"]]
        _check(
            "chain node %d constrained by all ancestors" % i,
            len(distances) == i,
            str(distances),
        )
        # 约束按 (distance, from) 排序：单链上第 j 个祖先的距离恰为 i - j
        want = sorted(
            (("pkg-%03d@1.0.0" % j), i - j) for j in range(i)
        )
        got = sorted(zip(sources, distances))
        _check("chain node %d distances are shortest hops" % i, got == want, str(got))
        _check(
            "chain node %d has no hard conflicts" % i,
            node["conflict_count"] == 0,
            str(node["conflict_count"]),
        )


def test_long_chain_conflict_count_and_paths() -> None:
    """长链末端硬冲突：conflict_count 逐节点累计，冲突路径/距离与最短路一致。"""
    n = 40
    # 全部 GPL-2.0，末端一个 Apache-2.0：每个祖先对末端都是硬冲突
    result = analyzer.analyze_manifest(
        _build_chain(n, lambda i: "Apache-2.0" if i == n - 1 else "GPL-2.0")
    )
    leaf = "pkg-%03d@1.0.0" % (n - 1)
    leaf_conflicts = [c for c in result["conflicts"] if c["node"] == leaf]
    _check(
        "every ancestor conflicts with leaf",
        len(leaf_conflicts) == n - 1 and all(c["severity"] == "error" for c in leaf_conflicts),
        str(len(leaf_conflicts)),
    )
    for conflict in leaf_conflicts:
        j = int(conflict["ancestor"].split("@")[0].rsplit("-", 1)[1])
        want_distance = n - 1 - j
        _check(
            "conflict distance is shortest hops",
            conflict["distance"] == want_distance
            and len(conflict["path"]) == want_distance + 1
            and conflict["path"][0] == conflict["ancestor"]
            and conflict["path"][-1] == leaf,
            str(conflict["path"]),
        )
    nodes = {node["id"]: node for node in result["nodes"]}
    _check(
        "leaf accumulates all hard conflicts",
        nodes[leaf]["conflict_count"] == n - 1,
        str(nodes[leaf]["conflict_count"]),
    )
    _check(
        "other nodes have no hard conflicts",
        all(nodes["pkg-%03d@1.0.0" % i]["conflict_count"] == 0 for i in range(n - 1)),
    )


def main() -> None:
    test_normalization()
    test_matrix_rules()
    test_transitive_and_shortest_path()
    test_cycle_safe()
    test_unresolved_and_filter()
    test_inline_dependency_registration_order()
    test_inline_dependency_unique_name_still_resolves()
    test_long_chain_constraint_distances()
    test_long_chain_conflict_count_and_paths()
    print("\nall tests passed.")


if __name__ == "__main__":
    main()
