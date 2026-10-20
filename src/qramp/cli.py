# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ti Zhang
"""qramp.cli — command-line interface."""
from __future__ import annotations

import argparse
import json
import sys

from . import Inventory, scan, assess as A, plan as P, report as R, diff as model_diff
from .collectors.tls import sign_scope


def _policy_worse_count(rep: dict) -> int:
    """Count 'worse' changes in a policy-diff report for the CI gate: assets
    promoted to a more urgent tier, newly blocked, or newly un-suppressed."""
    kind = rep.get("kind")
    if kind == "rules":
        return rep.get("worsened", 0)
    if kind == "provider-map":
        return len(rep.get("newly_blocked", []))
    if kind == "vex":
        return len(rep.get("removed", []))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="qramp", description="Cryptographic inventory & PQC migration planning")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="collect evidence into a CBOM")
    s.add_argument("--source"); s.add_argument("--sbom"); s.add_argument("--certs")
    s.add_argument("--config"); s.add_argument("--scope"); s.add_argument("--scope-key")
    s.add_argument("--manifests", nargs="?", const="__source__", metavar="DIR",
                   help="auto-discover components from package manifests "
                        "(package-lock.json, requirements.txt, go.mod, pom.xml, "
                        "Cargo.lock); defaults to --source if no DIR given")
    s.add_argument("--alias-map",
                   help="manifest package-name alias map YAML (default: built-in)")
    s.add_argument("--provider-map"); s.add_argument("--owners",
                   help="YAML mapping of filename -> owning team")
    s.add_argument("--query-dir",
                   help="directory of site .scm query files (overrides/extends "
                        "built-in detection rules; also QRAMP_QUERY_DIR or "
                        "./.qramp/queries)")
    s.add_argument("-o", "--out", default="cbom.json")

    a = sub.add_parser("assess", help="classify and prioritise a CBOM")
    a.add_argument("cbom"); a.add_argument("--rules", required=True)
    a.add_argument("--lifetimes", required=True); a.add_argument("-o", "--out", default="assessment.json")

    p = sub.add_parser("plan", help="compile a migration plan")
    p.add_argument("assessment"); p.add_argument("--capacity", required=True)
    p.add_argument("--horizon", default="24m"); p.add_argument("-o", "--out", default="plan.yaml")
    p.add_argument("--solver", choices=["auto", "cpsat", "list"], default="auto",
                   help="scheduling backend (default: auto = cp-sat if OR-Tools present)")
    p.add_argument("--time-limit", type=float, default=10.0,
                   help="CP-SAT time limit in seconds")

    v = sub.add_parser("verify", help="evaluate task acceptance against a supplied fresh CBOM")
    v.add_argument("plan"); v.add_argument("--against", required=True, help="freshly collected CBOM")
    v.add_argument("--phase", type=int); v.add_argument("--evidence-out", default="evidence.json")
    v.add_argument("--active-probe", action="store_true",
                   help="confirm enable-hybrid-kex with a real PQ handshake")
    v.add_argument("--scope", help="signed scope file naming probe targets")
    v.add_argument("--scope-key", help="HMAC key for the scope file")
    v.add_argument("--attempts", type=int, default=5,
                   help="handshakes per endpoint for the success-rate measurement")

    d = sub.add_parser("diff", help="compare two CBOMs")
    d.add_argument("old"); d.add_argument("new")
    d.add_argument("--detailed", action="store_true",
                   help="provenance-aware diff: coverage gaps + classification conflicts")

    im = sub.add_parser("import", help="import a third-party CycloneDX CBOM")
    im.add_argument("cbom", help="external CycloneDX 1.6 JSON file")
    im.add_argument("--tool", help="override the producing-tool name for provenance")
    im.add_argument("--merge", help="an existing QRAMP CBOM to merge the import into")
    im.add_argument("-o", "--out", required=True)

    ip = sub.add_parser("impact", help="dependency-graph impact of a library or asset")
    ip.add_argument("cbom", help="a CBOM/assessment carrying SBOM components")
    ip.add_argument("--component", help="show crypto assets a component provides "
                    "(and which would be lost if it were removed)")
    ip.add_argument("--algorithm", help="show which components provide an algorithm")
    ip.add_argument("--list", action="store_true", help="list all components and their provides counts")

    ch = sub.add_parser("chain", help="certificate trust-chain / weakest-link analysis")
    ch.add_argument("cbom", help="a CBOM/assessment carrying certificate nodes")
    ch.add_argument("--leaf", help="analyse one leaf by subject substring (default: all leaves)")
    ch.add_argument("--weak-only", action="store_true",
                    help="show only chains with a weakest-link problem")

    e = sub.add_parser("export", help="export plan as issues/csv, a CBOM as CycloneDX/SARIF, or VEX")
    e.add_argument("plan"); e.add_argument("--format",
                   choices=["issues", "csv", "cyclonedx", "sarif", "vex"], default="issues")
    e.add_argument("--rules", help="rule pack YAML (for SARIF rule metadata)")
    e.add_argument("--min-level", choices=["error", "warning", "note"], default="note",
                   help="SARIF: drop results below this severity")
    e.add_argument("--include-ok", action="store_true",
                   help="SARIF: also emit PQ-ready/OK assets as notes")
    e.add_argument("--vex", help="a VEX document to apply as suppressions (SARIF export)")
    e.add_argument("--vex-format", choices=["openvex", "cyclonedx"], default="openvex",
                   help="VEX export dialect")
    e.add_argument("-o", "--out", required=True)

    r = sub.add_parser("report", help="render static HTML dashboard")
    r.add_argument("cbom"); r.add_argument("-o", "--out", default="dashboard.html")
    r.add_argument("--map", help="provider-map YAML for the readiness panel "
                   "(default: the built-in map)")
    r.add_argument("--vex", help="a VEX document; suppressed assets are marked in the table")
    r.add_argument("--history", nargs="+", metavar="CBOM",
                   help="one or more historical assessed CBOMs (or a directory); "
                        "embeds a migration-progress trend chart")

    gr = sub.add_parser("graph",
                        help="export a graph as Graphviz DOT or Mermaid text")
    gr.add_argument("cbom", help="an assessed CBOM")
    gr.add_argument("--which", choices=["dependency", "chain"], default="dependency",
                    help="which graph to export (default: dependency)")
    gr.add_argument("--format", choices=["dot", "mermaid"], default="dot",
                    help="output notation (default: dot)")
    gr.add_argument("-o", "--out", help="write to this file (default: stdout)")

    bd = sub.add_parser("bundle",
                        help="assemble a shareable static report site (dashboard, "
                             "progress report, graphs, and data exports + index)")
    bd.add_argument("cbom", help="an assessed CBOM")
    bd.add_argument("-o", "--out", default="qramp-report",
                    help="output directory (default: qramp-report)")
    bd.add_argument("--map", help="provider-map YAML (default: the built-in map)")
    bd.add_argument("--vex", help="a VEX document; applied to the dashboard and SARIF")
    bd.add_argument("--history", nargs="+", metavar="CBOM",
                    help="historical assessed CBOMs (or a directory) for the "
                         "progress report")
    bd.add_argument("--rules", help="the rule pack (for SARIF rule descriptions)")
    bd.add_argument("--title", default="QRAMP report",
                    help="title shown on the index page")

    rcd = sub.add_parser("repo-card",
                         help="emit a compact per-repo posture card for the org "
                              "dashboard")
    rcd.add_argument("assessment", help="an assessed CBOM")
    rcd.add_argument("-o", "--out", required=True, help="write the card JSON here")
    rcd.add_argument("--name", required=True, help="the repository name")
    rcd.add_argument("--map", help="provider-map YAML (for the readiness metric)")
    rcd.add_argument("--gates", help="the CI gates.json for this repo")
    rcd.add_argument("--url", help="a link to the repo's run or report")

    od = sub.add_parser("org-dashboard",
                        help="aggregate repo cards into one static org dashboard")
    od.add_argument("cards", nargs="+",
                    help="repo-card JSON files or directories of them")
    od.add_argument("-o", "--out", required=True, help="write the HTML dashboard here")
    od.add_argument("--title", default="PQC migration — organisation",
                    help="dashboard heading")

    pc = sub.add_parser("pr-comment",
                        help="emit a compact Markdown summary of a scan for a "
                             "pull-request comment")
    pc.add_argument("cbom", help="an assessed CBOM")
    pc.add_argument("--map", help="provider-map YAML (default: the built-in map)")
    pc.add_argument("--history", nargs="+", metavar="CBOM",
                    help="historical assessed CBOMs (or a directory) for the trend")
    pc.add_argument("--base", metavar="CBOM",
                    help="the base-branch assessed CBOM; adds a 'change vs base' "
                         "section showing which assets this PR adds/removes")
    pc.add_argument("--gates", metavar="JSON",
                    help="a JSON file mapping gate name -> outcome "
                         "(success/failure/skipped); adds a 'Gate results' section")
    pc.add_argument("--title", default="QRAMP — PQC posture",
                    help="heading shown in the comment")
    pc.add_argument("--subtitle", help="a branding line under the heading "
                    "(e.g. a company or service name)")
    pc.add_argument("--compact", action="store_true",
                    help="fold the trend and recommendation sections into a "
                    "collapsible block to keep the comment short")
    pc.add_argument("--report-url", help="link to the full report (e.g. an "
                    "artifact or pages URL)")
    pc.add_argument("-o", "--out", help="write to this file (default: stdout)")

    sc = sub.add_parser("sign-scope", help="HMAC-sign a TLS scope file")
    sc.add_argument("scope"); sc.add_argument("--key", required=True)

    lr = sub.add_parser("lint-rules", help="static-check a rule pack; optional snapshot regression")
    lr.add_argument("rules", help="rule pack YAML")
    lr.add_argument("--snapshot", help="a snapshot JSON to regress against "
                    "(fixtures + expected classifications)")
    lr.add_argument("--update-snapshot", action="store_true",
                    help="rewrite the snapshot's expected classifications from the current rule pack")
    lr.add_argument("--strict", action="store_true",
                    help="exit non-zero on warnings too, not just errors")

    lp = sub.add_parser("lint-provider-map", help="static-check a provider map")
    lp.add_argument("map", nargs="?", help="provider-map YAML (default: the built-in map)")
    lp.add_argument("--snapshot", help="a resolution snapshot JSON to regress against")
    lp.add_argument("--strict", action="store_true",
                    help="exit non-zero on warnings too, not just errors")

    lv = sub.add_parser("lint-vex", help="static-check a VEX document")
    lv.add_argument("vex", help="VEX YAML/JSON document")
    lv.add_argument("--cbom", help="an assessed CBOM to check every statement "
                    "targets a real asset")
    lv.add_argument("--strict", action="store_true",
                    help="exit non-zero on warnings too, not just errors")

    bl = sub.add_parser("baseline",
                        help="freeze the currently-exposed assets as an accepted "
                             "backlog so a gate blocks only new regressions")
    bl.add_argument("assessment", help="an assessed CBOM")
    bl.add_argument("-o", "--out", required=True, help="write the baseline JSON here")
    bl.add_argument("--exposure", default="quantum_broken",
                    help="comma-separated exposure classes to baseline "
                         "(default: quantum_broken)")

    bc = sub.add_parser("baseline-check",
                        help="fail only when a new exposed asset appears that is "
                             "not in the accepted baseline")
    bc.add_argument("assessment", help="an assessed CBOM")
    bc.add_argument("--baseline", required=True, help="the baseline JSON")
    bc.add_argument("--exposure",
                    help="override the exposure classes (default: the baseline's)")
    bc.add_argument("--strict", action="store_true",
                    help="also fail when the baseline has stale entries (assets no "
                         "longer exposed), forcing the acceptance to ratchet down")

    la = sub.add_parser("lint-aliases",
                        help="static-check a manifest package-name alias map")
    la.add_argument("aliases", nargs="?",
                    help="alias map YAML (default: the built-in map)")
    la.add_argument("--map", help="a provider map to check alias targets against")
    la.add_argument("--snapshot",
                    help="a resolution snapshot JSON to regress against")
    la.add_argument("--update-snapshot", action="store_true",
                    help="rewrite the --snapshot file from the current alias map")
    la.add_argument("--cbom", help="an assessed CBOM; report the wrapper coverage "
                    "of the packages it discovered")
    la.add_argument("--max-wrapper-pct", type=float, metavar="PCT",
                    help="fail if more than PCT%% of the CBOM's mapped packages "
                    "resolve through wrappers (needs --cbom)")
    la.add_argument("--strict", action="store_true",
                    help="exit non-zero on warnings too, not just errors")

    pv = sub.add_parser("provenance",
                        help="print the rule-pack provenance table (rule → class "
                             "→ governing standards) for audit documentation")
    pv.add_argument("rules", nargs="?",
                    help="rule pack YAML (default: the built-in pack)")
    pv.add_argument("--format", choices=["text", "markdown", "json"], default="text",
                    help="output format (default: text)")
    pv.add_argument("--cbom", help="an assessed CBOM; restrict to rules that "
                    "actually fired, with occurrence counts")
    pv.add_argument("--require-references", action="store_true",
                    help="exit non-zero if any rule (or, with --cbom, any rule "
                    "that fired) has no governing-standard references — a "
                    "coverage gate so an un-sourced classification cannot ship")

    pd = sub.add_parser("policy-diff",
                        help="show what a policy change does to a real inventory")
    pd.add_argument("cbom", help="an assessed CBOM (the real assets to re-evaluate)")
    pd.add_argument("--kind", required=True,
                    choices=["rules", "provider-map", "vex"],
                    help="which policy file is changing")
    pd.add_argument("--old", required=True, help="the current policy file")
    pd.add_argument("--new", required=True, help="the proposed policy file")
    pd.add_argument("--lifetimes", help="data-lifetimes YAML (for rules tier re-computation)")
    pd.add_argument("--json", action="store_true", help="emit the full diff as JSON")
    pd.add_argument("--fail-on-worse", action="store_true",
                    help="exit non-zero if any asset is promoted to a more urgent tier "
                    "or newly blocked / un-suppressed")

    rp = sub.add_parser("resolve-provider",
                        help="show which capabilities a component version provides")
    rp.add_argument("component", help="component name, e.g. openssl")
    rp.add_argument("version", help="version, e.g. 3.5.0")
    rp.add_argument("--map", help="provider-map YAML (default: the built-in map)")

    rd = sub.add_parser("readiness",
                        help="migration readiness score + ROI-ranked upgrade advice")
    rd.add_argument("cbom", help="an assessed CBOM carrying SBOM components")
    rd.add_argument("--map", help="provider-map YAML (default: the built-in map)")
    rd.add_argument("--json", action="store_true", help="emit the full report as JSON")
    rd.add_argument("--min-readiness", type=float, metavar="PCT",
                    help="exit non-zero if migration readiness is below PCT percent")
    rd.add_argument("--max-unaddressable", type=int, metavar="N",
                    help="exit non-zero if more than N blocked assets cannot be "
                    "addressed by any available library upgrade")

    sm = sub.add_parser("simulate",
                        help="model the effect of a library upgrade before doing it")
    sm.add_argument("cbom", help="an assessed CBOM carrying SBOM components")
    sm.add_argument("--upgrade", action="append", required=True, metavar="NAME=VERSION",
                    help="a component upgrade, e.g. --upgrade openssl=3.5 "
                    "(repeatable)")
    sm.add_argument("--map", help="provider-map YAML (default: the built-in map)")
    sm.add_argument("--json", action="store_true", help="emit the full diff as JSON")

    tl = sub.add_parser("timeline",
                        help="track migration progress across a series of scans")
    tl.add_argument("cbom", nargs="+",
                    help="two or more assessed CBOMs (or a directory of them)")
    tl.add_argument("--label", action="append",
                    help="a label per CBOM, in order (repeatable)")
    tl.add_argument("--series", default="P0,P1",
                    help="comma-separated tiers to plot (default: P0,P1)")
    tl.add_argument("--svg", help="write the trend chart to this SVG file")
    tl.add_argument("--html", help="write a standalone HTML progress report here")
    tl.add_argument("--json", action="store_true", help="emit the full series as JSON")
    tl.add_argument("--min-improvement", type=int, metavar="N",
                    help="exit non-zero if the urgent (P0+P1) count did not fall "
                    "by at least N since the first scan (a CI progress ratchet)")

    args = ap.parse_args(argv)

    if args.cmd == "scan":
        if not any((args.source, args.sbom, args.certs, args.config, args.scope, args.manifests)):
            ap.error("scan requires at least one evidence source")
        if args.manifests == "__source__" and not args.source:
            ap.error("--manifests without a directory requires --source")
        inv = Inventory()
        owner_map = None
        if args.owners:
            import yaml as _yaml
            owner_map = _yaml.safe_load(open(args.owners, encoding="utf-8"))
        manifests_dir = None
        if args.manifests is not None:
            manifests_dir = (args.source if args.manifests == "__source__"
                             else args.manifests)
        scan(inv, source_dir=args.source, sbom_path=args.sbom, cert_dir=args.certs,
             config_dir=args.config, scope_path=args.scope, scope_key=args.scope_key,
             provider_map=args.provider_map, owner_map=owner_map,
             query_dir=args.query_dir, manifests_dir=manifests_dir,
             alias_map=args.alias_map)
        inv.save(args.out)
        print(f"[scan] {len(inv)} assets, {inv.occurrence_count()} occurrences -> {args.out}")
        for c in inv.meta["collectors"]:
            print("       ", c)
        return 0

    if args.cmd == "assess":
        summ = A.assess(args.cbom, args.rules, args.lifetimes, args.out)
        print(f"[assess] rule pack {summ['rule_pack']['version']} ({summ['rule_pack']['hash']})")
        print("         classes:", summ["classes"])
        print("         tiers:  ", summ["tiers"])
        return 0

    if args.cmd == "plan":
        horizon = int(args.horizon.rstrip("m"))
        doc = P.plan(args.assessment, args.capacity, horizon, args.out,
                     solver=args.solver, time_limit_s=args.time_limit)
        sm = doc.get("solver_meta", {})
        extra = ""
        if doc["solver"] == "cp-sat":
            extra = (f" status={sm.get('status')} optimal={sm.get('proven_optimal')}"
                     f" wall={sm.get('wall_time_s')}s")
        elif sm.get("fallback_reason"):
            extra = f" ({sm['fallback_reason']})"
        print(f"[plan] solver={doc['solver']}{extra} tasks={doc['task_count']} "
              f"phases={doc['phases']} weighted_exposure_days={doc['weighted_exposure_days']} -> {args.out}")
        return 0

    if args.cmd == "verify":
        b = R.verify(args.plan, args.against, args.evidence_out, phase=args.phase,
                     active_probe=args.active_probe, scope_path=args.scope,
                     scope_key=args.scope_key, attempts=args.attempts)
        cap = b.get("probe_capability")
        if args.active_probe and cap:
            print(f"[verify] active-probe capability: pq_capable={cap['pq_capable']}"
                  + (f" ({cap['reason']})" if cap.get("reason") else ""))
        print(f"[verify] phase={args.phase} checked={b['checked']} "
              f"passed={b['passed']} failed={b['failed']} -> {args.evidence_out}")
        for res in b["results"]:
            mark = res.get("status", "pass" if res["passed"] else "fail").upper()
            print(f"         [{mark}] {res['id']} {res['type']}: {res['detail']}")
        for finding in b.get("unplanned_target_occurrences", []):
            print(f"         [UNPLANNED] {finding['display']} at {finding['path']}")
        if b.get("selection_note"):
            print(f"         [DEFERRED] {b['selection_note']}")
        return 0 if b["accepted"] else 2

    if args.cmd == "diff":
        old, new = Inventory.load(args.old), Inventory.load(args.new)
        if getattr(args, "detailed", False):
            from .model import diff_detailed
            print(json.dumps(diff_detailed(old, new, "old", "new"), indent=2, ensure_ascii=False))
        else:
            print(json.dumps(model_diff(old, new), indent=2))
        return 0

    if args.cmd == "import":
        import json as _json
        from .cyclonedx import from_cyclonedx
        doc = _json.load(open(args.cbom, encoding="utf-8"))
        imported = from_cyclonedx(doc, source_tool=args.tool)
        if args.merge:
            base = Inventory.load(args.merge)
            stats = base.merge(imported)
            base.save(args.out)
            print(f"[import] merged {len(imported)} imported asset(s) into "
                  f"{args.merge}: {stats['in_both']} shared, "
                  f"{stats['only_imported']} new from import, "
                  f"{stats['only_local']} local-only -> {args.out}")
        else:
            imported.save(args.out)
            tool = imported.meta["collectors"][-1]["name"] if imported.meta.get("collectors") else "unknown"
            print(f"[import] {len(imported)} asset(s) from {tool} -> {args.out}")
        return 0

    if args.cmd == "impact":
        inv = Inventory.load(args.cbom)
        if args.list or not (args.component or args.algorithm):
            if not inv.components:
                print("[impact] no SBOM components in this CBOM "
                      "(scan with --sbom to populate the dependency graph)")
                return 0
            print(f"[impact] {len(inv.components)} component(s):")
            for c in inv.components:
                provided = inv.assets_provided_by(c)
                print(f"  {c.display}: provides {len(provided)} crypto asset(s)")
                for a in provided:
                    others = [o.name for o in inv.providers_of(a) if o.key != c.key]
                    shared = f"  (also: {', '.join(others)})" if others else "  [unique]"
                    exp = f" — {a.exposure_class}" if a.exposure_class else ""
                    print(f"      → {a.display}{exp}{shared}")
            return 0
        if args.component:
            match = [c for c in inv.components if c.name.lower() == args.component.lower()]
            if not match:
                print(f"[impact] no component named {args.component!r}; "
                      f"known: {', '.join(c.name for c in inv.components) or '(none)'}")
                return 1
            print(json.dumps(inv.impact_of_removing(match[0]), indent=2, ensure_ascii=False))
            return 0
        if args.algorithm:
            from .model import canon_algorithm
            want = canon_algorithm(args.algorithm.lower())
            hits = [a for a in inv.assets if a.algorithm == want]
            if not hits:
                print(f"[impact] no asset with algorithm {want!r} in the inventory")
                return 1
            for a in hits:
                provs = inv.providers_of(a)
                print(f"{a.display}: provided by "
                      f"{', '.join(c.display for c in provs) if provs else '(no mapped component)'}")
            return 0
        return 0

    if args.cmd == "chain":
        inv = Inventory.load(args.cbom)
        inv.link_chain()          # (re)resolve issuer→subject links
        if not inv.certificates:
            print("[chain] no certificate nodes in this CBOM "
                  "(scan with --certs to populate the trust chain)")
            return 0
        leaves = [c for c in inv.certificates if not c.is_ca]
        if args.leaf:
            leaves = [c for c in leaves if args.leaf.lower() in c.subject.lower()]
        shown = 0
        for leaf in leaves:
            wl = inv.weakest_link(leaf)
            if args.weak_only and not wl["chain_broken_by"] and not wl["chain_weaknesses"]:
                continue
            shown += 1
            broken = wl["chain_broken_by"]
            head = f"{leaf.subject}"
            if broken:
                print(f"⚠  {head}: strong leaf, but chain broken by {broken}")
            elif wl["chain_weaknesses"]:
                print(f"⚠  {head}: weaknesses {wl['chain_weaknesses']}")
            else:
                print(f"✓  {head}: chain clean ({wl['chain_length']} cert(s))")
            for row in wl["chain"]:
                flag = f"  ← {', '.join(row['weak'])}" if row["weak"] else ""
                print(f"      {row['role']:4} {row['cert']}{flag}")
        if shown == 0:
            print("[chain] no matching leaf certificates"
                  + (" with weaknesses" if args.weak_only else ""))
        return 0

    if args.cmd == "export":
        if args.format == "issues":
            R.plan_to_issues(args.plan, args.out)
        elif args.format == "cyclonedx":
            import json as _json
            from .model import Inventory as _Inv
            from .cyclonedx import to_cyclonedx
            inv = _Inv.load(args.plan)   # 'plan' arg is a CBOM/assessment here
            doc = to_cyclonedx(inv)
            with open(args.out, "w", encoding="utf-8") as f:
                _json.dump(doc, f, indent=2, ensure_ascii=False)
            print(f"[export] cyclonedx ({len(doc['components'])} components) -> {args.out}")
            return 0
        elif args.format == "sarif":
            import json as _json
            import yaml as _yaml
            from .model import Inventory as _Inv
            from .sarif import to_sarif
            inv = _Inv.load(args.plan)   # an assessed CBOM
            if args.vex:
                from . import vex as _vex
                vdoc = _yaml.safe_load(open(args.vex, encoding="utf-8"))
                summary = _vex.apply(inv, _vex.parse(vdoc))
                print(f"[export] applied VEX: {summary['applied']} statement(s), "
                      f"{summary['suppressed_assets']} asset(s) suppressed"
                      + (f", {len(summary['unmatched'])} unmatched" if summary['unmatched'] else ""))
            rules_doc = _yaml.safe_load(open(args.rules, encoding="utf-8")) if args.rules else {}
            doc = to_sarif(inv, rules_doc, min_level=args.min_level,
                           include_ok=args.include_ok)
            with open(args.out, "w", encoding="utf-8") as f:
                _json.dump(doc, f, indent=2, ensure_ascii=False)
            n = len(doc["runs"][0]["results"])
            sup = sum(1 for r in doc["runs"][0]["results"] if "suppressions" in r)
            print(f"[export] sarif ({n} result(s), {sup} suppressed) -> {args.out}")
            return 0
        elif args.format == "vex":
            import json as _json
            import yaml as _yaml
            from .model import Inventory as _Inv
            from . import vex as _vex
            inv = _Inv.load(args.plan)
            vsrc = args.vex or None
            if not vsrc:
                print("[export] vex format needs --vex <statements.yaml> "
                      "(the exceptions to serialise)")
                return 1
            vdoc = _yaml.safe_load(open(vsrc, encoding="utf-8"))
            stmts = _vex.parse(vdoc)
            if args.vex_format == "cyclonedx":
                out = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                       "vulnerabilities": _vex.to_cyclonedx_vex(inv, stmts)}
            else:
                out = _vex.to_openvex(inv, stmts)
            with open(args.out, "w", encoding="utf-8") as f:
                _json.dump(out, f, indent=2, ensure_ascii=False)
            print(f"[export] vex/{args.vex_format} ({len(stmts)} statement(s)) -> {args.out}")
            return 0
            return 0
        else:
            R.plan_to_csv(args.plan, args.out)
        print(f"[export] {args.format} -> {args.out}")
        return 0

    if args.cmd == "report":
        import yaml as _yaml
        import os as _os
        pmap = None
        if args.map:
            pmap = _yaml.safe_load(open(args.map, encoding="utf-8"))
        vdoc = None
        if args.vex:
            vdoc = _yaml.safe_load(open(args.vex, encoding="utf-8"))
        history = None
        if args.history:
            history = []
            for h in args.history:
                if _os.path.isdir(h):
                    history.extend(sorted(_os.path.join(h, f)
                                          for f in _os.listdir(h) if f.endswith(".json")))
                else:
                    history.append(h)
        R.dashboard(args.cbom, args.out, provider_map=pmap, vex_doc=vdoc,
                    history=history)
        print(f"[report] dashboard -> {args.out}")
        return 0

    if args.cmd == "graph":
        from .graphexport import export
        inv = Inventory.load(args.cbom)
        text = export(inv, args.which, args.format)
        if args.out:
            open(args.out, "w", encoding="utf-8").write(text + "\n")
            print(f"[graph] {args.which}/{args.format} -> {args.out}")
        else:
            try:
                print(text)
            except BrokenPipeError:
                pass          # piped to head/less that closed early
        return 0

    if args.cmd == "bundle":
        import yaml as _yaml
        import os as _os
        from .bundle import build_bundle
        pmap = None
        if args.map:
            pmap = _yaml.safe_load(open(args.map, encoding="utf-8"))
        vdoc = None
        if args.vex:
            vdoc = _yaml.safe_load(open(args.vex, encoding="utf-8"))
        rules_doc = None
        if args.rules:
            rules_doc = _yaml.safe_load(open(args.rules, encoding="utf-8"))
        history = None
        if args.history:
            history = []
            for h in args.history:
                if _os.path.isdir(h):
                    history.extend(sorted(_os.path.join(h, f)
                                          for f in _os.listdir(h) if f.endswith(".json")))
                else:
                    history.append(h)
        manifest = build_bundle(args.cbom, args.out, provider_map=pmap,
                                vex_doc=vdoc, history=history, rules_doc=rules_doc,
                                title=args.title)
        n = (len(manifest["pages"]) + len(manifest["graphs"])
             + len(manifest["data"]) + 1)
        print(f"[bundle] wrote {n} file(s) to {args.out}/")
        print(f"[bundle] open {_os.path.join(args.out, 'index.html')}")
        return 0

    if args.cmd == "repo-card":
        import yaml as _yaml
        from . import orgdash
        pmap = None
        if args.map:
            pmap = _yaml.safe_load(open(args.map, encoding="utf-8"))
        gates = None
        if args.gates:
            gates = json.load(open(args.gates, encoding="utf-8"))
        inv = Inventory.load(args.assessment)
        card = orgdash.repo_card(inv, name=args.name, provider_map=pmap,
                                 gates=gates, url=args.url)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(card, f, indent=2, ensure_ascii=False)
        m = card["metrics"]
        print(f"[repo-card] {args.name}: {m['urgent']} urgent, "
              f"{m['quantum_broken']} quantum-broken -> {args.out}")
        return 0

    if args.cmd == "org-dashboard":
        from . import orgdash
        cards = orgdash.load_cards(args.cards)
        html_doc = orgdash.render_dashboard(cards, title=args.title)
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(html_doc)
        agg = orgdash.aggregate(cards)
        print(f"[org-dashboard] {agg['repos']} repo(s): "
              f"{agg['gate_fail_repos']} with failing gates, "
              f"{agg['total_urgent']} total urgent -> {args.out}")
        return 0

    if args.cmd == "pr-comment":
        import yaml as _yaml
        import os as _os
        from .prcomment import build_comment
        pmap = None
        if args.map:
            pmap = _yaml.safe_load(open(args.map, encoding="utf-8"))
        history = None
        if args.history:
            history = []
            for h in args.history:
                if _os.path.isdir(h):
                    history.extend(sorted(_os.path.join(h, f)
                                          for f in _os.listdir(h) if f.endswith(".json")))
                else:
                    history.append(h)
        gates = None
        if args.gates:
            import json as _json_g
            gates = _json_g.load(open(args.gates, encoding="utf-8"))
        md = build_comment(args.cbom, provider_map=pmap, history=history,
                           title=args.title, report_url=args.report_url,
                           base_cbom=args.base, gates=gates,
                           subtitle=args.subtitle, compact=args.compact)
        if args.out:
            open(args.out, "w", encoding="utf-8").write(md)
            print(f"[pr-comment] wrote {args.out}")
        else:
            try:
                print(md, end="")
            except BrokenPipeError:
                pass
        return 0

    if args.cmd == "sign-scope":
        sig = sign_scope(args.scope, args.key)
        print(f"[sign-scope] signed {args.scope}: {sig}")
        return 0

    if args.cmd == "lint-rules":
        import yaml as _yaml
        import json as _json
        from .rulelint import lint, classify_snapshot, diff_snapshot
        doc = _yaml.safe_load(open(args.rules, encoding="utf-8"))
        findings = lint(doc)
        errors = [f for f in findings if f.level == "error"]
        warnings = [f for f in findings if f.level == "warning"]
        infos = [f for f in findings if f.level == "info"]
        for f in findings:
            mark = {"error": "✗", "warning": "⚠", "info": "·"}[f.level]
            print(f"  {mark} [{f.level:7}] {f.rule_id}: {f.message}")
        print(f"[lint-rules] {len(errors)} error(s), {len(warnings)} warning(s), "
              f"{len(infos)} info")

        rc = 1 if errors else 0
        if args.strict and warnings:
            rc = 1

        # snapshot regression
        if args.snapshot:
            snap = _json.load(open(args.snapshot, encoding="utf-8"))
            fixtures = snap.get("assets", [])
            current = classify_snapshot(doc, fixtures)
            if args.update_snapshot:
                snap["expected"] = current
                _json.dump(snap, open(args.snapshot, "w", encoding="utf-8"),
                           indent=2, ensure_ascii=False)
                print(f"[lint-rules] snapshot updated: {len(current)} classifications frozen")
            else:
                baseline = snap.get("expected", {})
                d = diff_snapshot(baseline, current)
                if d["regressions"]:
                    print(f"[lint-rules] SNAPSHOT REGRESSION: "
                          f"{d['regressions']} asset(s) changed classification:")
                    for ch in d["changed"]:
                        was, now = ch["was"], ch["now"]
                        print(f"    {ch['asset']}: {was['class']} (by {was['rule']}) "
                              f"-> {now['class']} (by {now['rule']})")
                    rc = 1
                else:
                    print(f"[lint-rules] snapshot OK: "
                          f"{len(current)} classification(s) unchanged")
        return rc

    if args.cmd == "lint-provider-map":
        import yaml as _yaml
        import os as _os
        from .providermap import lint as _lint_pm
        path = args.map or _os.path.join(_os.path.dirname(__file__),
                                         "data", "provider-map.yaml")
        doc = _yaml.safe_load(open(path, encoding="utf-8"))
        findings = _lint_pm(doc)
        errors = [f for f in findings if f.level == "error"]
        warnings = [f for f in findings if f.level == "warning"]
        infos = [f for f in findings if f.level == "info"]
        for f in findings:
            mark = {"error": "✗", "warning": "⚠", "info": "·"}[f.level]
            print(f"  {mark} [{f.level:7}] {f.component}: {f.message}")
        print(f"[lint-provider-map] {len(errors)} error(s), "
              f"{len(warnings)} warning(s), {len(infos)} info")
        rc = 1 if errors else 0
        if args.strict and warnings:
            rc = 1
        # resolution snapshot regression
        if args.snapshot:
            from .providermap import resolve
            import json as _json2
            snap = _json2.load(open(args.snapshot, encoding="utf-8"))
            entries = {e.get("component", "").lower(): e for e in doc.get("components", [])}
            drift = []
            for case in snap.get("cases", []):
                entry = entries.get(case["component"].lower())
                got = sorted({c.algorithm for c in resolve(entry, case["version"])}) if entry else []
                exp = sorted(case["expect"])
                if got != exp:
                    drift.append((case["component"], case["version"], exp, got))
            if drift:
                print(f"[lint-provider-map] SNAPSHOT DRIFT: {len(drift)} case(s) changed:")
                for comp, ver, exp, got in drift:
                    print(f"    {comp}@{ver}: expected {exp}, got {got}")
                rc = 1
            else:
                print(f"[lint-provider-map] snapshot OK: "
                      f"{len(snap.get('cases', []))} resolution(s) unchanged")
        return rc

    if args.cmd == "lint-vex":
        import yaml as _yaml
        from . import vex as _vex
        doc = _yaml.safe_load(open(args.vex, encoding="utf-8"))
        findings = _vex.lint(doc)
        errors = [f for f in findings if f.level == "error"]
        warnings = [f for f in findings if f.level == "warning"]
        infos = [f for f in findings if f.level == "info"]
        for f in findings:
            mark = {"error": "✗", "warning": "⚠", "info": "·"}[f.level]
            print(f"  {mark} [{f.level:7}] {f.stmt_id}: {f.message}")
        print(f"[lint-vex] {len(errors)} error(s), {len(warnings)} warning(s), "
              f"{len(infos)} info")
        rc = 1 if errors else 0
        if args.strict and warnings:
            rc = 1
        # optional: check statements target real assets in a CBOM
        if args.cbom:
            inv = Inventory.load(args.cbom)
            summary = _vex.apply(inv, _vex.parse(doc))
            if summary["unmatched"]:
                print(f"[lint-vex] {len(summary['unmatched'])} statement(s) target "
                      f"assets not in the CBOM:")
                for aid in summary["unmatched"]:
                    print(f"    {aid}")
                rc = 1
            else:
                print(f"[lint-vex] all {summary['applied']} statement(s) match a "
                      f"real asset ({summary['suppressed_assets']} suppressed)")
        return rc

    if args.cmd == "baseline":
        from . import baseline as _baseline
        exposures = tuple(e.strip() for e in args.exposure.split(",") if e.strip())
        inv = Inventory.load(args.assessment)
        doc = _baseline.generate(inv, exposures)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2, ensure_ascii=False)
        print(f"[baseline] froze {len(doc['accepted'])} exposed asset(s) "
              f"({', '.join(exposures)}) as accepted backlog -> {args.out}")
        return 0

    if args.cmd == "baseline-check":
        from . import baseline as _baseline
        inv = Inventory.load(args.assessment)
        doc = json.load(open(args.baseline, encoding="utf-8"))
        exposures = None
        if args.exposure:
            exposures = tuple(e.strip() for e in args.exposure.split(",") if e.strip())
        ev = _baseline.evaluate(inv, doc, exposures)
        print(f"[baseline-check] {ev['new_count']} new, "
              f"{ev['accepted_count']} accepted (baselined), "
              f"{ev['resolved_count']} resolved "
              f"({', '.join(ev['exposures'])})")
        if ev["resolved_count"]:
            print(f"    {ev['resolved_count']} baselined asset(s) no longer "
                  f"exposed — regenerate the baseline to ratchet down")
        rc = 0
        if ev["new_count"]:
            print(f"[baseline-check] BASELINE GATE FAILED: "
                  f"{ev['new_count']} new exposed asset(s) not in the baseline:")
            for a in ev["new"]:
                print(f"    {a['display']}  ({a['tier']}, {a['exposure_class']})")
            rc = 1
        elif args.strict and ev["resolved_count"]:
            print("[baseline-check] --strict: failing on stale baseline entries")
            rc = 1
        if rc == 0 and not ev["new_count"]:
            print("[baseline-check] no new exposure beyond the accepted baseline")
        return rc

    if args.cmd == "lint-aliases":
        import yaml as _yaml
        import os as _os
        from .aliasmap import lint as _lint_aliases, DEFAULT_ALIASES
        path = args.aliases or DEFAULT_ALIASES
        doc = _yaml.safe_load(open(path, encoding="utf-8"))
        pmap = None
        if args.map:
            pmap = _yaml.safe_load(open(args.map, encoding="utf-8"))
        else:
            # default to the built-in provider map so target checks run
            dm = _os.path.join(_os.path.dirname(__file__), "data", "provider-map.yaml")
            if _os.path.exists(dm):
                pmap = _yaml.safe_load(open(dm, encoding="utf-8"))
        findings = _lint_aliases(doc, pmap)
        errors = [f for f in findings if f.level == "error"]
        warnings = [f for f in findings if f.level == "warning"]
        infos = [f for f in findings if f.level == "info"]
        for f in findings:
            mark = {"error": "✗", "warning": "⚠", "info": "·"}[f.level]
            print(f"  {mark} [{f.level:7}] {f.package}: {f.message}")
        print(f"[lint-aliases] {len(errors)} error(s), {len(warnings)} warning(s), "
              f"{len(infos)} info")
        rc = 1 if errors else 0
        if args.strict and warnings:
            rc = 1

        # resolution snapshot: freeze package -> (component, tracks_version)
        if args.update_snapshot:
            if not args.snapshot:
                print("[lint-aliases] --update-snapshot needs --snapshot PATH")
                return 1
            import json as _json2
            from .aliasmap import resolve_snapshot
            snap = {"description": "Known-good package-name resolutions for the "
                    "manifest alias map. Guards against edits that change a known "
                    "mapping or flip a wrapper's version-tracking flag.",
                    "resolutions": resolve_snapshot(doc)}
            with open(args.snapshot, "w", encoding="utf-8") as f:
                _json2.dump(snap, f, indent=2, ensure_ascii=False)
            print(f"[lint-aliases] snapshot written: {len(snap['resolutions'])} "
                  f"resolution(s) -> {args.snapshot}")
        elif args.snapshot:
            import json as _json2
            from .aliasmap import resolve_snapshot, diff_snapshot
            baseline = _json2.load(open(args.snapshot, encoding="utf-8"))
            drift = diff_snapshot(baseline.get("resolutions", {}),
                                  resolve_snapshot(doc))
            if drift["regressions"]:
                print(f"[lint-aliases] SNAPSHOT DRIFT: "
                      f"{drift['regressions']} regression(s):")
                for c in drift["changed"]:
                    print(f"    {c['package']}: {c['baseline']} -> {c['current']}")
                for p in drift["only_in_baseline"]:
                    print(f"    {p}: removed (was in baseline)")
                rc = 1
            else:
                added = len(drift["only_in_current"])
                extra = f" (+{added} new)" if added else ""
                print(f"[lint-aliases] snapshot OK: "
                      f"{len(baseline.get('resolutions', {}))} resolution(s) "
                      f"unchanged{extra}")

        # wrapper coverage of a real scan's discovered packages
        if args.cbom:
            from .aliasmap import resolutions_from_cbom, wrapper_coverage
            inv = Inventory.load(args.cbom)
            cov = wrapper_coverage(resolutions_from_cbom(inv))
            if cov["discovered"] == 0:
                print("[lint-aliases] no manifest-discovered packages in "
                      f"{args.cbom} — wrapper coverage not applicable")
            else:
                print(f"[lint-aliases] wrapper coverage: {cov['wrappers']}/"
                      f"{cov['mapped']} mapped package(s) are wrappers "
                      f"({cov['wrapper_pct']}%); {cov['unmapped']} unmapped, "
                      f"{cov['discovered']} discovered")
                if cov["wrappers"]:
                    print("    wrappers (version-gated capabilities withheld): "
                          + ", ".join(cov["wrapper_packages"]))
                if args.max_wrapper_pct is not None and \
                        cov["wrapper_pct"] > args.max_wrapper_pct:
                    print(f"[lint-aliases] WRAPPER COVERAGE GATE FAILED: "
                          f"{cov['wrapper_pct']}% > {args.max_wrapper_pct}% — "
                          f"too much of the dependency surface has version-gated "
                          f"capabilities withheld; PQC attribution is conservative")
                    rc = 1
        elif args.max_wrapper_pct is not None:
            print("[lint-aliases] --max-wrapper-pct needs --cbom")
            rc = 1
        return rc

    if args.cmd == "provenance":
        import yaml as _yaml
        import os as _os
        import json as _json
        path = args.rules or _os.path.join(_os.path.dirname(__file__), "rules",
                                           "transition-2024.yaml")
        doc = _yaml.safe_load(open(path, encoding="utf-8"))
        rules = doc.get("rules", [])

        # optional: restrict to rules that fired in a real CBOM, with counts
        fired_counts = None
        if args.cbom:
            fired_counts = {}
            inv = Inventory.load(args.cbom)
            for a in inv.assets:
                if a.rule_id:
                    fired_counts[a.rule_id] = fired_counts.get(a.rule_id, 0) + 1
            rules = [r for r in rules if r.get("id") in fired_counts]

        def _cites(r):
            out = []
            for ref in r.get("references") or []:
                if not isinstance(ref, dict):
                    out.append(str(ref)); continue
                s = ref.get("standard", "")
                if ref.get("section"):
                    s += f" {ref['section']}"
                out.append(s)
            return out

        def _has_valid_reference(r):
            refs = r.get("references")
            if not isinstance(refs, list) or not refs:
                return False
            return any(isinstance(ref, dict) and ref.get("standard") for ref in refs)

        def _coverage_gate():
            """Return 0, or 1 (after reporting) if --require-references is set and
            some rule in scope lacks a valid governing-standard reference."""
            if not args.require_references:
                return 0
            missing = [r.get("id") for r in rules if not _has_valid_reference(r)]
            scope = ("rules that fired" if fired_counts is not None
                     else "rules in the pack")
            if missing:
                print(f"[provenance] COVERAGE GATE FAILED: {len(missing)} "
                      f"{scope} have no governing-standard reference:")
                for rid in missing:
                    n = f" (×{fired_counts.get(rid, 0)})" if fired_counts is not None else ""
                    print(f"    {rid}{n}")
                return 1
            print(f"[provenance] coverage OK: all {len(rules)} {scope} cite a "
                  f"governing standard")
            return 0

        if args.format == "json":
            rows = []
            for r in rules:
                row = {"id": r.get("id"), "class": r.get("class"),
                       "why": r.get("why"), "references": r.get("references") or []}
                if fired_counts is not None:
                    row["occurrences"] = fired_counts.get(r.get("id"), 0)
                rows.append(row)
            print(_json.dumps({"version": doc.get("version"), "rules": rows},
                              indent=2, ensure_ascii=False))
            return _coverage_gate()

        if args.format == "markdown":
            print(f"# QRAMP rule provenance — `{doc.get('version')}`\n")
            hdr = "| Rule | Class | Governing standards |"
            sep = "| --- | --- | --- |"
            if fired_counts is not None:
                hdr = "| Rule | Class | Occurrences | Governing standards |"
                sep = "| --- | --- | --- | --- |"
            print(hdr); print(sep)
            for r in rules:
                cites = ", ".join(_cites(r)) or "—"
                if fired_counts is not None:
                    print(f"| {r.get('id')} | {r.get('class')} | "
                          f"{fired_counts.get(r.get('id'), 0)} | {cites} |")
                else:
                    print(f"| {r.get('id')} | {r.get('class')} | {cites} |")
            return _coverage_gate()

        # text
        print(f"QRAMP rule provenance — {doc.get('version')}"
              + (f" (rules that fired in {args.cbom})" if fired_counts is not None else ""))
        for r in rules:
            head = f"  {r.get('id')}  [{r.get('class')}]"
            if fired_counts is not None:
                head += f"  ×{fired_counts.get(r.get('id'), 0)}"
            print(head)
            for c in _cites(r):
                print(f"      · {c}")
            if not _cites(r):
                print("      · (no references)")
        return _coverage_gate()

    if args.cmd == "policy-diff":
        import json as _json
        from .policydiff import policy_diff
        rep = policy_diff(args.cbom, kind=args.kind, old_path=args.old,
                          new_path=args.new, lifetimes_path=args.lifetimes)
        if args.json:
            print(_json.dumps(rep, indent=2, ensure_ascii=False))
            worse = _policy_worse_count(rep)
            return 1 if (args.fail_on_worse and worse) else 0

        worse = _policy_worse_count(rep)
        if args.kind == "rules":
            print(f"[policy-diff] rule pack: {rep['changed_count']} asset(s) change "
                  f"({rep['worsened']} worsened, {rep['improved']} improved)")
            if rep["tier_before"] != rep["tier_after"]:
                print(f"  tier distribution: {rep['tier_before']} → {rep['tier_after']}")
            for c in rep["changed"]:
                arrow = {"worse": "⬆", "better": "⬇", "lateral": "→"}[c["severity"]]
                cls = (f"{c['class'][0]}→{c['class'][1]}"
                       if c['class'][0] != c['class'][1] else c['class'][1])
                rule = (f"rule {c['rule'][0]}→{c['rule'][1]}"
                        if c['rule'][0] != c['rule'][1] else "")
                tier = (f"tier {c['tier'][0]}→{c['tier'][1]}"
                        if c['tier'][0] != c['tier'][1] else "")
                extra = ", ".join(x for x in (rule, tier) if x)
                print(f"  {arrow} {c['asset']}: {cls}" + (f" ({extra})" if extra else ""))
        elif args.kind == "provider-map":
            print(f"[policy-diff] provider map: migration-blocked "
                  f"{rep['blocked_before']} → {rep['blocked_after']}")
            for x in rep["newly_blocked"]:
                print(f"  ⬆ newly blocked: {x['asset']}")
            for x in rep["newly_unblocked"]:
                print(f"  ⬇ newly unblocked: {x['asset']}")
        elif args.kind == "vex":
            print(f"[policy-diff] VEX: suppressions "
                  f"{rep['suppressions_before']} → {rep['suppressions_after']}")
            for x in rep["added"]:
                print(f"  + suppress {x['asset']} ({x['justification']})")
            for x in rep["removed"]:
                print(f"  ⬆ un-suppress {x['asset']} (was {x['was_justification']})")
            for x in rep["changed"]:
                print(f"  ~ {x['asset']}: justification {x['justification'][0]} → {x['justification'][1]}")
        if not worse and args.kind == "rules" and rep["changed_count"] == 0:
            print("  no asset changes")
        return 1 if (args.fail_on_worse and worse) else 0

    if args.cmd == "resolve-provider":
        import yaml as _yaml
        import os as _os
        from .providermap import resolve
        path = args.map or _os.path.join(_os.path.dirname(__file__),
                                         "data", "provider-map.yaml")
        doc = _yaml.safe_load(open(path, encoding="utf-8"))
        entry = next((e for e in doc.get("components", [])
                      if e.get("component", "").lower() == args.component.lower()), None)
        if entry is None:
            print(f"[resolve-provider] no component named {args.component!r} in the map")
            return 1
        caps = resolve(entry, args.version)
        print(f"{args.component}@{args.version} provides {len(caps)} capabilit"
              f"{'y' if len(caps) == 1 else 'ies'}:")
        for c in caps:
            gate = f"  (gated {c.version_gate})" if c.version_gate else ""
            kl = f"-{c.key_length}" if c.key_length else ""
            print(f"    {c.primitive:16} {c.algorithm}{kl}  conf={c.confidence}{gate}")
        return 0

    if args.cmd == "readiness":
        import yaml as _yaml
        import os as _os
        import json as _json
        from .readiness import readiness_report
        path = args.map or _os.path.join(_os.path.dirname(__file__),
                                         "data", "provider-map.yaml")
        pmap = _yaml.safe_load(open(path, encoding="utf-8"))
        inv = Inventory.load(args.cbom)
        rep = readiness_report(inv, pmap)

        def _readiness_gate():
            msgs, failed = [], False
            if args.min_readiness is not None and rep["readiness_pct"] < args.min_readiness:
                msgs.append(f"readiness {rep['readiness_pct']}% is below the "
                            f"required {args.min_readiness}%")
                failed = True
            if (args.max_unaddressable is not None
                    and rep["blocked_unaddressable"] > args.max_unaddressable):
                msgs.append(f"{rep['blocked_unaddressable']} unaddressable blocked "
                            f"asset(s) exceed the limit of {args.max_unaddressable}")
                failed = True
            for m in msgs:
                print(f"[readiness] GATE FAILED: {m}")
            return 1 if failed else 0

        if args.json:
            print(_json.dumps(rep, indent=2, ensure_ascii=False))
            return _readiness_gate()
        if not inv.components:
            print("[readiness] no SBOM components in this CBOM — scan with "
                  "--sbom so upgrade advice can be computed")
        print(f"[readiness] {rep['readiness_pct']}% of PQC-migration assets are already "
              f"migratable ({rep['already_migratable']}/{rep['pqc_migration_assets']})")
        print(f"  migration-blocked: {rep['migration_blocked']} "
              f"({rep['blocked_addressable_by_upgrade']} addressable by a library upgrade, "
              f"{rep['blocked_unaddressable']} need new libraries or code changes)")
        ups = rep["recommended_upgrades"]
        if not ups:
            print("  no upgrade in the provider map would unblock a blocked asset")
            return _readiness_gate()
        print("\n  ROI-ranked upgrade recommendations:")
        for i, o in enumerate(ups, 1):
            by = ", ".join(f"{t}×{n}" for t, n in sorted(o["by_tier"].items()))
            print(f"   {i}. {o['component']} {o['upgrade']}")
            print(f"      unlocks {', '.join(o['unlocks'])} → unblocks "
                  f"{o['unblocks']} asset(s) ({by})   [ROI {o['roi_score']}]")
            if o["examples"]:
                print(f"      e.g. {', '.join(o['examples'])}")
        return _readiness_gate()

    if args.cmd == "simulate":
        import yaml as _yaml
        import os as _os
        import json as _json
        from .simulate import simulate, parse_upgrades
        path = args.map or _os.path.join(_os.path.dirname(__file__),
                                         "data", "provider-map.yaml")
        pmap = _yaml.safe_load(open(path, encoding="utf-8"))
        inv = Inventory.load(args.cbom)
        try:
            ups = parse_upgrades(args.upgrade)
        except ValueError as e:
            print(f"[simulate] {e}")
            return 1
        rep = simulate(inv, pmap, ups)
        if args.json:
            print(_json.dumps(rep, indent=2, ensure_ascii=False))
            return 0
        if not inv.components:
            print("[simulate] no SBOM components in this CBOM — scan with --sbom")
            return 1
        for iv in rep["invalid_upgrades"]:
            print(f"[simulate] skipped {iv['component']}: {iv['reason']}")
        for name in rep["unknown_components"]:
            print(f"[simulate] {name!r} is not a deployed component")
        if not rep["upgrades"]:
            print("[simulate] no applicable upgrade")
            return 1
        applied = ", ".join(f"{k} ({v})" for k, v in rep["upgrades"].items())
        print(f"[simulate] upgrading {applied}")
        for cc in rep["capability_changes"]:
            if cc["added"]:
                print(f"  + {cc['component']} gains: {', '.join(cc['added'])}")
            if cc["removed"]:
                print(f"  − {cc['component']} drops: {', '.join(cc['removed'])}")
        print(f"\n  migration readiness: {rep['readiness_before_pct']}% "
              f"→ {rep['readiness_after_pct']}%")
        print(f"  migration-blocked assets: {rep['blocked_before']} "
              f"→ {rep['blocked_after']}  (unblocks {rep['unblocked']})")
        if rep["unblocked_by_tier"]:
            by = ", ".join(f"{t}×{n}" for t, n in sorted(rep["unblocked_by_tier"].items()))
            print(f"  unblocked by tier: {by}   (risk-cleared weight {rep['risk_cleared_weight']})")
        if rep["unblocked_examples"]:
            print(f"  e.g. {', '.join(rep['unblocked_examples'])}")
        return 0

    if args.cmd == "timeline":
        import os as _os
        import json as _json
        from .timeline import build, deltas, summarise
        # expand a single directory argument into its .json files
        paths = list(args.cbom)
        if len(paths) == 1 and _os.path.isdir(paths[0]):
            d = paths[0]
            paths = sorted(_os.path.join(d, f) for f in _os.listdir(d)
                           if f.endswith(".json"))
        if len(paths) < 2:
            print("[timeline] need at least two CBOMs (or a directory of them)")
            return 1
        points = build(paths, labels=args.label)
        series = [s.strip() for s in args.series.split(",") if s.strip()]
        summ = summarise(points)
        dls = deltas(points)

        if args.json:
            print(_json.dumps({
                "points": [p.as_dict() for p in points],
                "deltas": dls, "summary": summ}, indent=2, ensure_ascii=False))
        else:
            print(f"[timeline] {summ['scans']} scans, {summ['from']} → {summ['to']}: "
                  f"trend {summ['trend']}")
            print(f"  urgent (P0+P1): {summ['urgent_first']} → {summ['urgent_last']} "
                  f"({summ['urgent_change']:+d})")
            print(f"  quantum-broken: {summ['quantum_broken_first']} → "
                  f"{summ['quantum_broken_last']} ({summ['quantum_broken_change']:+d})")
            print(f"  net assets remediated over the window: {summ['net_remediated']}")
            for d in dls:
                print(f"  {d['from']} → {d['to']}: urgent {d['urgent_delta']:+d}, "
                      f"remediated {d['assets_remediated']}, "
                      f"introduced {d['assets_introduced']}")

        if args.svg or args.html:
            from .svggraph import timeline_svg
            svg = timeline_svg(points, series=tuple(series))
            if args.svg:
                open(args.svg, "w", encoding="utf-8").write(svg)
                print(f"[timeline] trend chart -> {args.svg}")
            if args.html:
                from .report import timeline_report
                timeline_report(points, dls, summ, svg, args.html)
                print(f"[timeline] progress report -> {args.html}")

        # CI progress ratchet: fail if urgent count did not fall enough
        if args.min_improvement is not None:
            drop = summ["urgent_first"] - summ["urgent_last"]
            if drop < args.min_improvement:
                print(f"[timeline] GATE FAILED: urgent count fell by {drop}, "
                      f"need at least {args.min_improvement}")
                return 1
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
