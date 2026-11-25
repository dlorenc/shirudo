#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# shield-k: turn a guest run (guest.py output) into THE TABLE.
#
#   table.py <raw.json> <out-prefix>     writes <out-prefix>.json and .md,
#                                        prints the markdown, exits 0 on pass
import json
import sys


def cell(refuse, fired):
    if refuse and fired:
        return "covered"
    if refuse:
        return "false_positive"
    if fired:
        return "missed_route"
    return "fine"


def pos(v):
    return v is not None and v > 0


def main():
    raw = json.load(open(sys.argv[1]))
    meta = json.load(open(sys.argv[3])) if len(sys.argv) > 3 else {}
    mode = raw["mode"]
    rows = []
    for r in raw["rows"]:
        d = r["delta"]
        row = {
            "input": r["input"], "kind": r["kind"], "rep": r["rep"],
            "guard_refused": d.get("guard_hits"),
            "oracle_hits": d.get("oracle_hits"),
            "guard_activity": d.get("guard_activity"),
            "oracle_activity": d.get("oracle_activity"),
            "kernel_reports": len(r["kernel_reports"]),
            "rc": r["rc"], "secs": r["secs"],
            "stdout": r["stdout"].strip()[-120:],
        }
        if mode == "record":
            row["cell"] = cell(pos(row["guard_refused"]), pos(row["oracle_hits"]))
        rows.append(row)

    problems = []
    if raw.get("error"):
        problems.append(raw["error"])
    for r in rows:
        tag = f"{r['input']}#{r['rep']}"
        if r["guard_refused"] is None or r["oracle_hits"] is None:
            problems.append(f"{tag}: counters unreadable")
        if mode == "record":
            if r["cell"] == "missed_route":
                problems.append(f"{tag}: missed route (oracle fired, guard would not refuse)")
            if r["cell"] == "false_positive":
                problems.append(f"{tag}: false positive (guard would refuse, oracle silent)")
            if r["kind"] == "reproducer" and not pos(r["oracle_hits"]):
                problems.append(f"{tag}: reproducer did not fire the oracle")
            if r["kernel_reports"] and not pos(r["oracle_hits"]):
                problems.append(f"{tag}: kernel report without oracle hit (oracle too narrow?)")
        else:
            if r["kind"] in ("reproducer", "attack"):
                if not pos(r["guard_refused"]):
                    problems.append(f"{tag}: not refused")
                if pos(r["oracle_hits"]):
                    problems.append(f"{tag}: oracle fired under enforce")
                if r["kernel_reports"]:
                    problems.append(f"{tag}: kernel report (KASAN/BUG) under enforce")
            else:
                if pos(r["guard_refused"]):
                    problems.append(f"{tag}: workload refused under enforce")
                if pos(r["oracle_hits"]) or r["kernel_reports"]:
                    problems.append(f"{tag}: workload fired oracle/KASAN")
                if r["rc"] != 0:
                    problems.append(f"{tag}: workload exit {r['rc']}")
    wl = [r for r in rows if r["kind"] == "workload"]
    wl_activity = sum(r["guard_activity"] or 0 for r in wl)
    if wl and wl_activity <= 0:
        problems.append("workload rows show no guard hook activity (path not exercised)")
    if raw.get("taint_end", 0) != raw.get("taint_start", 0):
        problems.append(f"kernel taint changed {raw.get('taint_start')} -> {raw.get('taint_end')}")

    out = {"mode": mode, "kernel": raw["kernel"], "pass": not problems,
           "problems": problems, "workload_guard_activity": wl_activity,
           "rows": rows, "guest_secs": raw.get("guest_secs"), **meta}
    if mode == "record":
        counts = {}
        for r in rows:
            counts[r["cell"]] = counts.get(r["cell"], 0) + 1
        out["cells"] = counts

    md = [f"### shield-k {mode} on `{raw['kernel']}`: {'PASS' if not problems else 'FAIL'}", ""]
    if mode == "record":
        md += ["| input | kind | guard would refuse | oracle hits | cell | guard activity | KASAN/BUG | rc |",
               "|---|---|---|---|---|---|---|---|"]
        for r in rows:
            md.append(f"| {r['input']}#{r['rep']} | {r['kind']} | {r['guard_refused']} | {r['oracle_hits']} | "
                      f"**{r['cell']}** | {r['guard_activity']} | {r['kernel_reports']} | {r['rc']} |")
    else:
        md += ["| input | kind | refused | oracle hits | KASAN/BUG | guard activity | rc | stdout |",
               "|---|---|---|---|---|---|---|---|"]
        for r in rows:
            md.append(f"| {r['input']}#{r['rep']} | {r['kind']} | {r['guard_refused']} | {r['oracle_hits']} | "
                      f"{r['kernel_reports']} | {r['guard_activity']} | {r['rc']} | `{r['stdout'][-40:]}` |")
    md.append("")
    md += [f"- {p}" for p in problems] or ["- no problems"]
    if meta.get("timings"):
        md.append("- timings (s): " + ", ".join(f"{k}={v}" for k, v in meta["timings"].items()))
    text = "\n".join(md) + "\n"
    prefix = sys.argv[2]
    json.dump(out, open(prefix + ".json", "w"), indent=1)
    open(prefix + ".md", "w").write(text)
    print(json.dumps(out, indent=1))
    print(text)
    sys.exit(0 if not problems else 1)


if __name__ == "__main__":
    main()
