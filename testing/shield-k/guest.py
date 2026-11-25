#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# shield-k guest side: runs as root in the shirudo test VM. Loads the oracle
# and the guard, runs each input with counter snapshots around it, reads
# dmesg and taint, unloads both, and prints one JSON document on stdout.
#
#   guest.py <manifest.json>
import json
import os
import re
import subprocess
import sys
import time

SHIRUDO = os.environ.get("SHIRUDO_RUNTIME", "shirudo-runtime")
BAD = re.compile(r"BUG: KASAN|KASAN:|BUG:|WARNING:|general protection|Oops|"
                 r"UBSAN:|kernel BUG|refcount_t:|list_add corruption|"
                 r"list_del corruption|stack-protector|Kernel panic")


def sh(args, timeout=120, inp=None):
    t0 = time.monotonic()
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                           stdin=subprocess.DEVNULL if inp is None else None,
                           input=inp)
        rc, out, err = p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        rc, out, err = "timeout", (e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or ""), "timeout"
    return {"rc": rc, "out": out, "err": err, "secs": round(time.monotonic() - t0, 3)}


def numbers(v, skip=("key", "cpu", "n_cpus", "max_entries", "schema", "index", "id")):
    """Sum every integer leaf that is not a key or metadata."""
    if isinstance(v, bool):
        return 0
    if isinstance(v, int):
        return v
    if isinstance(v, list):
        return sum(numbers(x) for x in v)
    if isinstance(v, dict):
        return sum(numbers(x) for k, x in v.items() if k not in skip)
    return 0


def read_map(upatch, name):
    r = sh([SHIRUDO, "upatch", "map", upatch, name, "--json"])
    if r["rc"] == 0:
        try:
            doc = json.loads(r["out"].strip().splitlines()[-1])
            entries = doc.get("entries", doc.get("values", doc))
            return {"sum": numbers(entries), "raw": r["out"][:2000]}
        except (ValueError, IndexError, AttributeError):
            pass
    # Human output: sum the numbers after "value"/"=" or ":" on each line.
    h = sh([SHIRUDO, "upatch", "map", upatch, name, "--show-full"])
    if h["rc"] != 0:
        return {"sum": None, "raw": (r["err"] + h["err"])[:2000]}
    total = 0
    for line in h["out"].splitlines():
        m = re.search(r"(?:value|val|count)\W*[:=]\s*(\d+)", line, re.I)
        if m:
            total += int(m.group(1))
    return {"sum": total, "raw": h["out"][:2000]}


def snapshot(man):
    snap = {}
    for role in ("guard", "oracle"):
        u = man[role]["name"]
        for key in ("hits", "activity"):
            m = man["maps"][f"{role}_{key}"]
            if m:
                snap[f"{role}_{key}"] = read_map(u, m)
    return snap


def kmsg(marker):
    try:
        with open("/dev/kmsg", "w") as f:
            f.write(f"shield-k: {marker}\n")
    except OSError:
        pass


def dmesg_since(marker):
    out = sh(["dmesg"])["out"].splitlines()
    idx = 0
    for i, line in enumerate(out):
        if f"shield-k: {marker}" in line:
            idx = i
    tail = out[idx + 1:]
    return [l for l in tail if BAD.search(l)], tail[-200:]


def taint():
    try:
        return int(open("/proc/sys/kernel/tainted").read().strip())
    except OSError:
        return -1


def run_input(inp):
    path = inp["path"]
    if path.endswith(".py"):
        cmd = ["python3", path]
    elif path.endswith(".sh"):
        cmd = ["sh", path]
    else:
        cmd = [path]
    return sh(cmd + inp.get("args", []), timeout=inp.get("timeout", 120))


def main():
    man = json.load(open(sys.argv[1]))
    doc = {"kernel": os.uname().release, "mode": man["mode"], "steps": {},
           "rows": [], "taint_start": taint()}
    t0 = time.monotonic()
    for role in ("oracle", "guard"):
        r = sh([SHIRUDO, "upatch", "load", "--report=-", man[role]["load"]])
        doc["steps"][f"load_{role}"] = r
        if r["rc"] != 0:
            doc["error"] = f"load {role} failed"
            break
    if "error" not in doc:
        for inp in man["inputs"]:
            for rep in range(inp.get("repeat", 1)):
                marker = f"{man['run_id']}-{inp['name']}-{rep}"
                before = snapshot(man)
                kmsg(marker)
                res = run_input(inp)
                bad, tail = dmesg_since(marker)
                after = snapshot(man)
                delta = {}
                for k in after:
                    a, b = after[k]["sum"], before.get(k, {}).get("sum")
                    delta[k] = None if a is None or b is None else a - b
                doc["rows"].append({
                    "input": inp["name"], "kind": inp["kind"], "rep": rep,
                    "rc": res["rc"], "secs": res["secs"],
                    "stdout": res["out"][-1000:], "stderr": res["err"][-1000:],
                    "delta": delta, "kernel_reports": bad,
                    "raw_after": {k: v["raw"][:400] for k, v in after.items()},
                })
    for role in ("guard", "oracle"):
        r = sh([SHIRUDO, "upatch", "unload", "--report=-", man[role]["unload"]])
        doc["steps"][f"unload_{role}"] = r
    doc["taint_end"] = taint()
    doc["status_after"] = sh([SHIRUDO, "status"])["out"][-1500:]
    doc["guest_secs"] = round(time.monotonic() - t0, 3)
    json.dump(doc, sys.stdout, indent=1)


if __name__ == "__main__":
    main()
