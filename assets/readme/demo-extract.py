#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 n0dal
# SPDX-License-Identifier: Apache-2.0
#
# Copies selected, verbatim results of a finished Demo A run (tests/demoa/run.sh) into
# assets/readme/demo-capture.json, which demo-replay.py prints for the README recording (demo.tape).
# Nothing is edited or invented: tool arguments, Nodkey's responses and the harness rows are copied
# as recorded. Only fields not needed for the recording are left out.
#
#   tests/demoa/run.sh > run.out
#   python3 -I assets/readme/demo-extract.py var/demoa run.out assets/readme/demo-capture.json
import glob, json, os, sys

STEPS = ["S0", "S2", "S3", "S6", "S8"]
ROWS = ["S2", "S3", "S6", "S8", "S-final-ledger", "S-final-mail"]


def main(src, stdout_file, dst):
    pass_no = 2
    agent = glob.glob(os.path.join(src, f"agent-pass{pass_no}-S0p_*.jsonl"))
    if len(agent) != 1:
        sys.exit(f"expected one agent-pass{pass_no}-S0p_*.jsonl in {src}, found {len(agent)}")
    ticket, steps = None, {}
    for line in open(agent[0], encoding="utf-8"):
        e = json.loads(line)
        if e.get("event") == "ticket":
            ticket = e["text"]
        elif e.get("event") == "step" and e.get("step") in STEPS:
            resp = e.get("response", {})
            first = resp.get("result", {}).get("structuredContent") or resp.get("error") \
                or resp.get("result", {}).get("content")
            polls = e.get("polls") or []
            final = polls[-1].get("result", {}).get("structuredContent") if polls else None
            steps[e["step"]] = {"tool": e.get("tool"), "arguments": e.get("arguments"),
                                "because": e.get("because"), "response": first,
                                "final_status": final}
    results = json.load(open(os.path.join(src, "results.json"), encoding="utf-8"))
    rows = [{k: r[k] for k in ("pass", "id", "result", "title")}
            for r in results if r.get("pass") == pass_no and r.get("id") in ROWS]
    counts = {}
    for r in results:
        if r.get("pass") == pass_no:
            counts[r["result"]] = counts.get(r["result"], 0) + 1
    summary = [l.strip() for l in open(stdout_file, encoding="utf-8") if " PASS / " in l]
    if not summary:
        sys.exit(f"no summary line in {stdout_file}")
    missing = [s for s in STEPS if s not in steps] + [i for i in ROWS if i not in {r["id"] for r in rows}]
    if ticket is None or missing:
        sys.exit(f"incomplete run output; missing: {missing or 'ticket'}")
    out = {"source": "tests/demoa/run.sh, pass 2 (fresh local stack)",
           "ticket": ticket, "steps": [dict(step=s, **steps[s]) for s in STEPS],
           "rows": rows, "pass2_counts": counts,
           "summary_line": summary[-1]}
    with open(dst, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1, ensure_ascii=False)
        f.write("\n")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit("usage: demo-extract.py <var/demoa> <run.sh stdout> <out.json>")
    main(sys.argv[1], sys.argv[2], sys.argv[3])
