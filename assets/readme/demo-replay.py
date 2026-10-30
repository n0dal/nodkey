#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Henry Cuevas
# SPDX-License-Identifier: Apache-2.0
#
# Prints the verbatim Demo A results in demo-capture.json (made by demo-extract.py from a real run of
# tests/demoa/run.sh) for the README recording (demo.tape). It contacts nothing and decides nothing:
# every argument, status, error and harness row is printed as recorded. The only added text is the
# headings and a short reading of each status (succeeded -> executed, rejected -> denied, ...).
#
#   python3 -I assets/readme/demo-replay.py [capture.json] [--pace SECONDS]
import json, os, sys, textwrap, time

W = 84
RED, GREEN, AMBER = "\033[38;2;229;83;75m", "\033[38;2;87;171;90m", "\033[38;2;198;144;38m"
DIM, BOLD, OFF = "\033[38;2;150;158;168m", "\033[1m", "\033[0m"


def out(text="", color="", indent=0, pause=0.0, hang=0):
    pad = " " * indent
    lines = textwrap.wrap(text, W - indent, subsequent_indent=" " * hang,
                          break_long_words=True) if text else [""]
    for ln in lines:
        print(f"{pad}{color}{ln}{OFF if color else ''}", flush=True)
    time.sleep(pause)


def args_text(a):
    return json.dumps(a, ensure_ascii=False, separators=(",", ":"))


def main():
    argv = sys.argv[1:]
    pace = 1.0
    if "--pace" in argv:
        i = argv.index("--pace"); pace = float(argv[i + 1]); del argv[i:i + 2]
    path = argv[0] if argv else os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                            "demo-capture.json")
    cap = json.load(open(path, encoding="utf-8"))
    steps = {s["step"]: s for s in cap["steps"]}
    rows = {r["id"]: r for r in cap["rows"]}

    out(f"Recorded results of {cap['source']}", DIM, pause=0.4 * pace)
    out()
    t = cap["ticket"].split("\n\n", 1)
    out("Ticket the scripted, fully prompt-injected agent obeys:", BOLD)
    out(t[1].strip() if len(t) == 2 else cap["ticket"].strip(), indent=2, pause=2.2 * pace)
    out()
    m = steps["S0"]["arguments"]
    out(f"Earlier, the approver granted a mandate for customer {m['customer_sub']}: up to "
        f"{m['refund_max_count']} refunds, {m['refund_max_per_call_minor'] / 100:.2f} each, "
        f"{m['refund_max_total_minor'] / 100:.2f} {m['currency']} in total.", DIM, pause=1.2 * pace)

    reading = {"succeeded": ("executed", GREEN), "rejected": ("denied by the approver; nothing ran", RED),
               "denied": ("denied; nothing ran", RED)}
    for sid in ("S2", "S3", "S6", "S8"):
        s = steps[sid]
        out()
        out(f"{sid}  agent -> {s['tool']} {args_text(s['arguments'])}", hang=4, pause=0.5 * pace)
        r, final = s["response"], s["final_status"]
        if isinstance(r, dict) and "status" in r:
            chain = r["status"] + (f" -> {final['status']}" if final else "")
            last = final["status"] if final else r["status"]
            word, color = reading.get(last, (last, ""))
            if sid == "S8":
                word, color = "executed: allowed channel, stated limit R-A2", AMBER
            out(f"nodkey: {chain}   [{word}]", color, indent=4, pause=0.3 * pace)
        else:
            out(f"nodkey: {args_text(r)}   [rejected; no record created]", RED, indent=4,
                pause=0.3 * pace)
        time.sleep(1.2 * pace)

    out()
    out("Harness checks (provider ledger, mail sink, effect records):", BOLD)
    out("   ".join(f"{rid} {rows[rid]['result']}" for rid in ("S2", "S3", "S6", "S8")), DIM,
        indent=2, pause=0.4 * pace)
    for rid in ("S-final-ledger", "S-final-mail"):
        out(f"{rid} {rows[rid]['result']}: {rows[rid]['title']}", DIM, indent=2, hang=4,
            pause=0.4 * pace)
    out()
    out(f"Whole run: {cap['summary_line']}", BOLD, pause=0.2 * pace)


if __name__ == "__main__":
    main()
