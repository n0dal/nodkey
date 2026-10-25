#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Henry Cuevas
# SPDX-License-Identifier: Apache-2.0
#
# Containment test runner for the LOCAL, INTENTIONALLY VULNERABLE php-ledger demo.
#
#   tests/containment/run.sh [both|protected|baseline]   (default: both)
#
# For each profile it starts the stack, runs tests/containment/probes.php inside the workload
# (via `docker compose exec` and via the HTTP RCE endpoint), runs out-of-workload checks, and
# writes results to var/containment/results-<profile>.json.
#
# Result values: PASS, FAIL, NOT TESTED, NOT APPLICABLE, INCONCLUSIVE.
#  - A probe that did not report is NOT TESTED (never silently dropped).
#  - A protected-profile PASS on a probe listed in SENSITIVE is downgraded to INCONCLUSIVE unless the
#    same probe FAILED in the baseline (proof that the probe detects the breach it looks for).
# Exit status: 0 if every protected-profile result is PASS or NOT APPLICABLE; 1 if any FAIL;
# 2 if none FAIL but some are INCONCLUSIVE or NOT TESTED. Run `both` for meaningful results.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEMO="$ROOT/examples/php-ledger"
OUT="$ROOT/var/containment"
PROBES="$ROOT/tests/containment/probes.php"
WHICH="${1:-both}"
mkdir -p "$OUT"

# IDs probes.php must emit (per transport), and IDs that need a breach in the baseline to count.
IN_WORKLOAD_IDS="N-01 N-02 N-04 N-05 N-06 N-07 C-01 C-02 A-01 P-01 P-02 P-03 P-04 F-01 F-02 F-00 S-01 S-02 B-01 B-02 B-03 B-04 B-05 B-06 B-07 B-08 B-09 B-10 B-11 B-12"
RUNNER_IDS="K-DB K-NET C-03 R-01 X-01 F-03 P-05"
SENSITIVE="N-01 N-02 N-04 N-05 N-07 C-01 C-03 A-01 F-02 P-01 P-02 P-04 X-01"

gen_secrets() {  # local demo secrets; never reused anywhere else
  local p="$1" d="$OUT/secrets/$1"
  mkdir -p "$d"
  for s in db_broker_password db_superuser_password db_app_password; do
    [ -s "$d/$s" ] || openssl rand -hex 24 > "$d/$s"
  done
  chmod 0644 "$d"/*   # bind-mounted into containers running as other uids (local demo only)
  if [ "$p" = baseline ]; then
    printf 'DATABASE_DSN=pgsql:host=db;port=5432;dbname=ledger;connect_timeout=2\nDATABASE_USER=ledger_app\nDATABASE_PASSWORD=%s\n' \
      "$(cat "$d/db_app_password")" > "$d/app.env"
  fi
}

compose() { docker compose -f "$DEMO/compose.$PROFILE.yaml" "$@"; }

rec() {  # id si expect observed result detail  -> one JSON result line from the runner itself
  php -r 'echo json_encode(["id"=>$argv[1],"si"=>$argv[2],"expect"=>$argv[3],"observed"=>$argv[4],"result"=>$argv[5],"detail"=>$argv[6],"via"=>"run"], JSON_UNESCAPED_SLASHES),"\n";' -- "$@"
}

# Search the workload for a secret value supplied on stdin (never in argv or env).
search_secret() {
  compose exec -T app sh -c 'read -r s; { grep -rlF "$s" / --exclude-dir=proc --exclude-dir=sys 2>/dev/null; for f in /proc/[0-9]*/environ /proc/[0-9]*/cmdline; do grep -lF "$s" "$f" 2>/dev/null; done; } | grep -v "^/proc/self/" | head -5' < "$1" || true
}

run_profile() {
  PROFILE="$1"
  local res="$OUT/raw-$PROFILE.jsonl" net="nodkey-${PROFILE}_data" port
  [ "$PROFILE" = protected ] && port=8080 || port=8081
  : > "$res"
  gen_secrets "$PROFILE"
  echo "== [$PROFILE] starting stack" >&2
  compose down -v --remove-orphans >/dev/null 2>&1 || true
  compose up -d --build --wait >/dev/null

  # ---- positive controls (run OUTSIDE the workload)
  local k_db=FAIL k_net=FAIL
  docker run --rm --network "$net" postgres:17-alpine pg_isready -q -h db -t 3 && k_db=PASS
  compose exec -T web wget -q -T 3 -O /dev/null https://1.1.1.1/ >/dev/null 2>&1 && k_net=PASS
  rec K-DB control "db reachable from its own network" "$k_db" "$k_db" "" >> "$res"
  rec K-NET control "VM has internet egress" "$k_net" "$k_net" "" >> "$res"

  # ---- in-workload probes via docker exec (same namespaces, uid, and mounts as the app)
  compose exec -T app php < "$PROBES" | grep '^{' | sed 's/^{/{"via":"exec",/' >> "$res" || true

  # ---- the same probes via the HTTP RCE endpoint (models a real remote attacker)
  tail -n +2 "$PROBES" | curl -s --max-time 90 -X POST --data-binary @- "http://127.0.0.1:$port/debug/eval" \
    | grep '^{' | sed 's/^{/{"via":"http",/' >> "$res" || true

  # ---- C-03: exact broker-secret search inside the workload. Control C-03K: the same search
  # finds a secret that IS present (baseline only: the app's own DB password is in its env).
  local hits
  hits=$(search_secret "$OUT/secrets/$PROFILE/db_broker_password")
  if [ -z "$hits" ]; then rec C-03 SI-02 "broker DB secret absent from workload" "not found" PASS "fs + /proc/*/environ,cmdline" >> "$res"
  else rec C-03 SI-02 "broker DB secret absent from workload" "found" FAIL "$(echo "$hits" | tr '\n' ' ')" >> "$res"; fi
  if [ "$PROFILE" = baseline ]; then
    hits=$(search_secret "$OUT/secrets/baseline/db_app_password")
    if [ -n "$hits" ]; then rec C-03K control "search finds a secret that is present" PASS PASS "$(echo "$hits" | tr '\n' ' ')" >> "$res"
    else rec C-03K control "search finds a secret that is present" FAIL FAIL "" >> "$res"; fi
  fi

  # ---- R-01 (SI-03): db rejects even the CORRECT broker password from a non-broker address.
  # PASS only on the server's pg_hba rejection (proves the server was reached and refused by policy).
  local err
  err=$(docker run --rm --network "$net" -e PGPASSWORD="$(cat "$OUT/secrets/$PROFILE/db_broker_password")" \
         postgres:17-alpine psql -h db -U nodkey_broker -d ledger -tAc 'select 1' 2>&1 >/dev/null || true)
  if echo "$err" | grep -q 'no pg_hba.conf entry\|rejects connection'; then
    rec R-01 SI-03 "db rejects broker creds from non-broker address" "rejected by pg_hba" PASS "" >> "$res"
  elif [ -z "$err" ]; then
    rec R-01 SI-03 "db rejects broker creds from non-broker address" "accepted" FAIL "" >> "$res"
  else
    rec R-01 SI-03 "db rejects broker creds from non-broker address" "other error" INCONCLUSIVE "$(echo "$err" | head -c 120)" >> "$res"
  fi

  # ---- X-01 (AR-15): app response header must not trigger an nginx internal redirect
  local body
  body=$(curl -s --max-time 10 -X POST --data-binary 'header("X-Accel-Redirect: /_internal/x"); echo "app-body";' \
         "http://127.0.0.1:$port/debug/eval" || true)
  if echo "$body" | grep -q NODKEY-INTERNAL-CANARY; then rec X-01 SI-01 "X-Accel-Redirect ignored" "redirect followed" FAIL "" >> "$res"
  elif echo "$body" | grep -q app-body; then rec X-01 SI-01 "X-Accel-Redirect ignored" "ignored" PASS "" >> "$res"
  else rec X-01 SI-01 "X-Accel-Redirect ignored" "no response" INCONCLUSIVE "" >> "$res"; fi

  # ---- P-05: out-of-workload configuration drift check of the app container
  local cid
  cid=$(compose ps -q app)
  docker inspect "$cid" | php -r '
    $c = json_decode(stream_get_contents(STDIN), true)[0]; $h = $c["HostConfig"]; $bad = [];
    if ($h["Privileged"]) $bad[] = "privileged";
    if (!empty($h["CapAdd"])) $bad[] = "cap_add=" . implode(",", $h["CapAdd"]);
    if (!in_array("ALL", $h["CapDrop"] ?? [], true)) $bad[] = "cap_drop!=ALL";
    if (!$h["ReadonlyRootfs"]) $bad[] = "rootfs rw";
    if ($h["NetworkMode"] !== "none") $bad[] = "network_mode=" . $h["NetworkMode"];
    if (($h["PidMode"] ?? "") !== "") $bad[] = "pid=" . $h["PidMode"];
    if (($h["IpcMode"] ?? "") !== "private") $bad[] = "ipc=" . $h["IpcMode"];
    $so = implode(",", $h["SecurityOpt"] ?? []);
    if (!str_contains($so, "no-new-privileges")) $bad[] = "no-new-privileges missing";
    if (str_contains($so, "unconfined")) $bad[] = "unconfined: $so";
    if (!empty($h["Devices"])) $bad[] = "devices";
    $allowed = ["/run/fcgi", "/run/nodkey", "/tmp"];
    foreach ($c["Mounts"] as $m) if (!in_array($m["Destination"], $allowed, true)) $bad[] = "mount " . $m["Destination"];
    foreach ($c["Mounts"] as $m) if ($m["Destination"] === "/run/nodkey" && $m["RW"]) $bad[] = "broker socket dir rw";
    echo json_encode(["id"=>"P-05","si"=>"P0","expect"=>"app container config matches P0","observed"=>$bad ? implode("; ", $bad) : "matches","result"=>$bad ? "FAIL" : "PASS","detail"=>"docker inspect","via"=>"run"]), "\n";
  ' >> "$res"

  # ---- F-03 (AR-12, D1-03): nothing the workload wrote survives recreating ONLY the app
  # (web keeps the shared socket volume mounted, which is the case that used to leak).
  compose up -d --force-recreate --no-deps --wait app >/dev/null
  local left
  left=$(compose exec -T app sh -c 'ls /tmp/persist-marker /run/fcgi/persist-marker 2>/dev/null' || true)
  if [ -z "$left" ]; then rec F-03 SI-13 "no persistence across app recreate" "absent" PASS "requires F-00" >> "$res"
  else rec F-03 SI-13 "no persistence across app recreate" "present" FAIL "$left" >> "$res"; fi

  compose down -v --remove-orphans >/dev/null 2>&1 || true
}

summarize() {
  IN_WORKLOAD_IDS="$IN_WORKLOAD_IDS" RUNNER_IDS="$RUNNER_IDS" SENSITIVE="$SENSITIVE" php -d display_errors=stderr -r '
    [$_, $prof, $raw, $out, $baselineRaw] = $argv;
    $load = fn($f) => is_file($f) ? array_values(array_filter(array_map(fn($l) => json_decode($l, true), file($f, FILE_IGNORE_NEW_LINES)))) : [];
    $rows = $load($raw);
    $ctl = []; foreach ($rows as $r) if ($r["si"] === "control") $ctl[$r["id"]] = $r["result"];

    // Completeness: every expected probe must have reported on every transport.
    $have = []; foreach ($rows as $r) $have[$r["via"] . "/" . $r["id"]] = true;
    foreach (["exec", "http"] as $via) foreach (explode(" ", getenv("IN_WORKLOAD_IDS")) as $id)
      if (!isset($have["$via/$id"])) $rows[] = ["via"=>$via,"id"=>$id,"si"=>"?","expect"=>"(probe did not report)","observed"=>"missing","result"=>"NOT TESTED","detail"=>""];
    foreach (explode(" ", getenv("RUNNER_IDS")) as $id)
      if (!isset($have["run/$id"])) $rows[] = ["via"=>"run","id"=>$id,"si"=>"?","expect"=>"(check did not report)","observed"=>"missing","result"=>"NOT TESTED","detail"=>""];

    // Baseline sensitivity: the same probe must have detected the breach in the baseline.
    $base = []; foreach ($load($baselineRaw) as $b) $base[$b["id"]][$b["via"]] = $b["result"];
    $baseCtl = $base["C-03K"]["run"] ?? null;
    $sensitive = explode(" ", getenv("SENSITIVE"));
    $f00 = []; foreach ($rows as $r) if ($r["id"] === "F-00") $f00[] = $r["result"];

    foreach ($rows as &$r) {
      if ($r["si"] === "control" || $r["result"] !== "PASS") continue;
      if ($r["id"] === "N-06") { $r["result"] = "NOT APPLICABLE"; $r["detail"] = "no metadata service in the local VM; re-test on cloud hosts"; continue; }
      if (in_array($r["id"], ["N-01","N-02","A-01"]) && ($ctl["K-DB"] ?? "") !== "PASS") { $r["result"] = "INCONCLUSIVE"; $r["detail"] .= " [control K-DB failed]"; continue; }
      if ($r["id"] === "N-05" && ($ctl["K-NET"] ?? "") !== "PASS") { $r["result"] = "INCONCLUSIVE"; $r["detail"] .= " [control K-NET failed]"; continue; }
      if ($r["id"] === "F-03" && in_array("INCONCLUSIVE", $f00, true)) { $r["result"] = "INCONCLUSIVE"; $r["detail"] .= " [markers were not written]"; continue; }
      if ($prof !== "protected" || !in_array($r["id"], $sensitive, true)) continue;
      if ($r["id"] === "C-03") { $ok = $baseCtl === "PASS"; }
      else { $b = $base[$r["id"]][$r["via"]] ?? ($base[$r["id"]]["exec"] ?? null); $ok = $b === "FAIL"; }
      if (!$ok) { $r["result"] = "INCONCLUSIVE"; $r["detail"] .= " [no baseline breach detected: probe sensitivity unverified]"; }
    }
    unset($r);

    file_put_contents($out, json_encode(["profile"=>$prof, "generated_at"=>gmdate("c"), "results"=>$rows], JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES));
    printf("\n%s profile\n%-5s %-6s %-12s %-46s %-14s %s\n", strtoupper($prof), "VIA", "ID", "INVARIANT", "EXPECTATION", "RESULT", "OBSERVED");
    $worst = 0; $count = [];
    foreach ($rows as $r) {
      printf("%-5s %-6s %-12s %-46s %-14s %s\n", $r["via"], $r["id"], $r["si"], substr($r["expect"],0,46), $r["result"], substr($r["observed"],0,70));
      $count[$r["result"]] = ($count[$r["result"]] ?? 0) + 1;
      if ($r["result"] === "FAIL") $worst = 1;
      elseif (in_array($r["result"], ["INCONCLUSIVE","NOT TESTED"]) && $worst === 0) $worst = 2;
    }
    ksort($count); echo "TOTALS ", json_encode($count), "\n";
    exit($prof === "protected" ? $worst : 0);
  ' -- "$1" "$OUT/raw-$1.jsonl" "$OUT/results-$1.json" "$OUT/raw-baseline.jsonl"
}

status=0
if [ "$WHICH" = baseline ] || [ "$WHICH" = both ]; then run_profile baseline; summarize baseline || true; fi
if [ "$WHICH" = protected ] || [ "$WHICH" = both ]; then run_profile protected; summarize protected || status=$?; fi
echo
echo "Baseline is a POSITIVE CONTROL: its FAIL rows are expected (a conventional deployment is breachable)."
echo "Protected-profile exit status: $status (0 = all PASS/NOT APPLICABLE, 1 = FAIL, 2 = INCONCLUSIVE/NOT TESTED)"
exit "$status"
