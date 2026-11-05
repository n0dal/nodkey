<?php
// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0
//
// Helpers for Demo P probes (copied from tests/demo2/probes/lib.php). Runs INSIDE the untrusted workload (via the RCE endpoint or
// `docker compose exec`), as attacker code would (threat actor C). The harness prepends it to each
// probe; the first line is dropped when the code is sent to /debug/eval.

const W_SOCK = '/run/nodkey/broker.sock';

function sock_call(string $sock, string $op, array $args): array|string
{
    $line = json_encode(['v' => 2, 'id' => 'p' . bin2hex(random_bytes(4)), 'op' => $op, 'args' => (object) $args],
        JSON_UNESCAPED_SLASHES) . "\n";
    return sock_raw($sock, $line);
}

function sock_raw(string $sock, string $bytes): array|string
{
    $s = @stream_socket_client("unix://$sock", $e, $es, 3.0);
    if ($s === false) { return "connect failed: $es"; }
    stream_set_timeout($s, 5);
    @fwrite($s, $bytes);
    $line = fgets($s, 65536);
    fclose($s);
    if ($line === false) { return 'no response'; }
    $j = json_decode($line, true);
    return is_array($j) ? $j : 'non-JSON response';
}

/** Runs a JSON list of [op, args] (or ["raw", line]) on $sock; prints one JSON array of responses. */
function run_calls(string $sock, string $b64json): void
{
    $out = [];
    foreach (json_decode(base64_decode($b64json), true) as [$op, $args]) {
        $out[] = $op === 'raw' ? sock_raw($sock, $args) : sock_call($sock, $op, $args);
    }
    echo json_encode($out, JSON_UNESCAPED_SLASHES), "\n";
}
