<?php
// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0
//
// Demo P containment probes. Runs INSIDE the untrusted shop workload (attacker C), after lib.php.
// One JSON object per line: {"id","si","expect","observed","result"} (PASS / FAIL), plus one
// {"id":"CANDIDATES", ...} line listing secret-shaped tokens found anywhere readable (the harness,
// not this probe, compares them with the real simpay key and K_idem; a planted decoy is the
// positive control).

function emit(string $id, string $si, string $expect, string $observed, bool $ok): void
{
    echo json_encode(['id' => $id, 'si' => $si, 'expect' => $expect, 'observed' => $observed,
        'result' => $ok ? 'PASS' : 'FAIL'], JSON_UNESCAPED_SLASHES), "\n";
}

function tcp(string $host, int $port): string
{
    $s = @stream_socket_client("tcp://$host:$port", $e, $es, 1.5);
    if ($s === false) { return "blocked($e)"; }
    fclose($s);
    return 'connected';
}

// Network (SI-01, PT-13 shop part)
$targets = [['172.30.30.20', 8443, 'simpay API'], ['172.30.40.20', 8081, 'simpay admin'],
    ['172.30.30.10', 8443, 'adapter address'], ['172.30.20.20', 5432, 'db'], ['172.30.20.10', 5432, 'broker address']];
$hits = [];
foreach ($targets as [$h, $p, $n]) { $r = tcp($h, $p); if ($r === 'connected') { $hits[] = "$n $h:$p"; } }
emit('C-NET', 'SI-01', 'no TCP to simpay API/admin, adapter, db, broker', $hits ? implode(',', $hits) : 'all blocked', !$hits);
emit('C-DNS', 'SI-01', 'no DNS (simpay.test, simpay, adapter, db)',
    implode(',', array_filter(['simpay.test', 'simpay', 'adapter', 'db'], fn($n) => @gethostbynamel($n))) ?: 'no answers',
    !array_filter(['simpay.test', 'simpay', 'adapter', 'db'], fn($n) => @gethostbynamel($n)));
$ifs = [];
foreach (@file('/proc/net/dev') ?: [] as $l) { if (preg_match('/^\s*([^:\s]+):/', $l, $m)) { $ifs[] = $m[1]; } }
emit('C-IF', 'SI-01', 'only loopback', implode(',', $ifs), array_diff($ifs, ['lo']) === []);

// Adapter socket, pg-adapter socket, adapter inputs, control sockets (SI-01, SI-02, PT-13, PT-31)
$paths = ['/run/nodkey/br-pay', '/run/nodkey/br-pay/adapter.sock', '/run/pg-adapter', '/run/pg-adapter/.s.PGSQL.5432',
    '/etc/nodkey-adapter', '/run/adapter-secrets', '/run/secrets', '/etc/nodkey', '/etc/simpay',
    '/var/lib/nodkey-authority', '/run/nodkey/gw-broker', '/run/nodkey/au-broker', '/run/nodkey/gw-authority',
    '/run/nodkey/wl', '/var/run/postgresql/.s.PGSQL.5432'];
$present = array_values(array_filter($paths, fn($p) => @file_exists($p)));
emit('C-PATH', 'SI-02/SI-13', 'no adapter/pg-adapter socket, adapter inputs, secrets, control sockets', $present ? implode(',', $present) : 'none', !$present);
$reached = [];
foreach (['/run/nodkey/br-pay/adapter.sock', '/run/pg-adapter/.s.PGSQL.5432', '/var/run/postgresql/.s.PGSQL.5432'] as $p) {
    $s = @stream_socket_client("unix://$p", $e, $es, 1.0);
    if ($s !== false) { $reached[] = $p; fclose($s); }
}
emit('C-SOCK', 'SI-01', 'adapter socket P and DB sockets not connectable', $reached ? implode(',', $reached) : 'none', !$reached);
$ls = array_values(array_diff(@scandir('/run/nodkey') ?: [], ['.', '..']));
emit('C-W', 'SI-01', '/run/nodkey holds only this workload\'s W socket', implode(',', $ls), $ls === ['broker.sock']);

// Adapter / control methods on W are never served (SI-16)
$bad = [];
foreach ([['refund.create', ['grant' => 'AAAA']], ['refund.find', ['grant' => 'AAAA']], ['adapter.hello', []],
          ['grant.deliver', ['pending_id' => str_repeat('A', 22), 'grant' => 'AAAA']],
          ['pending.get', ['pending_id' => str_repeat('A', 22)]]] as [$op, $a]) {
    $r = sock_call(W_SOCK, $op, $a);
    $c = is_array($r) ? (($r['ok'] ?? false) ? 'ok' : ($r['error']['code'] ?? '?')) : $r;
    if (!in_array($c, ['unknown_operation', 'operation_not_permitted'], true)) { $bad[] = "$op=$c"; }
}
emit('C-OPS', 'SI-16', 'adapter and control methods refused on W', $bad ? implode(',', $bad) : 'all refused', !$bad);

// Confinement (P0)
$st = [];
foreach (@file('/proc/self/status', FILE_IGNORE_NEW_LINES) ?: [] as $l) { [$k, $v] = array_pad(explode(':', $l, 2), 2, ''); $st[$k] = trim($v); }
emit('C-CAP', 'P0/PT-38', 'CapEff = 0, no_new_privs = 1, seccomp filter', ($st['CapEff'] ?? '?') . '/' . ($st['NoNewPrivs'] ?? '?') . '/' . ($st['Seccomp'] ?? '?'),
    ($st['CapEff'] ?? '') === '0000000000000000' && ($st['NoNewPrivs'] ?? '') === '1' && ($st['Seccomp'] ?? '') === '2');

// Secret-shaped tokens anywhere readable (PT-14): env, every /proc/<pid>/environ and cmdline, files.
$cands = [];
$scan = function (string $text) use (&$cands): void {
    if (preg_match_all('/rk_sim_[A-Za-z0-9_]+|sk_sim_[A-Za-z0-9_]+|(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])/', $text, $m)) {
        foreach ($m[0] as $t) { $cands[$t] = true; }
    }
};
$scan(implode("\n", array_map(fn($k, $v) => "$k=$v", array_keys(getenv()), getenv())));
foreach (glob('/proc/[0-9]*') ?: [] as $p) { $scan((string) @file_get_contents("$p/environ")); $scan((string) @file_get_contents("$p/cmdline")); }
$files = 0;
$walk = function (string $dir, int $depth) use (&$walk, $scan, &$files): void {
    if ($depth > 8 || $files > 20000) { return; }
    foreach (@scandir($dir) ?: [] as $e) {
        if ($e === '.' || $e === '..') { continue; }
        $p = rtrim($dir, '/') . '/' . $e;
        if (is_link($p)) { continue; }
        if (is_dir($p)) { $walk($p, $depth + 1); continue; }
        if (is_file($p) && is_readable($p) && @filesize($p) < 1048576) { $files++; $scan((string) @file_get_contents($p)); }
    }
};
foreach (['/etc', '/run', '/tmp', '/var', '/home', '/root', '/usr/local/etc', '/opt', '/srv', '/mnt'] as $d) { $walk($d, 0); }
echo json_encode(['id' => 'CANDIDATES', 'files_scanned' => $files, 'tokens' => array_keys($cands)], JSON_UNESCAPED_SLASHES), "\n";
