<?php
// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0
//
// Demo 2 containment probes (adapted from tests/containment/probes.php for the v2 topology).
// Runs INSIDE the untrusted app workload, after lib.php. One JSON object per line:
// {"id","si","expect","observed","result"} with result PASS / FAIL.

function emit(string $id, string $si, string $expect, string $observed, bool $ok): void
{
    echo json_encode(['id' => $id, 'si' => $si, 'expect' => $expect, 'observed' => $observed,
        'result' => $ok ? 'PASS' : 'FAIL'], JSON_UNESCAPED_SLASHES), "\n";
}

function tcp(string $host, int $port): bool
{
    $s = @stream_socket_client("tcp://$host:$port", $e, $es, 1.0);
    if ($s === false) { return false; }
    fclose($s);
    return true;
}

// Network (SI-01)
$hits = array_values(array_filter(['db', '172.30.20.20', '172.30.20.10'], fn($h) => tcp($h, 5432)));
emit('N-01', 'SI-01', 'no TCP to db (name or IP)', $hits ? implode(',', $hits) : 'blocked', !$hits);
emit('N-04', 'SI-01', 'no DNS', @gethostbynamel('example.com') ? 'resolved' : 'no answer', !@gethostbynamel('example.com'));
emit('N-05', 'SI-01', 'no egress', tcp('1.1.1.1', 443) ? 'connected' : 'blocked', !tcp('1.1.1.1', 443));
$gw = tcp('127.0.0.1', 8444) || tcp('127.0.0.1', 8443);
emit('N-08', 'SI-01', 'gateway listener not reachable from the workload', $gw ? 'connected' : 'blocked', !$gw);
$ifs = [];
foreach (@file('/proc/net/dev') ?: [] as $l) { if (preg_match('/^\s*([^:\s]+):/', $l, $m)) { $ifs[] = $m[1]; } }
$extra = array_diff($ifs, ['lo']);
emit('N-07', 'SI-01', 'only loopback', $extra ? implode(',', $ifs) : 'lo only', !$extra);

// Credentials and trusted-component files (SI-02, SI-05, SI-13)
$sus = [];
foreach (getenv() as $k => $v) { if ($k !== 'GPG_KEYS' && preg_match('/PASS|SECRET|TOKEN|DSN|DATABASE|PG|KEY/i', $k)) { $sus[] = $k; } }
emit('C-01', 'SI-02', 'no credential-like env vars', $sus ? implode(',', $sus) : 'none', !$sus);
$paths = ['/run/secrets', '/etc/nodkey', '/var/lib/nodkey-authority', '/var/lib/nodkey-authority/signing.key',
    '/var/lib/postgresql', '/run/nodkey/gw-broker', '/run/nodkey/au-broker', '/run/nodkey/gw-authority',
    '/run/nodkey/wl', '/run/app-http', '/run/gw-tls'];
$present = array_values(array_filter($paths, fn($p) => @file_exists($p)));
emit('C-02', 'SI-05/SI-13', 'no key, config, secret or control-socket paths', $present ? implode(',', $present) : 'none', !$present);
$ls = @scandir('/run/nodkey') ?: [];
$ls = array_values(array_diff($ls, ['.', '..']));
emit('S-01', 'SI-01', '/run/nodkey holds only this workload\'s W socket', implode(',', $ls), $ls === ['broker.sock']);

// Control sockets by path (T43): every attempt must fail to connect.
$reached = [];
foreach (['/run/nodkey/gw-broker/broker.sock', '/run/nodkey/au-broker/broker.sock',
          '/run/nodkey/gw-authority/authority.sock', '/run/nodkey/wl/app2/broker.sock', '/run/app-http/nginx.sock'] as $p) {
    $r = sock_call($p, 'config.digest', []);
    if (is_array($r)) { $reached[] = $p; }
}
emit('S-02', 'SI-01/SI-05', 'no control socket (G, A, I, W2, app-http) connectable', $reached ? implode(',', $reached) : 'none', !$reached);

// Control-channel methods on socket W (T16 analogue): never served.
$bad = [];
foreach ([['pending.render', ['pending_id' => str_repeat('A', 22), 'subject' => ['ten' => 'acme', 'sub' => 'user:alice']]],
          ['pending.deny', ['pending_id' => str_repeat('A', 22), 'digest' => str_repeat('0', 64), 'subject' => ['ten' => 'acme', 'sub' => 'user:alice']]],
          ['pending.get', ['pending_id' => str_repeat('A', 22)]],
          ['grant.deliver', ['pending_id' => str_repeat('A', 22), 'grant' => 'AAAA']],
          ['config.digest', []],
          ['approve', ['pending_id' => str_repeat('A', 22), 'digest_shown' => str_repeat('0', 64), 'subject' => ['ten' => 'acme', 'sub' => 'user:alice']]],
          ['read_grant', ['subject' => ['ten' => 'acme', 'sub' => 'user:alice'], 'wid' => 'x', 'rop' => ['ledger.get_balance']]]] as [$op, $a]) {
    $r = sock_call(W_SOCK, $op, $a);
    $c = is_array($r) ? (($r['ok'] ?? false) ? 'ok' : ($r['error']['code'] ?? '?')) : $r;
    if (!in_array($c, ['unknown_operation', 'operation_not_permitted'], true)) { $bad[] = "$op=$c"; }
}
emit('S-03', 'SI-16', 'control methods refused on W', $bad ? implode(',', $bad) : 'all refused', !$bad);

// Confinement (P0)
$st = [];
foreach (@file('/proc/self/status', FILE_IGNORE_NEW_LINES) ?: [] as $l) { [$k, $v] = array_pad(explode(':', $l, 2), 2, ''); $st[$k] = trim($v); }
emit('P-01', 'P0', 'no_new_privs=1', $st['NoNewPrivs'] ?? '?', ($st['NoNewPrivs'] ?? '') === '1');
emit('P-02', 'P0', 'zero effective capabilities', $st['CapEff'] ?? '?', ($st['CapEff'] ?? '') === '0000000000000000');
emit('P-03', 'P0', 'seccomp filter mode', $st['Seccomp'] ?? '?', ($st['Seccomp'] ?? '') === '2');
$w = @file_put_contents('/var/www/app/public/x.php', 'x');
emit('F-01', 'SI-13', 'app code read-only', $w === false ? 'write refused' : 'written', $w === false);
