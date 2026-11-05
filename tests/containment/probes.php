<?php
// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0
//
// Containment probes for the LOCAL php-ledger demo (examples/php-ledger). This script runs INSIDE
// the untrusted workload container, exactly as attacker code would (threat actor C), and checks
// that each path to a protected resource is closed. Targets are fixed to the demo's own services.
//
// Output: one JSON object per line: {"id","si","expect","observed","result","detail"}.
// `result` is the in-workload verdict: PASS (property held), FAIL (it did not), or INCONCLUSIVE
// (the probe could not tell). tests/containment/run.sh combines it with positive controls and
// baseline sensitivity checks, and marks any probe that did not report as NOT TESTED.
//
// The same file runs via `php` on stdin and via the demo's /debug/eval endpoint (first line dropped).

declare(strict_types=1);

$SOCK = '/run/nodkey/broker.sock';
$DB_IPS = ['172.30.10.20', '172.30.20.20'];  // db address in the protected and baseline networks

function emit(string $id, string $si, string $expect, string $observed, bool|string $result, string $detail = ''): void
{
    if (is_bool($result)) {
        $result = $result ? 'PASS' : 'FAIL';
    }
    echo json_encode([
        'id' => $id, 'si' => $si, 'expect' => $expect, 'observed' => $observed,
        'result' => $result, 'detail' => $detail,
    ], JSON_UNESCAPED_SLASHES), "\n";
}

function tcp(string $host, int $port, float $timeout = 2.0): array
{
    $errno = 0; $errstr = '';
    $s = @stream_socket_client("tcp://$host:$port", $errno, $errstr, $timeout);
    if ($s === false) {
        return [false, trim("errno=$errno $errstr")];
    }
    fclose($s);
    return [true, 'connected'];
}

/** Send one raw line to the broker socket; return decoded response or a transport error string. */
function broker_raw(string $sock, string $bytes): array|string
{
    $s = @stream_socket_client("unix://$sock", $e, $es, 3.0);
    if ($s === false) {
        return "connect failed: $es";
    }
    stream_set_timeout($s, 3);
    @fwrite($s, $bytes);
    $line = fgets($s, 65536);
    fclose($s);
    if ($line === false) {
        return 'no response';
    }
    $j = json_decode($line, true);
    return is_array($j) ? $j : 'non-JSON response';
}

function broker_req(string $op, array $args): string
{
    return json_encode(['v' => 1, 'id' => bin2hex(random_bytes(4)), 'op' => $op, 'args' => (object) $args]) . "\n";
}

function denied_with(array|string $r, string $code): bool
{
    return is_array($r) && ($r['ok'] ?? null) === false && (($r['error']['code'] ?? '') === $code);
}

function code_of(array|string $r): string
{
    if (!is_array($r)) {
        return $r;
    }
    return ($r['ok'] ?? false) ? 'ok' : ('deny:' . ($r['error']['code'] ?? '?'));
}

function proc_status(string $field): ?string
{
    foreach (@file('/proc/self/status', FILE_IGNORE_NEW_LINES) ?: [] as $line) {
        if (str_starts_with($line, "$field:")) {
            return trim(substr($line, strlen($field) + 1));
        }
    }
    return null;
}

// ---------------------------------------------------------------- network reach (SI-01)
[$ok, $d] = tcp('db', 5432);
emit('N-01', 'SI-01', 'no TCP to db by name', $ok ? 'connected' : 'blocked', !$ok, $d);

$reached = [];
foreach ($DB_IPS as $ip) {
    if (tcp($ip, 5432)[0]) {
        $reached[] = $ip;
    }
}
emit('N-02', 'SI-01', 'no TCP to db by IP', $reached ? 'connected: ' . implode(',', $reached) : 'blocked', !$reached);

$res = @gethostbynamel('example.com');
emit('N-04', 'SI-01', 'no DNS resolution', $res ? 'resolved' : 'no answer', !$res, $res ? implode(',', $res) : '');

[$ok, $d] = tcp('1.1.1.1', 443);
emit('N-05', 'SI-01', 'no internet egress', $ok ? 'connected' : 'blocked', !$ok, $d);

[$ok, $d] = tcp('169.254.169.254', 80);
emit('N-06', 'SI-01', 'no cloud metadata endpoint', $ok ? 'connected' : 'blocked', !$ok, $d);

$ifaces = [];
foreach (@file('/proc/net/dev') ?: [] as $line) {
    if (preg_match('/^\s*([^:\s]+):/', $line, $m)) {
        $ifaces[] = $m[1];
    }
}
$extra = array_values(array_diff($ifaces, ['lo']));
emit('N-07', 'SI-01', 'only loopback interface', $extra ? 'interfaces: ' . implode(',', $ifaces) : 'lo only', !$extra);

// ---------------------------------------------------------------- credential custody (SI-02)
$suspicious = [];
// Exact-name allowlist. GPG_KEYS is set by the upstream php image to the PUBLIC fingerprints of PHP
// release signers (used to verify PHP source at build time); it is not a credential.
$publicEnv = ['GPG_KEYS'];
foreach (getenv() as $k => $v) {
    if (!in_array($k, $publicEnv, true) && preg_match('/PASS|SECRET|TOKEN|DSN|DATABASE|PG|KEY/i', $k)) {
        $suspicious[] = $k;
    }
}
sort($suspicious);
emit('C-01', 'SI-02', 'no credential-like env vars', $suspicious ? implode(',', $suspicious) : 'none', !$suspicious);

$present = array_values(array_filter(['/run/secrets', '/etc/nodkey', '/var/lib/postgresql'], 'file_exists'));
emit('C-02', 'SI-02', 'no secret/config dirs of trusted components', $present ? implode(',', $present) : 'none', !$present);
// C-03 (exact secret value search across the filesystem and /proc) is run by run.sh with the
// secret supplied on stdin, so the value never appears in this script, the env, or argv.

// A-01: end-to-end attacker goal. Use whatever DB credential the workload has (baseline: env vars,
// as a conventional app would) to rewrite a balance directly, bypassing the broker. Tries the
// service name and both fixed db addresses so it does not depend on DNS alone.
$user = getenv('DATABASE_USER') ?: 'nodkey_broker';
$pass = getenv('DATABASE_PASSWORD') ?: '';
$errors = [];
$done = null;
foreach (array_merge(['db'], $DB_IPS) as $host) {
    try {
        $pdo = new PDO("pgsql:host=$host;port=5432;dbname=ledger;connect_timeout=2", $user, $pass,
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT => 2]);
        $n = $pdo->exec("UPDATE accounts SET balance_cents = balance_cents + 1000000 WHERE id = 'dave'");
        $done = "direct UPDATE via $host affected $n row(s)";
        break;
    } catch (Throwable $e) {
        $errors[] = "$host: " . substr($e->getMessage(), 0, 60);
    }
}
emit('A-01', 'SI-01,SI-02', 'cannot modify ledger directly', $done ?? 'failed', $done === null, implode(' | ', $errors));

// ---------------------------------------------------------------- confinement config (P0 drift)
$nnp = proc_status('NoNewPrivs');
$sec = proc_status('Seccomp');
emit('P-01', 'P0', 'no_new_privs set and seccomp filtering', "NoNewPrivs=$nnp Seccomp=$sec", $nnp === '1' && $sec === '2');

$caps = [];
foreach (['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'] as $c) {
    $caps[$c] = proc_status($c);
}
$allZero = !in_array(null, $caps, true) && count(array_filter($caps, fn($v) => ltrim($v, '0') !== '')) === 0;
emit('P-02', 'P0', 'no Linux capabilities (incl. bounding set)', http_build_query($caps, '', ' '), $allZero);

$aa = trim((string) @file_get_contents('/proc/self/attr/current'));
emit('P-03', 'P0', 'AppArmor profile enforcing', $aa === '' ? 'unreadable' : $aa,
    $aa === '' ? 'INCONCLUSIVE' : (str_ends_with($aa, '(enforce)') && $aa !== 'unconfined'));

$rootRo = null;
foreach (@file('/proc/mounts', FILE_IGNORE_NEW_LINES) ?: [] as $line) {
    $f = explode(' ', $line);
    if (($f[1] ?? '') === '/') {
        $rootRo = in_array('ro', explode(',', $f[3] ?? ''), true);
    }
}
emit('P-04', 'P0', 'root filesystem mounted read-only', $rootRo === null ? 'not found' : ($rootRo ? 'ro' : 'rw'),
    $rootRo === null ? 'INCONCLUSIVE' : $rootRo);

// ---------------------------------------------------------------- filesystem (SI-13, AR-12)
$w = @file_put_contents('/var/www/app/public/pwned.php', '<?php echo 1;');
emit('F-01', 'SI-13', 'app code not writable', $w === false ? 'write failed' : 'written', $w === false);

// F-02: busybox dispatches on argv[0], so the copy is named after a real applet ("true"): exit 0
// means the exec succeeded (FAIL), 126 means the kernel refused it (noexec: PASS).
$seen = []; $verdict = 'PASS'; $tried = 0;
foreach (['/tmp', '/run/fcgi', '/dev/shm', '/dev/mqueue'] as $dir) {
    if (!is_dir($dir) || !is_writable($dir)) {
        $seen[] = "$dir: not writable";
        continue;
    }
    $sub = "$dir/probe-exec-" . getmypid();
    if (!@mkdir($sub) || !@copy('/bin/busybox', "$sub/true")) {
        $seen[] = "$dir: copy failed";
        @rmdir($sub);
        continue;
    }
    $tried++;
    @chmod("$sub/true", 0755);
    $out = []; $rc = -1;
    @exec(escapeshellarg("$sub/true") . ' 2>&1', $out, $rc);
    @unlink("$sub/true"); @rmdir($sub);
    $seen[] = "$dir: rc=$rc";
    if ($rc === 0) {
        $verdict = 'FAIL';
    } elseif ($rc !== 126 && $verdict === 'PASS') {
        $verdict = 'INCONCLUSIVE';
    }
}
if ($tried === 0) {
    $verdict = 'INCONCLUSIVE';
}
emit('F-02', 'SI-13', 'no exec from writable mounts', implode('; ', $seen), $verdict);

$marked = [];
foreach (['/tmp', '/run/fcgi'] as $dir) {
    if (@file_put_contents("$dir/persist-marker", 'x') !== false) {   // F-03 checked by run.sh after recreate
        $marked[] = $dir;
    }
}
emit('F-00', 'SI-13', 'persistence markers written (F-03 precondition)', implode(',', $marked), $marked ? 'PASS' : 'INCONCLUSIVE');

// ---------------------------------------------------------------- sockets and IPC (SI-01, SI-13)
$other = array_values(array_filter([
    '/var/run/docker.sock', '/run/docker.sock', '/run/containerd/containerd.sock',
    '/run/nodkey/app1/broker.sock', '/run/nodkey/app2/broker.sock',
], 'file_exists'));
emit('S-01', 'SI-01', 'no runtime or other-workload sockets', $other ? implode(',', $other) : 'none', !$other);

$entries = array_values(array_diff(@scandir('/run/nodkey') ?: [], ['.', '..']));
emit('S-02', 'SI-01', 'only own broker socket mounted', implode(',', $entries), $entries === ['broker.sock']);

// ---------------------------------------------------------------- broker interface (SI-08, SI-16)
$r = broker_raw($SOCK, broker_req('ledger.get_balance', ['account' => 'alice']));
emit('B-01', 'SI-16', 'declared op succeeds (legit path works)', code_of($r), is_array($r) && ($r['ok'] ?? false) === true);

$r = broker_raw($SOCK, broker_req('ledger.delete_account', ['account' => 'alice']));
emit('B-02', 'SI-16', 'undeclared op denied', code_of($r), denied_with($r, 'unknown_operation'));

$r = broker_raw($SOCK, broker_req('sql.exec', ['query' => 'UPDATE accounts SET balance_cents = 999999']));
emit('B-03', 'SI-16', 'no raw SQL operation', code_of($r), denied_with($r, 'unknown_operation'));

$r = broker_raw($SOCK, "{\"v\":1,\"id\":\"x\",\"op\":\"ledger.get_balance\",\n");
emit('B-04', 'SI-08', 'malformed JSON denied', code_of($r), denied_with($r, 'malformed_request'));

$r = broker_raw($SOCK, '{"v":1,"id":"x","op":"ledger.get_balance","op":"ledger.transfer","args":{"account":"alice"}}' . "\n");
emit('B-05', 'SI-08', 'duplicate keys denied', code_of($r), denied_with($r, 'malformed_request'));

$r = broker_raw($SOCK, '{"v":1,"id":"x","op":"ledger.get_balance","args":{"account":"alice"},"admin":true}' . "\n");
emit('B-06', 'SI-08', 'unknown field denied', code_of($r), denied_with($r, 'malformed_request'));

$r = broker_raw($SOCK, broker_req('ledger.get_balance', ['account' => str_repeat('a', 20000)]));
emit('B-07', 'SI-08', 'oversized request denied', code_of($r), denied_with($r, 'request_too_large'));

$key = fn() => 'probe-' . bin2hex(random_bytes(8));
$r = broker_raw($SOCK, broker_req('ledger.transfer', ['from' => 'alice', 'to' => 'bob', 'amount_cents' => -500, 'idempotency_key' => $key()]));
emit('B-08', 'SI-16', 'negative amount denied', code_of($r), denied_with($r, 'invalid_argument'));

$r = broker_raw($SOCK, broker_req('ledger.transfer', ['from' => 'alice', 'to' => 'bob', 'amount_cents' => 50001, 'idempotency_key' => $key()]));
emit('B-09', 'SI-16', 'amount over per-op limit denied', code_of($r), denied_with($r, 'limit_exceeded'));

$r = broker_raw($SOCK, '{"v":2,"id":"x","op":"ledger.get_balance","args":{"account":"alice"}}' . "\n");
emit('B-10', 'SI-08', 'unknown protocol version denied', code_of($r), denied_with($r, 'unsupported_version'));

$r = broker_raw($SOCK, '{"v":1,"id":"x","op":"ledger.get_balance","args":{"account":"alice"},"grant":"forged"}' . "\n");
emit('B-11', 'SI-08', 'unrecognized grant field not silently ignored', code_of($r), denied_with($r, 'malformed_request'));

$bal = fn() => (broker_raw($SOCK, broker_req('ledger.get_balance', ['account' => 'alice']))['result']['balance_cents'] ?? null);
$k = $key();
$before = $bal();
$r = broker_raw($SOCK, broker_req('ledger.transfer', ['from' => 'alice', 'to' => 'bob', 'amount_cents' => 100, 'idempotency_key' => $k]));
$r2 = broker_raw($SOCK, broker_req('ledger.transfer', ['from' => 'alice', 'to' => 'bob', 'amount_cents' => 100, 'idempotency_key' => $k]));
$after = $bal();
$okResp = is_array($r) && ($r['ok'] ?? false) === true && is_array($r2) && ($r2['ok'] ?? false) === true;
$delta = (is_int($before) && is_int($after)) ? $before - $after : null;
emit('B-12', 'SI-09,SI-16', 'transfer succeeds; same-key retry debits once', code_of($r) . '/' . code_of($r2) . ' delta=' . var_export($delta, true), $okResp && $delta === 100);
