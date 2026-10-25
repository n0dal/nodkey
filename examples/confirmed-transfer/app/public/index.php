<?php
// SPDX-FileCopyrightText: 2026 Henry Cuevas
// SPDX-License-Identifier: Apache-2.0
//
// =====================================================================================
//  INTENTIONALLY VULNERABLE DEMO APPLICATION (Demo 2). LOCAL USE ONLY. NEVER EXPOSE IT.
//  POST /debug/eval executes arbitrary PHP supplied by the client (remote code execution).
//  It exists to model "attacker has code execution inside the workload" (threat actor C).
//  /balance also keeps the last read grant it received in /tmp: this models a compromised app
//  that retains whatever the gateway hands it (attack probes reuse it).
// =====================================================================================
//
// A protocol-v2 client app (untrusted): it proposes transfers, never holds a write grant, and
// learns outcomes through effect.status. It is enrolled to one principal (acme / user:alice).
declare(strict_types=1);

require __DIR__ . '/../lib/NodkeyClient.php';

use Nodkey\BrokerError;
use Nodkey\Client;

const BANNER = 'INTENTIONALLY VULNERABLE DEMO - contains a remote code execution endpoint - local use only';
// The workload's enrolled principal (broker registration approver_source = enrolled).
const APPROVER_TEN = 'acme';
const APPROVER_SUB = 'user:alice';
const FROM_ACCOUNT = 'alice';
const PID_RE = '/^[A-Za-z0-9_-]{22}$/D';

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

function h(string $s): string
{
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function page(string $body, int $status = 200): never
{
    http_response_code($status);
    header('Content-Type: text/html; charset=utf-8');
    echo '<!doctype html><html><head><meta charset="utf-8"><title>Nodkey Demo 2</title></head><body>',
        '<p style="background:#b00020;color:#fff;padding:8px;font-weight:bold">', h(BANNER), '</p>',
        $body, '</body></html>';
    exit;
}

$broker = new Client();

if ($method === 'POST' && $path === '/debug/eval') {
    // THE VULNERABILITY. Deliberate. Do not copy.
    header('Content-Type: text/plain; charset=utf-8');
    $code = file_get_contents('php://input');
    eval($code === false ? '' : $code);
    exit;
}

if ($method === 'GET' && $path === '/') {
    page(<<<HTML
        <h1>Ledger app (Demo 2: confirmed transfers)</h1>
        <ul>
          <li><a href="/.nodkey/login">Sign in</a> (gateway hand-off)</li>
          <li><a href="/balance?account=alice">Balance of account alice</a></li>
          <li><a href="/transfer">New transfer</a></li>
        </ul>
        HTML);
}

if ($method === 'GET' && $path === '/balance') {
    $account = (string) ($_GET['account'] ?? FROM_ACCOUNT);
    $grant = $_SERVER['HTTP_NODKEY_GRANT'] ?? null;
    if (!is_string($grant) || $grant === '') {
        page('<p id="result">NO READ GRANT: sign in first (<a href="/.nodkey/login">sign in</a>).</p>', 403);
    }
    // Models a compromised app retaining the grant (see the header comment).
    @file_put_contents('/tmp/last-read-grant', $grant);
    try {
        $bal = $broker->getBalance($account, $grant);
        page(sprintf('<p>Account <code>%s</code>: <span id="balance">%d</span> (minor units)</p>', h($account), $bal));
    } catch (BrokerError $e) {
        page(sprintf('<p id="result">DENIED: %s</p>', h($e->errorCode)), 403);
    }
}

if ($method === 'GET' && $path === '/transfer') {
    page(<<<HTML
        <h1>New transfer from account alice</h1>
        <form method="post" action="/transfer">
          to <input name="to" value="bob"> amount (minor units) <input name="amount_minor" value="100">
          <button type="submit">Request transfer</button>
        </form>
        <p>You will be sent to the sign-in origin to confirm the exact values.</p>
        HTML);
}

if ($method === 'POST' && $path === '/transfer') {
    $to = (string) ($_POST['to'] ?? '');
    $amount = filter_var((string) ($_POST['amount_minor'] ?? ''), FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
    if ($amount === false) {
        page('<p id="result">Amount must be a positive integer.</p>', 400);
    }
    try {
        $r = $broker->propose('ledger.transfer', ['from' => FROM_ACCOUNT, 'to' => $to, 'amount_minor' => $amount],
            APPROVER_TEN, APPROVER_SUB);
    } catch (BrokerError $e) {
        page(sprintf('<p id="result">PROPOSAL REFUSED: %s</p>', h($e->errorCode)), 400);
    }
    // Remember the pending id for the status page, then send the user to the auth origin.
    setcookie('demo_last_pid', $r['pending_id'], ['path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Lax']);
    header('Location: ' . $r['confirm_url'], true, 303);
    exit;
}

if ($method === 'GET' && preg_match('#^/status/([A-Za-z0-9_-]+)$#D', $path, $m) === 1) {
    $pid = $m[1];
    try {
        $s = $broker->status($pid);
    } catch (BrokerError $e) {
        page(sprintf('<p id="result">STATUS: %s</p>', h($e->errorCode)), 404);
    }
    $outcome = is_array($s['outcome'] ?? null) ? (string) ($s['outcome']['class'] ?? '') : '';
    page(sprintf(
        '<p>Pending <code>%s</code>: state <span id="state">%s</span> outcome <span id="outcome">%s</span></p>',
        h($pid), h((string) ($s['state'] ?? '?')), h($outcome),
    ));
}

page('<p>Not found</p>', 404);
