<?php
// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0
//
// =====================================================================================
//  INTENTIONALLY VULNERABLE DEMO APPLICATION (Demo P). LOCAL USE ONLY. NEVER EXPOSE IT.
//  POST /debug/eval executes arbitrary PHP supplied by the client (remote code execution).
//  It exists to model "attacker has code execution inside the workload" (threat actor C).
//  Payments are SIMULATED (tools/simpay); no real money or card data is involved.
// =====================================================================================
//
// A self-service shop (workload `shop`, approver_source `named`, untrusted). It shows the
// signed-in customer's orders (payments.get_order with the read grant the gateway attaches),
// proposes refunds (effect.propose payments.refund), sends the customer to the confirmation page
// on the auth origin, and shows the closed-enum outcome (effect.status). It never holds a write
// grant, a provider key or a database credential.
declare(strict_types=1);

require __DIR__ . '/../lib/NodkeyClient.php';

use Nodkey\BrokerError;
use Nodkey\Client;

const BANNER = 'INTENTIONALLY VULNERABLE DEMO - contains a remote code execution endpoint - local use only - SIMULATED payments';
const TENANT = 'acme';
// The shop's own order book (order ids only). Which of them belong to the signed-in customer is
// decided by the broker from its trusted `orders` table (read grant `sub`), not by the shop.
const CATALOGUE = [1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 1015,
    1016, 1017, 1018, 1019, 1020, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1030];
// ISO 4217 minor-unit exponents for display and input only (the broker and authority have their own).
const EXPONENT = ['USD' => 2, 'EUR' => 2, 'GBP' => 2, 'JPY' => 0];
const SUB_RE = '/^user:[a-z0-9]{1,32}$/D';

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
    echo '<!doctype html><html><head><meta charset="utf-8"><title>Nodkey Demo P shop</title></head><body>',
        '<p style="background:#b00020;color:#fff;padding:8px;font-weight:bold">', h(BANNER), '</p>',
        $body, '</body></html>';
    exit;
}

function fmt(int $minor, string $cur): string
{
    $e = EXPONENT[$cur] ?? 2;
    if ($e === 0) {
        return (string) $minor;
    }
    $p = 10 ** $e;
    return sprintf('%d.%0' . $e . 'd', intdiv($minor, $p), $minor % $p);
}

/** "12.50" (major units, exactly the currency's exponent) -> 1250; null if malformed. */
function to_minor(string $s, string $cur): ?int
{
    $e = EXPONENT[$cur] ?? null;
    if ($e === null) {
        return null;
    }
    $re = $e === 0 ? '/^[1-9][0-9]{0,11}$/D' : '/^(0|[1-9][0-9]{0,11})\.([0-9]{' . $e . '})$/D';
    if (preg_match($re, $s, $m) !== 1) {
        return null;
    }
    $v = $e === 0 ? (int) $m[0] : (int) $m[1] * (10 ** $e) + (int) $m[2];
    return $v >= 1 ? $v : null;
}

/**
 * The customer the shop believes is signed in. Nodkey does not tell the app who the user is
 * (gateway GW-6; the read grant is opaque to the workload), so this is an UNTRUSTED hint chosen by
 * the user. It only selects whom the proposal names as approver; the auth origin decides who may
 * see and approve it (tests/demop/FINDINGS.md DEMOP-F01).
 */
function customer(): string
{
    $c = (string) ($_POST['customer'] ?? $_GET['customer'] ?? $_COOKIE['shop_customer'] ?? '');
    return preg_match(SUB_RE, $c) === 1 ? $c : '';
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
        <h1>Demo shop (Demo P: confirmed refunds, SIMULATED payments)</h1>
        <ul>
          <li><a href="/.nodkey/login">Sign in</a> (gateway hand-off)</li>
          <li><a href="/orders">My orders</a></li>
        </ul>
        HTML);
}

if ($method === 'GET' && ($path === '/orders' || preg_match('#^/orders/([0-9]{1,16})$#D', $path, $om) === 1)) {
    $grant = $_SERVER['HTTP_NODKEY_GRANT'] ?? null;
    if (!is_string($grant) || $grant === '') {
        page('<p id="result">NO READ GRANT: sign in first (<a href="/.nodkey/login">sign in</a>).</p>', 403);
    }
    $ids = isset($om[1]) ? [(int) $om[1]] : CATALOGUE;
    $rows = '';
    $cust = customer();
    foreach ($ids as $id) {
        try {
            $o = $broker->getOrder($id, $grant);
        } catch (BrokerError $e) {
            continue; // not this customer's order (uniform denial) or unavailable
        }
        $cur = (string) $o['currency'];
        $rows .= sprintf(
            '<tr class="order" data-order="%d"><td>%d</td><td>%s %s</td><td>%s %s</td><td>%s</td><td>'
            . '<form method="post" action="/refund"><input type="hidden" name="order_id" value="%d">'
            . '<input type="hidden" name="currency" value="%s"><input type="hidden" name="customer" value="%s">'
            . 'amount <input name="amount" placeholder="%s"> <button type="submit">Request refund</button></form></td></tr>',
            $id, $id, h(fmt((int) $o['amount_minor'], $cur)), h($cur), h(fmt((int) $o['refunded_minor'], $cur)), h($cur),
            h((string) $o['status']), $id, h($cur), h($cust), h(fmt(1, $cur)),
        );
    }
    page('<h1>My orders</h1>'
        . '<form method="post" action="/whoami">I am <input name="customer" value="' . h($cust) . '"> '
        . '<button>Remember</button> (shop-side hint only)</form>'
        . '<table id="orders"><tr><th>Order</th><th>Amount</th><th>Refunded</th><th>Status</th><th></th></tr>'
        . $rows . '</table><p>Refunds are confirmed on the sign-in origin before anything happens.</p>');
}

if ($method === 'POST' && $path === '/whoami') {
    $c = customer();
    setcookie('shop_customer', $c, ['path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Lax']);
    header('Location: /orders', true, 303);
    exit;
}

if ($method === 'POST' && $path === '/refund') {
    $order = filter_var((string) ($_POST['order_id'] ?? ''), FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
    $cur = (string) ($_POST['currency'] ?? '');
    $cust = customer();
    $amount = isset($_POST['amount_minor'])
        ? filter_var((string) $_POST['amount_minor'], FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]])
        : to_minor(trim((string) ($_POST['amount'] ?? '')), $cur);
    if ($order === false || $amount === false || $amount === null || $cust === '') {
        page('<p id="result">Order, amount (as shown, e.g. ' . h(fmt(1250, 'USD')) . ') and customer are required.</p>', 400);
    }
    try {
        $r = $broker->propose('payments.refund', ['order_id' => $order, 'amount_minor' => $amount, 'currency' => $cur],
            TENANT, $cust);
    } catch (BrokerError $e) {
        page(sprintf('<p id="result">PROPOSAL REFUSED: %s</p>', h($e->errorCode)), 400);
    }
    setcookie('shop_last_pid', $r['pending_id'], ['path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Lax']);
    header('Location: ' . $r['confirm_url'], true, 303);
    exit;
}

if ($method === 'GET' && preg_match('#^/status/([A-Za-z0-9_-]{22})$#D', $path, $m) === 1) {
    try {
        $s = $broker->status($m[1]);
    } catch (BrokerError $e) {
        page(sprintf('<p id="result">STATUS: %s</p>', h($e->errorCode)), 404);
    }
    $o = is_array($s['outcome'] ?? null) ? $s['outcome'] : [];
    page(sprintf(
        '<p>Refund request <code>%s</code>: state <span id="state">%s</span> outcome <span id="outcome">%s</span>'
        . ' reason <span id="reason">%s</span></p>',
        h($m[1]), h((string) ($s['state'] ?? '?')), h((string) ($o['class'] ?? '')), h((string) ($o['reason'] ?? '')),
    ));
}

page('<p>Not found</p>', 404);
