<?php
// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0
//
// Minimal Nodkey workload client, protocol v2 (docs/specs/effect-protocol-v2.md §2). A
// convenience, NOT an enforcement boundary: attacker code in the workload can talk to the socket
// directly, and the broker assumes it does.
declare(strict_types=1);

namespace Nodkey;

final class BrokerError extends \RuntimeException
{
    public function __construct(
        public readonly string $errorCode,
        string $message,
        public readonly ?string $correlationId = null,
    ) {
        parent::__construct($message);
    }
}

final class Client
{
    private const MAX_RESPONSE_BYTES = 65536;

    public function __construct(
        private readonly string $socketPath = '/run/nodkey/broker.sock',
        private readonly float $timeoutSeconds = 5.0,
    ) {
    }

    /**
     * effect.propose: a request without authority. Returns pending_id, confirm_url, expires_at.
     *
     * @param array<string,int|string> $params
     * @return array{pending_id:string, confirm_url:string, expires_at:int}
     */
    public function propose(string $op, array $params, string $ten, string $sub): array
    {
        return $this->call('effect.propose', [
            'op' => $op,
            'params' => (object) $params,
            'approver' => ['ten' => $ten, 'sub' => $sub],
        ]);
    }

    /** @return array<string,mixed> effect.status result */
    public function status(string $pendingId): array
    {
        return $this->call('effect.status', ['pending_id' => $pendingId]);
    }

    /** ledger.get_balance with the read grant the gateway attached to this request. */
    public function getBalance(string $account, string $grant): int
    {
        $r = $this->call('ledger.get_balance', ['account' => $account, 'grant' => $grant]);
        if (!is_int($r['balance_minor'] ?? null)) {
            throw new BrokerError('bad_response', 'missing balance_minor');
        }
        return $r['balance_minor'];
    }

    /** @return array<string,mixed> the `result` of a successful response */
    public function call(string $op, array $args): array
    {
        $resp = self::raw($this->socketPath, self::line($op, $args, $id), $this->timeoutSeconds);
        if (!is_array($resp) || ($resp['v'] ?? null) !== 2 || ($resp['id'] ?? null) !== $id) {
            throw new BrokerError('bad_response', is_string($resp) ? $resp : 'response does not match request');
        }
        if (($resp['ok'] ?? false) === true && is_array($resp['result'] ?? null)) {
            return $resp['result'];
        }
        $err = is_array($resp['error'] ?? null) ? $resp['error'] : [];
        throw new BrokerError(
            (string) ($err['code'] ?? 'bad_response'),
            (string) ($err['message'] ?? 'broker error'),
            isset($resp['correlation_id']) ? (string) $resp['correlation_id'] : null,
        );
    }

    public static function line(string $op, array $args, ?string &$id = null): string
    {
        $id = bin2hex(random_bytes(8));
        return json_encode(['v' => 2, 'id' => $id, 'op' => $op, 'args' => (object) $args],
            JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . "\n";
    }

    /** Sends raw bytes, returns the decoded response or a transport error string. */
    public static function raw(string $socketPath, string $bytes, float $timeout = 5.0): array|string
    {
        $errno = 0;
        $errstr = '';
        $sock = @stream_socket_client('unix://' . $socketPath, $errno, $errstr, $timeout);
        if ($sock === false) {
            return "connect failed: $errstr";
        }
        try {
            stream_set_timeout($sock, (int) ceil($timeout));
            if (@fwrite($sock, $bytes) !== strlen($bytes)) {
                return 'write failed';
            }
            $line = fgets($sock, self::MAX_RESPONSE_BYTES);
            if ($line === false) {
                return 'no response';
            }
            $j = json_decode($line, true, 32);
            return is_array($j) ? $j : 'non-JSON response';
        } finally {
            fclose($sock);
        }
    }
}
