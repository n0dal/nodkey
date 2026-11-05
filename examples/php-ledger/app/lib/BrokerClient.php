<?php
// SPDX-FileCopyrightText: 2026 n0dal
// SPDX-License-Identifier: Apache-2.0
//
// Minimal Nodkey broker client (prototype SDK). This client is a convenience, NOT an enforcement
// boundary: all checks that matter happen in the broker. Attacker code in the workload can
// bypass this file entirely and talk to the socket directly; the broker must (and does) assume so.
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

final class BrokerClient
{
    private const MAX_RESPONSE_BYTES = 65536;

    public function __construct(
        private readonly string $socketPath = '/run/nodkey/broker.sock',
        private readonly float $timeoutSeconds = 5.0,
    ) {
    }

    public function getBalance(string $account): int
    {
        $r = $this->call('ledger.get_balance', ['account' => $account]);
        if (!is_int($r['balance_cents'] ?? null)) {
            throw new BrokerError('bad_response', 'missing balance_cents');
        }
        return $r['balance_cents'];
    }

    /**
     * Requests a transfer. $idempotencyKey (16-64 chars of [A-Za-z0-9_-]) must be generated once per
     * intended transfer and reused for every retry of it: the broker executes at most one transfer
     * per key and answers repeats with the original result ("replayed": true).
     *
     * Throws BrokerError with code `outcome_unknown` when the request was sent but no complete
     * response arrived: the transfer may have committed. Retry only with the SAME key.
     * Code `unavailable` means nothing was executed.
     *
     * @return array{transfer_id:int, from:string, to:string, amount_cents:int, from_balance_cents:int, replayed:bool}
     */
    public function transfer(string $from, string $to, int $amountCents, string $idempotencyKey): array
    {
        return $this->call(
            'ledger.transfer',
            ['from' => $from, 'to' => $to, 'amount_cents' => $amountCents, 'idempotency_key' => $idempotencyKey],
            effectful: true,
        );
    }

    /** A fresh random idempotency key (32 hex chars). */
    public static function newIdempotencyKey(): string
    {
        return bin2hex(random_bytes(16));
    }

    /**
     * @param bool $effectful true for operations that change state: a failure after the request was
     *                        sent is then reported as `outcome_unknown` instead of `unavailable`.
     * @return array<string,mixed> the `result` object of a successful response
     */
    public function call(string $op, array $args, bool $effectful = false): array
    {
        $id = bin2hex(random_bytes(8));
        $line = json_encode(
            ['v' => 1, 'id' => $id, 'op' => $op, 'args' => (object) $args],
            JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES,
        );
        $resp = $this->roundTrip($line . "\n", $effectful);
        if (($resp['v'] ?? null) !== 1 || ($resp['id'] ?? null) !== $id) {
            throw new BrokerError('bad_response', 'response does not match request');
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

    /** @return array<string,mixed> */
    private function roundTrip(string $bytes, bool $effectful): array
    {
        $errno = 0;
        $errstr = '';
        $sock = @stream_socket_client('unix://' . $this->socketPath, $errno, $errstr, $this->timeoutSeconds);
        if ($sock === false) {
            throw new BrokerError('unavailable', 'broker not reachable');
        }
        try {
            stream_set_timeout($sock, (int) ceil($this->timeoutSeconds));
            // The broker executes a request only once it has read the terminating newline, which is
            // the last byte. A short or failed write therefore never delivered a complete request.
            if (@fwrite($sock, $bytes) !== strlen($bytes)) {
                throw new BrokerError('unavailable', 'write failed');
            }
            // From here on the broker may have executed the request.
            $afterSend = $effectful ? 'outcome_unknown' : 'unavailable';
            $line = fgets($sock, self::MAX_RESPONSE_BYTES);
            if ($line === false || !str_ends_with($line, "\n")) {
                $why = stream_get_meta_data($sock)['timed_out'] ? 'timeout' : 'connection closed';
                throw new BrokerError($afterSend, "request sent, no complete response ($why)");
            }
            $resp = json_decode($line, true, 16);
            if (!is_array($resp)) {
                throw new BrokerError($effectful ? 'outcome_unknown' : 'bad_response', 'response is not JSON');
            }
            return $resp;
        } finally {
            fclose($sock);
        }
    }
}
