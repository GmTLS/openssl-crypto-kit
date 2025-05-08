<?php

namespace GmTLS\CryptoKit\Contracts;

interface PublicKey
{
    /**
     * Verify signature using public key
     *
     * @param string $data      Original data
     * @param string $signature Raw binary signature
     * @param int    $algorithm Signature algorithm
     *
     * @return bool
     */
    public function verify(string $data, string $signature, int $algorithm = OPENSSL_ALGO_SHA256): bool;

    /**
     * Verify base64-encoded signature using public key
     *
     * @param string $data            Original data
     * @param string $base64Signature Base64-encoded signature
     * @param int    $algorithm       Signature algorithm
     *
     * @return bool
     */
    public function base64Verify(string $data, string $base64Signature, int $algorithm = OPENSSL_ALGO_SHA256): bool;
}
