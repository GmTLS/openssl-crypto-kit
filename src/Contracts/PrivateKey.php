<?php

namespace GmTLS\CryptoKit\Contracts;

interface PrivateKey
{
    /**
     * Sign data using private key
     *
     * @param string $data      Data to sign
     * @param int    $algorithm Signature algorithm
     *
     * @return string         Raw binary signature
     */
    public function sign(string $data, int $algorithm = OPENSSL_ALGO_SHA256): string;

    /**
     * Sign data using private key and return base64-encoded signature
     *
     * @param string $data      Data to sign
     * @param int    $algorithm Signature algorithm
     *
     * @return string         Base64-encoded signature
     */
    public function base64Sign(string $data, int $algorithm = OPENSSL_ALGO_SHA256): string;
}
