<?php

namespace GmTLS\CryptoKit\Contracts;

interface Provider
{
    public function getPrivateKeys(): array;

    public function getPublicKeys(): array;

    /**
     * Encrypt data with provided public certificate
     *
     * @param string $data Data to encrypt
     * @param int    $padding
     *
     * @return string Encrypted data
     */
    public function encrypt(string $data, int $padding = OPENSSL_PKCS1_PADDING): string;

    /**
     * Encrypt data and then base64_encode it
     *
     * @param string $data Data to encrypt
     * @param int    $padding
     *
     * @return string Base64-encrypted data
     */
    public function base64Encrypt(string $data, int $padding = OPENSSL_PKCS1_PADDING): string;

    /**
     * Decrypt data with provided private certificate
     *
     * @param string $data Data to encrypt
     * @param int    $padding
     *
     * @return string Decrypted data
     */
    public function decrypt(string $data, int $padding = OPENSSL_PKCS1_PADDING): string;

    /**
     * base64_decode data and then decrypt it
     *
     * @param string $data Base64-encoded data to decrypt
     * @param int    $padding
     *
     * @return string Decrypted data
     */
    public function base64Decrypt(string $data, int $padding = OPENSSL_PKCS1_PADDING): string;

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
