<?php

namespace GmTLS\CryptoKit\Crypto;

use GmTLS\CryptoKit\Contracts\Keypair as KeypairContract;
use GmTLS\CryptoKit\Contracts\PublicKey as PublicKeyContract;
use GmTLS\CryptoKit\Keypair;
use InvalidArgumentException;
use RuntimeException;

class PublicKey implements PublicKeyContract
{
    public function __construct(
        protected ?KeypairContract $keypair = null,
    )
    {
        $this->keypair = $keypair ?? new Keypair();
    }

    public function getKeypair(): KeypairContract
    {
        return $this->keypair;
    }

    /**
     * Verify signature using public key
     *
     * @param string $data      Original data
     * @param string $signature Raw binary signature
     * @param int    $algorithm Signature algorithm
     *
     * @return bool
     */
    public function verify(string $data, string $signature, int $algorithm = OPENSSL_ALGO_SHA256): bool
    {
        if (is_null($this->getKeypair()->getPublicKey())) {
            throw new RuntimeException("Unable to verify: No public key provided.");
        }

        $publicKey = openssl_pkey_get_public($this->getKeypair()->getPublicKey());

        if ($publicKey === false) {
            throw new RuntimeException("OpenSSL: Unable to get public key for verification. Is the key correct?");
        }

        $result = openssl_verify($data, $signature, $publicKey, $algorithm);

        if ($result === -1) {
            throw new RuntimeException("Verification process failed.");
        }

        return $result === 1;
    }

    /**
     * Verify base64-encoded signature using public key
     *
     * @param string $data            Original data
     * @param string $base64Signature Base64-encoded signature
     * @param int    $algorithm       Signature algorithm
     *
     * @return bool
     */
    public function base64Verify(string $data, string $base64Signature, int $algorithm = OPENSSL_ALGO_SHA256): bool
    {
        $decoded = base64_decode($base64Signature, true);
        if ($decoded === false) {
            throw new InvalidArgumentException("The provided signature is not valid base64.");
        }

        return $this->verify($data, $decoded, $algorithm);
    }
}
