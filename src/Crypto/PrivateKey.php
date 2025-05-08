<?php

namespace GmTLS\CryptoKit\Crypto;

use GmTLS\CryptoKit\Contracts\Keypair as KeypairContract;
use GmTLS\CryptoKit\Contracts\PrivateKey as PrivateKeyContract;
use GmTLS\CryptoKit\Keypair;
use RuntimeException;

class PrivateKey implements PrivateKeyContract
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
     * Sign data using private key
     *
     * @param string $data      Data to sign
     * @param int    $algorithm Signature algorithm
     *
     * @return string         Raw binary signature
     */
    public function sign(string $data, int $algorithm = OPENSSL_ALGO_SHA256): string
    {
        if (is_null($this->getKeypair()->getPrivateKey())) {
            throw new RuntimeException("Unable to sign: No private key provided.");
        }

        $privateKey = openssl_pkey_get_private($this->getKeypair()->getPrivateKey(), $this->getKeypair()->getPassphrase());

        if ($privateKey === false) {
            throw new RuntimeException("OpenSSL: Unable to get private key for signing. Is the key correct? Does it require a passphrase?");
        }

        if (!openssl_sign($data, $signature, $privateKey, $algorithm)) {
            throw new RuntimeException("Signing failed. Ensure you are using a valid PRIVATE key.");
        }

        return $signature;
    }

    /**
     * Sign data using private key and return base64-encoded signature
     *
     * @param string $data      Data to sign
     * @param int    $algorithm Signature algorithm
     *
     * @return string         Base64-encoded signature
     */
    public function base64Sign(string $data, int $algorithm = OPENSSL_ALGO_SHA256): string
    {
        return base64_encode($this->sign($data, $algorithm));
    }
}
