<?php

namespace GmTLS\CryptoKit\Providers;

use GmTLS\CryptoKit\Encoding\Encoder;
use GmTLS\CryptoKit\Contracts\Encoding;
use GmTLS\CryptoKit\Contracts\Keypair;
use GmTLS\CryptoKit\Contracts\Provider;
use InvalidArgumentException;
use RuntimeException;

abstract class AbstractProvider implements Provider
{
    public function __construct(
        protected Keypair   $keypair,
        protected ?Encoding $encoder = null,
    )
    {
        $this->encoder ??= new Encoder();
    }


    public function getPrivateKeys(): array
    {
        $privateKey = $this->keypair->getPrivateKey();

        if (is_null($privateKey)) {
            throw new RuntimeException('Invalid private key');
        }

        $resource = openssl_pkey_get_private($privateKey, $this->keypair->getPassphrase());
        if ($resource === false) {
            throw new RuntimeException('Invalid private key');
        }

        $details = openssl_pkey_get_details($resource);
        if ($details === false) {
            throw new RuntimeException('Failed to get key details');
        }

        return $this->converterToKeys($details);
    }

    public function getPublicKeys(): array
    {
        $publicKey = $this->keypair->getPublicKey();

        if (is_null($publicKey)) {
            throw new RuntimeException('Invalid private key');
        }

        $resource = openssl_pkey_get_public($publicKey);
        if ($resource === false) {
            throw new RuntimeException('Invalid public key');
        }

        $details = openssl_pkey_get_details($resource);
        if ($details === false) {
            throw new RuntimeException('Failed to get key details');
        }

        return $this->converterToKeys($details);
    }

    abstract protected function converterToKeys(array $details): array;

    /**
     * Encrypt data with provided public certificate
     *
     * @param string $data Data to encrypt
     * @param int    $padding
     *
     * @return string Encrypted data
     */
    public function encrypt(string $data, int $padding = OPENSSL_PKCS1_PADDING): string
    {
        if (is_null($this->keypair->getPublicKey())) {
            throw new RuntimeException("Unable to encrypt: No public key provided.");
        }

        $publicKey = openssl_pkey_get_public($this->keypair->getPublicKey());

        if ($publicKey === false) {
            throw new RuntimeException("OpenSSL: Unable to get public key for encryption. Is the location correct? Does this key require a password?");
        }

        if (!openssl_public_encrypt($data, $encryptedData, $publicKey, $padding)) {
            throw new RuntimeException("Encryption failed. Ensure you are using a PUBLIC key.");
        }

        return $encryptedData;
    }

    /**
     * Encrypt data and then base64_encode it
     *
     * @param string $data Data to encrypt
     * @param int    $padding
     *
     * @return string Base64-encrypted data
     */
    public function base64Encrypt(string $data, int $padding = OPENSSL_PKCS1_PADDING): string
    {
        return base64_encode($this->encrypt($data, $padding));
    }

    /**
     * Decrypt data with provided private certificate
     *
     * @param string $data Data to encrypt
     * @param int    $padding
     *
     * @return string Decrypted data
     */
    public function decrypt(string $data, int $padding = OPENSSL_PKCS1_PADDING): string
    {
        if (is_null($this->keypair->getPrivateKey())) {
            throw new RuntimeException("Unable to decrypt: No private key provided.");
        }

        $privateKey = openssl_pkey_get_private($this->keypair->getPrivateKey(), $this->keypair->getPassphrase());
        if ($privateKey === false) {
            throw new RuntimeException('OpenSSL: Unable to get private key for decryption. Is the location correct? If this key requires a password, have you supplied the correct one?');
        }

        if (!openssl_private_decrypt($data, $decryptedData, $privateKey, $padding)) {
            throw new RuntimeException("Decryption failed. Ensure you are using (1) a PRIVATE key, and (2) the correct one.");
        }

        return $decryptedData;
    }

    /**
     * base64_decode data and then decrypt it
     *
     * @param string $data Base64-encoded data to decrypt
     * @param int    $padding
     *
     * @return string Decrypted data
     */
    public function base64Decrypt(string $data, int $padding = OPENSSL_PKCS1_PADDING): string
    {
        return $this->decrypt(base64_decode($data), $padding);
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
        if (is_null($this->keypair->getPrivateKey())) {
            throw new RuntimeException("Unable to sign: No private key provided.");
        }

        $privateKey = openssl_pkey_get_private($this->keypair->getPrivateKey(), $this->keypair->getPassphrase());

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
        if (is_null($this->keypair->getPublicKey())) {
            throw new RuntimeException("Unable to verify: No public key provided.");
        }

        $publicKey = openssl_pkey_get_public($this->keypair->getPublicKey());

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
