<?php

namespace GmTLS\CryptoKit\Crypto\RSA;

use RuntimeException;

class PublicKey extends \GmTLS\CryptoKit\Crypto\PublicKey
{
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
        if (is_null($this->getKeypair()->getPublicKey())) {
            throw new RuntimeException("Unable to encrypt: No public key provided.");
        }

        $publicKey = openssl_pkey_get_public($this->getKeypair()->getPublicKey());

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
}
