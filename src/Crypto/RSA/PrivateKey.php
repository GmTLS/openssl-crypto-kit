<?php

namespace GmTLS\CryptoKit\Crypto\RSA;

use RuntimeException;

class PrivateKey extends \GmTLS\CryptoKit\Crypto\PrivateKey
{
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
        if (is_null($this->getKeypair()->getPrivateKey())) {
            throw new RuntimeException("Unable to decrypt: No private key provided.");
        }

        $privateKey = openssl_pkey_get_private($this->getKeypair()->getPrivateKey(), $this->getKeypair()->getPassphrase());
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
}
