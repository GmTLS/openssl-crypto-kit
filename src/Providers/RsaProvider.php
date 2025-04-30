<?php

namespace GmTLS\CryptoKit\Providers;

use GmTLS\CryptoKit\Contracts\Key as KeyContract;
use GmTLS\CryptoKit\Key;
use RuntimeException;

class RsaProvider extends AbstractProvider
{
    /**
     * @param int         $keySize
     * @param string|null $passphrase
     * @param array       $options
     *
     * @return KeyContract
     */
    public static function generateKeypair(int $keySize = 2048, string $passphrase = null, array $options = []): KeyContract
    {
        $resource = openssl_pkey_new(array_merge([
            'private_key_bits' => $keySize,
        ], $options, [
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]));
        if ($resource === false) {
            throw new RuntimeException('[OpenSSL Error] Failed to generate RSA key pair.');
        }

        $export = openssl_pkey_export($resource, $privateKey, $passphrase);
        if ($export === false) {
            throw new RuntimeException('[OpenSSL Error] key parameter is not a valid private key');
        }

        $details = openssl_pkey_get_details($resource);
        if ($details === false) {
            throw new RuntimeException('[OpenSSL Error] Failed to get key details.');
        }

        return new Key(
            $privateKey,
            $details['key'],
            $passphrase,
            $details,
        );
    }
}
