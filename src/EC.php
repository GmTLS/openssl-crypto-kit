<?php

namespace GmTLS\CryptoKit;

use GmTLS\CryptoKit\Concerns\AsymmetricKey;
use GmTLS\CryptoKit\Contracts\Keypair as KeypairContract;
use GmTLS\CryptoKit\Crypto\PrivateKey;
use GmTLS\CryptoKit\Crypto\PublicKey;
use RuntimeException;

class EC extends AsymmetricKey
{
    /**
     * @param string      $curveName
     * @param string|null $passphrase
     * @param array       $options
     *
     * @return KeypairContract
     */
    public static function createKey(string $curveName = 'prime256v1', string $passphrase = null, array $options = []): KeypairContract
    {
        $resource = openssl_pkey_new(array_merge([
            'curve_name' => match ($curveName) {
                'secp256r1', 'prime256v1' => 'prime256v1',
                'secp384r1' => 'secp384r1',
                'secp521r1' => 'secp521r1',
                default => throw new RuntimeException('Unsupported curve name.'),
            },
        ], $options, [
            'private_key_type' => OPENSSL_KEYTYPE_EC,
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

        return new Keypair(
            $details['key'],
            $privateKey,
            $passphrase,
            $details
        );
    }

    public function getPublicKey(): PublicKey
    {
        return new PublicKey(new Keypair(
            publicKey: $this->getKeypair()->getPublicKey()
        ));
    }

    public function getPrivateKey(): PrivateKey
    {
        return new PrivateKey(new Keypair(
            publicKey: $this->getKeypair()->getPublicKey(),
            privateKey: $this->getKeypair()->getPrivateKey(),
            passphrase: $this->getKeypair()->getPassphrase(),
        ));
    }
}
