<?php

namespace GmTLS\CryptoKit\Providers;

use GmTLS\CryptoKit\Contracts\Keypair as KeypairContract;
use GmTLS\CryptoKit\Keypair;
use RuntimeException;

class RsaProvider extends AbstractProvider
{
    /**
     * @param int         $keySize
     * @param string|null $passphrase
     * @param array       $options
     *
     * @return KeypairContract
     */
    public static function generateKeypair(int $keySize = 2048, string $passphrase = null, array $options = []): KeypairContract
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

        return new Keypair(
            $privateKey,
            $details['key'],
            $passphrase,
            $details,
        );
    }

    public function getKeyType(): string
    {
        return 'rsa';
    }

    public function getEncodedKeys(): array
    {
        $details = $this->keypair->getOptions();
        $keys    = [
            'kty' => 'RSA',
            'n'   => $this->encoder->base64UrlEncode($details['rsa']['n']),
            'e'   => $this->encoder->base64UrlEncode($details['rsa']['e']),
        ];

        if (array_key_exists('d', $details['rsa'])) {
            $keys['d']  = $this->encoder->base64UrlEncode($details['rsa']['d']);
            $keys['p']  = $this->encoder->base64UrlEncode($details['rsa']['p']);
            $keys['q']  = $this->encoder->base64UrlEncode($details['rsa']['q']);
            $keys['dp'] = $this->encoder->base64UrlEncode($details['rsa']['dmp1']);
            $keys['dq'] = $this->encoder->base64UrlEncode($details['rsa']['dmq1']);
            $keys['qi'] = $this->encoder->base64UrlEncode($details['rsa']['iqmp']);
        }

        return $keys;
    }
}
