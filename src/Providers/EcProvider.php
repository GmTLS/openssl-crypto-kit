<?php

namespace GmTLS\CryptoKit\Providers;

use GmTLS\CryptoKit\Contracts\Keypair as KeypairContract;
use GmTLS\CryptoKit\Keypair;
use RuntimeException;

class EcProvider extends AbstractProvider
{
    /**
     * @inheritdoc
     *
     * @return string
     */
    public function encrypt(string $data, int $padding = OPENSSL_PKCS1_PADDING): string
    {
        throw new RuntimeException('operation not supported for this key type');
    }

    /**
     * @inheritdoc
     *
     * @return string
     */
    public function base64Encrypt(string $data, int $padding = OPENSSL_PKCS1_PADDING): string
    {
        throw new RuntimeException('operation not supported for this key type');
    }

    /**
     * @inheritdoc
     *
     * @return string
     */
    public function decrypt(string $data, int $padding = OPENSSL_PKCS1_PADDING): string
    {
        throw new RuntimeException('operation not supported for this key type');
    }

    /**
     * @inheritdoc
     *
     * @return string
     */
    public function base64Decrypt(string $data, int $padding = OPENSSL_PKCS1_PADDING): string
    {
        throw new RuntimeException('operation not supported for this key type');
    }

    /**
     * @param string      $curveName
     * @param string|null $passphrase
     * @param array       $options
     *
     * @return KeypairContract
     */
    public static function generateKeypair(string $curveName = 'prime256v1', string $passphrase = null, array $options = []): KeypairContract
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
            $privateKey,
            $details['key'],
            $passphrase,
            $details
        );
    }

    protected function converterToKeys(array $details): array
    {
        if (is_null($curveName = $details['ec']['curve_name'] ?: null)) {
            throw new RuntimeException('Missing EC curve name');
        }

        $crv = match ($curveName) {
            'secp256r1', 'prime256v1' => 'P-256',
            'secp384r1' => 'P-384',
            'secp521r1' => 'P-521',
            default => throw new RuntimeException("Unsupported curve: {$curveName}"),
        };

        $x = $details['ec']['x'];
        $y = $details['ec']['y'];

        $keys = [
            'kty' => 'EC',
            'crv' => $crv,
            'x'   => $this->base64Ur->encode($x),
            'y'   => $this->base64Ur->encode($y),
        ];

        if (array_key_exists('d', $details['ec'])) {
            $keys['d'] = $this->base64Ur->encode($details['ec']['d']);
        }

        return $keys;
    }
}
