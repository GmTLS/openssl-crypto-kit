<?php

namespace GmTLS\CryptoKit\Providers;

use GmTLS\CryptoKit\Concerns\EncodeParameters;
use GmTLS\CryptoKit\Contracts\Keypair as KeypairContract;
use GmTLS\CryptoKit\Keypair;
use InvalidArgumentException;
use RuntimeException;

class RsaProvider extends AbstractProvider
{
    use EncodeParameters;

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

        $export = openssl_pkey_export($resource, $privateKey, $passphrase, [
            'encrypt_key' => false,
            'type'        => OPENSSL_KEYTYPE_RSA,
        ]);
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

    public function getEncodedKeys(array $details = []): array
    {
        $details = $details ?: $this->keypair->getOptions();
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

    public function toUnencryptedPem(array $jwk = []): string
    {
        $jwk = $jwk ?: $this->getEncodedKeys();

        if (isset($jwk['d'])) {
            // Private Key
            if (count($fields = array_diff(['n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi'], array_keys($jwk)))) {
                throw new InvalidArgumentException(sprintf(
                    "Missing field %s in RSA private JWK",
                    implode(', ', $fields)
                ));
            }

            $components = array_map([$this->encoder, 'base64urlDecode'], [
                'n'  => $jwk['n'],
                'e'  => $jwk['e'],
                'd'  => $jwk['d'],
                'p'  => $jwk['p'],
                'q'  => $jwk['q'],
                'dp' => $jwk['dp'],
                'dq' => $jwk['dq'],
                'qi' => $jwk['qi'],
            ]);

            $encoded = self::encodeSequence(
                self::encodeInteger("\x00") .
                self::encodeInteger($components['n']) .
                self::encodeInteger($components['e']) .
                self::encodeInteger($components['d']) .
                self::encodeInteger($components['p']) .
                self::encodeInteger($components['q']) .
                self::encodeInteger($components['dp']) .
                self::encodeInteger($components['dq']) .
                self::encodeInteger($components['qi'])
            );

            return self::wrapKey($encoded, 'RSA PRIVATE KEY');
        } else {
            // Public Key
            if (count($fields = array_diff(['n', 'e'], array_keys($jwk)))) {
                throw new InvalidArgumentException(sprintf(
                    "Missing field %s in RSA public JWK",
                    implode(', ', $fields)
                ));
            }

            $components = array_map([$this->encoder, 'base64urlDecode'], [
                'n' => $jwk['n'],
                'e' => $jwk['e'],
            ]);

            $encoded = self::encodeSequence(
                self::encodeInteger($components['n']) .
                self::encodeInteger($components['e'])
            );

            // RSA OID
            $encoded = self::encodeSequence(
                hex2bin('300d06092a864886f70d0101010500') .
                self::encodeBitString($encoded)
            );

            return self::wrapKey($encoded, 'PUBLIC KEY');
        }
    }
}
