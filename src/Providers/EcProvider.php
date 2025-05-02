<?php

namespace GmTLS\CryptoKit\Providers;

use GmTLS\CryptoKit\Concerns\EncodeParameters;
use GmTLS\CryptoKit\Contracts\Keypair as KeypairContract;
use GmTLS\CryptoKit\Keypair;
use InvalidArgumentException;
use RuntimeException;

class EcProvider extends AbstractProvider
{
    use EncodeParameters;

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

        $export = openssl_pkey_export($resource, $privateKey, $passphrase, [
            'encrypt_key' => false,
            'type'        => OPENSSL_KEYTYPE_EC,
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
            $details
        );
    }

    public function getKeyType(): string
    {
        return 'ec';
    }

    public function getEncodedKeys(array $details = []): array
    {
        $details = $details ?: $this->keypair->getOptions();

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
            'x'   => $this->encoder->base64UrlEncode($x),
            'y'   => $this->encoder->base64UrlEncode($y),
        ];

        if (array_key_exists('d', $details['ec'])) {
            $keys['d'] = $this->encoder->base64UrlEncode($details['ec']['d']);
        }

        return $keys;
    }

    public function toUnencryptedPem(array $jwk = []): string
    {
        $jwk = $jwk ?: $this->getEncodedKeys();

        if (count($fields = array_diff(['crv', 'x', 'y'], array_keys($jwk)))) {
            throw new InvalidArgumentException(sprintf(
                "Missing field %s in EC JWK",
                implode(', ', $fields)
            ));
        }

        $crv         = $jwk['crv'];
        $curveLength = match ($crv) {
            'P-256' => 32,
            'P-384' => 48,
            'P-521' => 66, // 注意P-521实际是528bit -> 66字节
            default => throw new InvalidArgumentException('Unsupported curve length.'),
        };
        $components  = [
            'x' => str_pad($this->encoder->base64urlDecode($jwk['x']), $curveLength, "\x00", STR_PAD_LEFT),
            'y' => str_pad($this->encoder->base64urlDecode($jwk['y']), $curveLength, "\x00", STR_PAD_LEFT),
        ];
        $publicKey   = "\x04" . $components['x'] . $components['y']; // Uncompressed point
        $oid         = match ($crv) {
            'P-256' => hex2bin('2A8648CE3D030107'),
            'P-384' => hex2bin('2B81040022'),
            'P-521' => hex2bin('2B81040023'),
            default => throw new InvalidArgumentException("Unsupported curve: {$crv}"),
        };

        // EC Private Key
        // PrivateKeyInfo ::= SEQUENCE {
        //     version                   INTEGER,
        //     privateKeyAlgorithm       AlgorithmIdentifier,
        //     privateKey                OCTET STRING,
        //     attributes           [0]  IMPLICIT Attributes OPTIONAL
        // }
        if (isset($jwk['d'])) {
            $sequence = self::encodeSequence(
                self::encodeInteger("\x01") .
                self::encodeOctetString($this->encoder->base64UrlDecode($jwk['d'])) .
                self::encodeTagged(0, self::encodeOID($oid)) .
                self::encodeTagged(1, self::encodeBitString($publicKey))
            );

            return self::wrapKey($sequence, 'EC PRIVATE KEY');
        }
        // EC Public Key
        $algorithm = self::encodeSequence(
            self::encodeOID(hex2bin('2A8648CE3D0201')) .
            self::encodeOID($oid)
        );
        $bitString = self::encodeBitString($publicKey);
        $sequence  = self::encodeSequence($algorithm . $bitString);

        return self::wrapKey($sequence, 'PUBLIC KEY');
    }

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
    public function decrypt(string $data, int $padding = OPENSSL_PKCS1_PADDING): string
    {
        throw new RuntimeException('operation not supported for this key type');
    }
}
