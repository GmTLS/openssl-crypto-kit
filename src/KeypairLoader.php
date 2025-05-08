<?php

namespace GmTLS\CryptoKit;

use GmTLS\CryptoKit\Contracts\Keypair as KeypairContract;
use RuntimeException;

class KeypairLoader implements Contracts\KeypairLoader
{
    public static function fromFile(string $file, string $passphrase = null): KeypairContract
    {
        return self::fromString(self::getContentFromFile($file), $passphrase);
    }

    public static function fromPrivateKeyFile(string $file, string $passphrase = null): KeypairContract
    {
        return self::fromPrivateKeyString(self::getContentFromFile($file), $passphrase);
    }

    public static function fromPublicKeyFile(string $file): KeypairContract
    {
        return self::fromPublicKeyString(self::getContentFromFile($file));
    }

    protected static function getContentFromFile(string $file): string
    {
        if (!file_exists($file)) {
            throw new RuntimeException("The specified file was not found: {$file}");
        }

        $content = file_get_contents($file);
        if (false === $content) {
            throw new RuntimeException("Failed to read file: {$file}");
        }

        return $content;
    }

    public static function fromString(string $pemKey, string $passphrase = null): KeypairContract
    {
        $resource = openssl_pkey_get_public($pemKey);
        if ($resource === false) {
            throw new RuntimeException('Invalid public key');
        }

        $details = openssl_pkey_get_details($resource);
        if ($details === false) {
            throw new RuntimeException('Failed to get key details');
        }

        $privateKey = mb_substr($pemKey, mb_strlen($details['key']));

        return self::fromPrivateKeyString($privateKey, $passphrase);
    }

    public static function fromPrivateKeyString(string $privateKeyPem, string $passphrase = null): KeypairContract
    {
        $resource = openssl_pkey_get_private($privateKeyPem, $passphrase);
        if ($resource === false) {
            throw new RuntimeException('Invalid private key');
        }

        $details = openssl_pkey_get_details($resource);
        if ($details === false) {
            throw new RuntimeException('Failed to get key details');
        }

        return new Keypair(
            publicKey: $details['key'],
            privateKey: trim($privateKeyPem),
            passphrase: $passphrase,
            options: $details,
        );
    }

    public static function fromPublicKeyString(string $publicKeyPem): KeypairContract
    {
        $resource = openssl_pkey_get_public($publicKeyPem);
        if ($resource === false) {
            throw new RuntimeException('Invalid public key');
        }

        $details = openssl_pkey_get_details($resource);
        if ($details === false) {
            throw new RuntimeException('Failed to get key details');
        }

        return new Keypair(
            publicKey: $details['key'],
            options: $details,
        );
    }
}
