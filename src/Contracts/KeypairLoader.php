<?php

namespace GmTLS\CryptoKit\Contracts;

interface KeypairLoader
{
    public static function fromFile(string $file, string $passphrase = null): Keypair;

    public static function fromPrivateKeyFile(string $file, string $passphrase = null): Keypair;

    public static function fromPublicKeyFile(string $file): Keypair;

    public static function fromString(string $pemKey, string $passphrase = null): Keypair;

    public static function fromPrivateKeyString(string $privateKeyPem, string $passphrase = null): Keypair;

    public static function fromPublicKeyString(string $publicKeyPem): Keypair;
}
