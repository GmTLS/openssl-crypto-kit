<?php

namespace GmTLS\CryptoKit\Contracts;

interface KeypairParser
{
    public function getKeypair(): Keypair;

    public static function create(Keypair $keypair): static;

    public static function load(array|string $parameters, string $passphrase = null): Keypair;

    public function toArray(string $format = 'PKCS8', array $options = []): array;

    public function toPublicKey(string $format = 'PKCS8', array $options = []): string;

    public function toPrivateKey(string $format = 'PKCS8', array $options = []): string;
}
