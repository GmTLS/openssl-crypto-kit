<?php

namespace GmTLS\CryptoKit\Contracts;

interface AsymmetricKey
{
    public function __construct(Keypair $keypair);

    public static function createKey(): Keypair;

    public function getKeypair(): Keypair;

    public function getPublicKey(): PublicKey;

    public function getPrivateKey(): PrivateKey;
}
