<?php

namespace GmTLS\CryptoKit;

use GmTLS\CryptoKit\Concerns\AsymmetricKey;
use GmTLS\CryptoKit\Keypair;
use GmTLS\CryptoKit\Crypto\PrivateKey;
use GmTLS\CryptoKit\Crypto\PublicKey;
use RuntimeException;

class DSA extends AsymmetricKey
{
    public static function createKey(): Keypair
    {
        throw new RuntimeException('Direct generation of DSA keys is not supported');
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
