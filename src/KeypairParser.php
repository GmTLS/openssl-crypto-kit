<?php

namespace GmTLS\CryptoKit;

use GmTLS\CryptoKit\Contracts\Keypair;
use phpseclib3\Crypt\Common\PrivateKey;
use phpseclib3\Crypt\PublicKeyLoader;
use RuntimeException;

class KeypairParser implements Contracts\KeypairParser
{
    public function __construct(protected Keypair $keypair)
    {
        //
    }

    public function getKeypair(): Keypair
    {
        return $this->keypair;
    }

    public static function create(Keypair $keypair): static
    {
        return new static($keypair);
    }

    public static function load(array|string $parameters, string $passphrase = null): Keypair
    {
        $key = PublicKeyLoader::load($parameters, $passphrase ?? false);
        if ($key instanceof PrivateKey) {
            $publicKey  = $key->getPublicKey()->toString('PKCS8');
            $privateKey = $key->toString('PKCS8');
        } else {
            $publicKey  = $key->toString('PKCS8');
            $privateKey = null;
        }

        $key = new \GmTLS\CryptoKit\Keypair(
            $publicKey,
            $privateKey,
            $passphrase
        );

        return self::create($key)->getKeypair();
    }

    public function toArray(string $format = 'PKCS8', array $options = []): array
    {
        $publicKey = $this->getKeypair()->getPublicKey();
        if (openssl_pkey_get_public($publicKey) === false) {
            throw new RuntimeException('Invalid public key');
        }

        $privateKey = $this->getKeypair()->getPrivateKey();
        $passphrase = $this->getKeypair()->getPassphrase();
        if (openssl_pkey_get_private($privateKey, $passphrase) === false) {
            throw new RuntimeException('Invalid private key');
        }

        $publicKey  = PublicKeyLoader::loadPublicKey($publicKey)
            ->toString($format, $options);
        $privateKey = PublicKeyLoader::loadPrivateKey($privateKey, $passphrase ?? false)
            ->toString($format, $options);

        return compact('publicKey', 'privateKey');
    }

    public function toPublicKey(string $format = 'PKCS8', array $options = []): string
    {
        $publicKey = $this->getKeypair()->getPublicKey();
        if (openssl_pkey_get_public($publicKey) === false) {
            throw new RuntimeException('Invalid public key');
        }

        return PublicKeyLoader::loadPublicKey($publicKey)->toString($format, $options);
    }

    public function toPrivateKey(string $format = 'PKCS8', array $options = []): string
    {
        $privateKey = $this->getKeypair()->getPrivateKey();
        $passphrase = $this->getKeypair()->getPassphrase();
        if (openssl_pkey_get_private($privateKey, $passphrase) === false) {
            throw new RuntimeException('Invalid private key');
        }

        return PublicKeyLoader::loadPrivateKey($privateKey, $passphrase ?? false)->toString($format, $options);
    }
}
