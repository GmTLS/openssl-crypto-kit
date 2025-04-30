<?php

namespace GmTLS\CryptoKit;

use GmTLS\CryptoKit\Contracts\Key as KeyContract;
use RuntimeException;

class Key implements KeyContract
{
    public function __construct(
        protected ?string $privateKey = null,
        protected ?string $publicKey = null,
        protected ?string $passphrase = null,
        protected array   $options = [],
    )
    {
        //
    }

    public function fromFile(string $file, string $passphrase = null): static
    {
        return $this->fromString($this->getContentFromFile($file), $passphrase);
    }

    public function fromPrivateKeyFile(string $file, string $passphrase = null): static
    {
        return $this->fromPrivateKeyString($this->getContentFromFile($file), $passphrase);
    }

    public function fromPublicKeyFile(string $file): static
    {
        return $this->fromPublicKeyString($this->getContentFromFile($file));
    }

    protected function getContentFromFile(string $file): string
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

    public function fromString(string $pemKey, string $passphrase = null): static
    {
        // preg_match('/-----BEGIN PUBLIC KEY-----(.*?)-----END PUBLIC KEY-----/s', $pemKey, $publicMatch);
        // preg_match('/-----BEGIN ENCRYPTED PRIVATE KEY-----(.*?)-----END ENCRYPTED PRIVATE KEY-----/s', $pemKey, $privateMatch);
        //
        // $publicKey  = isset($publicMatch[0]) ? trim($publicMatch[0]) : null;
        // $privateKey = isset($privateMatch[0]) ? trim($privateMatch[0]) : null;

        $resource = openssl_pkey_get_public($pemKey);
        if ($resource === false) {
            throw new RuntimeException('Invalid public key');
        }

        $details = openssl_pkey_get_details($resource);
        if ($details === false) {
            throw new RuntimeException('Failed to get key details');
        }

        $privateKey = str_replace($details['key'], '', $pemKey);

        return $this->fromPrivateKeyString($privateKey, $passphrase);
    }

    public function fromPrivateKeyString(string $privateKeyPem, string $passphrase = null): static
    {
        $resource = openssl_pkey_get_private($privateKeyPem, $passphrase);
        if ($resource === false) {
            throw new RuntimeException('Invalid private key');
        }

        $details = openssl_pkey_get_details($resource);
        if ($details === false) {
            throw new RuntimeException('Failed to get key details');
        }

        $key = new Key(
            privateKey: $privateKeyPem,
            publicKey: $details['key'],
            passphrase: $passphrase,
            options: $details,
        );

        $this->setPrivateKey($key->getPrivateKey());
        $this->setPublicKey($key->getPublicKey());
        $this->setPassphrase($key->getPassphrase());
        $this->setOptions($key->getOptions());

        return $this;
    }

    public function fromPublicKeyString(string $publicKeyPem): static
    {
        $resource = openssl_pkey_get_public($publicKeyPem);
        if ($resource === false) {
            throw new RuntimeException('Invalid public key');
        }

        $details = openssl_pkey_get_details($resource);
        if ($details === false) {
            throw new RuntimeException('Failed to get key details');
        }

        $key = new Key(
            publicKey: $details['key'],
            options: $details,
        );

        $this->setPrivateKey($key->getPrivateKey());
        $this->setPublicKey($key->getPublicKey());
        $this->setPassphrase($key->getPassphrase());
        $this->setOptions($key->getOptions());

        return $this;
    }

    public function saveTo(string $file, bool $overwrite = false): bool
    {
        $this->ensureWritableDirectory($file, $overwrite);

        if (is_null($this->getPublicKey()) || is_null($this->getPrivateKey())) {
            throw new RuntimeException('Failed to export key');
        }

        $data = $this->getPublicKey() . PHP_EOL . $this->getPrivateKey();

        if (file_put_contents($file, $data) === false) {
            throw new RuntimeException("Unable to save key to file: {$file}");
        }

        return true;
    }

    public function savePrivateKeyTo(string $file, bool $overwrite = false): bool
    {
        $this->ensureWritableDirectory($file, $overwrite);

        if (is_null($this->getPrivateKey())) {
            throw new RuntimeException('Failed to export private key');
        }

        if (file_put_contents($file, $this->getPrivateKey()) === false) {
            throw new RuntimeException("Failed to save private key to file: {$file}");
        }

        return true;
    }

    public function savePublicKeyTo(string $file, bool $overwrite = false): bool
    {
        $this->ensureWritableDirectory($file, $overwrite);

        if (is_null($this->getPublicKey())) {
            throw new RuntimeException('Failed to export public key');
        }

        if (file_put_contents($file, $this->getPublicKey()) === false) {
            throw new RuntimeException("Failed to save public key to file: {$file}");
        }

        return true;
    }

    protected function ensureWritableDirectory(string $file, bool $overwrite = false): void
    {
        $dir = dirname($file);

        if (file_exists($file) && !$overwrite) {
            throw new RuntimeException("File already exists: {$file}");
        }

        if (!is_dir($dir) && !mkdir($dir, 0775, true) && !is_dir($dir)) {
            throw new RuntimeException("Failed to create directory: {$dir}");
        }

        if (!is_writable($dir)) {
            throw new RuntimeException("Directory is not writable: {$dir}");
        }
    }

    public function getPrivateKey(): ?string
    {
        if (is_null($this->privateKey)) {
            return null;
        }
        return trim($this->privateKey);
    }

    public function setPrivateKey(?string $privateKey): static
    {
        $this->privateKey = $privateKey;
        return $this;
    }

    public function getPublicKey(): ?string
    {
        if (is_null($this->publicKey)) {
            return null;
        }
        return trim($this->publicKey);
    }

    public function setPublicKey(?string $publicKey): static
    {
        $this->publicKey = $publicKey;
        return $this;
    }

    public function getPassphrase(): ?string
    {
        return $this->passphrase;
    }

    public function setPassphrase(?string $passphrase): static
    {
        $this->passphrase = $passphrase;
        return $this;
    }

    public function getOptions(): array
    {
        return $this->options;
    }

    public function setOptions(array $options): static
    {
        $this->options = $options;
        return $this;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->options);
    }

    public function get(string $key): mixed
    {
        return $this->options[$key] ?? null;
    }

    public function option(string $key, mixed $value): static
    {
        $this->options[$key] = $value;
        return $this;
    }
}
