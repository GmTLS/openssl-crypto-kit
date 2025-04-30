<?php

namespace GmTLS\CryptoKit;

use GmTLS\CryptoKit\Contracts\Key as KeyContract;

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

    public function getPrivateKey(): ?string
    {
        return trim($this->privateKey);
    }

    public function setPrivateKey(?string $privateKey): static
    {
        $this->privateKey = $privateKey;
        return $this;
    }

    public function getPublicKey(): ?string
    {
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
