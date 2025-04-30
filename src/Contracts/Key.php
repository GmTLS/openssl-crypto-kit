<?php

namespace GmTLS\CryptoKit\Contracts;

interface Key
{
    public function getPrivateKey(): ?string;

    public function setPrivateKey(?string $privateKey): static;

    public function getPublicKey(): ?string;

    public function setPublicKey(?string $publicKey): static;

    public function getPassphrase(): ?string;

    public function setPassphrase(?string $passphrase): static;

    public function getOptions(): array;

    public function setOptions(array $options): static;

    public function has(string $key): bool;

    public function get(string $key): mixed;

    public function option(string $key, mixed $value): static;
}
