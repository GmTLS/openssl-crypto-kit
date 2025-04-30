<?php

namespace GmTLS\CryptoKit\Contracts;

interface Key
{
    public function fromFile(string $file, string $passphrase = null): static;

    public function fromPrivateKeyFile(string $file, string $passphrase = null): static;

    public function fromPublicKeyFile(string $file): static;

    public function fromString(string $pemKey, string $passphrase = null): static;

    public function fromPrivateKeyString(string $privateKeyPem, string $passphrase = null): static;

    public function fromPublicKeyString(string $publicKeyPem): static;

    public function saveTo(string $file, bool $overwrite = false): bool;

    public function savePrivateKeyTo(string $file, bool $overwrite = false): bool;

    public function savePublicKeyTo(string $file, bool $overwrite = false): bool;

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
