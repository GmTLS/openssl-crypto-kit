<?php

namespace GmTLS\CryptoKit\Contracts;

interface Keypair
{
    public function parse(): KeypairParser;

    public function export(): KeypairExporter;

    public function getPublicKey(): ?string;

    public function setPublicKey(?string $publicKey): static;

    public function getPrivateKey(): ?string;

    public function setPrivateKey(?string $privateKey): static;

    public function getPassphrase(): ?string;

    public function setPassphrase(?string $passphrase): static;

    public function getOptions(string $key = null): mixed;

    public function setOptions(array $options): static;

    public function option(string $key, mixed $value): static;
}
