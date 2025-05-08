<?php

namespace GmTLS\CryptoKit\Contracts;

interface KeypairExporter
{
    public function getKeypair(): Keypair;

    public static function create(Keypair $keypair): static;

    public function saveKeys(string $file, bool $overwrite = false): bool;

    public function savePrivateKey(string $file, bool $overwrite = false): bool;

    public function savePublicKey(string $file, bool $overwrite = false): bool;
}
