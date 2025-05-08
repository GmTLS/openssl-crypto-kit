<?php

namespace GmTLS\CryptoKit;

use GmTLS\CryptoKit\Contracts\Keypair;
use RuntimeException;

class KeypairExporter implements Contracts\KeypairExporter
{
    public function __construct(
        protected Keypair $keypair,
    )
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

    public function saveKeys(string $file, bool $overwrite = false): bool
    {
        if (is_null($this->getKeypair()->getPublicKey()) || is_null($this->getKeypair()->getPrivateKey())) {
            throw new RuntimeException('Failed to export key');
        }

        return $this->filePutContents($file, implode(PHP_EOL, [
            $this->getKeypair()->getPublicKey(),
            $this->getKeypair()->getPrivateKey(),
        ]), $overwrite);
    }

    public function savePrivateKey(string $file, bool $overwrite = false): bool
    {
        if (is_null($this->getKeypair()->getPrivateKey())) {
            throw new RuntimeException('Failed to export private key');
        }

        return $this->filePutContents($file, $this->getKeypair()->getPrivateKey(), $overwrite);
    }

    public function savePublicKey(string $file, bool $overwrite = false): bool
    {
        if (is_null($this->getKeypair()->getPublicKey())) {
            throw new RuntimeException('Failed to export public key');
        }

        return $this->filePutContents($file, $this->getKeypair()->getPublicKey(), $overwrite);
    }

    protected function filePutContents(string $file, mixed $data, bool $overwrite = false): bool
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

        if (file_put_contents($file, $data) === false) {
            throw new RuntimeException("Unable to save key to file: {$file}");
        }

        return true;
    }
}
