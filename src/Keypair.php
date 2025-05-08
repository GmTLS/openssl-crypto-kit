<?php

namespace GmTLS\CryptoKit;

use GmTLS\CryptoKit\Contracts\Keypair as KeypairContract;
use GmTLS\CryptoKit\Contracts\KeypairExporter as KeypairExporterContract;
use GmTLS\CryptoKit\Contracts\KeypairParser as KeypairParserContract;
use RuntimeException;

class Keypair implements KeypairContract
{
    public function __construct(
        protected ?string $publicKey = null,
        protected ?string $privateKey = null,
        protected ?string $passphrase = null,
        protected array   $options = [],
    )
    {
        $publicKey && $this->setPublicKey($publicKey);
        $privateKey && $this->setPrivateKey($privateKey);
    }

    public function parse(): KeypairParserContract
    {
        return KeypairParser::create($this);
    }

    public function export(): KeypairExporterContract
    {
        return KeypairExporter::create($this);
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
        if ($publicKey) {
            return $this->pkey($publicKey);
        }
        return $this;
    }

    protected function pkey(string $key, bool $isPublicKey = true): static
    {
        $resource = $isPublicKey ? openssl_pkey_get_public($key) : openssl_pkey_get_private($key, $this->passphrase);
        if ($resource === false) {
            throw new RuntimeException('Invalid key');
        }

        $details = openssl_pkey_get_details($resource);
        if ($details === false) {
            throw new RuntimeException('Failed to get key details');
        }
        $this->publicKey  = $details['key'];
        $this->privateKey = $isPublicKey ? $this->privateKey : $key;
        $this->options    = $details;
        return $this;
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
        if ($privateKey) {
            return $this->pkey($privateKey, false);
        }
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

    public function getOptions(string $key = null): mixed
    {
        if (is_null($key)) {
            return $this->options;
        }
        return $this->options[$key] ?? null;
    }

    public function setOptions(array $options): static
    {
        $this->options = $options;
        return $this;
    }

    public function option(string $key, mixed $value): static
    {
        $this->options[$key] = $value;
        return $this;
    }
}
