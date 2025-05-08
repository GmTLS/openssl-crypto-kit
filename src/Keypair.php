<?php

namespace GmTLS\CryptoKit;

use GmTLS\CryptoKit\Contracts\Keypair as KeypairContract;
use GmTLS\CryptoKit\Contracts\KeypairExporter as KeypairExporterContract;
use GmTLS\CryptoKit\Contracts\KeypairParser as KeypairParserContract;

class Keypair implements KeypairContract
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

    public function parse(): KeypairParserContract
    {
        return KeypairParser::create($this);
    }

    public function export(): KeypairExporterContract
    {
        return KeypairExporter::create($this);
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
