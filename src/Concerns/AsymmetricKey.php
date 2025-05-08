<?php

namespace GmTLS\CryptoKit\Concerns;

use GmTLS\CryptoKit\Contracts\AsymmetricKey as AsymmetricKeyContract;
use GmTLS\CryptoKit\Contracts\Keypair as KeypairContract;
use GmTLS\CryptoKit\Keypair;

abstract class AsymmetricKey implements AsymmetricKeyContract
{
    public function __construct(
        protected ?KeypairContract $keypair = null,
    )
    {
        $this->keypair = $keypair ?? new Keypair();
    }

    public function getKeypair(): KeypairContract
    {
        return $this->keypair;
    }
}
