<?php

namespace GmTLS\CryptoKit\Concerns;

use GmTLS\CryptoKit\Contracts\Base64UrlConverter as Base64Url;

class Base64UrlConverter implements Base64Url
{
    /**
     * {@inheritdoc}
     *
     * @return string
     */
    public function decode(string $data, bool $strict = false): string
    {
        return base64_decode(strtr($data, '-_', '+/'), $strict);
    }

    /**
     * {@inheritdoc}
     *
     * @return string
     */
    public function encode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}
