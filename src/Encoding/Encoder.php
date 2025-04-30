<?php

namespace GmTLS\CryptoKit\Encoding;

use GmTLS\CryptoKit\Contracts\Encoding;

class Encoder implements Encoding
{
    /**
     * {@inheritdoc}
     *
     * @return string
     */
    public function base64UrlDecode(string $data, bool $strict = false): string
    {
        return base64_decode(strtr($data, '-_', '+/'), $strict);
    }

    /**
     * {@inheritdoc}
     *
     * @return string
     */
    public function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}
