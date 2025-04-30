<?php

namespace GmTLS\CryptoKit\Contracts;

interface Base64UrlConverter
{
    /**
     * Decodes Base64url formatted data to a string.
     *
     * @param string $data
     * @param bool   $strict
     *
     * @return string
     */
    public function decode(string $data, bool $strict = false): string;

    /**
     * Encodes a string to a base64url formatted data.
     *
     * @param string $data
     *
     * @return string
     */
    public function encode(string $data): string;
}
