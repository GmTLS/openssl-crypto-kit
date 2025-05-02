<?php

namespace GmTLS\CryptoKit\Concerns;

trait EncodeParameters
{
    /**
     * @param string $der
     * @param string $label
     *
     * @return string
     */
    protected static function wrapKey(string $der, string $label): string
    {
        return "-----BEGIN {$label}-----\r\n" .
            chunk_split(base64_encode($der), 64) .
            "-----END {$label}-----\r\n";
    }

    /**
     * @param string $data
     *
     * @return string
     */
    protected static function encodeSequence(string $data): string
    {
        return "\x30" . self::encodeLength(strlen($data)) . $data;
    }

    /**
     * @param string $data
     *
     * @return string
     */
    protected static function encodeInteger(string $data): string
    {
        if (ord($data[0]) > 0x7F) {
            $data = "\x00" . $data;
        }
        return "\x02" . self::encodeLength(strlen($data)) . $data;
    }

    /**
     * @param string $data
     *
     * @return string
     */
    protected static function encodeBitString(string $data): string
    {
        return "\x03" . self::encodeLength(strlen($data) + 1) . "\x00" . $data;
    }

    /**
     * @param string $data
     *
     * @return string
     */
    protected static function encodeOctetString(string $data): string
    {
        return "\x04" . self::encodeLength(strlen($data)) . $data;
    }

    /**
     * Generate the ASN.1 NULL encoding.
     *
     * @return string The encoded NULL as per ASN.1 encoding rules.
     */
    protected static function encodeNull(): string
    {
        return "\x05\x00";
    }

    /**
     * @param string $oid
     *
     * @return string
     */
    protected static function encodeOID(string $oid): string
    {
        return "\x06" . self::encodeLength(strlen($oid)) . $oid;
    }

    /**
     * @param int    $tag
     * @param string $data
     *
     * @return string
     */
    protected static function encodeTagged(int $tag, string $data): string
    {
        return chr(0xa0 + $tag) . self::encodeLength(strlen($data)) . $data;
    }

    /**
     * @param int $length
     *
     * @return string
     */
    protected static function encodeLength(int $length): string
    {
        if ($length < 128) {
            return chr($length);
        }
        $len = ltrim(pack('N', $length), "\x00");
        return chr(0x80 | strlen($len)) . $len;
    }
}
