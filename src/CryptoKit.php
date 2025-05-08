<?php

namespace GmTLS\CryptoKit;

use Closure;
use GmTLS\CryptoKit\Contracts\AsymmetricKey;
use InvalidArgumentException;

class CryptoKit
{
    /**
     * The registered custom provider creators.
     */
    public static array $customProviderCreators = [];

    /**
     * Register a custom provider creator Closure.
     *
     * @param string  $provider
     * @param Closure $callback
     *
     * @return void
     */
    public static function extend(string $provider, Closure $callback): void
    {
        self::$customProviderCreators[$provider] = $callback;
    }

    /**
     * Create the user provider implementation for the provider.
     * Resolve the given provider.
     *
     * @param Keypair     $keypair
     * @param string|null $type
     *
     * @return AsymmetricKey
     */
    public static function keypair(Keypair $keypair, string $type = null): AsymmetricKey
    {
        $type = $type ?? $keypair->getOptions('type');

        if (isset(self::$customProviderCreators[$type])) {
            return call_user_func(self::$customProviderCreators[$type], $keypair);
        }

        return match ($type) {
            OPENSSL_KEYTYPE_RSA => self::RSA($keypair),
            OPENSSL_KEYTYPE_EC => self::EC($keypair),
            default => throw new InvalidArgumentException(
                "CryptoKit user provider [{$type}] is not defined."
            ),
        };
    }

    /**
     * @param Keypair $keypair
     *
     * @return RSA
     */
    public static function RSA(Keypair $keypair): RSA
    {
        return new RSA($keypair);
    }

    /**
     * @param Keypair $keypair
     *
     * @return EC
     */
    public static function EC(Keypair $keypair): EC
    {
        return new EC($keypair);
    }
}
