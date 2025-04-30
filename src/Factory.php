<?php

namespace GmTLS\CryptoKit;

use Closure;
use GmTLS\CryptoKit\Contracts\Key;
use GmTLS\CryptoKit\Contracts\Provider;
use GmTLS\CryptoKit\Providers\EcProvider;
use GmTLS\CryptoKit\Providers\RsaProvider;
use InvalidArgumentException;

class Factory
{
    /**
     * The registered custom provider creators.
     */
    protected static array $customProviderCreators = [];

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
     * @param Key $key
     *
     * @return Provider
     */
    public static function provider(Key $key): Provider
    {
        $type = $key->get('type');

        if (isset(self::$customProviderCreators[$type])) {
            return call_user_func(self::$customProviderCreators[$type], $key);
        }

        return match ($type) {
            OPENSSL_KEYTYPE_RSA => self::createRsaProvider($key),
            OPENSSL_KEYTYPE_EC => self::createEcProvider($key),
            default => throw new InvalidArgumentException(
                "CryptoKit user provider [{$type}] is not defined."
            ),
        };
    }

    /**
     * @param Key $key
     *
     * @return RsaProvider
     */
    public static function createRsaProvider(Key $key): RsaProvider
    {
        return new RsaProvider($key);
    }

    /**
     * @param Key $key
     *
     * @return EcProvider
     */
    public static function createEcProvider(Key $key): EcProvider
    {
        return new EcProvider($key);
    }
}
