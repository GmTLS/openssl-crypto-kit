<?php

namespace GmTLS\CryptoKit;

use Closure;
use GmTLS\CryptoKit\Contracts\Keypair;
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
     * @param Keypair $keypair
     *
     * @return Provider
     */
    public static function provider(Keypair $keypair): Provider
    {
        $type = $keypair->get('type');

        if (isset(self::$customProviderCreators[$type])) {
            return call_user_func(self::$customProviderCreators[$type], $keypair);
        }

        return match ($type) {
            OPENSSL_KEYTYPE_RSA => self::createRsaProvider($keypair),
            OPENSSL_KEYTYPE_EC => self::createEcProvider($keypair),
            default => throw new InvalidArgumentException(
                "CryptoKit user provider [{$type}] is not defined."
            ),
        };
    }

    /**
     * @param Keypair $keypair
     *
     * @return RsaProvider
     */
    public static function createRsaProvider(Keypair $keypair): RsaProvider
    {
        return new RsaProvider($keypair);
    }

    /**
     * @param Keypair $keypair
     *
     * @return EcProvider
     */
    public static function createEcProvider(Keypair $keypair): EcProvider
    {
        return new EcProvider($keypair);
    }
}
