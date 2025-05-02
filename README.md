# OpenSSL Crypto Kit

A modern and extensible PHP cryptography toolkit powered by OpenSSL.  
Supports RSA for encryption, decryption, and digital signatures, and EC for high-performance digital signing and key exchange.  
Also includes X.509 certificate generation, passphrase protection, and pluggable algorithm support.

[![GitHub Tag](https://img.shields.io/github/v/tag/dependencies-packagist/openssl-crypto-kit)](https://github.com/dependencies-packagist/openssl-crypto-kit/tags)
[![Total Downloads](https://img.shields.io/packagist/dt/gmtls/openssl-crypto-kit?style=flat-square)](https://packagist.org/packages/gmtls/openssl-crypto-kit)
[![Packagist Version](https://img.shields.io/packagist/v/gmtls/openssl-crypto-kit)](https://packagist.org/packages/gmtls/openssl-crypto-kit)
[![Packagist PHP Version Support](https://img.shields.io/packagist/php-v/gmtls/openssl-crypto-kit)](https://github.com/dependencies-packagist/openssl-crypto-kit)
[![Packagist License](https://img.shields.io/github/license/dependencies-packagist/openssl-crypto-kit)](https://github.com/dependencies-packagist/openssl-crypto-kit)

A modern PHP cryptography toolkit powered by OpenSSL.  
Features include:

- [x] RSA: key generation, signing, verification, encryption, decryption
- [x] EC: key generation, signing, verification
- [ ] X.509 certificate creation
- [x] Passphrase protection and pluggable algorithm support

## Installation

You can install the package via [Composer](https://getcomposer.org/):

```bash
composer require gmtls/openssl-crypto-kit
```

## Usage

### Generation

```php
use GmTLS\CryptoKit\Providers\EcProvider;
use GmTLS\CryptoKit\Providers\RsaProvider;

$key = EcProvider::generateKeypair('secp521r1', 'password');
$key = RsaProvider::generateKeypair(1024, 'password');
```

Or, load from an existing key

```php
use GmTLS\CryptoKit\Keypair;

$key = new Keypair();
$key->fromPrivateKeyFile(realpath('private.pem'), 'password');
$key->fromPublicKeyFile(realpath('public.pem'));
$key->fromFile(realpath('key.pem'), 'password');
```

Save the key to a file

```php
$key->savePrivateKey(__DIR__ . '/private.pem');
$key->savePublicKey(__DIR__ . '/public.pem');
$key->saveKeys(__DIR__ . '/key.pem');
```

### Signing && Verification

```php
use GmTLS\CryptoKit\Factory;

$rsa = Factory::provider($key);
// or
$rsa = Factory::createRsaProvider($key);
// or
$rsa = new RsaProvider($key);

$data   = '...';
$sign   = $rsa->sign($data);
$verify = $rsa->verify($data, $sign);
var_dump($sign, $verify);

$sign   = $rsa->base64Sign($data);
$verify = $rsa->base64Verify($data, $sign);
var_dump($sign, $verify);
```

### Encryption && Decryption

```php
$data    = '...';
$encrypt = $rsa->encrypt($data);
$decrypt = $rsa->decrypt($encrypt);
var_dump($encrypt, $decrypt);

$encrypt = $rsa->base64Encrypt($data);
$decrypt = $rsa->base64Decrypt($encrypt);
var_dump($encrypt, $decrypt);
```

## Advanced

Create a new `YourProvider` class that extends `\GmTLS\CryptoKit\Providers\AbstractProvider` and implement `generateKeypair`, `converterToKeys` and the methods you need to override.

```php
use GmTLS\CryptoKit\Contracts\Keypair as KeypairContract;
use GmTLS\CryptoKit\Keypair;
use GmTLS\CryptoKit\Providers\AbstractProvider;
use RuntimeException;

class YourProvider extends AbstractProvider
{
    public static function generateKeypair(): KeypairContract
    {
        // ...
        return new Keypair(
            $privateKey,
            $details['key'],
            $passphrase,
            $details,
        );
    }

    public function getKeyType(): string
    {
        return '...';
    }

    public function getEncodedKeys(array $details = []): array
    {
        // ...
        return [];
    }
}
```

Extending Provider:

```php
use GmTLS\CryptoKit\Factory;
use GmTLS\CryptoKit\Keypair;

Factory::extend(YourProvider::class, function (Keypair $keypair) {
    return new YourProvider($keypair);
});
```

Calling using Factory:

```php
Factory::provider(YourProvider::class)->sign($data);
Factory::provider(YourProvider::class)->verify($data, $sign);
// ...
```

## License

Nacosvel Contracts is made available under the MIT License (MIT). Please see [License File](LICENSE) for more information.
