# OpenSSL Crypto Kit

A modern and extensible PHP cryptography toolkit powered by OpenSSL.  
Supports RSA for encryption, decryption, and digital signatures, and EC for high-performance digital signing and key exchange.  
Also includes X.509 certificate generation, passphrase protection, and pluggable algorithm support.

[![GitHub Tag](https://img.shields.io/github/v/tag/gmtls/openssl-crypto-kit)](https://github.com/gmtls/openssl-crypto-kit/tags)
[![Total Downloads](https://img.shields.io/packagist/dt/gmtls/openssl-crypto-kit?style=flat-square)](https://packagist.org/packages/gmtls/openssl-crypto-kit)
[![Packagist Version](https://img.shields.io/packagist/v/gmtls/openssl-crypto-kit)](https://packagist.org/packages/gmtls/openssl-crypto-kit)
[![Packagist PHP Version Support](https://img.shields.io/packagist/php-v/gmtls/openssl-crypto-kit)](https://github.com/gmtls/openssl-crypto-kit)
[![Packagist License](https://img.shields.io/github/license/gmtls/openssl-crypto-kit)](https://github.com/gmtls/openssl-crypto-kit)

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
use GmTLS\CryptoKit\EC;
use GmTLS\CryptoKit\RSA;

$key = EC::createKey('secp521r1', 'password');
$key = RSA::createKey(1024, 'password');
```

Or, load from an existing key

```php
use GmTLS\CryptoKit\KeypairLoader;

KeypairLoader::fromPrivateKeyFile(realpath('private.pem'), 'password');
KeypairLoader::fromPublicKeyFile(realpath('public.pem'));
KeypairLoader::fromFile(realpath('key.pem'), 'password');
```

Save the key to a file

```php
$key->export()->savePrivateKey(__DIR__ . '/private1.pem');
$key->export()->savePublicKey(__DIR__ . '/public1.pem');
$key->export()->saveKeys(__DIR__ . '/key1.pem');
```

### Signing && Verification

```php
use GmTLS\CryptoKit\CryptoKit;
use GmTLS\CryptoKit\RSA;

$key = RSA::createKey(1024, 'password');
$rsa = CryptoKit::keypair($key);

$data   = '...';
$sign   = $rsa->getPrivateKey()->sign($data);
$verify = $rsa->getPublicKey()->verify($data, $sign);
var_dump($sign, $verify);

$sign   = $rsa->getPrivateKey()->base64Sign($data);
$verify = $rsa->getPublicKey()->base64Verify($data, $sign);
var_dump($sign, $verify);
```

### Encryption && Decryption

```php
use GmTLS\CryptoKit\CryptoKit;
use GmTLS\CryptoKit\RSA;

$key = RSA::createKey(1024, 'password');
$rsa = CryptoKit::RSA($key);

$data    = '...';
$encrypt = $rsa->getPublicKey()->encrypt($data);
$decrypt = $rsa->getPrivateKey()->decrypt($encrypt);
var_dump($encrypt, $decrypt);

$encrypt = $rsa->getPublicKey()->base64Encrypt($data);
$decrypt = $rsa->getPrivateKey()->base64Decrypt($encrypt);
var_dump($encrypt, $decrypt);
```

## Advanced

### Extensions

```shell
openssl dsaparam -out dsaparam.pem 1024

openssl gendsa -out private_dsa.pem dsaparam.pem

openssl dsa -in private_dsa.pem -pubout -out public_dsa.pem
```

Create a new `DSA` class that extends `\GmTLS\CryptoKit\Concerns\AsymmetricKey` and implement the methods you need to override.

```php
use GmTLS\CryptoKit\Concerns\AsymmetricKey;
use GmTLS\CryptoKit\Keypair;
use GmTLS\CryptoKit\Crypto\PrivateKey;
use GmTLS\CryptoKit\Crypto\PublicKey;
use RuntimeException;

class DSA extends AsymmetricKey
{
    public static function createKey(): Keypair
    {
        throw new RuntimeException('Direct generation of DSA keys is not supported');
    }

    public function getPublicKey(): PublicKey
    {
        return new PublicKey(new Keypair(
            publicKey: $this->getKeypair()->getPublicKey()
        ));
    }

    public function getPrivateKey(): PrivateKey
    {
        return new PrivateKey(new Keypair(
            privateKey: $this->getKeypair()->getPrivateKey(),
            publicKey: $this->getKeypair()->getPublicKey(),
            passphrase: $this->getKeypair()->getPassphrase(),
        ));
    }
}
```

Extending CryptoKit:

```php
use GmTLS\CryptoKit\CryptoKit;
use GmTLS\CryptoKit\Keypair;
use GmTLS\CryptoKit\KeypairLoader;

CryptoKit::extend(OPENSSL_KEYTYPE_DSA, function (Keypair $keypair) {
    return new DSA($keypair);
});
```

Calling using CryptoKit:

```php
$keypair = KeypairLoader::fromFile(realpath('dsa.pem'));
$dsa     = CryptoKit::keypair($keypair);

$data   = '...';
$sign   = $dsa->getPrivateKey()->sign($data);
$verify = $dsa->getPublicKey()->verify($data, $sign);
var_dump($sign, $verify);

$sign   = $dsa->getPrivateKey()->base64Sign($data);
$verify = $dsa->getPublicKey()->base64Verify($data, $sign);
var_dump($sign, $verify);
```

### JWK

```php
use GmTLS\CryptoKit\RSA;

$key = RSA::createKey(1024, 'password');
echo $key->parse()->toPrivateKey('JWK');
//{
//    "keys": [
//        {
//            "kty": "RSA",
//            "n": "...",
//            "e": "...",
//            "d": "...",
//            "p": "...",
//            "q": "...",
//            "dp": "...",
//            "dq": "...",
//            "qi": "..."
//        }
//    ]
//}
```

```php
use GmTLS\CryptoKit\KeypairParser;

echo KeypairParser::load($jwk)->getPublicKey();
// -----BEGIN PRIVATE KEY-----
// MIICdwIBAD...
// -----END PRIVATE KEY-----
echo KeypairParser::load($jwk)->getPrivateKey();
// -----BEGIN PUBLIC KEY-----
// MIGfMA0GCS...
// -----END PUBLIC KEY-----
```

## License

Nacosvel Contracts is made available under the MIT License (MIT). Please see [License File](LICENSE) for more information.
