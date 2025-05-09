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

### Extension Algorithm

Create a new `DSA` class that extends `\GmTLS\CryptoKit\Concerns\AsymmetricKey` and implement the methods you need to override.

- Generate DSA Key Pair Using OpenSSL:

```shell
openssl dsaparam -out dsaparam.pem 1024

openssl gendsa -out private_dsa.pem dsaparam.pem

openssl dsa -in private_dsa.pem -pubout -out public_dsa.pem
```

- Extension Class – DSA Key Wrapper

> The DSA class provides a wrapper for handling DSA asymmetric keys in the GmTLS\CryptoKit framework, and it extends the base class AsymmetricKey.

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

- Extending CryptoKit:

```php
use GmTLS\CryptoKit\CryptoKit;
use GmTLS\CryptoKit\Keypair;
use GmTLS\CryptoKit\KeypairLoader;

CryptoKit::extend(OPENSSL_KEYTYPE_DSA, function (Keypair $keypair) {
    return new DSA($keypair);
});
```

- Calling using CryptoKit:

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

Generate JWK using `RSA`:

```php
use GmTLS\CryptoKit\RSA;

$key = RSA::createKey(1024, 'password');
echo $key->parse()->toPrivateKey('JWK');
```

Output:

```json
{
    "keys": [
        {
            "kty": "RSA",
            "n": "0J9js7Tmn5meaal0h1eooKtVkiAykS8WQLOjdGXHq5MX6iimYHna04N_u18bWu02OsULOFj96nuA9C4MvYdFMxPGN8v6j_a2CQRnuIoAtizy1umYkZyBT5LnTmOMG3UOqAFIXDyVrsegYHRTsn0cr8ncYUhHhpBZX7A-Ly7gbYk=",
            "e": "AQAB",
            "d": "yEAmmKnNMWdoam3w37ThtQ-g_LmRMFDtYD_OZv0HcwanTumkAjkVNjAkHHvHKzlE85aOFZE-caQI_Nly-z3rycbHxouVDoWSKaPFZ89yPyo-CEJYLSoEuyYVrjUthl285-5mgXf1Oi8T_EUrT_yn-QDKWpGL1YIiOLMlpsPmIB0=",
            "p": "6GXT1Kr0u3viwmiX80ajArGnwNsL6cetlnnpN3naJ0c5Yto6tn-2mOMsCZXT0M8Uch0IDK8wT2ZPUi4y0qpaZw==",
            "q": "5c9s6uFY0Ie8131Nx_rSenayMxZYW-tHrCH6YYRi1NQNj2AWb8MEJlSvtspE2aVLL9H0-RLJtrOXtqI4My_ijw==",
            "dp": "h9IrUVlwmro2tuQmGjooPwTRQ_dBKSpYG1-4m4GNq_MGaO2d7tcJQqVSMW_tUVYVXvP0pmUk2OK0bRUvAswo9Q==",
            "dq": "X8WB7qDbEox-9o8RyzWMYdz1hrTZPfVfeSzv25QAXBHDVO0GbK0pHZBNajABYXKxUsx8-xAJYEqX_1S7dxmNoQ==",
            "qi": "sHJGFOo2PGOw0wYc8qkhDa-Qzuf4UNM-XoXwMy7UqtTgjaK_7QCaXjF5E7it3oBBnOiNutyrl2zXIerXm7-TiQ=="
        }
    ]
}
```

Get the public or private key based on the JWK using KeypairParser:

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
