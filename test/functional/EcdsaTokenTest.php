<?php
/**
 * This file is part of Auth0\Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Auth0\Lcobucci\JWT\FunctionalTests;

use Auth0\Lcobucci\JWT\Builder;
use Auth0\Lcobucci\JWT\Parser;
use Auth0\Lcobucci\JWT\Signer\Key;
use Auth0\Lcobucci\JWT\Token;
use Auth0\Lcobucci\JWT\Signature;
use Auth0\Lcobucci\JWT\Signer\Ecdsa\Sha256;
use Auth0\Lcobucci\JWT\Signer\Ecdsa\Sha512;
use Auth0\Lcobucci\JWT\Signer\Keychain;
use Auth0\Lcobucci\JWT\Keys;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.1.0
 */
class EcdsaTokenTest extends \PHPUnit\Framework\TestCase
{
    use Keys;

    /**
     * @var Sha256
     */
    private $signer;

    /**
     * @before
     */
    public function createSigner()
    {
        $this->signer = new Sha256();
    }

    /**
     * @test
     *
     * @expectedException \InvalidArgumentException
     *
     * @covers Auth0\Lcobucci\JWT\Builder
     * @covers Auth0\Lcobucci\JWT\Token
     * @covers Auth0\Lcobucci\JWT\Signature
     * @covers Auth0\Lcobucci\JWT\Claim\Factory
     * @covers Auth0\Lcobucci\JWT\Claim\Basic
     * @covers Auth0\Lcobucci\JWT\Parsing\Encoder
     * @covers Auth0\Lcobucci\JWT\Signer\Key
     * @covers Auth0\Lcobucci\JWT\Signer\BaseSigner
     * @covers Auth0\Lcobucci\JWT\Signer\Ecdsa
     * @covers \Auth0\Lcobucci\JWT\Signer\Ecdsa\MultibyteStringConverter
     * @covers Auth0\Lcobucci\JWT\Signer\Ecdsa\Sha256
     * @covers \Auth0\Lcobucci\JWT\Signer\OpenSSL
     */
    public function builderShouldRaiseExceptionWhenKeyIsInvalid()
    {
        $user = (object) ['name' => 'testing', 'email' => 'testing@abc.com'];

        (new Builder())->setId(1)
                       ->setAudience('http://client.abc.com')
                       ->setIssuer('http://api.abc.com')
                       ->set('user', $user)
                       ->getToken($this->signer, new Key('testing'));
    }

    /**
     * @test
     *
     * @expectedException \InvalidArgumentException
     *
     * @covers Auth0\Lcobucci\JWT\Builder
     * @covers Auth0\Lcobucci\JWT\Token
     * @covers Auth0\Lcobucci\JWT\Signature
     * @covers Auth0\Lcobucci\JWT\Claim\Factory
     * @covers Auth0\Lcobucci\JWT\Claim\Basic
     * @covers Auth0\Lcobucci\JWT\Parsing\Encoder
     * @covers Auth0\Lcobucci\JWT\Signer\Key
     * @covers Auth0\Lcobucci\JWT\Signer\BaseSigner
     * @covers Auth0\Lcobucci\JWT\Signer\Ecdsa
     * @covers \Auth0\Lcobucci\JWT\Signer\Ecdsa\MultibyteStringConverter
     * @covers Auth0\Lcobucci\JWT\Signer\Ecdsa\Sha256
     * @covers \Auth0\Lcobucci\JWT\Signer\OpenSSL
     */
    public function builderShouldRaiseExceptionWhenKeyIsNotEcdsaCompatible()
    {
        $user = (object) ['name' => 'testing', 'email' => 'testing@abc.com'];

        (new Builder())->setId(1)
                       ->setAudience('http://client.abc.com')
                       ->setIssuer('http://api.abc.com')
                       ->set('user', $user)
                       ->getToken($this->signer, static::$rsaKeys['private']);
    }

    /**
     * @test
     *
     * @covers Auth0\Lcobucci\JWT\Builder
     * @covers Auth0\Lcobucci\JWT\Token
     * @covers Auth0\Lcobucci\JWT\Signature
     * @covers Auth0\Lcobucci\JWT\Claim\Factory
     * @covers Auth0\Lcobucci\JWT\Claim\Basic
     * @covers Auth0\Lcobucci\JWT\Parsing\Encoder
     * @covers Auth0\Lcobucci\JWT\Signer\Key
     * @covers Auth0\Lcobucci\JWT\Signer\BaseSigner
     * @covers Auth0\Lcobucci\JWT\Signer\Ecdsa
     * @covers \Auth0\Lcobucci\JWT\Signer\Ecdsa\MultibyteStringConverter
     * @covers Auth0\Lcobucci\JWT\Signer\Ecdsa\Sha256
     * @covers \Auth0\Lcobucci\JWT\Signer\OpenSSL
     */
    public function builderCanGenerateAToken()
    {
        $user = (object) ['name' => 'testing', 'email' => 'testing@abc.com'];

        $token = (new Builder())->setId(1)
                              ->setAudience('http://client.abc.com')
                              ->setIssuer('http://api.abc.com')
                              ->set('user', $user)
                              ->setHeader('jki', '1234')
                              ->sign($this->signer, static::$ecdsaKeys['private'])
                              ->getToken();

        $this->assertAttributeInstanceOf(Signature::class, 'signature', $token);
        $this->assertEquals('1234', $token->getHeader('jki'));
        $this->assertEquals('http://client.abc.com', $token->getClaim('aud'));
        $this->assertEquals('http://api.abc.com', $token->getClaim('iss'));
        $this->assertEquals($user, $token->getClaim('user'));

        return $token;
    }

    /**
     * @test
     *
     * @depends builderCanGenerateAToken
     *
     * @covers Auth0\Lcobucci\JWT\Builder
     * @covers Auth0\Lcobucci\JWT\Parser
     * @covers Auth0\Lcobucci\JWT\Token
     * @covers Auth0\Lcobucci\JWT\Signature
     * @covers Auth0\Lcobucci\JWT\Claim\Factory
     * @covers Auth0\Lcobucci\JWT\Claim\Basic
     * @covers Auth0\Lcobucci\JWT\Parsing\Encoder
     * @covers Auth0\Lcobucci\JWT\Parsing\Decoder
     * @covers Auth0\Lcobucci\JWT\Signer\Ecdsa
     */
    public function parserCanReadAToken(Token $generated)
    {
        $read = (new Parser())->parse((string) $generated);

        $this->assertEquals($generated, $read);
        $this->assertEquals('testing', $read->getClaim('user')->name);
    }

    /**
     * @test
     *
     * @depends builderCanGenerateAToken
     *
     * @covers Auth0\Lcobucci\JWT\Builder
     * @covers Auth0\Lcobucci\JWT\Parser
     * @covers Auth0\Lcobucci\JWT\Token
     * @covers Auth0\Lcobucci\JWT\Signature
     * @covers Auth0\Lcobucci\JWT\Parsing\Encoder
     * @covers Auth0\Lcobucci\JWT\Claim\Factory
     * @covers Auth0\Lcobucci\JWT\Claim\Basic
     * @covers Auth0\Lcobucci\JWT\Signer\Key
     * @covers Auth0\Lcobucci\JWT\Signer\BaseSigner
     * @covers Auth0\Lcobucci\JWT\Signer\Ecdsa
     * @covers \Auth0\Lcobucci\JWT\Signer\Ecdsa\MultibyteStringConverter
     * @covers Auth0\Lcobucci\JWT\Signer\Ecdsa\Sha256
     * @covers \Auth0\Lcobucci\JWT\Signer\OpenSSL
     */
    public function verifyShouldReturnFalseWhenKeyIsNotRight(Token $token)
    {
        $this->assertFalse($token->verify($this->signer, static::$ecdsaKeys['public2']));
    }

    /**
     * @test
     *
     * @depends builderCanGenerateAToken
     *
     * @covers Auth0\Lcobucci\JWT\Builder
     * @covers Auth0\Lcobucci\JWT\Parser
     * @covers Auth0\Lcobucci\JWT\Token
     * @covers Auth0\Lcobucci\JWT\Signature
     * @covers Auth0\Lcobucci\JWT\Parsing\Encoder
     * @covers Auth0\Lcobucci\JWT\Claim\Factory
     * @covers Auth0\Lcobucci\JWT\Claim\Basic
     * @covers Auth0\Lcobucci\JWT\Signer\Key
     * @covers Auth0\Lcobucci\JWT\Signer\BaseSigner
     * @covers Auth0\Lcobucci\JWT\Signer\Ecdsa
     * @covers \Auth0\Lcobucci\JWT\Signer\Ecdsa\MultibyteStringConverter
     * @covers Auth0\Lcobucci\JWT\Signer\Ecdsa\Sha256
     * @covers Auth0\Lcobucci\JWT\Signer\Ecdsa\Sha512
     * @covers \Auth0\Lcobucci\JWT\Signer\OpenSSL
     */
    public function verifyShouldReturnFalseWhenAlgorithmIsDifferent(Token $token)
    {
        $this->assertFalse($token->verify(new Sha512(), static::$ecdsaKeys['public1']));
    }

    /**
     * @test
     *
     * @expectedException \InvalidArgumentException
     *
     * @depends builderCanGenerateAToken
     *
     * @covers Auth0\Lcobucci\JWT\Builder
     * @covers Auth0\Lcobucci\JWT\Parser
     * @covers Auth0\Lcobucci\JWT\Token
     * @covers Auth0\Lcobucci\JWT\Signature
     * @covers Auth0\Lcobucci\JWT\Parsing\Encoder
     * @covers Auth0\Lcobucci\JWT\Claim\Factory
     * @covers Auth0\Lcobucci\JWT\Claim\Basic
     * @covers Auth0\Lcobucci\JWT\Signer\Key
     * @covers Auth0\Lcobucci\JWT\Signer\BaseSigner
     * @covers Auth0\Lcobucci\JWT\Signer\Ecdsa
     * @covers \Auth0\Lcobucci\JWT\Signer\Ecdsa\MultibyteStringConverter
     * @covers Auth0\Lcobucci\JWT\Signer\Ecdsa\Sha256
     * @covers \Auth0\Lcobucci\JWT\Signer\OpenSSL
     */
    public function verifyShouldRaiseExceptionWhenKeyIsNotEcdsaCompatible(Token $token)
    {
        $this->assertFalse($token->verify($this->signer, static::$rsaKeys['public']));
    }

    /**
     * @test
     *
     * @depends builderCanGenerateAToken
     *
     * @covers Auth0\Lcobucci\JWT\Builder
     * @covers Auth0\Lcobucci\JWT\Parser
     * @covers Auth0\Lcobucci\JWT\Token
     * @covers Auth0\Lcobucci\JWT\Signature
     * @covers Auth0\Lcobucci\JWT\Parsing\Encoder
     * @covers Auth0\Lcobucci\JWT\Claim\Factory
     * @covers Auth0\Lcobucci\JWT\Claim\Basic
     * @covers Auth0\Lcobucci\JWT\Signer\Key
     * @covers Auth0\Lcobucci\JWT\Signer\BaseSigner
     * @covers Auth0\Lcobucci\JWT\Signer\Ecdsa
     * @covers \Auth0\Lcobucci\JWT\Signer\Ecdsa\MultibyteStringConverter
     * @covers Auth0\Lcobucci\JWT\Signer\Ecdsa\Sha256
     * @covers \Auth0\Lcobucci\JWT\Signer\OpenSSL
     */
    public function verifyShouldReturnTrueWhenKeyIsRight(Token $token)
    {
        $this->assertTrue($token->verify($this->signer, static::$ecdsaKeys['public1']));
    }

    /**
     * @test
     *
     * @covers Auth0\Lcobucci\JWT\Builder
     * @covers Auth0\Lcobucci\JWT\Token
     * @covers Auth0\Lcobucci\JWT\Signature
     * @covers Auth0\Lcobucci\JWT\Claim\Factory
     * @covers Auth0\Lcobucci\JWT\Claim\Basic
     * @covers Auth0\Lcobucci\JWT\Parsing\Encoder
     * @covers Auth0\Lcobucci\JWT\Signer\Key
     * @covers Auth0\Lcobucci\JWT\Signer\BaseSigner
     * @covers Auth0\Lcobucci\JWT\Signer\Ecdsa
     * @covers \Auth0\Lcobucci\JWT\Signer\Ecdsa\MultibyteStringConverter
     * @covers Auth0\Lcobucci\JWT\Signer\Ecdsa\Sha256
     * @covers \Auth0\Lcobucci\JWT\Signer\OpenSSL
     */
    public function everythingShouldWorkWithAKeyWithParams()
    {
        $user = (object) ['name' => 'testing', 'email' => 'testing@abc.com'];

        $token = (new Builder())->setId(1)
                                ->setAudience('http://client.abc.com')
                                ->setIssuer('http://api.abc.com')
                                ->set('user', $user)
                                ->setHeader('jki', '1234')
                                ->sign($this->signer, static::$ecdsaKeys['private-params'])
                                ->getToken();

        $this->assertTrue($token->verify($this->signer, static::$ecdsaKeys['public-params']));
    }

    /**
     * @test
     *
     * @covers Auth0\Lcobucci\JWT\Builder
     * @covers Auth0\Lcobucci\JWT\Parser
     * @covers Auth0\Lcobucci\JWT\Token
     * @covers Auth0\Lcobucci\JWT\Signature
     * @covers Auth0\Lcobucci\JWT\Signer\Key
     * @covers Auth0\Lcobucci\JWT\Signer\BaseSigner
     * @covers Auth0\Lcobucci\JWT\Signer\Ecdsa
     * @covers \Auth0\Lcobucci\JWT\Signer\Ecdsa\MultibyteStringConverter
     * @covers Auth0\Lcobucci\JWT\Signer\Ecdsa\Sha512
     * @covers \Auth0\Lcobucci\JWT\Signer\OpenSSL
     * @covers Auth0\Lcobucci\JWT\Signer\Keychain
     * @covers Auth0\Lcobucci\JWT\Claim\Factory
     * @covers Auth0\Lcobucci\JWT\Claim\Basic
     * @covers Auth0\Lcobucci\JWT\Parsing\Encoder
     * @covers Auth0\Lcobucci\JWT\Parsing\Decoder
     */
    public function everythingShouldWorkWhenUsingATokenGeneratedByOtherLibs()
    {
        $data = 'eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6IndvcmxkIn0.'
                . 'AQx1MqdTni6KuzfOoedg2-7NUiwe-b88SWbdmviz40GTwrM0Mybp1i1tVtm'
                . 'TSQ91oEXGXBdtwsN6yalzP9J-sp2YATX_Tv4h-BednbdSvYxZsYnUoZ--ZU'
                . 'dL10t7g8Yt3y9hdY_diOjIptcha6ajX8yzkDGYG42iSe3f5LywSuD6FO5c';

        $key = '-----BEGIN PUBLIC KEY-----' . PHP_EOL
               . 'MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAcpkss6wI7PPlxj3t7A1RqMH3nvL4' . PHP_EOL
               . 'L5Tzxze/XeeYZnHqxiX+gle70DlGRMqqOq+PJ6RYX7vK0PJFdiAIXlyPQq0B3KaU' . PHP_EOL
               . 'e86IvFeQSFrJdCc0K8NfiH2G1loIk3fiR+YLqlXk6FAeKtpXJKxR1pCQCAM+vBCs' . PHP_EOL
               . 'mZudf1zCUZ8/4eodlHU=' . PHP_EOL
               . '-----END PUBLIC KEY-----';

        $keychain = new Keychain();
        $token = (new Parser())->parse((string) $data);

        $this->assertEquals('world', $token->getClaim('hello'));
        $this->assertTrue($token->verify(new Sha512(), $keychain->getPublicKey($key)));
    }
}
