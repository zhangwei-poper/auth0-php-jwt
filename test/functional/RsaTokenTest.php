<?php
/**
 * This file is part of Auth0\Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Auth0\Lcobucci\JWT\FunctionalTests;

use Auth0\Lcobucci\JWT\Builder;
use Auth0\Lcobucci\JWT\Keys;
use Auth0\Lcobucci\JWT\Parser;
use Auth0\Lcobucci\JWT\Signer\Key;
use Auth0\Lcobucci\JWT\Token;
use Auth0\Lcobucci\JWT\Signature;
use Auth0\Lcobucci\JWT\Signer\Rsa\Sha256;
use Auth0\Lcobucci\JWT\Signer\Rsa\Sha512;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.1.0
 */
class RsaTokenTest extends \PHPUnit\Framework\TestCase
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
     * @covers \Auth0\Lcobucci\JWT\Signer\OpenSSL
     * @covers \Auth0\Lcobucci\JWT\Signer\Rsa
     * @covers \Auth0\Lcobucci\JWT\Signer\Rsa\Sha256
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
     * @covers \Auth0\Lcobucci\JWT\Signer\OpenSSL
     * @covers \Auth0\Lcobucci\JWT\Signer\Rsa
     * @covers \Auth0\Lcobucci\JWT\Signer\Rsa\Sha256
     */
    public function builderShouldRaiseExceptionWhenKeyIsNotRsaCompatible()
    {
        $user = (object) ['name' => 'testing', 'email' => 'testing@abc.com'];

        (new Builder())->setId(1)
                       ->setAudience('http://client.abc.com')
                       ->setIssuer('http://api.abc.com')
                       ->set('user', $user)
                       ->getToken($this->signer, static::$ecdsaKeys['private']);
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
     * @covers \Auth0\Lcobucci\JWT\Signer\OpenSSL
     * @covers \Auth0\Lcobucci\JWT\Signer\Rsa
     * @covers \Auth0\Lcobucci\JWT\Signer\Rsa\Sha256
     */
    public function builderCanGenerateAToken()
    {
        $user = (object) ['name' => 'testing', 'email' => 'testing@abc.com'];

        $token = (new Builder())->setId(1)
                              ->setAudience('http://client.abc.com')
                              ->setIssuer('http://api.abc.com')
                              ->set('user', $user)
                              ->setHeader('jki', '1234')
                              ->sign($this->signer, static::$rsaKeys['private'])
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
     * @covers \Auth0\Lcobucci\JWT\Signer\OpenSSL
     * @covers \Auth0\Lcobucci\JWT\Signer\Rsa
     * @covers \Auth0\Lcobucci\JWT\Signer\Rsa\Sha256
     */
    public function verifyShouldReturnFalseWhenKeyIsNotRight(Token $token)
    {
        $this->assertFalse($token->verify($this->signer, self::$rsaKeys['encrypted-public']));
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
     * @covers \Auth0\Lcobucci\JWT\Signer\OpenSSL
     * @covers \Auth0\Lcobucci\JWT\Signer\Rsa
     * @covers \Auth0\Lcobucci\JWT\Signer\Rsa\Sha256
     * @covers \Auth0\Lcobucci\JWT\Signer\Rsa\Sha512
     */
    public function verifyShouldReturnFalseWhenAlgorithmIsDifferent(Token $token)
    {
        $this->assertFalse($token->verify(new Sha512(), self::$rsaKeys['public']));
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
     * @covers \Auth0\Lcobucci\JWT\Signer\OpenSSL
     * @covers \Auth0\Lcobucci\JWT\Signer\Rsa
     * @covers \Auth0\Lcobucci\JWT\Signer\Rsa\Sha256
     */
    public function verifyShouldRaiseExceptionWhenKeyIsNotRsaCompatible(Token $token)
    {
        $this->assertFalse($token->verify($this->signer, self::$ecdsaKeys['public1']));
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
     * @covers \Auth0\Lcobucci\JWT\Signer\OpenSSL
     * @covers \Auth0\Lcobucci\JWT\Signer\Rsa
     * @covers \Auth0\Lcobucci\JWT\Signer\Rsa\Sha256
     */
    public function verifyShouldReturnTrueWhenKeyIsRight(Token $token)
    {
        $this->assertTrue($token->verify($this->signer, self::$rsaKeys['public']));
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
     * @covers \Auth0\Lcobucci\JWT\Signer\OpenSSL
     * @covers \Auth0\Lcobucci\JWT\Signer\Rsa
     * @covers \Auth0\Lcobucci\JWT\Signer\Rsa\Sha256
     * @covers Auth0\Lcobucci\JWT\Claim\Factory
     * @covers Auth0\Lcobucci\JWT\Claim\Basic
     * @covers Auth0\Lcobucci\JWT\Parsing\Encoder
     * @covers Auth0\Lcobucci\JWT\Parsing\Decoder
     */
    public function everythingShouldWorkWhenUsingATokenGeneratedByOtherLibs()
    {
        $data = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXUyJ9.eyJoZWxsbyI6IndvcmxkIn0.s'
                . 'GYbB1KrmnESNfJ4D9hOe1Zad_BMyxdb8G4p4LNP7StYlOyBWck6q7XPpPj_6gB'
                . 'Bo1ohD3MA2o0HY42lNIrAStaVhfsFKGdIou8TarwMGZBPcif_3ThUV1pGS3fZc'
                . 'lFwF2SP7rqCngQis_xcUVCyqa8E1Wa_v28grnl1QZrnmQFO8B5JGGLqcrfUHJO'
                . 'nJCupP-Lqh4TmIhftIimSCgLNmJg80wyrpUEfZYReE7hPuEmY0ClTqAGIMQoNS'
                . '98ljwDxwhfbSuL2tAdbV4DekbTpWzspe3dOJ7RSzmPKVZ6NoezaIazKqyqkmHZfcMaHI1lQeGia6LTbHU1bp0gINi74Vw';

        $token = (new Parser())->parse((string) $data);

        $this->assertEquals('world', $token->getClaim('hello'));
        $this->assertTrue($token->verify($this->signer, self::$rsaKeys['public']));
    }
}
