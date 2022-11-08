<?php
/**
 * This file is part of Auth0\Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Auth0\Lcobucci\JWT\FunctionalTests;

use Auth0\Lcobucci\JWT\Builder;
use Auth0\Lcobucci\JWT\Parser;
use Auth0\Lcobucci\JWT\Token;
use Auth0\Lcobucci\JWT\Signature;
use Auth0\Lcobucci\JWT\Signer\Hmac\Sha256;
use Auth0\Lcobucci\JWT\Signer\Hmac\Sha512;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.1.0
 */
class HmacTokenTest extends \PHPUnit\Framework\TestCase
{
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
     * @covers Auth0\Lcobucci\JWT\Builder
     * @covers Auth0\Lcobucci\JWT\Token
     * @covers Auth0\Lcobucci\JWT\Signature
     * @covers Auth0\Lcobucci\JWT\Claim\Factory
     * @covers Auth0\Lcobucci\JWT\Claim\Basic
     * @covers Auth0\Lcobucci\JWT\Parsing\Encoder
     * @covers Auth0\Lcobucci\JWT\Signer\Key
     * @covers Auth0\Lcobucci\JWT\Signer\BaseSigner
     * @covers Auth0\Lcobucci\JWT\Signer\Hmac
     * @covers Auth0\Lcobucci\JWT\Signer\Hmac\Sha256
     */
    public function builderCanGenerateAToken()
    {
        $user = (object) ['name' => 'testing', 'email' => 'testing@abc.com'];

        $token = (new Builder())->setId(1)
                              ->setAudience('http://client.abc.com')
                              ->setIssuer('http://api.abc.com')
                              ->set('user', $user)
                              ->setHeader('jki', '1234')
                              ->sign($this->signer, 'testing')
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
     * @covers Auth0\Lcobucci\JWT\Signer\Hmac
     * @covers Auth0\Lcobucci\JWT\Signer\Hmac\Sha256
     */
    public function verifyShouldReturnFalseWhenKeyIsNotRight(Token $token)
    {
        $this->assertFalse($token->verify($this->signer, 'testing1'));
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
     * @covers Auth0\Lcobucci\JWT\Signer\Hmac
     * @covers Auth0\Lcobucci\JWT\Signer\Hmac\Sha256
     * @covers Auth0\Lcobucci\JWT\Signer\Hmac\Sha512
     */
    public function verifyShouldReturnFalseWhenAlgorithmIsDifferent(Token $token)
    {
        $this->assertFalse($token->verify(new Sha512(), 'testing'));
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
     * @covers Auth0\Lcobucci\JWT\Signer\Hmac
     * @covers Auth0\Lcobucci\JWT\Signer\Hmac\Sha256
     */
    public function verifyShouldReturnTrueWhenKeyIsRight(Token $token)
    {
        $this->assertTrue($token->verify($this->signer, 'testing'));
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
     * @covers Auth0\Lcobucci\JWT\Signer\Hmac
     * @covers Auth0\Lcobucci\JWT\Signer\Hmac\Sha256
     * @covers Auth0\Lcobucci\JWT\Claim\Factory
     * @covers Auth0\Lcobucci\JWT\Claim\Basic
     * @covers Auth0\Lcobucci\JWT\Parsing\Encoder
     * @covers Auth0\Lcobucci\JWT\Parsing\Decoder
     */
    public function everythingShouldWorkWhenUsingATokenGeneratedByOtherLibs()
    {
        $data = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJoZWxsbyI6IndvcmxkIn0.Rh'
                . '7AEgqCB7zae1PkgIlvOpeyw9Ab8NGTbeOH7heHO0o';

        $token = (new Parser())->parse((string) $data);

        $this->assertEquals('world', $token->getClaim('hello'));
        $this->assertTrue($token->verify($this->signer, 'testing'));
    }
}
