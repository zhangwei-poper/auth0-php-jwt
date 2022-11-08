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
use Auth0\Lcobucci\JWT\ValidationData;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.1.0
 */
class UnsignedTokenTest extends \PHPUnit\Framework\TestCase
{
    const CURRENT_TIME = 100000;

    /**
     * @test
     *
     * @covers Auth0\Lcobucci\JWT\Builder
     * @covers Auth0\Lcobucci\JWT\Token
     * @covers Auth0\Lcobucci\JWT\Claim\Factory
     * @covers Auth0\Lcobucci\JWT\Claim\Basic
     * @covers Auth0\Lcobucci\JWT\Parsing\Encoder
     */
    public function builderCanGenerateAToken()
    {
        $user = (object) ['name' => 'testing', 'email' => 'testing@abc.com'];

        $token = (new Builder())->setId(1)
                              ->setAudience('http://client.abc.com')
                              ->setIssuer('http://api.abc.com')
                              ->setExpiration(self::CURRENT_TIME + 3000)
                              ->set('user', $user)
                              ->getToken();

        $this->assertAttributeEquals(null, 'signature', $token);
        $this->assertEquals('http://client.abc.com', $token->getClaim('aud'));
        $this->assertEquals('http://api.abc.com', $token->getClaim('iss'));
        $this->assertEquals(self::CURRENT_TIME + 3000, $token->getClaim('exp'));
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
     * @covers Auth0\Lcobucci\JWT\ValidationData
     * @covers Auth0\Lcobucci\JWT\Claim\Factory
     * @covers Auth0\Lcobucci\JWT\Claim\Basic
     * @covers Auth0\Lcobucci\JWT\Claim\EqualsTo
     * @covers Auth0\Lcobucci\JWT\Claim\GreaterOrEqualsTo
     * @covers Auth0\Lcobucci\JWT\Parsing\Encoder
     * @covers Auth0\Lcobucci\JWT\Parsing\Decoder
     */
    public function tokenValidationShouldReturnWhenEverythingIsFine(Token $generated)
    {
        $data = new ValidationData(self::CURRENT_TIME - 10);
        $data->setAudience('http://client.abc.com');
        $data->setIssuer('http://api.abc.com');

        $this->assertTrue($generated->validate($data));
    }

    /**
     * @test
     *
     * @dataProvider invalidValidationData
     *
     * @depends builderCanGenerateAToken
     *
     * @covers Auth0\Lcobucci\JWT\Builder
     * @covers Auth0\Lcobucci\JWT\Parser
     * @covers Auth0\Lcobucci\JWT\Token
     * @covers Auth0\Lcobucci\JWT\ValidationData
     * @covers Auth0\Lcobucci\JWT\Claim\Factory
     * @covers Auth0\Lcobucci\JWT\Claim\Basic
     * @covers Auth0\Lcobucci\JWT\Claim\EqualsTo
     * @covers Auth0\Lcobucci\JWT\Claim\GreaterOrEqualsTo
     * @covers Auth0\Lcobucci\JWT\Parsing\Encoder
     * @covers Auth0\Lcobucci\JWT\Parsing\Decoder
     */
    public function tokenValidationShouldReturnFalseWhenExpectedDataDontMatch(ValidationData $data, Token $generated)
    {
        $this->assertFalse($generated->validate($data));
    }

    /**
     * @test
     *
     * @depends builderCanGenerateAToken
     *
     * @covers Auth0\Lcobucci\JWT\Builder
     * @covers Auth0\Lcobucci\JWT\Parser
     * @covers Auth0\Lcobucci\JWT\Token
     * @covers Auth0\Lcobucci\JWT\ValidationData
     * @covers Auth0\Lcobucci\JWT\Claim\Factory
     * @covers Auth0\Lcobucci\JWT\Claim\Basic
     * @covers Auth0\Lcobucci\JWT\Claim\EqualsTo
     * @covers Auth0\Lcobucci\JWT\Claim\GreaterOrEqualsTo
     * @covers Auth0\Lcobucci\JWT\Parsing\Encoder
     * @covers Auth0\Lcobucci\JWT\Parsing\Decoder
     */
    public function tokenValidationShouldReturnTrueWhenExpectedDataMatchBecauseOfLeeway(Token $generated)
    {
        $notExpiredDueToLeeway = new ValidationData(self::CURRENT_TIME + 3020, 50);
        $notExpiredDueToLeeway->setAudience('http://client.abc.com');
        $notExpiredDueToLeeway->setIssuer('http://api.abc.com');
        $this->assertTrue($generated->validate($notExpiredDueToLeeway));
    }

    public function invalidValidationData()
    {
        $expired = new ValidationData(self::CURRENT_TIME + 3020);
        $expired->setAudience('http://client.abc.com');
        $expired->setIssuer('http://api.abc.com');

        $invalidAudience = new ValidationData(self::CURRENT_TIME - 10);
        $invalidAudience->setAudience('http://cclient.abc.com');
        $invalidAudience->setIssuer('http://api.abc.com');

        $invalidIssuer = new ValidationData(self::CURRENT_TIME - 10);
        $invalidIssuer->setAudience('http://client.abc.com');
        $invalidIssuer->setIssuer('http://aapi.abc.com');

        return [[$expired], [$invalidAudience], [$invalidIssuer]];
    }
}
