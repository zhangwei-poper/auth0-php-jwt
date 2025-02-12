<?php
/**
 * This file is part of Auth0\Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Auth0\Lcobucci\JWT\Signer\Hmac;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 */
class Sha384Test extends \PHPUnit\Framework\TestCase
{
    /**
     * @test
     *
     * @covers Auth0\Lcobucci\JWT\Signer\Hmac\Sha384::getAlgorithmId
     */
    public function getAlgorithmIdMustBeCorrect()
    {
        $signer = new Sha384();

        $this->assertEquals('HS384', $signer->getAlgorithmId());
    }

    /**
     * @test
     *
     * @covers Auth0\Lcobucci\JWT\Signer\Hmac\Sha384::getAlgorithm
     */
    public function getAlgorithmMustBeCorrect()
    {
        $signer = new Sha384();

        $this->assertEquals('sha384', $signer->getAlgorithm());
    }
}
