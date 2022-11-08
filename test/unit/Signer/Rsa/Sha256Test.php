<?php
/**
 * This file is part of Auth0\Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Auth0\Lcobucci\JWT\Signer\Rsa;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.1.0
 */
class Sha256Test extends \PHPUnit\Framework\TestCase
{
    /**
     * @test
     *
     * @covers Auth0\Lcobucci\JWT\Signer\Rsa\Sha256::getAlgorithmId
     */
    public function getAlgorithmIdMustBeCorrect()
    {
        $signer = new Sha256();

        $this->assertEquals('RS256', $signer->getAlgorithmId());
    }

    /**
     * @test
     *
     * @covers Auth0\Lcobucci\JWT\Signer\Rsa\Sha256::getAlgorithm
     */
    public function getAlgorithmMustBeCorrect()
    {
        $signer = new Sha256();

        $this->assertEquals(OPENSSL_ALGO_SHA256, $signer->getAlgorithm());
    }
}
