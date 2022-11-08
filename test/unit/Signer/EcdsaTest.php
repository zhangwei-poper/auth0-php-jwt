<?php
/**
 * This file is part of Auth0\Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Auth0\Lcobucci\JWT\Signer;

use Auth0\Lcobucci\JWT\Keys;
use Auth0\Lcobucci\JWT\Signer\Ecdsa\MultibyteStringConverter;
use const OPENSSL_ALGO_SHA256;
use function openssl_pkey_get_private;
use function openssl_pkey_get_public;
use function openssl_sign;
use function openssl_verify;

class EcdsaTest extends \PHPUnit\Framework\TestCase
{
    use Keys;

    /**
     * @var MultibyteStringConverter
     */
    private $pointsManipulator;

    /**
     * @before
     */
    public function createDependencies()
    {
        $this->pointsManipulator = new MultibyteStringConverter();
    }

    private function getSigner()
    {
        $signer = $this->getMockForAbstractClass(Ecdsa::class, [$this->pointsManipulator]);

        $signer->method('getAlgorithm')
            ->willReturn(OPENSSL_ALGO_SHA256);

        $signer->method('getAlgorithmId')
            ->willReturn('ES256');

        $signer->method('getKeyLength')
            ->willReturn(64);

        return $signer;
    }

    /**
     * @test
     *
     * @covers \Auth0\Lcobucci\JWT\Signer\Ecdsa::createHash
     * @covers \Auth0\Lcobucci\JWT\Signer\Ecdsa::getKeyType
     * @covers \Auth0\Lcobucci\JWT\Signer\Ecdsa\MultibyteStringConverter
     * @covers \Auth0\Lcobucci\JWT\Signer\OpenSSL
     * @covers \Auth0\Lcobucci\JWT\Signer\BaseSigner
     *
     * @uses \Auth0\Lcobucci\JWT\Signer\Ecdsa::__construct
     * @uses \Auth0\Lcobucci\JWT\Signer\Key
     * @uses \Auth0\Lcobucci\JWT\Signature
     */
    public function createHashShouldReturnTheAHashBasedOnTheOpenSslSignature()
    {
        $payload = 'testing';

        $signer    = $this->getSigner();
        $signature = $signer->sign($payload, self::$ecdsaKeys['private']);

        $publicKey = openssl_pkey_get_public(self::$ecdsaKeys['public1']->getContent());

        self::assertInternalType('resource', $publicKey);
        self::assertSame(
            1,
            openssl_verify(
                $payload,
                $this->pointsManipulator->toAsn1($signature, $signer->getKeyLength()),
                $publicKey,
                OPENSSL_ALGO_SHA256
            )
        );
    }

    /**
     * @test
     *
     * @covers \Auth0\Lcobucci\JWT\Signer\Ecdsa::doVerify
     * @covers \Auth0\Lcobucci\JWT\Signer\Ecdsa::getKeyType
     * @covers \Auth0\Lcobucci\JWT\Signer\Ecdsa\MultibyteStringConverter
     * @covers \Auth0\Lcobucci\JWT\Signer\OpenSSL
     * @covers \Auth0\Lcobucci\JWT\Signer\BaseSigner
     *
     * @uses \Auth0\Lcobucci\JWT\Signer\Ecdsa::__construct
     * @uses \Auth0\Lcobucci\JWT\Signer\Key
     */
    public function doVerifyShouldDelegateToEcdsaSignerUsingPublicKey()
    {
        $payload    = 'testing';
        $privateKey = openssl_pkey_get_private(self::$ecdsaKeys['private']->getContent());

        self::assertInternalType('resource', $privateKey);

        $signature = '';
        openssl_sign($payload, $signature, $privateKey, OPENSSL_ALGO_SHA256);

        $signer = $this->getSigner();

        self::assertTrue(
            $signer->verify(
                $this->pointsManipulator->fromAsn1($signature, $signer->getKeyLength()),
                $payload,
                self::$ecdsaKeys['public1']
            )
        );
    }
}
