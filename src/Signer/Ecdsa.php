<?php
/**
 * This file is part of Auth0\Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Auth0\Lcobucci\JWT\Signer;

use Auth0\Lcobucci\JWT\Signer\Ecdsa\MultibyteStringConverter;
use Auth0\Lcobucci\JWT\Signer\Ecdsa\SignatureConverter;
use const OPENSSL_KEYTYPE_EC;

/**
 * Base class for ECDSA signers
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.1.0
 */
abstract class Ecdsa extends OpenSSL
{
    /**
     * @var SignatureConverter
     */
    private $converter;

    public function __construct(SignatureConverter $converter = null)
    {
        $this->converter = $converter ?: new MultibyteStringConverter();
    }

    /**
     * {@inheritdoc}
     */
    public function createHash($payload, Key $key)
    {
        return $this->converter->fromAsn1(
            parent::createHash($payload, $key),
            $this->getKeyLength()
        );
    }

    /**
     * {@inheritdoc}
     */
    public function doVerify($expected, $payload, Key $key)
    {
        return parent::doVerify(
            $this->converter->toAsn1($expected, $this->getKeyLength()),
            $payload,
            $key
        );
    }

    /**
     * Returns the length of each point in the signature, so that we can calculate and verify R and S points properly
     *
     * @internal
     */
    abstract public function getKeyLength();

    /**
     * {@inheritdoc}
     */
    final public function getKeyType()
    {
        return OPENSSL_KEYTYPE_EC;
    }
}
