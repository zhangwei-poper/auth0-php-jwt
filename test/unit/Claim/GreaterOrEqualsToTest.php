<?php
/**
 * This file is part of Auth0\Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Auth0\Lcobucci\JWT\Claim;

use Auth0\Lcobucci\JWT\ValidationData;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.0.0
 */
class GreaterOrEqualsToTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @test
     *
     * @uses Auth0\Lcobucci\JWT\Claim\Basic::__construct
     * @uses Auth0\Lcobucci\JWT\Claim\Basic::getName
     * @uses Auth0\Lcobucci\JWT\ValidationData::__construct
     * @uses Auth0\Lcobucci\JWT\ValidationData::has
     * @uses Auth0\Lcobucci\JWT\ValidationData::setCurrentTime
     *
     * @covers Auth0\Lcobucci\JWT\Claim\GreaterOrEqualsTo::validate
     */
    public function validateShouldReturnTrueWhenValidationDontHaveTheClaim()
    {
        $claim = new GreaterOrEqualsTo('iss', 10);

        $this->assertTrue($claim->validate(new ValidationData()));
    }

    /**
     * @test
     *
     * @uses Auth0\Lcobucci\JWT\Claim\Basic::__construct
     * @uses Auth0\Lcobucci\JWT\Claim\Basic::getName
     * @uses Auth0\Lcobucci\JWT\Claim\Basic::getValue
     * @uses Auth0\Lcobucci\JWT\ValidationData::__construct
     * @uses Auth0\Lcobucci\JWT\ValidationData::setIssuer
     * @uses Auth0\Lcobucci\JWT\ValidationData::has
     * @uses Auth0\Lcobucci\JWT\ValidationData::get
     * @uses Auth0\Lcobucci\JWT\ValidationData::setCurrentTime
     *
     * @covers Auth0\Lcobucci\JWT\Claim\GreaterOrEqualsTo::validate
     */
    public function validateShouldReturnTrueWhenValueIsGreaterThanValidationData()
    {
        $claim = new GreaterOrEqualsTo('iss', 11);

        $data = new ValidationData();
        $data->setIssuer(10);

        $this->assertTrue($claim->validate($data));
    }

    /**
     * @test
     *
     * @uses Auth0\Lcobucci\JWT\Claim\Basic::__construct
     * @uses Auth0\Lcobucci\JWT\Claim\Basic::getName
     * @uses Auth0\Lcobucci\JWT\Claim\Basic::getValue
     * @uses Auth0\Lcobucci\JWT\ValidationData::__construct
     * @uses Auth0\Lcobucci\JWT\ValidationData::setIssuer
     * @uses Auth0\Lcobucci\JWT\ValidationData::has
     * @uses Auth0\Lcobucci\JWT\ValidationData::get
     * @uses Auth0\Lcobucci\JWT\ValidationData::setCurrentTime
     *
     * @covers Auth0\Lcobucci\JWT\Claim\GreaterOrEqualsTo::validate
     */
    public function validateShouldReturnTrueWhenValueIsEqualsToValidationData()
    {
        $claim = new GreaterOrEqualsTo('iss', 10);

        $data = new ValidationData();
        $data->setIssuer(10);

        $this->assertTrue($claim->validate($data));
    }

    /**
     * @test
     *
     * @uses Auth0\Lcobucci\JWT\Claim\Basic::__construct
     * @uses Auth0\Lcobucci\JWT\Claim\Basic::getName
     * @uses Auth0\Lcobucci\JWT\Claim\Basic::getValue
     * @uses Auth0\Lcobucci\JWT\ValidationData::__construct
     * @uses Auth0\Lcobucci\JWT\ValidationData::setIssuer
     * @uses Auth0\Lcobucci\JWT\ValidationData::has
     * @uses Auth0\Lcobucci\JWT\ValidationData::get
     * @uses Auth0\Lcobucci\JWT\ValidationData::setCurrentTime
     *
     * @covers Auth0\Lcobucci\JWT\Claim\GreaterOrEqualsTo::validate
     */
    public function validateShouldReturnFalseWhenValueIsLesserThanValidationData()
    {
        $claim = new GreaterOrEqualsTo('iss', 10);

        $data = new ValidationData();
        $data->setIssuer(11);

        $this->assertFalse($claim->validate($data));
    }
}
