<?php
/**
 * This file is part of Auth0\Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Auth0\Lcobucci\JWT;

use JsonSerializable;

/**
 * Basic interface for token claims
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.0.0
 */
interface Claim extends JsonSerializable
{
    /**
     * Returns the claim name
     *
     * @return string
     */
    public function getName();

    /**
     * Returns the claim value
     *
     * @return mixed
     */
    public function getValue();

    /**
     * Returns the string representation of the claim
     *
     * @return string
     */
    public function __toString();
}
