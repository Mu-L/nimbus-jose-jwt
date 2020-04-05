/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.nimbusds.jose.produce;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSProvider;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.JWK;


/**
 * JSON Web Signature (JWS) signer factory to create a signer out of a JSON Web
 * Key (JWK).
 *
 * @author Justin Richer
 * @version 2020-03-26
 */
public interface JWSSignerFactory extends JWSProvider {

	/**
	 * Create a JWS signer based on the key.
	 */
	JWSSigner createJWSSigner(final JWK key)
		throws JOSEException;

	/**
	 * Create a JWS signer based on the key and algorithm. Ensures
	 * that the key supports the given algorithm.
	 */
	JWSSigner createJWSSigner(final JWK key, final JWSAlgorithm alg)
		throws JOSEException;
}
