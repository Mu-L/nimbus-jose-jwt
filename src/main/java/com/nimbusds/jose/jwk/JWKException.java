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

package com.nimbusds.jose.jwk;

import com.nimbusds.jose.KeyException;


/**
 * JSON Web Key (JWK) related exception.
 *
 * @author jricher
 */
public class JWKException extends KeyException {
	
	
	/**
	 * Creates a new JWK with the specified message.
	 *
	 * @param message The exception message.
	 */
	public JWKException(String message) {
		super(message);
	}

	
	/**
	 * Creates a new JWK type exception.
	 *
	 * @param expectedJWKClass The expected JWK class. Should not be
	 *                         {@code null}.
	 */
	public static JWKException expectedClass(final Class<? extends JWK> expectedJWKClass) {
		return new JWKException("Invalid JWK: Must be an instance of " + expectedJWKClass);
	}


	public static JWKException expectedPrivate() {
		return new JWKException("Expected private JWK but none available");
	}
}
