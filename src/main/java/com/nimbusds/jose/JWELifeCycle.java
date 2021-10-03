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

package com.nimbusds.jose;


/**
 * Life cycle of a JSON Web Encryption (JWE) secured object.
 *
 * @author Vladimir Dzhuvinov
 * @version 2021-10-03
 */
public interface JWELifeCycle {
	
	
	/**
	 * Enumeration of the states of a JSON Web Encryption (JWE) secured
	 * object.
	 */
	enum State {
		
		
		/**
		 * The JWE secured object is created but not encrypted yet.
		 */
		UNENCRYPTED,
		
		
		/**
		 * The JWE secured object is encrypted.
		 */
		ENCRYPTED,
		
		
		/**
		 * The JWE secured object is decrypted.
		 */
		DECRYPTED
	}
	
	
	/**
	 * Returns the state of the JWE secured object.
	 *
	 * @return The state.
	 */
	State getState();
}
