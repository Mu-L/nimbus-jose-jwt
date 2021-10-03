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
 * Life cycle of a JSON Web Signature (JWS) secured object.
 *
 * @author Vladimir Dzhuvinov
 * @version 2021-10-03
 */
public interface JWSLifeCycle {
	
	
	/**
	 * Enumeration of the states of a JSON Web Signature (JWS) secured
	 * object.
	 */
	enum State {
		
		
		/**
		 * The JWS secured object is created but not signed yet.
		 */
		UNSIGNED,
		
		
		/**
		 * The JWS secured object is signed but its signature is not
		 * verified.
		 */
		SIGNED,
		
		
		/**
		 * The JWS secured object is signed and its signature was successfully verified.
		 */
		VERIFIED
	}
	
	
	/**
	 * Returns the state of the JWS secured object.
	 *
	 * @return The state.
	 */
	State getState();
}
