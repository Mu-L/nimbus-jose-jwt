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

package com.nimbusds.jose.crypto.opts;


import net.jcip.annotations.Immutable;

import com.nimbusds.jose.JWSSignerOption;


/**
 * JSON Web Signature (JWS) option to prompt the user to authenticate in order
 * to complete the signing operation. Android applications can use this option
 * to trigger a biometric prompt that is required to unlock a private key
 * created with {@code setUserAuthenticationRequired(true)}.
 */
@Immutable
public final class UserAuthenticationRequired implements JWSSignerOption {
	
	
	private static final UserAuthenticationRequired SINGLETON = new UserAuthenticationRequired();
	
	
	/**
	 * Returns an instance of this class.
	 *
	 * @return The instance.
	 */
	public static UserAuthenticationRequired getInstance() {
		return SINGLETON;
	}
	
	
	private UserAuthenticationRequired() {
	}
	
	
	@Override
	public String toString() {
		return "UserAuthenticationRequired";
	}
}
