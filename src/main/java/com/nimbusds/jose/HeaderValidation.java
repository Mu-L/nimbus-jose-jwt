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
 * JOSE header validation utility.
 */
class HeaderValidation {
	
	
	/**
	 * Ensures the parameter names in the JWS protected header and the
	 * unprotected header are disjoint.
	 *
	 * <p>See https://datatracker.ietf.org/doc/html/rfc7515#section-7.2.1
	 *
	 * @param jwsHeader         The JWS protected header, {@code null} if
	 *                          not specified.
	 * @param unprotectedHeader The unprotected header, {@code null} if
	 *                          not specified.
	 *
	 * @throws IllegalHeaderException If both headers are specified and not
	 *                                disjoint.
	 */
	static void ensureDisjoint(final JWSHeader jwsHeader, final UnprotectedHeader unprotectedHeader)
		throws IllegalHeaderException {
		
		if (jwsHeader == null || unprotectedHeader == null) {
			return;
		}
		
		for (String unprotectedParamName: unprotectedHeader.getIncludedParams()) {
			if (jwsHeader.getIncludedParams().contains(unprotectedParamName)) {
				throw new IllegalHeaderException("The parameters in the JWS protected header and the unprotected header must be disjoint");
			}
		}
	}
}
