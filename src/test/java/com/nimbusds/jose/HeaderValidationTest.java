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


import junit.framework.TestCase;


public class HeaderValidationTest extends TestCase {
	
	
	public void testEnsureDisjointJWS_null_null()
		throws IllegalHeaderException {
		
		HeaderValidation.ensureDisjoint(null, null);
	}
	
	
	public void testEnsureDisjointJWS_protected_null()
		throws IllegalHeaderException {
		
		JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.HS256);
		
		HeaderValidation.ensureDisjoint(jwsHeader, null);
	}
	
	
	public void testEnsureDisjointJWS_null_unprotected()
		throws IllegalHeaderException {
		
		UnprotectedHeader unprotectedHeader = new UnprotectedHeader.Builder()
			.keyID("123")
			.build();
		
		HeaderValidation.ensureDisjoint(null, unprotectedHeader);
	}
	
	
	public void testEnsureDisjointJWS_protected_unprotected_disjoint()
		throws IllegalHeaderException {
		
		JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.HS256);
		
		UnprotectedHeader unprotectedHeader = new UnprotectedHeader.Builder()
			.keyID("123")
			.build();
		
		HeaderValidation.ensureDisjoint(jwsHeader, unprotectedHeader);
	}
	
	
	public void testEnsureDisjointJWS_protected_unprotected_notDisjoint() {
		
		JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256)
			.keyID("123")
			.build();
		
		UnprotectedHeader unprotectedHeader = new UnprotectedHeader.Builder()
			.keyID("456")
			.build();
		
		try {
			HeaderValidation.ensureDisjoint(jwsHeader, unprotectedHeader);
			fail();
		} catch (IllegalHeaderException e) {
			assertEquals("The parameters in the JWS protected header and the unprotected header must be disjoint", e.getMessage());
		}
	}
}
