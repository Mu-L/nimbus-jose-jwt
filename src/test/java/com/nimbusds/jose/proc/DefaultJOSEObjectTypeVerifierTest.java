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

package com.nimbusds.jose.proc;


import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import junit.framework.TestCase;

import com.nimbusds.jose.JOSEObjectType;


public class DefaultJOSEObjectTypeVerifierTest extends TestCase {
	
	
	public void testStdVerifiers() {
		
		assertEquals(new HashSet<>(Arrays.asList(JOSEObjectType.JOSE, null)), DefaultJOSEObjectTypeVerifier.JOSE.getAllowedTypes());
		assertEquals(new HashSet<>(Arrays.asList(JOSEObjectType.JWT, null)), DefaultJOSEObjectTypeVerifier.JWT.getAllowedTypes());
	}
	
	
	public void testDefaultConstructor_noneAllowed() throws BadJOSEException {
		
		DefaultJOSEObjectTypeVerifier verifier = new DefaultJOSEObjectTypeVerifier();
		
		assertEquals(Collections.singleton(null), verifier.getAllowedTypes());
		assertTrue(verifier.getAllowedTypes().contains(null));
		
		verifier.verify(null, null);
		
		try {
			verifier.verify(new JOSEObjectType("at+jwt"), null);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("JOSE header typ (type) at+jwt not allowed", e.getMessage());
		}
	}
	
	
	public void testSetConstructor_noneAllowed() throws BadJOSEException {
		
		Set<JOSEObjectType> allowedTypes = new HashSet<>();
		allowedTypes.add(null); // none
		
		DefaultJOSEObjectTypeVerifier verifier = new DefaultJOSEObjectTypeVerifier(allowedTypes);
		
		assertEquals(allowedTypes, verifier.getAllowedTypes());
		assertTrue(verifier.getAllowedTypes().contains(null));
		
		verifier.verify(null, null);
		
		try {
			verifier.verify(new JOSEObjectType("at+jwt"), null);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("JOSE header typ (type) at+jwt not allowed", e.getMessage());
		}
	}
	
	
	public void testVarargConstructor_noneAllowed() throws BadJOSEException {
		
		DefaultJOSEObjectTypeVerifier verifier = new DefaultJOSEObjectTypeVerifier((JOSEObjectType)null);
		
		assertEquals(Collections.singleton(null), verifier.getAllowedTypes());
		assertTrue(verifier.getAllowedTypes().contains(null));
		
		verifier.verify(null, null);
		
		try {
			verifier.verify(new JOSEObjectType("at+jwt"), null);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("JOSE header typ (type) at+jwt not allowed", e.getMessage());
		}
	}
	
	
	public void testSetConstructor_noneAndJWTAllowed() throws BadJOSEException {
		
		Set<JOSEObjectType> allowedTypes = new HashSet<>();
		allowedTypes.add(null); // none
		allowedTypes.add(JOSEObjectType.JWT);
		
		DefaultJOSEObjectTypeVerifier verifier = new DefaultJOSEObjectTypeVerifier(allowedTypes);
		
		assertEquals(allowedTypes, verifier.getAllowedTypes());
		assertTrue(verifier.getAllowedTypes().contains(null));
		assertTrue(verifier.getAllowedTypes().contains(JOSEObjectType.JWT));
		
		verifier.verify(null, null);
		verifier.verify(JOSEObjectType.JWT, null);
		
		try {
			verifier.verify(new JOSEObjectType("at+jwt"), null);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("JOSE header typ (type) at+jwt not allowed", e.getMessage());
		}
	}
	
	
	public void testVarargConstructor_noneAndJWTAllowed() throws BadJOSEException {
		
		DefaultJOSEObjectTypeVerifier verifier = new DefaultJOSEObjectTypeVerifier(null, JOSEObjectType.JWT);
		
		assertEquals(new HashSet<>(Arrays.asList(null, JOSEObjectType.JWT)), verifier.getAllowedTypes());
		assertTrue(verifier.getAllowedTypes().contains(null));
		assertTrue(verifier.getAllowedTypes().contains(JOSEObjectType.JWT));
		
		verifier.verify(null, null);
		verifier.verify(JOSEObjectType.JWT, null);
		
		try {
			verifier.verify(new JOSEObjectType("at+jwt"), null);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("JOSE header typ (type) at+jwt not allowed", e.getMessage());
		}
	}
	
	
	public void testVarargConstructor_ATAllowed_caseInsensitive() throws BadJOSEException {
		
		DefaultJOSEObjectTypeVerifier verifier = new DefaultJOSEObjectTypeVerifier(new JOSEObjectType("at+jwt"));
		
		assertEquals(Collections.singleton(new JOSEObjectType("at+jwt")), verifier.getAllowedTypes());
		assertTrue(verifier.getAllowedTypes().contains(new JOSEObjectType("at+jwt")));
		assertTrue(verifier.getAllowedTypes().contains(new JOSEObjectType("AT+JWT")));
		
		verifier.verify(new JOSEObjectType("at+jwt"), null);
		verifier.verify(new JOSEObjectType("AT+JWT"), null);
		
		try {
			verifier.verify(null, null);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("Required JOSE header typ (type) parameter is missing", e.getMessage());
		}
	}
	
	
	public void testIllegalArgumentException_nullSet() {
		
		try {
			new DefaultJOSEObjectTypeVerifier((Set)null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The allowed types must not be null or empty", e.getMessage());
		}
	}
	
	
	public void testIllegalArgumentException_emptySet() {
		
		try {
			new DefaultJOSEObjectTypeVerifier(Collections.<JOSEObjectType>emptySet());
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The allowed types must not be null or empty", e.getMessage());
		}
	}
	
	
	public void testIllegalArgumentException_nullArray() {
		
		try {
			new DefaultJOSEObjectTypeVerifier((JOSEObjectType[])null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The allowed types must not be null or empty", e.getMessage());
		}
	}
	
	
	public void testIllegalArgumentException_emptyArray() {
		
		try {
			new DefaultJOSEObjectTypeVerifier(new JOSEObjectType[]{});
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The allowed types must not be null or empty", e.getMessage());
		}
	}
}
