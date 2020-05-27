/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd.
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

package com.nimbusds.jwt.proc;


import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;

import junit.framework.TestCase;

import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;


public class DefaultJWTClaimsVerifierTest extends TestCase {
	
	
	public void testDefaultConstructor() {
		
		DefaultJWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier();
		assertNull(verifier.getAcceptedAudienceValues());
		assertTrue(verifier.getExactMatchClaims().getClaims().isEmpty());
		assertTrue(verifier.getRequiredClaims().isEmpty());
		assertTrue(verifier.getProhibitedClaims().isEmpty());
		assertEquals(60, verifier.getMaxClockSkew());
	}


	public void testValidNoClaims()
		throws BadJOSEException {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().build();
		JWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier();
		verifier.verify(claimsSet);
	}


	public void testNotExpired()
		throws BadJOSEException {

		final Date now = new Date();
		Date tomorrow = new Date(now.getTime() + 24 * 60 * 60 *1000);
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.expirationTime(tomorrow)
			.build();
		JWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier();
		verifier.verify(claimsSet);
	}


	public void testExpired() {

		final Date now = new Date();
		Date yesterday = new Date(now.getTime() - 24 * 60 * 60 *1000);
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.expirationTime(yesterday)
			.build();
		JWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier();

		try {
			verifier.verify(claimsSet);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("Expired JWT", e.getMessage());
		}
	}


	public void testNbfAccepted()
		throws BadJOSEException {

		final Date now = new Date();
		Date yesterday = new Date(now.getTime() - 24 * 60 * 60 *1000);
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.notBeforeTime(yesterday)
			.build();
		JWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier();
		verifier.verify(claimsSet);
	}


	public void testNbfDenied() {

		final Date now = new Date();
		Date tomorrow = new Date(now.getTime() + 24 * 60 * 60 *1000);
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.notBeforeTime(tomorrow)
			.build();
		JWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier();

		try {
			verifier.verify(claimsSet);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("JWT before use time", e.getMessage());
		}
	}


	public void testAllAccepted()
		throws BadJOSEException {

		final Date now = new Date();
		Date yesterday = new Date(now.getTime() - 24 * 60 * 60 *1000);
		Date tomorrow = new Date(now.getTime() + 24 * 60 * 60 *1000);
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.expirationTime(tomorrow)
			.notBeforeTime(yesterday)
			.build();
		JWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier();
		verifier.verify(claimsSet);
	}


	public void testDefaultClockSkewConstant() {

		assertEquals(60, DefaultJWTClaimsVerifier.DEFAULT_MAX_CLOCK_SKEW_SECONDS);
	}


	public void testExpirationWithClockSkew()
		throws BadJOSEException {

		final Date now = new Date();

		final Date thirtySecondsAgo = new Date(now.getTime() - 30*1000L);

		new DefaultJWTClaimsVerifier().verify(new JWTClaimsSet.Builder().expirationTime(thirtySecondsAgo).build());
	}


	public void testNotBeforeWithClockSkew()
		throws BadJOSEException {

		final Date now = new Date();

		final Date thirtySecondsAhead = new Date(now.getTime() + 30*1000L);

		new DefaultJWTClaimsVerifier().verify(new JWTClaimsSet.Builder().notBeforeTime(thirtySecondsAhead).build());
	}


	public void testClockSkew() {

		DefaultJWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier();
		assertEquals(DefaultJWTClaimsVerifier.DEFAULT_MAX_CLOCK_SKEW_SECONDS, verifier.getMaxClockSkew());
		verifier.setMaxClockSkew(120);
		assertEquals(120, verifier.getMaxClockSkew());
	}
	
	
	public void testIssuer() throws BadJWTException {
		
		String iss = "https://c2id.com";
		DefaultJWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier(
			null,
			new JWTClaimsSet.Builder().issuer(iss).build(),
			null);
		
		assertNull(verifier.getAcceptedAudienceValues());
		assertEquals(Collections.singleton("iss"), verifier.getRequiredClaims());
		assertEquals(Collections.singleton("iss"), verifier.getExactMatchClaims().getClaims().keySet());
		assertTrue(verifier.getProhibitedClaims().isEmpty());
		
		verifier.verify(new JWTClaimsSet.Builder().issuer(iss).build(), null);
	}
	
	
	public void testIssuerMissing() {
		
		String iss = "https://c2id.com";
		DefaultJWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier(
			null,
			new JWTClaimsSet.Builder().issuer(iss).build(),
			null);
		
		assertNull(verifier.getAcceptedAudienceValues());
		assertEquals(Collections.singleton("iss"), verifier.getRequiredClaims());
		assertEquals(Collections.singleton("iss"), verifier.getExactMatchClaims().getClaims().keySet());
		assertTrue(verifier.getProhibitedClaims().isEmpty());
		
		try {
			verifier.verify(new JWTClaimsSet.Builder().build(), null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT missing required claims: [iss]", e.getMessage());
		}
	}
	
	
	public void testIssuerRejected() {
		
		String iss = "https://c2id.com";
		DefaultJWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier(
			null,
			new JWTClaimsSet.Builder().issuer(iss).build(),
			null);
		
		assertNull(verifier.getAcceptedAudienceValues());
		assertEquals(Collections.singleton("iss"), verifier.getRequiredClaims());
		assertEquals(Collections.singleton("iss"), verifier.getExactMatchClaims().getClaims().keySet());
		assertTrue(verifier.getProhibitedClaims().isEmpty());
		
		try {
			verifier.verify(new JWTClaimsSet.Builder().issuer("https://example.com").build(), null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT \"iss\" claim has value https://example.com but should be https://c2id.com", e.getMessage());
		}
	}
	
	
	public void testAudienceAcceptSetOrNull() throws BadJWTException {
		
		String aud = "123";
		DefaultJWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier(new HashSet<>(Arrays.asList(aud, null)), null, null, null);
		assertTrue(verifier.getAcceptedAudienceValues().contains(aud));
		assertTrue(verifier.getAcceptedAudienceValues().contains(null));
		assertEquals(2, verifier.getAcceptedAudienceValues().size());
		
		verifier.verify(new JWTClaimsSet.Builder().build(), null);
		verifier.verify(new JWTClaimsSet.Builder().audience(aud).build(), null);
		verifier.verify(new JWTClaimsSet.Builder().audience(Arrays.asList(aud, "456")).build(), null);
		
		try {
			verifier.verify(new JWTClaimsSet.Builder().audience("456").build(), null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT audience rejected: [456]", e.getMessage());
		}
	}
	
	
	public void testAudienceViaExactMatch() throws BadJWTException {
		
		String aud = "123";
		DefaultJWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier(null, new JWTClaimsSet.Builder().audience(aud).build(), null, null);
		assertNull(verifier.getAcceptedAudienceValues());
		
		verifier.verify(new JWTClaimsSet.Builder().audience(aud).build(), null);
		
		try {
			verifier.verify(new JWTClaimsSet.Builder().build(), null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT missing required claims: [aud]", e.getMessage());
		}
		
		try {
			verifier.verify(new JWTClaimsSet.Builder().audience("456").build(), null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT \"aud\" claim has value [456] but should be [123]", e.getMessage());
		}
	}
	
	
	public void testAudienceMissing() {
		
		String aud = "123";
		DefaultJWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier(aud, null, null);
		assertEquals(Collections.singleton(aud), verifier.getAcceptedAudienceValues());
		
		try {
			verifier.verify(new JWTClaimsSet.Builder().build(), null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT missing required audience", e.getMessage());
		}
	}
	
	
	public void testAudienceRejected() {
		
		String aud = "123";
		DefaultJWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier(aud, null, null);
		assertEquals(Collections.singleton(aud), verifier.getAcceptedAudienceValues());
		
		try {
			verifier.verify(new JWTClaimsSet.Builder().audience("456").build(), null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT audience rejected: [456]", e.getMessage());
		}
	}
	
	
	public void testAudienceRejected_multi() {
		
		String aud = "123";
		DefaultJWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier(aud, null, null);
		assertEquals(Collections.singleton(aud), verifier.getAcceptedAudienceValues());
		
		try {
			verifier.verify(new JWTClaimsSet.Builder().audience(Arrays.asList("456", "789")).build(), null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT audience rejected: [456, 789]", e.getMessage());
		}
	}
	
	
	public void testProhibitedClaims() throws BadJWTException {
		
		DefaultJWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier(null, null, null, Collections.singleton("scope"));
		
		verifier.verify(new JWTClaimsSet.Builder().build(), null);
		verifier.verify(new JWTClaimsSet.Builder().subject("alice").build(), null);
		
		try {
			verifier.verify(new JWTClaimsSet.Builder().claim("scope", "openid").build(), null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT has prohibited claims: [scope]", e.getMessage());
		}
	}
	
	
	public void testRequiresIAT() throws BadJWTException {
		
		DefaultJWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier(null, null, Collections.singleton("iat"));
		
		verifier.verify(new JWTClaimsSet.Builder().issueTime(new Date()).build(), null);
		
		try {
			verifier.verify(new JWTClaimsSet.Builder().build(), null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT missing required claims: [iat]", e.getMessage());
		}
	}
	
	
	public void testRequiresEXP() throws BadJWTException {
		
		DefaultJWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier(null, null, Collections.singleton("exp"));
		
		verifier.verify(new JWTClaimsSet.Builder().expirationTime(new Date()).build(), null);
		
		try {
			verifier.verify(new JWTClaimsSet.Builder().build(), null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT missing required claims: [exp]", e.getMessage());
		}
	}
	
	
	public void testRequiresNBF() throws BadJWTException {
		
		DefaultJWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier(null, null, Collections.singleton("nbf"));
		
		verifier.verify(new JWTClaimsSet.Builder().notBeforeTime(new Date()).build(), null);
		
		try {
			verifier.verify(new JWTClaimsSet.Builder().build(), null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT missing required claims: [nbf]", e.getMessage());
		}
	}
}
