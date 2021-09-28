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


import java.util.*;

import junit.framework.TestCase;

import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimNames;
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
		JWTClaimsSetVerifier verifier = new DefaultJWTClaimsVerifier();
		verifier.verify(claimsSet, null);
	}


	public void testNotExpired()
		throws BadJOSEException {

		final Date now = new Date();
		Date tomorrow = new Date(now.getTime() + 24 * 60 * 60 *1000);
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.expirationTime(tomorrow)
			.build();
		JWTClaimsSetVerifier verifier = new DefaultJWTClaimsVerifier();
		verifier.verify(claimsSet, null);
	}


	public void testExpired() {

		final Date now = new Date();
		Date yesterday = new Date(now.getTime() - 24 * 60 * 60 *1000);
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.expirationTime(yesterday)
			.build();
		JWTClaimsSetVerifier verifier = new DefaultJWTClaimsVerifier();

		try {
			verifier.verify(claimsSet, null);
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
		JWTClaimsSetVerifier verifier = new DefaultJWTClaimsVerifier();
		verifier.verify(claimsSet, null);
	}


	public void testNbfDenied() {

		final Date now = new Date();
		Date tomorrow = new Date(now.getTime() + 24 * 60 * 60 *1000);
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.notBeforeTime(tomorrow)
			.build();
		JWTClaimsSetVerifier verifier = new DefaultJWTClaimsVerifier();

		try {
			verifier.verify(claimsSet, null);
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
		JWTClaimsSetVerifier verifier = new DefaultJWTClaimsVerifier();
		verifier.verify(claimsSet, null);
	}


	public void testDefaultClockSkewConstant() {

		assertEquals(60, DefaultJWTClaimsVerifier.DEFAULT_MAX_CLOCK_SKEW_SECONDS);
	}


	public void testExpirationWithClockSkew()
		throws BadJOSEException {

		final Date now = new Date();

		final Date thirtySecondsAgo = new Date(now.getTime() - 30*1000L);

		new DefaultJWTClaimsVerifier().verify(new JWTClaimsSet.Builder().expirationTime(thirtySecondsAgo).build(), null);
	}


	public void testNotBeforeWithClockSkew()
		throws BadJOSEException {

		final Date now = new Date();

		final Date thirtySecondsAhead = new Date(now.getTime() + 30*1000L);

		new DefaultJWTClaimsVerifier().verify(new JWTClaimsSet.Builder().notBeforeTime(thirtySecondsAhead).build(), null);
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
		assertEquals(Collections.singleton(JWTClaimNames.ISSUER), verifier.getRequiredClaims());
		assertEquals(Collections.singleton(JWTClaimNames.ISSUER), verifier.getExactMatchClaims().getClaims().keySet());
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
		assertEquals(Collections.singleton(JWTClaimNames.ISSUER), verifier.getRequiredClaims());
		assertEquals(Collections.singleton(JWTClaimNames.ISSUER), verifier.getExactMatchClaims().getClaims().keySet());
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
		assertEquals(Collections.singleton(JWTClaimNames.ISSUER), verifier.getRequiredClaims());
		assertEquals(Collections.singleton(JWTClaimNames.ISSUER), verifier.getExactMatchClaims().getClaims().keySet());
		assertTrue(verifier.getProhibitedClaims().isEmpty());

		try {
			verifier.verify(new JWTClaimsSet.Builder().issuer("https://example.com").build(), null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT iss claim has value https://example.com, must be https://c2id.com", e.getMessage());
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
			assertEquals("JWT aud claim has value [456], must be [123]", e.getMessage());
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


	public void testNamesOfProhibitedClaimsMustBeSorted() {

		Set<String> prohibitedClaims = new HashSet<>(Arrays.asList(
				JWTClaimNames.ISSUER,
				JWTClaimNames.AUDIENCE,
				JWTClaimNames.ISSUED_AT,
				JWTClaimNames.EXPIRATION_TIME,
				JWTClaimNames.JWT_ID));
		
		DefaultJWTClaimsVerifier<?> verifier = new DefaultJWTClaimsVerifier<>(
			null,
			null,
			null,
			prohibitedClaims);

		try {
			verifier.verify(
				new JWTClaimsSet.Builder()
					.issuer("https://issuer.example.com")
					.audience("https://audience.example.com")
					.issueTime(new Date())
					.expirationTime(new Date(new Date().getTime() + 3_600_1000L))
					.jwtID("3cb541d5-51d6-462f-9038-a37185cbf041")
					.build(),
				null);
			fail();
		} catch (BadJWTException e) {
			// Prohibited claim names must be sorted
			assertEquals("JWT has prohibited claims: " + new TreeSet<>(prohibitedClaims), e.getMessage());
		}
	}


	public void testRequiresIAT() throws BadJWTException {

		DefaultJWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier(null, null, Collections.singleton(JWTClaimNames.ISSUED_AT));

		verifier.verify(new JWTClaimsSet.Builder().issueTime(new Date()).build(), null);

		try {
			verifier.verify(new JWTClaimsSet.Builder().build(), null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT missing required claims: [iat]", e.getMessage());
		}
	}


	public void testRequiresEXP() throws BadJWTException {

		DefaultJWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier(null, null, Collections.singleton(JWTClaimNames.EXPIRATION_TIME));

		verifier.verify(new JWTClaimsSet.Builder().expirationTime(new Date()).build(), null);

		try {
			verifier.verify(new JWTClaimsSet.Builder().build(), null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT missing required claims: [exp]", e.getMessage());
		}
	}


	public void testRequiresEXP_illegalValue() throws BadJWTException {

		DefaultJWTClaimsVerifier verifier = new DefaultJWTClaimsVerifier(null, null, Collections.singleton(JWTClaimNames.EXPIRATION_TIME));

		verifier.verify(new JWTClaimsSet.Builder().claim(JWTClaimNames.EXPIRATION_TIME, "illegal-value").build(), null);

		try {
			verifier.verify(new JWTClaimsSet.Builder().build(), null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT missing required claims: [exp]", e.getMessage());
		}
	}


	public void testRequiresMultiple() throws BadJWTException {

		DefaultJWTClaimsVerifier<?> verifier = new DefaultJWTClaimsVerifier<>(
			new JWTClaimsSet.Builder()
				.issuer("https://example.com")
				.build(),
			new HashSet<>(Arrays.asList(JWTClaimNames.ISSUER, JWTClaimNames.ISSUED_AT, JWTClaimNames.JWT_ID)));

		assertEquals(new HashSet<>(Arrays.asList(JWTClaimNames.ISSUER, JWTClaimNames.ISSUED_AT, JWTClaimNames.JWT_ID)), verifier.getRequiredClaims());

		verifier.verify(
			new JWTClaimsSet.Builder()
				.issuer("https://example.com")
				.issueTime(new Date())
				.jwtID("34f8774a-1ede-45be-9b68-595f91a0ab35")
				.build(),
			null);

		try {
			verifier.verify(new JWTClaimsSet.Builder().build(), null);
			fail();
		} catch (BadJWTException e) {
			// Missing claim names must be sorted
			SortedSet<String> missingClaims = new TreeSet<>(Arrays.asList("iss", "iat", "jti"));
			assertEquals("JWT missing required claims: " + missingClaims, e.getMessage());
		}
	}


	// https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/444
	public void testNamesOfMissingRequiredClaimsMustBeSorted() {
		
		Set<String> requiredClaims = new HashSet<>(Arrays.asList(
			JWTClaimNames.ISSUER,
			JWTClaimNames.AUDIENCE,
			JWTClaimNames.ISSUED_AT,
			JWTClaimNames.EXPIRATION_TIME,
			JWTClaimNames.JWT_ID));
		
		DefaultJWTClaimsVerifier<?> verifier = new DefaultJWTClaimsVerifier<>(
			new JWTClaimsSet.Builder()
				.issuer("https://example.com")
				.build(),
			requiredClaims);

		assertEquals(requiredClaims, verifier.getRequiredClaims());

		try {
			verifier.verify(new JWTClaimsSet.Builder().build(), null);
			fail();
		} catch (BadJWTException e) {
			// Missing claim names must be sorted
			SortedSet<String> missingClaims = new TreeSet<>(requiredClaims);
			assertEquals("JWT missing required claims: " + missingClaims, e.getMessage());
		}
	}


	public void testJavaDocExample() throws BadJWTException {

		DefaultJWTClaimsVerifier<?> verifier = new DefaultJWTClaimsVerifier<>(
			new JWTClaimsSet.Builder()
				.issuer("https://issuer.example.com")
				.audience("https://client.example.com")
				.build(),
			new HashSet<>(Arrays.asList(JWTClaimNames.EXPIRATION_TIME, JWTClaimNames.NOT_BEFORE, JWTClaimNames.JWT_ID)));

		assertEquals(new HashSet<>(Arrays.asList(JWTClaimNames.ISSUER, JWTClaimNames.AUDIENCE, JWTClaimNames.EXPIRATION_TIME, JWTClaimNames.NOT_BEFORE, JWTClaimNames.JWT_ID)), verifier.getRequiredClaims());

		Date now = new Date();
		Date exp = new Date(now.getTime() + 60_000);
		
		verifier.verify(
			new JWTClaimsSet.Builder()
				.issuer("https://issuer.example.com")
				.audience("https://client.example.com")
				.notBeforeTime(now)
				.expirationTime(exp)
				.jwtID("34f8774a-1ede-45be-9b68-595f91a0ab35")
				.build(),
			null);
	}
	
	
	public void testCurrentDate() {
		
		final Date now = new Date();
		final Date oneSecondAgo = new Date(now.getTime() - 60 * 1000);
		final Date oneSecondAhead = new Date(now.getTime() + 60 * 1000);
		
		final Date currentTime = new DefaultJWTClaimsVerifier<>(
			new JWTClaimsSet.Builder().build(),
			Collections.singleton("exp")
		).currentTime();
		
		assertTrue(currentTime.after(oneSecondAgo));
		assertTrue(currentTime.before(oneSecondAhead));
	}

	
	public void testCurrentDateOverride() throws BadJWTException {

		final Date t = new Date(60_000);
		final Date t_plus2Minutes = new Date(t.getTime() + 2 * 60 * 1000);
		final Date t_minus2Minutes = new Date(t.getTime() - 2 * 60 * 1000);
		
		JWTClaimsSetVerifier overriddenVerifier = new DefaultJWTClaimsVerifier(new JWTClaimsSet.Builder().build(), Collections.singleton("exp")) {
			@Override
			protected Date currentTime() {
				return t;
			}
		};
		
		// Pass
		overriddenVerifier.verify(
			new JWTClaimsSet.Builder()
				.expirationTime(t_plus2Minutes)
				.build(),
			null
		);
		
		// Expired
		try {
			overriddenVerifier.verify(
				new JWTClaimsSet.Builder()
					.expirationTime(t_minus2Minutes)
					.build(),
				null
			);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Expired JWT", e.getMessage());
		}
	}

	
	public void testCurrentDateOverrideReturnsNull_disablesExpCheck() throws BadJWTException {

		final Date now = new Date();
		Date yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.expirationTime(yesterday)
			.build();
		
		// Return null to disable exp check
		JWTClaimsSetVerifier overriddenVerifier = new DefaultJWTClaimsVerifier() {
			@Override
			protected Date currentTime() {
				return null;
			}
		};
		overriddenVerifier.verify(claimsSet, null);
		
		// Std behaviour is expired JWT
		try {
			new DefaultJWTClaimsVerifier<>().verify(claimsSet, null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Expired JWT", e.getMessage());
		}
	}

	
	public void testCurrentDateOverrideReturnsNull_disablesNbfCheck() throws BadJWTException {

		final Date now = new Date();
		Date tomorrow = new Date(now.getTime() + 24 * 60 * 60 * 1000);
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.notBeforeTime(tomorrow)
			.build();
		
		// Return null to disable nbf check
		JWTClaimsSetVerifier overriddenVerifier = new DefaultJWTClaimsVerifier(
			new JWTClaimsSet.Builder().build(),
			Collections.singleton("nbf")
		) {
			@Override
			protected Date currentTime() {
				return null;
			}
		};
		overriddenVerifier.verify(claimsSet, null);
		
		// Std behaviour is JWT is before use time
		try {
			new DefaultJWTClaimsVerifier<>().verify(claimsSet, null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT before use time", e.getMessage());
		}
	}
}
