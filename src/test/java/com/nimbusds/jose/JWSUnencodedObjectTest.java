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


import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Collections;

import junit.framework.TestCase;
import org.junit.Assert;

import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.StandardCharset;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;


/**
 * Tests JWS Unencoded Payload Option, https://tools.ietf.org/html/rfc7797
 *
 * @version 2020-04-17
 */
public class JWSUnencodedObjectTest extends TestCase {
	

	// https://tools.ietf.org/html/rfc7797#section-4
	private static final OctetSequenceKey HMAC_JWK;
	
	static {
		try {
			HMAC_JWK = OctetSequenceKey.parse("{"+
				"\"kty\":\"oct\","+
				"\"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\""+
				"}");
		} catch (ParseException e) {
			throw new RuntimeException(e);
		}
	}
	
	
	public void testPayloadAsBase64URL() {
		
		assertEquals("$.02", new Base64URL("JC4wMg").decodeToString());
	}
	
	
	public void testControlJWS()
		throws Exception {
		
		JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS256), new Payload("$.02"));
		jwsObject.sign(new MACSigner(HMAC_JWK));
		String expected = "eyJhbGciOiJIUzI1NiJ9.JC4wMg.5mvfOroL-g7HyqJoozehmsaqmvTYGEq5jTI1gVvoEoQ";
		assertEquals(expected, jwsObject.serialize());
	}
	
	
	public void testLifeCycleWithDetachedPayload() throws JOSEException, ParseException {
		
		Payload detachedPayload = new Payload("$.02");
		
		// Create JWS
		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
			.base64URLEncodePayload(false)
			.criticalParams(Collections.singleton("b64"))
			.build();
		
		JWSObject jwsObject = new JWSObject(header, detachedPayload);
		
		byte[] origSigningInput = jwsObject.getSigningInput();
		Assert.assertArrayEquals((header.toBase64URL() + "." + detachedPayload.toString()).getBytes(StandardCharset.UTF_8), origSigningInput);
		
		jwsObject.sign(new MACSigner(HMAC_JWK));
		
		boolean isDetached = true;
		String s = jwsObject.serialize(isDetached);
		
		// Check serialised parts
		Base64URL[] parts = JOSEObject.split(s);
		
		assertEquals(3, parts.length);
		
		JWSHeader parsedHeader = JWSHeader.parse(parts[0]);
		assertEquals(JWSAlgorithm.HS256, parsedHeader.getAlgorithm());
		assertFalse(parsedHeader.isBase64URLEncodePayload());
		assertEquals(Collections.singleton("b64"), parsedHeader.getCriticalParams());
		
		assertEquals("Payload part empty", "", parts[1].toString());
		
		assertTrue("Signature present", parts[2].toString().length() > 0);
		
		// Parse JWS with detached payload
		JWSObject parsedJWSObject = JWSObject.parse(s, detachedPayload);
		
		assertEquals(parts[0], parsedJWSObject.getParsedParts()[0]);
		assertEquals(parts[1], parsedJWSObject.getParsedParts()[1]);
		assertEquals(parts[2], parsedJWSObject.getParsedParts()[2]);
		
		assertEquals(JWSObject.State.SIGNED, parsedJWSObject.getState());
		
		assertEquals(new String(origSigningInput, StandardCharset.UTF_8), new String(parsedJWSObject.getSigningInput(), StandardCharset.UTF_8));
		
		assertEquals(JWSAlgorithm.HS256, parsedJWSObject.getHeader().getAlgorithm());
		assertFalse(parsedJWSObject.getHeader().isBase64URLEncodePayload());
		assertEquals(Collections.singleton("b64"), parsedJWSObject.getHeader().getCriticalParams());
		
		assertTrue(parsedJWSObject.verify(new MACVerifier(HMAC_JWK)));
		
		assertEquals("$.02", parsedJWSObject.getPayload().toString());
	}
	
	
	public void testJWTWithDetachedClaimsSet()
		throws Exception {
		
		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
			.base64URLEncodePayload(false)
			.build();
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.claim("foo", "bar")
			.build();
		
		//When sign JWT
		SignedJWT signedJWT = new SignedJWT(header, claimsSet);
		JWSSigner signer = new MACSigner(HMAC_JWK);
		signedJWT.sign(signer);
		String serializedJWT = signedJWT.serialize(true);
		
		Payload detachedPayload = signedJWT.getPayload();
		assertEquals("{\"foo\":\"bar\"}", detachedPayload.toString());
		
		JWSObject jwsObject = JWSObject.parse(serializedJWT, detachedPayload);
		
		assertFalse(jwsObject.getHeader().isBase64URLEncodePayload());
		
		JWSVerifier verifier = new MACVerifier(HMAC_JWK);
		byte[] payloadBytes = detachedPayload.toBytes();
		byte[] headerBytes = (header.toBase64URL().toString() + '.').getBytes(StandardCharsets.UTF_8);
		byte[] signingInput = new byte[headerBytes.length + payloadBytes.length];
		System.arraycopy(headerBytes, 0, signingInput, 0, headerBytes.length);
		System.arraycopy(payloadBytes, 0, signingInput, headerBytes.length, payloadBytes.length);
		
		assertTrue(verifier.verify(header, signingInput, signedJWT.getSignature()));
		
		assertTrue(jwsObject.verify(verifier));
	}
}
