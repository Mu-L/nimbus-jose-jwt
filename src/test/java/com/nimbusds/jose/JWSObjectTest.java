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

package com.nimbusds.jose;


import java.text.ParseException;

import junit.framework.TestCase;

import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.util.Base64URL;


/**
 * Tests JWS object methods.
 *
 * @author Vladimir Dzhuvinov
 * @version 2021-06-26
 */
public class JWSObjectTest extends TestCase {


	public void testBase64URLConstructor()
		throws Exception {

		JWSHeader header = new JWSHeader(JWSAlgorithm.RS256);

		Base64URL firstPart = header.toBase64URL();
		Base64URL secondPart = new Base64URL("abc");
		Base64URL thirdPart = new Base64URL("def");

		JWSObject jws = new JWSObject(firstPart, secondPart, thirdPart);

		assertEquals(firstPart, jws.getHeader().toBase64URL());
		assertEquals(secondPart, jws.getPayload().toBase64URL());
		assertEquals(thirdPart, jws.getSignature());

		assertEquals(firstPart.toString() + ".abc.def", jws.serialize());
		assertEquals(firstPart.toString() + ".abc.def", jws.getParsedString());

		assertEquals(JWSObject.State.SIGNED, jws.getState());
	}


	public void testSignAndSerialize()
		throws Exception {

		JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);

		JWSObject jwsObject = new JWSObject(header, new Payload("Hello world!"));

		Base64URL signingInput = Base64URL.encode(jwsObject.getSigningInput());

		assertTrue(signingInput.equals(Base64URL.encode(jwsObject.getSigningInput())));

		jwsObject.sign(new MACSigner("12345678901234567890123456789012"));

		String output = jwsObject.serialize();

		assertEquals(output, jwsObject.serialize());
	}
	
	
	public void testHeaderLengthJustBelowLimit() throws JOSEException, ParseException {
		
		StringBuilder s = new StringBuilder();
		for (int i = 0; i < Header.MAX_HEADER_STRING_LENGTH - 30; i++) {
			s.append("a");
		}
		
		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
			.customParam("data", s.toString())
			.build();
		
		assertTrue(header.toBase64URL().decodeToString().length() < Header.MAX_HEADER_STRING_LENGTH);
		
		JWSObject jwsObject = new JWSObject(header, new Payload("example"));
		OctetSequenceKey jwk = new OctetSequenceKeyGenerator(256).generate();
		jwsObject.sign(new MACSigner(jwk));
		
		String jws = jwsObject.serialize();
		
		jwsObject = JWSObject.parse(jws);
		assertTrue(jwsObject.verify(new MACVerifier(jwk)));
	}
	
	
	public void testHeaderLengthLimitExceeded() throws JOSEException {
		
		StringBuilder s = new StringBuilder();
		for (int i = 0; i < Header.MAX_HEADER_STRING_LENGTH; i++) {
			s.append("a");
		}
		
		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
			.customParam("data", s.toString())
			.build();
		
		assertTrue(header.toString().length() > Header.MAX_HEADER_STRING_LENGTH);
		
		JWSObject jwsObject = new JWSObject(header, new Payload("example"));
		jwsObject.sign(new MACSigner(new OctetSequenceKeyGenerator(256).generate()));
		
		String jws = jwsObject.serialize();
		
		try {
			JWSObject.parse(jws);
			fail();
		} catch (ParseException e) {
			assertEquals(
			"Invalid JWS header: The parsed string is longer than the max accepted size of " +
				Header.MAX_HEADER_STRING_LENGTH +
				" characters",
				e.getMessage()
			);
		}
	}
	
	
	public void testParseNestedJSONObjectInHeader() {
		
		int recursions = 8000;
		
		StringBuilder headerBuilder = new StringBuilder();
		
		for (int i = 0; i < recursions; i++) {
			headerBuilder.append("{\"\":");
		}
		
		String header = Base64URL.encode(headerBuilder.toString()).toString();
		String payload = Base64URL.encode("123").toString();
		String invalidSig = Base64URL.encode("123").toString();
		
		String token =  header + "." + payload + "." + invalidSig;
		
		try {
			JWSObject.parse(token);
			fail();
		} catch (ParseException e) {
			assertEquals(
				"Invalid JWS header: The parsed string is longer than the max accepted size of " +
					Header.MAX_HEADER_STRING_LENGTH +
					" characters",
				e.getMessage()
			);
		}
	}
	
	
	public void testParseWithExcessiveMixedNestingInHeader() {
	
		StringBuilder sb = new StringBuilder("{\"a\":");
		for (int i = 0; i < 6000; i++) {
			sb.append("[");
		}
		
		String jws = Base64URL.encode(sb.toString()) + ".aaaa.aaaa";
		
		try {
			JWSObject.parse(jws);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid JWS header: Excessive JSON object and / or array nesting", e.getMessage());
		}
	}
	
	
	public void testParseWithExcessiveMixedNestingInPayload() throws ParseException {
	
		
		StringBuilder sb = new StringBuilder("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjpb");
		for (int i = 0; i < 1000; i++) {
			sb.append("W1tb");
		}
		sb.append(".aaaa");
		
		JWSObject jwsObject = JWSObject.parse(sb.toString());
		
		Payload payload = jwsObject.getPayload();
		assertNotNull(payload.toString());
		assertNull(payload.toJSONObject());
	}
}