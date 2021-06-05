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
import java.util.Collections;
import java.util.Set;

import junit.framework.TestCase;

import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.jca.JWEJCAContext;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.util.Base64URL;


/**
 * Tests JWE object methods.
 *
 * @author Vladimir Dzhuvinov
 * @version 2021-06-05
 */
public class JWEObjectTest extends TestCase {


	public void testBase64URLConstructor()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.RSA1_5, 
			                         EncryptionMethod.A128CBC_HS256);

		Base64URL firstPart = header.toBase64URL();
		Base64URL secondPart = new Base64URL("abc");
		Base64URL thirdPart = new Base64URL("def");
		Base64URL fourthPart = new Base64URL("ghi");
		Base64URL fifthPart = new Base64URL("jkl");

		JWEObject jwe = new JWEObject(firstPart, secondPart,
				thirdPart, fourthPart, 
				fifthPart);

		assertEquals(firstPart, jwe.getHeader().toBase64URL());
		assertEquals(secondPart, jwe.getEncryptedKey());
		assertEquals(thirdPart, jwe.getIV());
		assertEquals(fourthPart, jwe.getCipherText());

		assertEquals(firstPart + ".abc.def.ghi.jkl", jwe.serialize());
		assertEquals(firstPart + ".abc.def.ghi.jkl", jwe.getParsedString());

		assertEquals(JWEObject.State.ENCRYPTED, jwe.getState());
	}


	public void testRejectUnsupportedJWEAlgorithmOnEncrypt() {

		JWEHeader header = new JWEHeader(JWEAlgorithm.RSA1_5, EncryptionMethod.A128CBC_HS256);
		JWEObject jwe = new JWEObject(header, new Payload("Hello world"));

		try {
			jwe.encrypt(new JWEEncrypter() {
				@Override
				public JWECryptoParts encrypt(JWEHeader header, byte[] clearText) throws JOSEException {
					return null;
				}
				@Override
				public Set<JWEAlgorithm> supportedJWEAlgorithms() {
					return Collections.singleton(new JWEAlgorithm("xyz"));
				}
				@Override
				public Set<EncryptionMethod> supportedEncryptionMethods() {
					return null;
				}
				@Override
				public JWEJCAContext getJCAContext() {
					return null;
				}
			});
		} catch (JOSEException e) {
			assertEquals("The \"RSA1_5\" algorithm is not supported by the JWE encrypter: Supported algorithms: [xyz]", e.getMessage());
		}
	}


	public void testRejectUnsupportedJWEMethodOnEncrypt() {

		JWEHeader header = new JWEHeader(JWEAlgorithm.RSA1_5, EncryptionMethod.A128CBC_HS256);
		JWEObject jwe = new JWEObject(header, new Payload("Hello world"));

		try {
			jwe.encrypt(new JWEEncrypter() {
				@Override
				public JWECryptoParts encrypt(JWEHeader header, byte[] clearText) throws JOSEException {
					return null;
				}
				@Override
				public Set<JWEAlgorithm> supportedJWEAlgorithms() {
					return Collections.singleton(JWEAlgorithm.RSA1_5);
				}
				@Override
				public Set<EncryptionMethod> supportedEncryptionMethods() {
					return Collections.singleton(new EncryptionMethod("xyz"));
				}
				@Override
				public JWEJCAContext getJCAContext() {
					return null;
				}
			});
		} catch (JOSEException e) {
			assertEquals("The \"A128CBC-HS256\" encryption method or key size is not supported by the JWE encrypter: Supported methods: [xyz]", e.getMessage());
		}
	}
	
	
	public void testHeaderLengthJustBelowLimit() throws JOSEException, ParseException {
		
		StringBuilder s = new StringBuilder();
		for (int i = 0; i < Header.MAX_HEADER_STRING_LENGTH - 40; i++) {
			s.append("a");
		}
		
		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128GCM)
			.customParam("data", s.toString())
			.build();
		
		assertTrue(header.toString().length() < Header.MAX_HEADER_STRING_LENGTH);
		
		JWEObject jweObject = new JWEObject(header, new Payload("example"));
		OctetSequenceKey jwk = new OctetSequenceKeyGenerator(128).generate();
		jweObject.encrypt(new DirectEncrypter(jwk));
		
		String jwe = jweObject.serialize();
		
		jweObject = JWEObject.parse(jwe);
		jweObject.decrypt(new DirectDecrypter(jwk));
		assertEquals(new Payload("example").toString(), jweObject.getPayload().toString());
	}
	
	
	public void testHeaderLengthLimit() throws JOSEException {
		
		StringBuilder s = new StringBuilder();
		for (int i = 0; i < Header.MAX_HEADER_STRING_LENGTH; i++) {
			s.append("a");
		}
		
		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128GCM)
			.customParam("data", s.toString())
			.build();
		
		assertTrue(header.toBase64URL().toString().length() > Header.MAX_HEADER_STRING_LENGTH);
		
		JWEObject jweObject = new JWEObject(header, new Payload("example"));
		jweObject.encrypt(new DirectEncrypter(new OctetSequenceKeyGenerator(128).generate()));
		
		String jwe = jweObject.serialize();
		
		try {
			JWEObject.parse(jwe);
			fail();
		} catch (ParseException e) {
			assertEquals(
				"Invalid JWE header: The parsed string is longer than the max accepted size of " +
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
		String encryptedKey = Base64URL.encode("123").toString();
		String iv = Base64URL.encode("123").toString();
		String cipherText = Base64URL.encode("123").toString();
		String authTag = Base64URL.encode("123").toString();
		
		String token =  header + "." + encryptedKey + "." + iv + "." + cipherText + "." + authTag;
		
		try {
			JWEObject.parse(token);
			fail();
		} catch (ParseException e) {
			assertEquals(
				"Invalid JWE header: The parsed string is longer than the max accepted size of " +
					Header.MAX_HEADER_STRING_LENGTH +
					" characters",
				e.getMessage()
			);
		}
	}
}
