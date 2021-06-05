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
import net.minidev.json.JSONObject;

import com.nimbusds.jose.util.Base64URL;


/**
 * Tests the base JOSE header class.
 *
 * @author Vladimir Dzhuvinov
 * @version 2021-06-05
 */
public class HeaderTest extends TestCase {
	
	
	public void testMaxHeaderSizeConstant() {
		
		assertEquals(10_000, Header.MAX_HEADER_STRING_LENGTH);
	}


	public void testParsePlainHeaderFromBase64URL()
		throws Exception {

		// Example BASE64URL from JWT spec
		Base64URL in = new Base64URL("eyJhbGciOiJub25lIn0");

		Header header = Header.parse(in);

		assertTrue(header instanceof PlainHeader);
		assertEquals(in, header.toBase64URL());
		assertEquals(Algorithm.NONE, header.getAlgorithm());
	}


	public void testParseJWSHeaderFromBase64URL()
		throws Exception {

		// Example BASE64URL from JWS spec
		Base64URL in = new Base64URL("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9");

		Header header = Header.parse(in);

		assertTrue(header instanceof JWSHeader);
		assertEquals(in, header.toBase64URL());
		assertEquals(JWSAlgorithm.HS256, header.getAlgorithm());
	}


	public void testParseJWEHeaderFromBase64URL()
		throws Exception {

		// Example BASE64URL from JWE spec
		Base64URL in = new Base64URL("eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0");

		Header header = Header.parse(in);

		assertTrue(header instanceof JWEHeader);
		assertEquals(in, header.toBase64URL());
		assertEquals(JWEAlgorithm.RSA1_5, header.getAlgorithm());

		JWEHeader jweHeader = (JWEHeader)header;
		assertEquals(EncryptionMethod.A128CBC_HS256, jweHeader.getEncryptionMethod());
	}
	
	
	public void testParseAlgorithm_nullAlg() {
		
		try {
			Header.parseAlgorithm(new JSONObject());
			fail();
		} catch (ParseException e) {
			assertEquals("Missing \"alg\" in header JSON object", e.getMessage());
		}
	}
	
	
	public void testParseHeader_nullAlg() {
		
		try {
			Header.parse(new JSONObject());
			fail();
		} catch (ParseException e) {
			assertEquals("Missing \"alg\" in header JSON object", e.getMessage());
		}
	}
	
	
	public void testHeaderSizeLimitExceeded() {
		
		StringBuilder s = new StringBuilder();
		for (int i = 0; i < Header.MAX_HEADER_STRING_LENGTH; i++) {
			s.append("a");
		}
		
		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
			.customParam("data", s.toString())
			.build();
		
		try {
			Header.parse(header.toBase64URL().toString());
			fail();
		} catch (ParseException e) {
			assertEquals(
				"The parsed string is longer than the max accepted size of " +
				Header.MAX_HEADER_STRING_LENGTH +
				" characters",
				e.getMessage()
			);
		}
	}
}
