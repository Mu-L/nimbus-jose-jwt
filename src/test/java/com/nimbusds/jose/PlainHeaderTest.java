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
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.nimbusds.jwt.JWTClaimNames;
import junit.framework.TestCase;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;


/**
 * Tests plain header parsing and serialisation.
 *
 * @author Vladimir Dzhuvinov
 * @version 2019-10-04
 */
public class PlainHeaderTest extends TestCase {


	public void testMinimalConstructor()
		throws Exception {

		PlainHeader h = new PlainHeader();

		assertEquals(Algorithm.NONE, h.getAlgorithm());
		assertNull(h.getType());
		assertNull(h.getContentType());
		assertNull(h.getCriticalParams());
		assertNull(h.getParsedBase64URL());

		Base64URL b64url = h.toBase64URL();

		// Parse back
		h = PlainHeader.parse(b64url);

		assertEquals(Algorithm.NONE, h.getAlgorithm());
		assertNull(h.getType());
		assertNull(h.getContentType());
		assertNull(h.getCriticalParams());
		assertEquals(b64url, h.getParsedBase64URL());
		assertEquals(b64url, h.toBase64URL());
	}


	public void testFullAndCopyConstructors()
		throws Exception {

		Set<String> crit = new HashSet<>();
		crit.add(JWTClaimNames.ISSUED_AT);
		crit.add(JWTClaimNames.EXPIRATION_TIME);
		crit.add(JWTClaimNames.NOT_BEFORE);

		Map<String,Object> customParams = new HashMap<>();
		customParams.put("xCustom", "abc");

		PlainHeader h = new PlainHeader(
			new JOSEObjectType("JWT"),
			"application/jwt",
			crit,
			customParams,
			null);

		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.ALGORITHM));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.TYPE));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.CONTENT_TYPE));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.CRITICAL));
		assertTrue(h.getIncludedParams().contains("xCustom"));
		assertEquals(5, h.getIncludedParams().size());

		assertEquals(Algorithm.NONE, h.getAlgorithm());
		assertEquals(new JOSEObjectType("JWT"), h.getType());
		assertEquals("application/jwt", h.getContentType());
		assertEquals(3, h.getCriticalParams().size());
		assertEquals("abc", (String)h.getCustomParam("xCustom"));
		assertEquals(1, h.getCustomParams().size());
		assertNull(h.getParsedBase64URL());

		Base64URL b64url = h.toBase64URL();

		// Parse back
		h = PlainHeader.parse(b64url);

		assertEquals(b64url, h.toBase64URL());

		assertEquals(Algorithm.NONE, h.getAlgorithm());
		assertEquals(new JOSEObjectType("JWT"), h.getType());
		assertEquals("application/jwt", h.getContentType());
		assertEquals(3, h.getCriticalParams().size());
		assertEquals("abc", (String)h.getCustomParam("xCustom"));
		assertEquals(1, h.getCustomParams().size());
		assertEquals(b64url, h.getParsedBase64URL());

		// Copy
		h = new PlainHeader(h);

		assertEquals(Algorithm.NONE, h.getAlgorithm());
		assertEquals(new JOSEObjectType("JWT"), h.getType());
		assertEquals("application/jwt", h.getContentType());
		assertEquals(3, h.getCriticalParams().size());
		assertEquals("abc", (String)h.getCustomParam("xCustom"));
		assertEquals(1, h.getCustomParams().size());
		assertEquals(b64url, h.getParsedBase64URL());
	}


	public void testBuilder()
		throws Exception {

		Set<String> crit = new HashSet<>();
		crit.add(JWTClaimNames.ISSUED_AT);
		crit.add(JWTClaimNames.EXPIRATION_TIME);
		crit.add(JWTClaimNames.NOT_BEFORE);

		PlainHeader h = new PlainHeader.Builder().
			type(new JOSEObjectType("JWT")).
			contentType("application/jwt").
			criticalParams(crit).
			customParam("xCustom", "abc").
			build();

		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.ALGORITHM));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.TYPE));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.CONTENT_TYPE));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.CRITICAL));
		assertTrue(h.getIncludedParams().contains("xCustom"));
		assertEquals(5, h.getIncludedParams().size());

		Base64URL b64url = h.toBase64URL();

		// Parse back
		h = PlainHeader.parse(b64url);

		assertEquals(b64url, h.toBase64URL());

		assertEquals(Algorithm.NONE, h.getAlgorithm());
		assertEquals(new JOSEObjectType("JWT"), h.getType());
		assertEquals("application/jwt", h.getContentType());
		assertEquals(3, h.getCriticalParams().size());
		assertEquals("abc", (String)h.getCustomParam("xCustom"));
		assertEquals(1, h.getCustomParams().size());
	}


	public void testParseExample()
		throws Exception {

		// Example BASE64URL from JWT spec
		Base64URL in = new Base64URL("eyJhbGciOiJub25lIn0");

		PlainHeader header = PlainHeader.parse(in);

		assertEquals(in, header.toBase64URL());

		assertEquals(Algorithm.NONE, header.getAlgorithm());
	}


	public void testBuilderWithCustomParams() {

		Map<String,Object> customParams = new HashMap<>();
		customParams.put("x", "1");
		customParams.put("y", "2");

		PlainHeader h = new PlainHeader.Builder().
			customParams(customParams).
			build();

		assertEquals("1", (String)h.getCustomParam("x"));
		assertEquals("2", (String)h.getCustomParam("y"));
		assertEquals(2, h.getCustomParams().size());
	}
	
	
	// iss #333
	public void testParseHeaderWithNullTyp()
		throws ParseException {
		
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put(HeaderParameterNames.ALGORITHM, Algorithm.NONE.getName());
		jsonObject.put(HeaderParameterNames.TYPE, null);
		assertEquals(2, jsonObject.size());
		
		Header header = PlainHeader.parse(JSONObjectUtils.toJSONString(jsonObject));
		assertNull(header.getType());
	}
	
	
	// iss #334
	public void testParseHeaderWithNullCrit()
		throws ParseException {
		
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put(HeaderParameterNames.ALGORITHM, Algorithm.NONE.getName());
		jsonObject.put(HeaderParameterNames.CRITICAL, null);
		assertEquals(2, jsonObject.size());
		
		Header header = PlainHeader.parse(JSONObjectUtils.toJSONString(jsonObject));
		assertNull(header.getCriticalParams());
	}
}

