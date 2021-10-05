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


import java.text.ParseException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;

import junit.framework.TestCase;

import com.nimbusds.jose.util.JSONObjectUtils;


public class UnprotectedHeaderTest extends TestCase {
	
	
	public void testLifeCycle()
		throws ParseException {
		
		String kid = "123";
		
		UnprotectedHeader header = new UnprotectedHeader.Builder()
			.keyID(kid)
			.build();
		
		assertEquals(kid, header.getKeyID());
		
		assertEquals(Collections.singleton("kid"), header.getIncludedParams());
		
		Map<String, Object> jsonObject = header.toJSONObject();
		assertEquals(kid, jsonObject.get("kid"));
		assertEquals(1, jsonObject.size());
		
		header = UnprotectedHeader.parse(jsonObject);
		
		assertEquals(kid, header.getKeyID());
		
		jsonObject = header.toJSONObject();
		assertEquals(kid, jsonObject.get("kid"));
		assertEquals(1, jsonObject.size());
	}
	
	
	public void testLifeCycle_withCustomParam_String()
		throws ParseException {
		
		String kid = "123";
		String customParamName = "x_custom";
		String customParamValue = "abc";
		
		UnprotectedHeader header = new UnprotectedHeader.Builder()
			.keyID(kid)
			.param(customParamName, customParamValue)
			.build();
		
		assertEquals(kid, header.getKeyID());
		assertEquals(customParamValue, header.getParam(customParamName));
		
		assertEquals(new HashSet<>(Arrays.asList("kid", customParamName)), header.getIncludedParams());
		
		Map<String, Object> jsonObject = header.toJSONObject();
		assertEquals(kid, jsonObject.get("kid"));
		assertEquals(customParamValue, jsonObject.get(customParamName));
		assertEquals(2, jsonObject.size());
		
		header = UnprotectedHeader.parse(jsonObject);
		
		assertEquals(kid, header.getKeyID());
		assertEquals(customParamValue, header.getParam(customParamName));
		
		jsonObject = header.toJSONObject();
		assertEquals(customParamValue, jsonObject.get(customParamName));
		assertEquals(2, jsonObject.size());
	}
	
	
	public void testLifeCycle_with2CustomParams_String()
		throws ParseException {
		
		String customParam1Name = "x_custom";
		String customParam1Value = "abc";
		String customParam2Name = "y_custom";
		String customParam2Value = "def";
		
		UnprotectedHeader header = new UnprotectedHeader.Builder()
			.param(customParam1Name, customParam1Value)
			.param(customParam2Name, customParam2Value)
			.build();
		
		assertNull(header.getKeyID());
		assertEquals(customParam1Value, header.getParam(customParam1Name));
		assertEquals(customParam2Value, header.getParam(customParam2Name));
		
		assertEquals(new HashSet<>(Arrays.asList(customParam1Name, customParam2Name)), header.getIncludedParams());
		
		Map<String, Object> jsonObject = header.toJSONObject();
		assertEquals(customParam1Value, jsonObject.get(customParam1Name));
		assertEquals(customParam2Value, jsonObject.get(customParam2Name));
		assertEquals(2, jsonObject.size());
		
		header = UnprotectedHeader.parse(jsonObject);
		
		assertNull(header.getKeyID());
		assertEquals(customParam1Value, header.getParam(customParam1Name));
		assertEquals(customParam2Value, header.getParam(customParam2Name));
		
		jsonObject = header.toJSONObject();
		assertEquals(customParam1Value, jsonObject.get(customParam1Name));
		assertEquals(customParam2Value, jsonObject.get(customParam2Name));
		assertEquals(2, jsonObject.size());
	}
	
	
	public void testLifeCycle_empty()
		throws ParseException {
		
		UnprotectedHeader header = new UnprotectedHeader.Builder()
			.build();
		
		assertTrue(header.getIncludedParams().isEmpty());
		
		Map<String, Object> jsonObject = header.toJSONObject();
		
		assertTrue(jsonObject.isEmpty());
		
		header = UnprotectedHeader.parse(jsonObject);
		
		assertTrue(header.getIncludedParams().isEmpty());
	}
	
	
	public void testSetKeyIDViaParamMethod() {
		
		UnprotectedHeader unprotectedHeader = new UnprotectedHeader.Builder()
			.param("kid", "123")
			.build();
		
		assertEquals("123", unprotectedHeader.getParam("kid"));
		assertEquals("123", unprotectedHeader.getKeyID());
		
		assertEquals(Collections.singleton("kid"), unprotectedHeader.getIncludedParams());
	}
	
	
	public void testParse_null()
		throws ParseException {
		
		assertNull(UnprotectedHeader.parse(null));
	}
	
	
	public void testParse_empty()
		throws ParseException {
		
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		
		assertTrue(UnprotectedHeader.parse(jsonObject).getIncludedParams().isEmpty());
	}
}
