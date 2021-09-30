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
import java.util.Collections;
import java.util.Map;

import junit.framework.TestCase;

import com.nimbusds.jose.util.JSONObjectUtils;


public class UnprotectedHeaderTest extends TestCase {


	public void testRegisteredParameterNames() {
		
		assertEquals(Collections.singleton("kid"), UnprotectedHeader.getRegisteredParameterNames());
	}
	
	
	public void testLifeCycle()
		throws ParseException {
		
		String kid = "123";
		
		UnprotectedHeader header = new UnprotectedHeader.Builder(kid)
			.build();
		
		assertEquals(kid, header.getKeyID());
		
		Map<String, Object> jsonObject = header.toJSONObject();
		assertEquals(kid, jsonObject.get("kid"));
		assertEquals(1, jsonObject.size());
		
		header = UnprotectedHeader.parse(jsonObject);
		
		assertEquals(kid, header.getKeyID());
		
		jsonObject = header.toJSONObject();
		assertEquals(kid, jsonObject.get("kid"));
		assertEquals(1, jsonObject.size());
	}
	
	
	public void testLifeCycle_withCustomParam()
		throws ParseException {
		
		String kid = "123";
		String customParamName = "x_custom";
		String customParamValue = "abc";
		
		UnprotectedHeader header = new UnprotectedHeader.Builder(kid)
			.customParam(customParamName, customParamValue)
			.build();
		
		assertEquals(kid, header.getKeyID());
		assertEquals(customParamValue, header.getCustomParam(customParamName));
		
		Map<String, Object> jsonObject = header.toJSONObject();
		assertEquals(kid, jsonObject.get("kid"));
		assertEquals(customParamValue, jsonObject.get(customParamName));
		assertEquals(2, jsonObject.size());
		
		header = UnprotectedHeader.parse(jsonObject);
		
		assertEquals(kid, header.getKeyID());
		assertEquals(customParamValue, header.getCustomParam(customParamName));
		
		jsonObject = header.toJSONObject();
		assertEquals(customParamValue, jsonObject.get(customParamName));
		assertEquals(2, jsonObject.size());
	}
	
	
	public void testBuilder_requireNonNullKeyID() {
		
		try {
			new UnprotectedHeader.Builder(null);
			fail();
		} catch (NullPointerException e) {
			assertEquals("The \"kid\" must not be null", e.getMessage());
		}
	}
	
	
	public void testParse_null()
		throws ParseException {
		
		assertNull(UnprotectedHeader.parse(null));
	}
	
	
	// TODO Define expected behaviour if kid == null
	public void testParse_missingKeyID()
		throws ParseException {
		
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		
		UnprotectedHeader.parse(jsonObject);
	}
}
