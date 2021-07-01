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

package com.nimbusds.jose.util;


import java.net.URI;
import java.text.ParseException;
import java.util.Arrays;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;
import org.junit.Assert;


/**
 * Tests the JSON object utilities.
 *
 * @author Vladimir Dzhuvinov
 * @version 2021-07-01
 */
public class JSONObjectUtilsTest extends TestCase {


	public void testParseTrailingWhiteSpace()
		throws Exception {

		assertEquals(0, JSONObjectUtils.parse("{} ").size());
		assertEquals(0, JSONObjectUtils.parse("{}\n").size());
		assertEquals(0, JSONObjectUtils.parse("{}\r\n").size());
	}
	
	
	// https://github.com/netplex/json-smart-v1/issues/7
	// 2021-04-06: JSON Smart 1.3.2 fixes CVE
	public void testParse_catchNumberFormatException() {
		
		String json = "{\"key\":2e+}";
		try {
			JSONObjectUtils.parse(json);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid JSON: Unexpected token 2e+ at position 10.", e.getMessage());
			assertNull(e.getCause());
		}
	}
	
	
	// Note, stack depth depends on the JVM config, test may fail because of that
	public void testParse_catchStackOverflowError() {
	
		StringBuilder sb = new StringBuilder("{\"a\":");
		for (int i = 0; i < 9000; i++) {
			sb.append("[");
		}
		
		try {
			JSONObjectUtils.parse(sb.toString());
			fail();
		} catch (ParseException e) {
			assertEquals("Excessive JSON object and / or array nesting", e.getMessage());
		}
	}
	
	
	public void testParse_withSizeLimit() {
		
		int sizeLimit = 100;
		
		StringBuilder s = new StringBuilder();
		for (int i=0; i < 101; i++) {
			s.append("a");
		}
		assertEquals(101, s.toString().length());
		
		try {
			JSONObjectUtils.parse(s.toString(), sizeLimit);
			fail();
		} catch (ParseException e) {
			assertEquals("The parsed string is longer than the max accepted size of 100 characters", e.getMessage());
		}
	}
	
	
	public void testParse_withNoSizeLimit() throws ParseException {
		
		JSONObject jsonObject = new JSONObject();
		
		StringBuilder s = new StringBuilder();
		for (int i=0; i < 101; i++) {
			s.append("a");
		}
		
		String value = s.toString();
		
		assertEquals(101, value.length());
		jsonObject.put("key", value);
		
		JSONObject out = JSONObjectUtils.parse(jsonObject.toJSONString(), -1);
		assertEquals(jsonObject, out);
		
		out = JSONObjectUtils.parse(jsonObject.toJSONString());
		assertEquals(jsonObject, out);
	}
	
	
	public void testGetBoolean_true()
		throws ParseException {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("key", true);
		assertTrue(JSONObjectUtils.getBoolean(jsonObject, "key"));
	}
	
	
	public void testGetBoolean_false()
		throws ParseException {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("key", false);
		assertFalse(JSONObjectUtils.getBoolean(jsonObject, "key"));
	}
	
	
	public void testGetBoolean_null() {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("key", null);
		
		try {
			JSONObjectUtils.getBoolean(jsonObject, "key");
			fail();
			
		} catch (ParseException e) {
			assertEquals("JSON object member with key \"key\" is missing or null", e.getMessage());
		}
	}
	
	
	public void testGetBoolean_missing() {
		
		JSONObject jsonObject = new JSONObject();
		
		try {
			JSONObjectUtils.getBoolean(jsonObject, "key");
			fail();
			
		} catch (ParseException e) {
			assertEquals("JSON object member with key \"key\" is missing or null", e.getMessage());
		}
	}
	
	
	public void testGetInt_null() {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("key", null);
		
		try {
			JSONObjectUtils.getInt(jsonObject, "key");
			fail();
			
		} catch (ParseException e) {
			assertEquals("JSON object member with key \"key\" is missing or null", e.getMessage());
		}
	}
	
	
	public void testGetInt_missing() {
		
		JSONObject jsonObject = new JSONObject();
		
		try {
			JSONObjectUtils.getInt(jsonObject, "key");
			fail();
			
		} catch (ParseException e) {
			assertEquals("JSON object member with key \"key\" is missing or null", e.getMessage());
		}
	}
	
	
	public void testGetInt_notNumber() {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("key", "abc");
		
		try {
			JSONObjectUtils.getInt(jsonObject, "key");
			fail();
			
		} catch (ParseException e) {
			assertEquals("Unexpected type of JSON object member with key \"key\"", e.getMessage());
		}
	}
	
	
	public void testGetLong_null() {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("key", null);
		
		try {
			JSONObjectUtils.getLong(jsonObject, "key");
			fail();
			
		} catch (ParseException e) {
			assertEquals("JSON object member with key \"key\" is missing or null", e.getMessage());
		}
	}
	
	
	public void testGetLong_missing() {
		
		JSONObject jsonObject = new JSONObject();
		
		try {
			JSONObjectUtils.getLong(jsonObject, "key");
			fail();
			
		} catch (ParseException e) {
			assertEquals("JSON object member with key \"key\" is missing or null", e.getMessage());
		}
	}
	
	
	public void testGetFloat_null() {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("key", null);
		
		try {
			JSONObjectUtils.getFloat(jsonObject, "key");
			fail();
			
		} catch (ParseException e) {
			assertEquals("JSON object member with key \"key\" is missing or null", e.getMessage());
		}
	}
	
	
	public void testGetFloat_missing() {
		
		JSONObject jsonObject = new JSONObject();
		
		try {
			JSONObjectUtils.getFloat(jsonObject, "key");
			fail();
			
		} catch (ParseException e) {
			assertEquals("JSON object member with key \"key\" is missing or null", e.getMessage());
		}
	}
	
	
	public void testGetDouble_null() {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("key", null);
		
		try {
			JSONObjectUtils.getDouble(jsonObject, "key");
			fail();
			
		} catch (ParseException e) {
			assertEquals("JSON object member with key \"key\" is missing or null", e.getMessage());
		}
	}
	
	
	public void testGetDouble_missing() {
		
		JSONObject jsonObject = new JSONObject();
		
		try {
			JSONObjectUtils.getDouble(jsonObject, "key");
			fail();
			
		} catch (ParseException e) {
			assertEquals("JSON object member with key \"key\" is missing or null", e.getMessage());
		}
	}
	
	
	public void testGetIntegerNumberAs_int_long_float_double() throws ParseException {
		
		JSONObject jsonObject = JSONObjectUtils.parse("{\"key\":10}");
		assertEquals(10, JSONObjectUtils.getInt(jsonObject, "key"));
		assertEquals(10L, JSONObjectUtils.getLong(jsonObject, "key"));
		assertEquals(10.0F, JSONObjectUtils.getFloat(jsonObject, "key"));
		assertEquals(10.0D, JSONObjectUtils.getDouble(jsonObject, "key"));
	}
	
	
	public void testGetDecimalNumberAs_int_long_float_double() throws ParseException {
		
		JSONObject jsonObject = JSONObjectUtils.parse("{\"key\":3.14}");
		assertEquals(3, JSONObjectUtils.getInt(jsonObject, "key"));
		assertEquals(3L, JSONObjectUtils.getLong(jsonObject, "key"));
		assertEquals(3.14F, JSONObjectUtils.getFloat(jsonObject, "key"));
		assertEquals(3.14D, JSONObjectUtils.getDouble(jsonObject, "key"));
	}
	
	
	public void testGetString() throws ParseException {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("key", "value");
		assertEquals("value", JSONObjectUtils.getString(jsonObject, "key"));
	}
	
	
	public void testGetString_null() throws ParseException {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("key", null);
		assertNull(JSONObjectUtils.getString(jsonObject, "key"));
	}
	
	
	public void testGetString_missing() throws ParseException {
		
		JSONObject jsonObject = new JSONObject();
		assertNull(JSONObjectUtils.getString(jsonObject, "key"));
	}
	
	
	public void testGetURI() throws ParseException {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("key", "https://c2id.net");
		assertEquals(URI.create("https://c2id.net"), JSONObjectUtils.getURI(jsonObject, "key"));
	}
	
	
	public void testGetURI_null() throws ParseException {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("key", null);
		assertNull(JSONObjectUtils.getURI(jsonObject, "key"));
	}
	
	
	public void testGetURI_missing() throws ParseException {
		
		JSONObject jsonObject = new JSONObject();
		assertNull(JSONObjectUtils.getURI(jsonObject, "key"));
	}
	
	
	public void testGetJSONArray_null() throws ParseException {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("key", null);
		assertNull(JSONObjectUtils.getJSONArray(jsonObject, "key"));
	}
	
	
	public void testGetJSONArray_missing() throws ParseException {
		
		JSONObject jsonObject = new JSONObject();
		assertNull(JSONObjectUtils.getJSONArray(jsonObject, "key"));
	}
	
	
	public void testGetStringArray() throws ParseException {
		
		JSONObject jsonObject = JSONObjectUtils.parse("{\"key\":[\"apple\",\"pear\"]}");
		Assert.assertArrayEquals(new String[]{"apple", "pear"}, JSONObjectUtils.getStringArray(jsonObject, "key"));
	}
	
	
	public void testGetStringArray_null() throws ParseException {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("key", null);
		assertNull(JSONObjectUtils.getStringArray(jsonObject, "key"));
	}
	
	
	public void testGetStringArray_missing() throws ParseException {
		
		JSONObject jsonObject = new JSONObject();
		assertNull(JSONObjectUtils.getStringArray(jsonObject, "key"));
	}
	
	
	public void testGetStringList() throws ParseException {
		
		JSONObject jsonObject = JSONObjectUtils.parse("{\"key\":[\"apple\",\"pear\"]}");
		assertEquals(Arrays.asList("apple", "pear"), JSONObjectUtils.getStringList(jsonObject, "key"));
	}
	
	
	public void testGetStringList_null() throws ParseException {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("key", null);
		assertNull(JSONObjectUtils.getStringList(jsonObject, "key"));
	}
	
	
	public void testGetStringList_missing() throws ParseException {
		
		JSONObject jsonObject = new JSONObject();
		assertNull(JSONObjectUtils.getStringList(jsonObject, "key"));
	}
	
	
	public void testGetJSONObject_null() throws ParseException {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("key", null);
		assertNull(JSONObjectUtils.getJSONObject(jsonObject, "key"));
	}
	
	
	public void testGetJSONObject_missing() throws ParseException {
		
		JSONObject jsonObject = new JSONObject();
		assertNull(JSONObjectUtils.getJSONObject(jsonObject, "key"));
	}
	
	
	public void testGetBase64URL() throws ParseException {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("x5t", "abc");
		Base64URL base64URL = JSONObjectUtils.getBase64URL(jsonObject, "x5t");
		assertEquals("abc", base64URL.toString());
	}
	
	
	public void testGetBase64URL_null() throws ParseException {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("x5t", null);
		assertNull(JSONObjectUtils.getBase64URL(jsonObject, "x5t"));
	}
	
	
	public void testGetBase64URL_missing() throws ParseException {
		
		JSONObject jsonObject = new JSONObject();
		assertNull(JSONObjectUtils.getBase64URL(jsonObject, "x5t"));
	}
}
