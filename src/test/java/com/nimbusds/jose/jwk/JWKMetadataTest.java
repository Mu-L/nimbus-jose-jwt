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

package com.nimbusds.jose.jwk;


import java.text.ParseException;

import junit.framework.TestCase;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;


public class JWKMetadataTest extends TestCase {
	
	
	public void testParseNoMembers()
		throws ParseException {
		
		JSONObject o = new JSONObject();
		
		try {
			JWKMetadata.parseKeyType(o);
			fail();
		} catch (ParseException e) {
			assertEquals("The key type to parse must not be null", e.getMessage());
		}
		
		assertNull(JWKMetadata.parseKeyUse(o));
		assertNull(JWKMetadata.parseKeyOperations(o));
		assertNull(JWKMetadata.parseAlgorithm(o));
		assertNull(JWKMetadata.parseKeyID(o));
		assertNull(JWKMetadata.parseX509CertURL(o));
		assertNull(JWKMetadata.parseX509CertThumbprint(o));
		assertNull(JWKMetadata.parseX509CertSHA256Thumbprint(o));
		assertNull(JWKMetadata.parseX509CertChain(o));
	}
	
	
	public void testParseNullMembers()
		throws ParseException {
		
		JSONObject o = new JSONObject();
		
		o.put("kty", null);
		o.put("use", null);
		o.put("key_ops", null);
		o.put("alg", null);
		o.put("kid", null);
		o.put("x5u", null);
		o.put("x5t", null);
		o.put("x5t#S256", null);
		o.put("x5c", null);
		
		try {
			JWKMetadata.parseKeyType(o);
			fail();
		} catch (ParseException e) {
			assertEquals("The key type to parse must not be null", e.getMessage());
		}
		
		assertNull(JWKMetadata.parseKeyUse(o));
		assertNull(JWKMetadata.parseKeyOperations(o));
		assertNull(JWKMetadata.parseAlgorithm(o));
		assertNull(JWKMetadata.parseKeyID(o));
		assertNull(JWKMetadata.parseX509CertURL(o));
		assertNull(JWKMetadata.parseX509CertThumbprint(o));
		assertNull(JWKMetadata.parseX509CertSHA256Thumbprint(o));
		assertNull(JWKMetadata.parseX509CertChain(o));
	}
	
	
	public void testParseEmptyX509CertChain()
		throws ParseException {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("x5c", new JSONArray()); // empty
		
		assertNull(JWKMetadata.parseX509CertChain(jsonObject));
	}
}
