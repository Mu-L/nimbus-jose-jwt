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
import java.util.Map;

import com.nimbusds.jose.util.JSONArrayUtils;
import com.nimbusds.jose.util.JSONObjectUtils;

import junit.framework.TestCase;


public class JWKMetadataTest extends TestCase {
	
	
	public void testParseNoMembers()
		throws ParseException {
		
		Map<String, Object> o = JSONObjectUtils.newJSONObject();
		
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

		Map<String, Object> o = JSONObjectUtils.newJSONObject();
		
		o.put(JWKParameterNames.KEY_TYPE, null);
		o.put(JWKParameterNames.PUBLIC_KEY_USE, null);
		o.put(JWKParameterNames.KEY_OPS, null);
		o.put(JWKParameterNames.ALGORITHM, null);
		o.put(JWKParameterNames.KEY_ID, null);
		o.put(JWKParameterNames.X_509_CERT_URL, null);
		o.put(JWKParameterNames.X_509_CERT_SHA_1_THUMBPRINT, null);
		o.put(JWKParameterNames.X_509_CERT_SHA_256_THUMBPRINT, null);
		o.put(JWKParameterNames.X_509_CERT_CHAIN, null);
		
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

		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put(JWKParameterNames.X_509_CERT_CHAIN, JSONArrayUtils.newJSONArray()); // empty
		
		assertNull(JWKMetadata.parseX509CertChain(jsonObject));
	}
}
