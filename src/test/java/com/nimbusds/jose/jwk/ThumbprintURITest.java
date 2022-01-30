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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64URL;


public class ThumbprintURITest extends TestCase {


	public void testPrefix() {
		
		assertEquals("urn:ietf:params:oauth:jwk-thumbprint:", ThumbprintURI.PREFIX);
	}
	
	
	public void testSpecExample() throws ParseException {
		
		Base64URL value = new Base64URL("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
		
		ThumbprintURI thumbprintURI = new ThumbprintURI(value);
		assertEquals(value, thumbprintURI.getThumbprint());
		
		assertEquals("urn:ietf:params:oauth:jwk-thumbprint:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", thumbprintURI.toString());
		assertEquals("urn:ietf:params:oauth:jwk-thumbprint:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", thumbprintURI.toURI().toString());
		
		thumbprintURI = ThumbprintURI.parse(thumbprintURI.toString());
		assertEquals(value, thumbprintURI.getThumbprint());
		
		thumbprintURI = ThumbprintURI.parse(thumbprintURI.toURI());
		assertEquals(value, thumbprintURI.getThumbprint());
		
		assertEquals("Equality", thumbprintURI, ThumbprintURI.parse(thumbprintURI.toURI()));
		assertEquals("Hash code", thumbprintURI.hashCode(), ThumbprintURI.parse(thumbprintURI.toURI()).hashCode());
	}
	
	
	public void testCompute_sha256() throws JOSEException {
		
		RSAKey rsaKey = new RSAKeyGenerator(2048)
			.generate();
		
		ThumbprintURI thumbprintURI = rsaKey.computeThumbprintURI();
		
		assertEquals(ThumbprintURI.PREFIX + ThumbprintUtils.compute(rsaKey), thumbprintURI.toString());
		
		assertEquals(thumbprintURI, ThumbprintURI.compute(rsaKey));
	}
	
	
	public void testParse_illegalPrefix() {
		
		try {
			ThumbprintURI.parse("urn:a:b:c");
			fail();
		} catch (ParseException e) {
			assertEquals("Illegal JWK thumbprint prefix", e.getMessage());
		}
	}
	
	
	public void testParse_emptyValue() {
		
		try {
			ThumbprintURI.parse(ThumbprintURI.PREFIX + "");
			fail();
		} catch (ParseException e) {
			assertEquals("Illegal JWK thumbprint: Empty value", e.getMessage());
		}
	}
}
