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


/**
 * Tests plaintext JOSE object parsing and serialisation.
 *
 * @author Vladimir Dzhuvinov
 * @version 2021-06-05
 */
public class PlainObjectTest extends TestCase {


	public void testSerializeAndParse()
		throws Exception {

		Payload payload = new Payload("Hello world!");

		PlainObject p = new PlainObject(payload);

		assertNotNull(p.getHeader());
		assertEquals("Hello world!", p.getPayload().toString());

		PlainHeader h = p.getHeader();
		assertEquals(Algorithm.NONE, h.getAlgorithm());
		assertNull(h.getType());
		assertNull(h.getContentType());
		assertTrue(h.getCustomParams().isEmpty());

		String serializedJOSEObject = p.serialize();

		p = PlainObject.parse(serializedJOSEObject);

		h = p.getHeader();
		assertEquals(Algorithm.NONE, h.getAlgorithm());
		assertNull(h.getType());
		assertNull(h.getContentType());
		assertTrue(h.getCustomParams().isEmpty());

		assertEquals("Hello world!", p.getPayload().toString());

		assertEquals(serializedJOSEObject, p.getParsedString());
	}
	
	
	public void testHeaderLengthJustBelowLimit() throws ParseException {
		
		StringBuilder s = new StringBuilder();
		for (int i = 0; i < Header.MAX_HEADER_STRING_LENGTH - 30; i++) {
			s.append("a");
		}
		
		PlainHeader header = new PlainHeader.Builder()
			.customParam("data", s.toString())
			.build();
		
		assertTrue(header.toBase64URL().decodeToString().length() < Header.MAX_HEADER_STRING_LENGTH);
		
		PlainObject plainObject = new PlainObject(header, new Payload("example"));
		
		String plainJOSE = plainObject.serialize();
		
		plainObject = PlainObject.parse(plainJOSE);
		assertEquals(header.toString(), plainObject.getHeader().toString());
	}
	
	
	public void testHeaderLengthLimitExceeded() {
		
		StringBuilder s = new StringBuilder();
		for (int i = 0; i < Header.MAX_HEADER_STRING_LENGTH; i++) {
			s.append("a");
		}
		
		PlainHeader header = new PlainHeader.Builder()
			.customParam("data", s.toString())
			.build();
		
		assertTrue(header.toBase64URL().toString().length() > Header.MAX_HEADER_STRING_LENGTH);
		
		PlainObject plainObject = new PlainObject(header, new Payload("example"));
		
		String plainJOSE = plainObject.serialize();
		
		try {
			PlainObject.parse(plainJOSE);
			fail();
		} catch (ParseException e) {
			assertEquals(
				"Invalid unsecured header: The parsed string is longer than the max accepted size of " +
					Header.MAX_HEADER_STRING_LENGTH +
					" characters",
				e.getMessage()
			);
		}
	}
}
