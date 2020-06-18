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


import java.math.BigInteger;

import com.nimbusds.jose.util.Base64;
import junit.framework.TestCase;


/**
 * Tests the Base64URL class.
 *
 * @author Vladimir Dzhuvinov
 * @version 2020-06-18
 */
public class Base64Test extends TestCase {


	public void testEncode() {

		// Test vector from rfc4648#section-10
		Base64 b64 = Base64.encode("foobar");
		assertEquals("Zm9vYmFy", b64.toString());
	}


	public void testDecode() {

		// Test vector from rfc4648#section-10
		Base64 b64 = new Base64("Zm9vYmFy");
		assertEquals("foobar", b64.decodeToString());
	}
	
	
	public void testDecodeIllegalInput() {
		
		assertEquals(0, new Base64URL("@.#$%").decode().length);
	}


	public void testBigIntegerEncodeAndDecode() {
		
		BigInteger bigInt = new BigInteger("12345678901234567890");
		Base64 b64 = Base64.encode(bigInt);
		assertEquals(bigInt, b64.decodeToBigInteger());
	}
	
	
	public void testFrom() {
		
		Base64 b64 = Base64.encode("foobar");
		assertEquals("Zm9vYmFy", b64.toString());
		
		Base64 base64From = Base64.from(b64.toString());
		assertEquals(b64, base64From);
	}
	
	
	public void testFromNull() {
		
		assertNull(Base64.from(null));
	}
}

