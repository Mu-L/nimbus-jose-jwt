/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2018, Connect2id Ltd.
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


import java.nio.charset.Charset;

import com.nimbusds.jose.util.Base64Codec;
import junit.framework.TestCase;
import org.apache.commons.lang.StringUtils;

/**
 * Tests the base 64 codec.
 */
public class Base64CodecTest extends TestCase {


	public void testComputeEncodedLength() {

		boolean urlSafe = false;
		assertEquals(0, Base64Codec.computeEncodedLength(0, urlSafe));
		assertEquals(4, Base64Codec.computeEncodedLength(1, urlSafe));
		assertEquals(4, Base64Codec.computeEncodedLength(2, urlSafe));
		assertEquals(4, Base64Codec.computeEncodedLength(3, urlSafe));
		assertEquals(8, Base64Codec.computeEncodedLength(4, urlSafe));
		assertEquals(8, Base64Codec.computeEncodedLength(5, urlSafe));
		assertEquals(8, Base64Codec.computeEncodedLength(6, urlSafe));

		urlSafe = true;
		assertEquals(0, Base64Codec.computeEncodedLength(0, urlSafe));
		assertEquals(2, Base64Codec.computeEncodedLength(1, urlSafe));
		assertEquals(3, Base64Codec.computeEncodedLength(2, urlSafe));
		assertEquals(4, Base64Codec.computeEncodedLength(3, urlSafe));
		assertEquals(6, Base64Codec.computeEncodedLength(4, urlSafe));
		assertEquals(7, Base64Codec.computeEncodedLength(5, urlSafe));
		assertEquals(8, Base64Codec.computeEncodedLength(6, urlSafe));
	}


	public void testTpSelect() {

		assertEquals(Base64Codec.tpSelect(0, 43927, 50985034), 50985034);
		assertEquals(Base64Codec.tpSelect(1, 43927, 50985034), 43927);
		assertEquals(Base64Codec.tpSelect(0, -39248, 43298), 43298);
		assertEquals(Base64Codec.tpSelect(1, -98432, 96283), -98432);
		assertEquals(Base64Codec.tpSelect(0, -34, -12), -12);
		assertEquals(Base64Codec.tpSelect(1, -98, -11), -98);
	}


	public void testTpLT() {

		assertEquals(Base64Codec.tpLT(23489, 0), 0);
		assertEquals(Base64Codec.tpLT(34, 9), 0);
		assertEquals(Base64Codec.tpLT(0, 9), 1);
		assertEquals(Base64Codec.tpLT(3, 9), 1);
		assertEquals(Base64Codec.tpLT(9, 9), 0);
		assertEquals(Base64Codec.tpLT(0, 0), 0);
		assertEquals(Base64Codec.tpLT(-23, -23), 0);
		assertEquals(Base64Codec.tpLT(-43, -23), 1);
		assertEquals(Base64Codec.tpLT(-43, 23), 1);
		assertEquals(Base64Codec.tpLT(43, -23), 0);
	}


	public void testTpGT() {

		assertEquals(Base64Codec.tpGT(0, 23489), 0);
		assertEquals(Base64Codec.tpGT(9, 34), 0);
		assertEquals(Base64Codec.tpGT(9, 0), 1);
		assertEquals(Base64Codec.tpGT(9, 3), 1);
		assertEquals(Base64Codec.tpGT(9, 9), 0);
		assertEquals(Base64Codec.tpGT(0, 0), 0);
		assertEquals(Base64Codec.tpGT(-23, -23), 0);
		assertEquals(Base64Codec.tpGT(-23, -43), 1);
		assertEquals(Base64Codec.tpGT(23, -43), 1);
		assertEquals(Base64Codec.tpGT(-23, 43), 0);
	}


	public void testTpEq() {

		assertEquals(Base64Codec.tpEq(0, 23489), 0);
		assertEquals(Base64Codec.tpEq(9, 34), 0);
		assertEquals(Base64Codec.tpEq(9, 0), 0);
		assertEquals(Base64Codec.tpEq(9, 3), 0);
		assertEquals(Base64Codec.tpEq(9, 9), 1);
		assertEquals(Base64Codec.tpEq(0, 0), 1);
		assertEquals(Base64Codec.tpEq(-23, -23), 1);
		assertEquals(Base64Codec.tpEq(-23, -43), 0);
		assertEquals(Base64Codec.tpEq(23, -43), 0);
		assertEquals(Base64Codec.tpEq(-23, 43), 0);
		assertEquals(Base64Codec.tpEq(0x7FFFFFFF, 0x7FFFFFFF), 1);
		assertEquals(Base64Codec.tpEq(0xFFFFFFFF, 0x7FFFFFFF), 0);
		assertEquals(Base64Codec.tpEq(0x7FFFFFFF, 0xFFFFFFFF), 0);
		assertEquals(Base64Codec.tpEq(0xFFFFFFFF, 0xFFFFFFFF), 1);
	}


	public void testEncode() {

		assertEquals("YWE+", Base64Codec.encodeToString("aa>".getBytes(Charset.forName("utf-8")), false));
		assertEquals("YmI/", Base64Codec.encodeToString("bb?".getBytes(Charset.forName("utf-8")), false));

		// Test vectors from rfc4648#section-10
		assertEquals("", Base64Codec.encodeToString("".getBytes(Charset.forName("utf-8")), false));
		assertEquals("Zg==", Base64Codec.encodeToString("f".getBytes(Charset.forName("utf-8")), false));
		assertEquals("Zm8=", Base64Codec.encodeToString("fo".getBytes(Charset.forName("utf-8")), false));
		assertEquals("Zm9v", Base64Codec.encodeToString("foo".getBytes(Charset.forName("utf-8")), false));
		assertEquals("Zm9vYg==", Base64Codec.encodeToString("foob".getBytes(Charset.forName("utf-8")), false));
		assertEquals("Zm9vYmE=", Base64Codec.encodeToString("fooba".getBytes(Charset.forName("utf-8")), false));
		assertEquals("Zm9vYmFy", Base64Codec.encodeToString("foobar".getBytes(Charset.forName("utf-8")), false));
	}


	public void testEncodeUrlSafe() {

		assertEquals("YWE-", Base64Codec.encodeToString("aa>".getBytes(Charset.forName("utf-8")), true));
		assertEquals("YmI_", Base64Codec.encodeToString("bb?".getBytes(Charset.forName("utf-8")), true));

		// Test vectors from rfc4648#section-10 with stripped padding
		assertEquals("", Base64Codec.encodeToString("".getBytes(Charset.forName("utf-8")), true));
		assertEquals("Zg", Base64Codec.encodeToString("f".getBytes(Charset.forName("utf-8")), true));
		assertEquals("Zm8", Base64Codec.encodeToString("fo".getBytes(Charset.forName("utf-8")), true));
		assertEquals("Zm9v", Base64Codec.encodeToString("foo".getBytes(Charset.forName("utf-8")), true));
		assertEquals("Zm9vYg", Base64Codec.encodeToString("foob".getBytes(Charset.forName("utf-8")), true));
		assertEquals("Zm9vYmE", Base64Codec.encodeToString("fooba".getBytes(Charset.forName("utf-8")), true));
		assertEquals("Zm9vYmFy", Base64Codec.encodeToString("foobar".getBytes(Charset.forName("utf-8")), true));
	}


	public void testDecode() {

		assertEquals("aa>", new String(Base64Codec.decode("YWE+"), Charset.forName("utf-8")));
		assertEquals("bb?", new String(Base64Codec.decode("YmI/"), Charset.forName("utf-8")));

		assertEquals("", new String(Base64Codec.decode(""), Charset.forName("utf-8")));
		assertEquals("f", new String(Base64Codec.decode("Zg=="), Charset.forName("utf-8")));
		assertEquals("fo", new String(Base64Codec.decode("Zm8="), Charset.forName("utf-8")));
		assertEquals("foo", new String(Base64Codec.decode("Zm9v"), Charset.forName("utf-8")));
		assertEquals("foob", new String(Base64Codec.decode("Zm9vYg=="), Charset.forName("utf-8")));
		assertEquals("fooba", new String(Base64Codec.decode("Zm9vYmE="), Charset.forName("utf-8")));
		assertEquals("foobar", new String(Base64Codec.decode("Zm9vYmFy"), Charset.forName("utf-8")));
	}

	public void testDecodeLargeString() {
		Base64Codec.decode(StringUtils.repeat(" ", Integer.MAX_VALUE / 4));
	}

	public void testDecodeWithIllegalChars() {

		assertEquals("", new String(Base64Codec.decode("\n"), Charset.forName("utf-8")));
		assertEquals("f", new String(Base64Codec.decode("Zg==\n"), Charset.forName("utf-8")));
		assertEquals("fo", new String(Base64Codec.decode("Zm8=\n"), Charset.forName("utf-8")));
		assertEquals("foo", new String(Base64Codec.decode("Zm9v\n"), Charset.forName("utf-8")));
		assertEquals("foob", new String(Base64Codec.decode("Zm9vYg==\n"), Charset.forName("utf-8")));
		assertEquals("fooba", new String(Base64Codec.decode("Zm9vYmE=\n"), Charset.forName("utf-8")));
		assertEquals("foobar", new String(Base64Codec.decode("Zm9vYmFy\n"), Charset.forName("utf-8")));
	}


	public void testDecodeUrlSafe() {

		assertEquals("aa>", new String(Base64Codec.decode("YWE-"), Charset.forName("utf-8")));
		assertEquals("bb?", new String(Base64Codec.decode("YmI_"), Charset.forName("utf-8")));

		assertEquals("", new String(Base64Codec.decode(""), Charset.forName("utf-8")));
		assertEquals("f", new String(Base64Codec.decode("Zg"), Charset.forName("utf-8")));
		assertEquals("fo", new String(Base64Codec.decode("Zm8"), Charset.forName("utf-8")));
		assertEquals("foo", new String(Base64Codec.decode("Zm9v"), Charset.forName("utf-8")));
		assertEquals("foob", new String(Base64Codec.decode("Zm9vYg"), Charset.forName("utf-8")));
		assertEquals("fooba", new String(Base64Codec.decode("Zm9vYmE"), Charset.forName("utf-8")));
		assertEquals("foobar", new String(Base64Codec.decode("Zm9vYmFy"), Charset.forName("utf-8")));
	}


	public void testDecodeUrlSafeWithIllegalChars() {

		assertEquals("", new String(Base64Codec.decode("\n"), Charset.forName("utf-8")));
		assertEquals("f", new String(Base64Codec.decode("Zg\n"), Charset.forName("utf-8")));
		assertEquals("fo", new String(Base64Codec.decode("Zm8\n"), Charset.forName("utf-8")));
		assertEquals("foo", new String(Base64Codec.decode("Zm9v\n"), Charset.forName("utf-8")));
		assertEquals("foob", new String(Base64Codec.decode("Zm9vYg\n"), Charset.forName("utf-8")));
		assertEquals("fooba", new String(Base64Codec.decode("Zm9vYmE\n"), Charset.forName("utf-8")));
		assertEquals("foobar", new String(Base64Codec.decode("Zm9vYmFy\n"), Charset.forName("utf-8")));
	}
}
