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

package com.nimbusds.jose.crypto.impl;


import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import static org.junit.Assert.assertArrayEquals;

import junit.framework.TestCase;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.ByteUtils;


/**
 * Tests the PBKDF2 static methods.
 */
public class PBKDF2Test extends TestCase {
	
	
	public static final byte[] PASSWORD_BYTES = "Thus from my lips, by yours, my sin is purged.".getBytes(StandardCharsets.UTF_8);
	
	
	public static final byte[] RAW_SALT_BYTES = new byte[] {
		(byte) 217, (byte) 96, (byte) 147, (byte) 112, (byte) 150, (byte) 117, (byte) 70, (byte) 247,
		(byte) 127, (byte)  8, (byte) 155, (byte) 137, (byte) 174, (byte)  42, (byte) 80, (byte) 215
	};
	
	
	public static final byte[] FORMATTED_SALT_BYTES = new byte[] {
		(byte) 80,  (byte) 66, (byte) 69,  (byte) 83,  (byte) 50, (byte) 45,  (byte) 72,  (byte) 83,
		(byte) 50,  (byte) 53, (byte) 54,  (byte) 43,  (byte) 65, (byte) 49,  (byte) 50,  (byte) 56,
		(byte) 75,  (byte) 87, (byte) 0,   (byte) 217, (byte) 96, (byte) 147, (byte) 112, (byte) 150,
		(byte) 117, (byte) 70, (byte) 247, (byte) 127, (byte) 8,  (byte) 155, (byte) 137, (byte) 174,
		(byte) 42,  (byte) 80, (byte) 215
	};
	
	
	public void testMinSaltLengthConstant() {
		
		assertEquals(8, PBKDF2.MIN_SALT_LENGTH);
	}
	
	
	public void testZeroByteConstant() {

		assertEquals((byte)0, PBKDF2.ZERO_BYTE[0]);
		assertEquals(1, PBKDF2.ZERO_BYTE.length);
	}
	
	
	public void testMaxDerivedKeyLengthConstant() {
		
		assertEquals((long) Math.pow(2, 32) - 1, PBKDF2.MAX_DERIVED_KEY_LENGTH);
	}


	public void testSaltFormat()
		throws Exception {

		final JWEAlgorithm alg = JWEAlgorithm.PBES2_HS256_A128KW;

		byte[] salt = new byte[PBKDF2.MIN_SALT_LENGTH];
		new SecureRandom().nextBytes(salt);

		byte[] formattedSalt = PBKDF2.formatSalt(alg, salt);

		byte[] expectedFormattedSalt = ByteUtils.concat(
			alg.toString().getBytes(StandardCharsets.UTF_8),
			PBKDF2.ZERO_BYTE,
			salt);
		
		assertArrayEquals(expectedFormattedSalt, formattedSalt);
	}


	public void testSaltFormat_nullValue() {

		try {
			PBKDF2.formatSalt(JWEAlgorithm.PBES2_HS256_A128KW, null);
			fail();
		} catch (JOSEException e) {
			assertEquals("The salt must not be null", e.getMessage());
		}
	}


	public void testSaltFormat_saltTooShort() {
		
		byte[] salt = new byte[PBKDF2.MIN_SALT_LENGTH - 1];
		new SecureRandom().nextBytes(salt);

		try {
			PBKDF2.formatSalt(JWEAlgorithm.PBES2_HS256_A128KW, salt);
			fail();
		} catch (JOSEException e) {
			assertEquals("The salt must be at least 8 bytes long", e.getMessage());
		}
	}


	// From http://tools.ietf.org/html/rfc7517#appendix-C
	public void testSaltFormatVector()
		throws Exception {

		final JWEAlgorithm alg = JWEAlgorithm.PBES2_HS256_A128KW;
		
		assertEquals("2WCTcJZ1Rvd_CJuJripQ1w", Base64URL.encode(RAW_SALT_BYTES).toString());

		byte[] concatSalt = PBKDF2.formatSalt(alg, RAW_SALT_BYTES);

		final byte[] expectedConcatSalt = {
			(byte) 80, (byte) 66, (byte) 69, (byte) 83, (byte) 50, (byte) 45, (byte) 72, (byte) 83,
			(byte) 50, (byte) 53, (byte) 54, (byte) 43, (byte) 65, (byte) 49, (byte) 50, (byte) 56,
			(byte) 75, (byte) 87, (byte)  0, (byte)217, (byte) 96, (byte)147, (byte)112, (byte)150,
			(byte)117, (byte) 70, (byte)247, (byte)127, (byte)  8, (byte)155, (byte)137, (byte)174,
			(byte) 42, (byte) 80, (byte)215
		};
		
		assertArrayEquals(expectedConcatSalt, concatSalt);
	}


	// From http://tools.ietf.org/html/rfc7517#appendix-C
	public void testDeriveKeyExample()
		throws Exception {
		
		final int iterationCount = 4096;
		final int dkLen = 16;

		SecretKey secretKey = PBKDF2.deriveKey(PASSWORD_BYTES, FORMATTED_SALT_BYTES, iterationCount, new PRFParams("HmacSHA256", null, dkLen));

		assertEquals(dkLen, secretKey.getEncoded().length);

		final byte[] expectedKey = {
			(byte)110, (byte)171, (byte)169, (byte) 92, (byte)129, (byte) 92, (byte)109, (byte)117,
			(byte)233, (byte)242, (byte)116, (byte)233, (byte)170, (byte) 14, (byte) 24, (byte) 75 };
		
		assertArrayEquals(expectedKey, secretKey.getEncoded());
	}
	
	
	public void testDeriveKey_requireNonNullSalt() {
		
		final int iterationCount = 4096;
		final int dkLen = 16;
		
		try {
			PBKDF2.deriveKey(PASSWORD_BYTES, null, iterationCount, new PRFParams("HmacSHA256", null, dkLen));
			fail();
		} catch (JOSEException e) {
			assertEquals("The formatted salt must not be null", e.getMessage());
		}
	}
	
	
	public void testDeriveKey_requirePositiveNumberOfIterations() {
		
		final int iterationCount = 0;
		final int dkLen = 16;

		try {
			PBKDF2.deriveKey(PASSWORD_BYTES, FORMATTED_SALT_BYTES, iterationCount, new PRFParams("HmacSHA256", null, dkLen));
			fail();
		} catch (JOSEException e) {
			assertEquals("The iteration count must be greater than 0", e.getMessage());
		}
	}
	
	
	public void testExtractBlock_requireNonNullSalt()
		throws JOSEException {
		
		final int iterationCount = 4096;
		final int dkLen = 16;
		PRFParams prfParams = new PRFParams("HmacSHA256", null, dkLen);
		SecretKey macKey = new SecretKeySpec(PASSWORD_BYTES, prfParams.getMACAlgorithm());
		Mac prf = HMAC.getInitMac(macKey, prfParams.getMacProvider());
		
		try {
			PBKDF2.extractBlock(null, iterationCount, 0, prf);
			fail();
		} catch (JOSEException e) {
			assertEquals("The formatted salt must not be null", e.getMessage());
		}
	}
	
	
	public void testExtractBlock_requirePositiveNumberOfIterations()
		throws JOSEException {
		
		final JWEAlgorithm alg = JWEAlgorithm.PBES2_HS256_A128KW;
		
		byte[] salt = new byte[PBKDF2.MIN_SALT_LENGTH];
		new SecureRandom().nextBytes(salt);
		
		byte[] formattedSalt = PBKDF2.formatSalt(alg, salt);
		
		final int iterationCount = 0;
		
		final int dkLen = 16;
		PRFParams prfParams = new PRFParams("HmacSHA256", null, dkLen);
		SecretKey macKey = new SecretKeySpec(PASSWORD_BYTES, prfParams.getMACAlgorithm());
		Mac prf = HMAC.getInitMac(macKey, prfParams.getMacProvider());
		
		try {
			PBKDF2.extractBlock(formattedSalt, iterationCount, 0, prf);
			fail();
		} catch (JOSEException e) {
			assertEquals("The iteration count must be greater than 0", e.getMessage());
		}
	}
	
	
	public void testExtractBlock()
		throws JOSEException {
		
		final JWEAlgorithm alg = JWEAlgorithm.PBES2_HS256_A128KW;
		
		byte[] salt = new byte[PBKDF2.MIN_SALT_LENGTH];
		new SecureRandom().nextBytes(salt);
		
		byte[] formattedSalt = PBKDF2.formatSalt(alg, salt);
		
		final int iterationCount = 4098;
		
		final int dkLen = 16;
		PRFParams prfParams = new PRFParams("HmacSHA256", null, dkLen);
		SecretKey macKey = new SecretKeySpec(PASSWORD_BYTES, prfParams.getMACAlgorithm());
		Mac prf = HMAC.getInitMac(macKey, prfParams.getMacProvider());
		
		byte[] block = PBKDF2.extractBlock(formattedSalt, iterationCount, 0, prf);
		assertEquals(32, block.length);
	}
}
