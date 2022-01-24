/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2021, Connect2id Ltd.
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


import junit.framework.TestCase;

/**
 * Tests the JWS Algorithm class.
 *
 * @author Vladimir Dzhuvinov
 * @version 2021-09-24
 */
public class JWEAlgorithmTest extends TestCase {


	public void testParse() {
		
		assertSame(JWEAlgorithm.RSA1_5, JWEAlgorithm.parse("RSA1_5"));
		assertSame(JWEAlgorithm.RSA_OAEP, JWEAlgorithm.parse("RSA-OAEP"));
		assertSame(JWEAlgorithm.RSA_OAEP_256, JWEAlgorithm.parse("RSA-OAEP-256"));
		assertSame(JWEAlgorithm.RSA_OAEP_384, JWEAlgorithm.parse("RSA-OAEP-384"));
		assertSame(JWEAlgorithm.RSA_OAEP_512, JWEAlgorithm.parse("RSA-OAEP-512"));
		
		assertSame(JWEAlgorithm.A128KW, JWEAlgorithm.parse("A128KW"));
		assertSame(JWEAlgorithm.A192KW, JWEAlgorithm.parse("A192KW"));
		assertSame(JWEAlgorithm.A256KW, JWEAlgorithm.parse("A256KW"));
		
		assertSame(JWEAlgorithm.DIR, JWEAlgorithm.parse("dir"));
		
		assertSame(JWEAlgorithm.ECDH_ES, JWEAlgorithm.parse("ECDH-ES"));
		
		assertSame(JWEAlgorithm.ECDH_ES_A128KW, JWEAlgorithm.parse("ECDH-ES+A128KW"));
		assertSame(JWEAlgorithm.ECDH_ES_A192KW, JWEAlgorithm.parse("ECDH-ES+A192KW"));
		assertSame(JWEAlgorithm.ECDH_ES_A256KW, JWEAlgorithm.parse("ECDH-ES+A256KW"));
		
		assertSame(JWEAlgorithm.ECDH_1PU, JWEAlgorithm.parse("ECDH-1PU"));
		
		assertSame(JWEAlgorithm.ECDH_1PU_A128KW, JWEAlgorithm.parse("ECDH-1PU+A128KW"));
		assertSame(JWEAlgorithm.ECDH_1PU_A192KW, JWEAlgorithm.parse("ECDH-1PU+A192KW"));
		assertSame(JWEAlgorithm.ECDH_1PU_A256KW, JWEAlgorithm.parse("ECDH-1PU+A256KW"));
		
		assertSame(JWEAlgorithm.A128GCMKW, JWEAlgorithm.parse("A128GCMKW"));
		assertSame(JWEAlgorithm.A192GCMKW, JWEAlgorithm.parse("A192GCMKW"));
		assertSame(JWEAlgorithm.A256GCMKW, JWEAlgorithm.parse("A256GCMKW"));
		
		assertSame(JWEAlgorithm.PBES2_HS256_A128KW, JWEAlgorithm.parse("PBES2-HS256+A128KW"));
		assertSame(JWEAlgorithm.PBES2_HS384_A192KW, JWEAlgorithm.parse("PBES2-HS384+A192KW"));
		assertSame(JWEAlgorithm.PBES2_HS512_A256KW, JWEAlgorithm.parse("PBES2-HS512+A256KW"));
	}


	public void testRSAFamily() {

		assertTrue(JWEAlgorithm.Family.RSA.contains(JWEAlgorithm.RSA1_5));
		assertTrue(JWEAlgorithm.Family.RSA.contains(JWEAlgorithm.RSA_OAEP));
		assertTrue(JWEAlgorithm.Family.RSA.contains(JWEAlgorithm.RSA_OAEP_256));
		assertTrue(JWEAlgorithm.Family.RSA.contains(JWEAlgorithm.RSA_OAEP_384));
		assertTrue(JWEAlgorithm.Family.RSA.contains(JWEAlgorithm.RSA_OAEP_512));
		assertEquals(5, JWEAlgorithm.Family.RSA.size());
	}


	public void testAxxxKWFamily() {

		assertTrue(JWEAlgorithm.Family.AES_KW.contains(JWEAlgorithm.A128KW));
		assertTrue(JWEAlgorithm.Family.AES_KW.contains(JWEAlgorithm.A192KW));
		assertTrue(JWEAlgorithm.Family.AES_KW.contains(JWEAlgorithm.A256KW));
		assertEquals(3, JWEAlgorithm.Family.AES_KW.size());
	}


	public void testAxxxGCMKWFamily() {

		assertTrue(JWEAlgorithm.Family.AES_GCM_KW.contains(JWEAlgorithm.A256GCMKW));
		assertTrue(JWEAlgorithm.Family.AES_GCM_KW.contains(JWEAlgorithm.A256GCMKW));
		assertTrue(JWEAlgorithm.Family.AES_GCM_KW.contains(JWEAlgorithm.A256GCMKW));
		assertEquals(3, JWEAlgorithm.Family.AES_GCM_KW.size());
	}


	public void testPBES2Family() {

		assertTrue(JWEAlgorithm.Family.PBES2.contains(JWEAlgorithm.PBES2_HS256_A128KW));
		assertTrue(JWEAlgorithm.Family.PBES2.contains(JWEAlgorithm.PBES2_HS256_A128KW));
		assertTrue(JWEAlgorithm.Family.PBES2.contains(JWEAlgorithm.PBES2_HS256_A128KW));
		assertEquals(3, JWEAlgorithm.Family.PBES2.size());
	}


	public void testECDHFamily() {

		assertTrue(JWEAlgorithm.Family.ECDH_ES.contains(JWEAlgorithm.ECDH_ES));
		assertTrue(JWEAlgorithm.Family.ECDH_ES.contains(JWEAlgorithm.ECDH_ES_A128KW));
		assertTrue(JWEAlgorithm.Family.ECDH_ES.contains(JWEAlgorithm.ECDH_ES_A192KW));
		assertTrue(JWEAlgorithm.Family.ECDH_ES.contains(JWEAlgorithm.ECDH_ES_A256KW));
		assertEquals(4, JWEAlgorithm.Family.ECDH_ES.size());
	}


	public void testECDH1PUFamily() {

		assertTrue(JWEAlgorithm.Family.ECDH_1PU.contains(JWEAlgorithm.ECDH_1PU));
		assertTrue(JWEAlgorithm.Family.ECDH_1PU.contains(JWEAlgorithm.ECDH_1PU_A128KW));
		assertTrue(JWEAlgorithm.Family.ECDH_1PU.contains(JWEAlgorithm.ECDH_1PU_A192KW));
		assertTrue(JWEAlgorithm.Family.ECDH_1PU.contains(JWEAlgorithm.ECDH_1PU_A256KW));
		assertEquals(4, JWEAlgorithm.Family.ECDH_ES.size());
	}
	
	
	public void testAsymmetricSuperFamily() {
		
		assertTrue(JWEAlgorithm.Family.ASYMMETRIC.contains(JWEAlgorithm.RSA1_5));
		assertTrue(JWEAlgorithm.Family.ASYMMETRIC.contains(JWEAlgorithm.RSA_OAEP));
		assertTrue(JWEAlgorithm.Family.ASYMMETRIC.contains(JWEAlgorithm.RSA_OAEP_256));
		assertTrue(JWEAlgorithm.Family.ASYMMETRIC.contains(JWEAlgorithm.RSA_OAEP_384));
		assertTrue(JWEAlgorithm.Family.ASYMMETRIC.contains(JWEAlgorithm.RSA_OAEP_512));
		assertTrue(JWEAlgorithm.Family.ASYMMETRIC.contains(JWEAlgorithm.ECDH_ES));
		assertTrue(JWEAlgorithm.Family.ASYMMETRIC.contains(JWEAlgorithm.ECDH_ES_A128KW));
		assertTrue(JWEAlgorithm.Family.ASYMMETRIC.contains(JWEAlgorithm.ECDH_ES_A192KW));
		assertTrue(JWEAlgorithm.Family.ASYMMETRIC.contains(JWEAlgorithm.ECDH_ES_A256KW));
		assertEquals(9, JWEAlgorithm.Family.ASYMMETRIC.size());
	}
	
	
	public void testSymmetricSuperFamily() {
		
		assertTrue(JWEAlgorithm.Family.SYMMETRIC.contains(JWEAlgorithm.A128KW));
		assertTrue(JWEAlgorithm.Family.SYMMETRIC.contains(JWEAlgorithm.A192KW));
		assertTrue(JWEAlgorithm.Family.SYMMETRIC.contains(JWEAlgorithm.A256KW));
		assertTrue(JWEAlgorithm.Family.SYMMETRIC.contains(JWEAlgorithm.A256GCMKW));
		assertTrue(JWEAlgorithm.Family.SYMMETRIC.contains(JWEAlgorithm.A256GCMKW));
		assertTrue(JWEAlgorithm.Family.SYMMETRIC.contains(JWEAlgorithm.A256GCMKW));
		assertTrue(JWEAlgorithm.Family.SYMMETRIC.contains(JWEAlgorithm.DIR));
		assertEquals(7, JWEAlgorithm.Family.SYMMETRIC.size());
	}
}
