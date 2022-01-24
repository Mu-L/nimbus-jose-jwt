/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2019, Connect2id Ltd and contributors.
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

package com.nimbusds.jose.crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.TestCase;

/**
 * Tests ECDH Encrypter with provided CEK.
 *
 * @author Fernando Gonzalez Callejas
 * @version 2019-01-24
 */
public class ECDHEncrypterTest extends TestCase {

	/**
	 * Test ECDH Encrypter with wrong provided CEK algorithm.
	 */
	public void testConstructorWithCEK_algNotAES() throws Exception {
		
		KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");
		ECGenParameterSpec ecParameterSpec = new ECGenParameterSpec("secp256r1");
		ecGen.initialize(ecParameterSpec);
		KeyPair ecKeyPair = ecGen.generateKeyPair();

		byte[] keyMaterial = new byte[16];
		new SecureRandom().nextBytes(keyMaterial);
		SecretKey cek = new SecretKeySpec(keyMaterial, "Not-AES");

		try {
			new ECDHEncrypter((ECPublicKey) ecKeyPair.getPublic(), cek);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The algorithm of the content encryption key (CEK) must be AES", e.getMessage());
		}
	}

}
