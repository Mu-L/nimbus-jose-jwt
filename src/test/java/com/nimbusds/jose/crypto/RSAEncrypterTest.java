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

package com.nimbusds.jose.crypto;


import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.TestCase;


public class RSAEncrypterTest extends TestCase {
	
	
	public void testWithContentEncryptionKeySpecified_unsupportedKeyAlgorithm()
		throws NoSuchAlgorithmException {
		
		KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
		rsaGen.initialize(2048);
		KeyPair rsaKeyPair = rsaGen.generateKeyPair();
		
		byte[] keyMaterial = new byte[16];
		new SecureRandom().nextBytes(keyMaterial);
		SecretKey cek = new SecretKeySpec(keyMaterial, "Unsupported-Alg");
		
		IllegalArgumentException exception = null;
		try {
			new RSAEncrypter((RSAPublicKey)rsaKeyPair.getPublic(), cek);
			fail();
		} catch (IllegalArgumentException e) {
			exception = e;
		}
		assertEquals("The algorithm of the content encryption key (CEK) must be AES or ChaCha20", exception.getMessage());
	}
}
