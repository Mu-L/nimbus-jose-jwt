/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2019, Connect2id Ltd.
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


import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import junit.framework.TestCase;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.Collections;
import java.util.HashSet;


/**
 * Tests ECDH-1PU encryption and decryption.
 *
 * @author Alexander Martynov
 * @version 2021-08-04
 */
public class ECDH1PUCryptoTest extends TestCase {


	private static ECKey generateECJWK(final Curve curve)
		throws Exception {

		ECParameterSpec ecParameterSpec = curve.toECParameterSpec();

		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
		generator.initialize(ecParameterSpec);
		KeyPair keyPair = generator.generateKeyPair();

		return new ECKey.Builder(curve, (ECPublicKey)keyPair.getPublic()).
			privateKey((ECPrivateKey) keyPair.getPrivate()).
			build();
	}


	public void testCycle_ECDH_1PU_Curve_P256()
		throws Exception {

		ECKey aliceKey = generateECJWK(Curve.P_256);
		ECKey bobKey = generateECJWK(Curve.P_256);

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_1PU, EncryptionMethod.A128GCM).
			agreementPartyUInfo(Base64URL.encode("Alice")).
			agreementPartyVInfo(Base64URL.encode("Bob")).
			build();

		JWEObject jweObject = new JWEObject(header, new Payload("Hello world!"));

		ECDH1PUEncrypter encrypter = new ECDH1PUEncrypter(aliceKey.toECPrivateKey(), bobKey.toECPublicKey());
		encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.encrypt(encrypter);

		ECKey epk = (ECKey) jweObject.getHeader().getEphemeralPublicKey();
		assertEquals(Curve.P_256, epk.getCurve());
		assertNotNull(epk.getX());
		assertNotNull(epk.getY());
		assertNull(epk.getD());

		assertNull(jweObject.getEncryptedKey());

		String jwe = jweObject.serialize();

		jweObject = JWEObject.parse(jwe);

		ECDH1PUDecrypter decrypter = new ECDH1PUDecrypter(bobKey.toECPrivateKey(), aliceKey.toECPublicKey());
		decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.decrypt(decrypter);

		assertEquals("Hello world!", jweObject.getPayload().toString());
	}


	public void testCycle_ECDH_1PU_Curve_P256_A128KW()
		throws Exception {

		ECKey aliceKey = generateECJWK(Curve.P_256);
		ECKey bobKey = generateECJWK(Curve.P_256);

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_1PU_A128KW, EncryptionMethod.A256CBC_HS512).
			agreementPartyUInfo(Base64URL.encode("Alice")).
			agreementPartyVInfo(Base64URL.encode("Bob")).
			build();

		JWEObject jweObject = new JWEObject(header, new Payload("Hello world!"));

		ECDH1PUEncrypter encrypter = new ECDH1PUEncrypter(aliceKey.toECPrivateKey(), bobKey.toECPublicKey());
		encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.encrypt(encrypter);

		ECKey epk = (ECKey) jweObject.getHeader().getEphemeralPublicKey();
		assertEquals(Curve.P_256, epk.getCurve());
		assertNotNull(epk.getX());
		assertNotNull(epk.getY());
		assertNull(epk.getD());

		assertNotNull(jweObject.getEncryptedKey());

		String jwe = jweObject.serialize();

		jweObject = JWEObject.parse(jwe);

		ECDH1PUDecrypter decrypter = new ECDH1PUDecrypter(bobKey.toECPrivateKey(), aliceKey.toECPublicKey());
		decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.decrypt(decrypter);

		assertEquals("Hello world!", jweObject.getPayload().toString());
	}
	
	/**
	 * Test ECDH Encrypter with provided CEK encryption and decryption cycle.
	 * 
	 * @throws Exception
	 */
	public void testCycle_ECDH_1PU_Curve_P256_A128KW_WithCekSpecified() throws Exception {
		ECKey aliceKey = generateECJWK(Curve.P_256);
		ECKey bobKey = generateECJWK(Curve.P_256);

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_1PU_A128KW, EncryptionMethod.A128GCM).
				agreementPartyUInfo(Base64URL.encode("Alice")).
				agreementPartyVInfo(Base64URL.encode("Bob")).
				build();

		JWEObject jweObject = new JWEObject(header, new Payload("Hello world!"));

		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(EncryptionMethod.A128GCM.cekBitLength());
		SecretKey cek = keyGenerator.generateKey();

		ECDH1PUEncrypter encrypter = new ECDH1PUEncrypter(aliceKey.toECPrivateKey(), bobKey.toECPublicKey(), cek);
		encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.encrypt(encrypter);

		ECKey epk = (ECKey) jweObject.getHeader().getEphemeralPublicKey();
		assertEquals(Curve.P_256, epk.getCurve());
		assertNotNull(epk.getX());
		assertNotNull(epk.getY());
		assertNull(epk.getD());

		assertNotNull(jweObject.getEncryptedKey());

		String jwe = jweObject.serialize();

		jweObject = JWEObject.parse(jwe);

		ECDH1PUDecrypter decrypter = new ECDH1PUDecrypter(bobKey.toECPrivateKey(), aliceKey.toECPublicKey());
		decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.decrypt(decrypter);

		assertEquals("Hello world!", jweObject.getPayload().toString());
	}

	public void testCycle_ECDH_1PU_Curve_P384()
		throws Exception {

		ECKey aliceKey = generateECJWK(Curve.P_384);
		ECKey bobKey = generateECJWK(Curve.P_384);

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_1PU, EncryptionMethod.A128GCM).
			agreementPartyUInfo(Base64URL.encode("Alice")).
			agreementPartyVInfo(Base64URL.encode("Bob")).
			build();

		JWEObject jweObject = new JWEObject(header, new Payload("Hello world!"));

		ECDH1PUEncrypter encrypter = new ECDH1PUEncrypter(aliceKey.toECPrivateKey(), bobKey.toECPublicKey());
		encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.encrypt(encrypter);

		ECKey epk = (ECKey) jweObject.getHeader().getEphemeralPublicKey();
		assertEquals(Curve.P_384, epk.getCurve());
		assertNotNull(epk.getX());
		assertNotNull(epk.getY());
		assertNull(epk.getD());

		assertNull(jweObject.getEncryptedKey());

		String jwe = jweObject.serialize();

		jweObject = JWEObject.parse(jwe);

		ECDH1PUDecrypter decrypter = new ECDH1PUDecrypter(bobKey.toECPrivateKey(), aliceKey.toECPublicKey());
		decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.decrypt(decrypter);

		assertEquals("Hello world!", jweObject.getPayload().toString());
	}


	public void testCycle_ECDH_1PU_Curve_P384_A128KW()
		throws Exception {

		ECKey aliceKey = generateECJWK(Curve.P_384);
		ECKey bobKey = generateECJWK(Curve.P_384);

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_1PU_A128KW, EncryptionMethod.A256CBC_HS512).
			agreementPartyUInfo(Base64URL.encode("Alice")).
			agreementPartyVInfo(Base64URL.encode("Bob")).
			build();

		JWEObject jweObject = new JWEObject(header, new Payload("Hello world!"));

		ECDH1PUEncrypter encrypter = new ECDH1PUEncrypter(aliceKey.toECPrivateKey(), bobKey.toECPublicKey());
		encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.encrypt(encrypter);

		ECKey epk = (ECKey) jweObject.getHeader().getEphemeralPublicKey();
		assertEquals(Curve.P_384, epk.getCurve());
		assertNotNull(epk.getX());
		assertNotNull(epk.getY());
		assertNull(epk.getD());

		assertNotNull(jweObject.getEncryptedKey());

		String jwe = jweObject.serialize();

		jweObject = JWEObject.parse(jwe);

		ECDH1PUDecrypter decrypter = new ECDH1PUDecrypter(bobKey.toECPrivateKey(), aliceKey.toECPublicKey());
		decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.decrypt(decrypter);

		assertEquals("Hello world!", jweObject.getPayload().toString());
	}


	public void testCycle_ECDH_1PU_Curve_P521()
		throws Exception {

		ECKey aliceKey = generateECJWK(Curve.P_521);
		ECKey bobKey = generateECJWK(Curve.P_521);

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_1PU, EncryptionMethod.A128GCM).
			agreementPartyUInfo(Base64URL.encode("Alice")).
			agreementPartyVInfo(Base64URL.encode("Bob")).
			build();

		JWEObject jweObject = new JWEObject(header, new Payload("Hello world!"));

		ECDH1PUEncrypter encrypter = new ECDH1PUEncrypter(aliceKey.toECPrivateKey(), bobKey.toECPublicKey());
		encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.encrypt(encrypter);

		ECKey epk = (ECKey) jweObject.getHeader().getEphemeralPublicKey();
		assertEquals(Curve.P_521, epk.getCurve());
		assertNotNull(epk.getX());
		assertNotNull(epk.getY());
		assertNull(epk.getD());

		assertNull(jweObject.getEncryptedKey());

		String jwe = jweObject.serialize();

		jweObject = JWEObject.parse(jwe);

		ECDH1PUDecrypter decrypter = new ECDH1PUDecrypter(bobKey.toECPrivateKey(), aliceKey.toECPublicKey());
		decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.decrypt(decrypter);

		assertEquals("Hello world!", jweObject.getPayload().toString());
	}


	public void testCycle_ECDH_1PU_Curve_P521_A128KW()
		throws Exception {

		ECKey aliceKey = generateECJWK(Curve.P_521);
		ECKey bobKey = generateECJWK(Curve.P_521);

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_1PU_A128KW, EncryptionMethod.A256CBC_HS512).
			agreementPartyUInfo(Base64URL.encode("Alice")).
			agreementPartyVInfo(Base64URL.encode("Bob")).
			build();

		JWEObject jweObject = new JWEObject(header, new Payload("Hello world!"));

		ECDH1PUEncrypter encrypter = new ECDH1PUEncrypter(aliceKey.toECPrivateKey(), bobKey.toECPublicKey());
		encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.encrypt(encrypter);

		ECKey epk = (ECKey) jweObject.getHeader().getEphemeralPublicKey();
		assertEquals(Curve.P_521, epk.getCurve());
		assertNotNull(epk.getX());
		assertNotNull(epk.getY());
		assertNull(epk.getD());

		assertNotNull(jweObject.getEncryptedKey());

		String jwe = jweObject.serialize();

		jweObject = JWEObject.parse(jwe);

		ECDH1PUDecrypter decrypter = new ECDH1PUDecrypter(bobKey.toECPrivateKey(), aliceKey.toECPublicKey());
		decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.decrypt(decrypter);

		assertEquals("Hello world!", jweObject.getPayload().toString());
	}

	public void testCritParamDeferral()
		throws Exception {

		ECKey aliceKey = generateECJWK(Curve.P_256);
		ECKey bobKey = generateECJWK(Curve.P_256);

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_1PU, EncryptionMethod.A128CBC_HS256).
			customParam("exp", "2014-04-24").
			criticalParams(new HashSet<>(Collections.singletonList("exp"))).
			build();

		JWEObject jweObject = new JWEObject(header, new Payload("Hello world!"));
		jweObject.encrypt(new ECDH1PUEncrypter(aliceKey.toECPrivateKey(), bobKey.toECPublicKey()));

		jweObject = JWEObject.parse(jweObject.serialize());

		jweObject.decrypt(new ECDH1PUDecrypter(
				bobKey.toECPrivateKey(),
				aliceKey.toECPublicKey(),
				new HashSet<>(Collections.singletonList("exp"))));

		assertEquals("Hello world!", jweObject.getPayload().toString());
	}


	public void testCritParamReject()
		throws Exception {

		ECKey aliceKey = generateECJWK(Curve.P_256);
		ECKey bobKey = generateECJWK(Curve.P_256);

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_1PU, EncryptionMethod.A128CBC_HS256).
			customParam("exp", "2014-04-24").
			criticalParams(new HashSet<>(Collections.singletonList("exp"))).
			build();

		JWEObject jweObject = new JWEObject(header, new Payload("Hello world!"));
		jweObject.encrypt(new ECDH1PUEncrypter(aliceKey.toECPrivateKey(), bobKey.toECPublicKey()));

		jweObject = JWEObject.parse(jweObject.serialize());

		try {
			jweObject.decrypt(new ECDH1PUDecrypter(bobKey.toECPrivateKey(), aliceKey.toECPublicKey()));
			fail();
		} catch (JOSEException e) {
			// ok
			assertEquals("Unsupported critical header parameter(s)", e.getMessage());
		}
	}
}
