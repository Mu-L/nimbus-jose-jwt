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

package com.nimbusds.jose.crypto;


import com.google.crypto.tink.subtle.X25519;
import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimNames;
import junit.framework.TestCase;

import java.util.Collections;


/**
 * Tests X25519 ECDH-1PU encryption and decryption.
 *
 * @author Alexander Martynov
 * @version 2021-08-04
 */
public class ECDH1PUX25519CryptoTest extends TestCase {


	private static OctetKeyPair generateOKP()
		throws Exception {

		byte[] privateKey = X25519.generatePrivateKey();
		byte[] publicKey = X25519.publicFromPrivate(privateKey);

		return new OctetKeyPair.Builder(Curve.X25519, Base64URL.encode(publicKey)).
			d(Base64URL.encode(privateKey)).
			build();
	}


	public void testCycle_ECDH_1PU_X25519()
		throws Exception {

		OctetKeyPair aliceKey = generateOKP();
		OctetKeyPair bobKey = generateOKP();

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_1PU, EncryptionMethod.A128GCM).
			agreementPartyUInfo(Base64URL.encode("Alice")).
			agreementPartyVInfo(Base64URL.encode("Bob")).
			build();

		JWEObject jweObject = new JWEObject(header, new Payload("Hello world!"));

		ECDH1PUX25519Encrypter encrypter = new ECDH1PUX25519Encrypter(aliceKey, bobKey.toPublicJWK());
		jweObject.encrypt(encrypter);

		OctetKeyPair epk = (OctetKeyPair) jweObject.getHeader().getEphemeralPublicKey();
		assertEquals(Curve.X25519, epk.getCurve());
		assertNotNull(epk.getX());
		assertNull(epk.getD());

		assertNull(jweObject.getEncryptedKey());

		String jwe = jweObject.serialize();

		jweObject = JWEObject.parse(jwe);

		ECDH1PUX25519Decrypter decrypter = new ECDH1PUX25519Decrypter(bobKey, aliceKey.toPublicJWK());
		jweObject.decrypt(decrypter);

		assertEquals("Hello world!", jweObject.getPayload().toString());
	}


	public void testCycle_ECDH_1PU_X25519_A128KW()
		throws Exception {

		OctetKeyPair aliceKey = generateOKP();
		OctetKeyPair bobKey = generateOKP();

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_1PU_A128KW, EncryptionMethod.A128GCM).
			agreementPartyUInfo(Base64URL.encode("Alice")).
			agreementPartyVInfo(Base64URL.encode("Bob")).
			build();

		JWEObject jweObject = new JWEObject(header, new Payload("Hello world!"));

		ECDH1PUX25519Encrypter encrypter = new ECDH1PUX25519Encrypter(aliceKey, bobKey.toPublicJWK());
		jweObject.encrypt(encrypter);

		OctetKeyPair epk = (OctetKeyPair) jweObject.getHeader().getEphemeralPublicKey();
		assertEquals(Curve.X25519, epk.getCurve());
		assertNotNull(epk.getX());
		assertNull(epk.getD());

		assertNotNull(jweObject.getEncryptedKey());

		String jwe = jweObject.serialize();

		jweObject = JWEObject.parse(jwe);

		ECDH1PUX25519Decrypter decrypter = new ECDH1PUX25519Decrypter(bobKey, aliceKey.toPublicJWK());
		jweObject.decrypt(decrypter);

		assertEquals("Hello world!", jweObject.getPayload().toString());
	}


	public void testCritParamDeferral()
		throws Exception {

		OctetKeyPair aliceKey = generateOKP();
		OctetKeyPair bobKey = generateOKP();

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_1PU, EncryptionMethod.A128CBC_HS256).
			customParam(JWTClaimNames.EXPIRATION_TIME, "2014-04-24").
			criticalParams(Collections.singleton(JWTClaimNames.EXPIRATION_TIME)).
			build();

		JWEObject jweObject = new JWEObject(header, new Payload("Hello world!"));
		ECDH1PUX25519Encrypter encrypter = new ECDH1PUX25519Encrypter(aliceKey, bobKey.toPublicJWK());
		jweObject.encrypt(encrypter);

		jweObject = JWEObject.parse(jweObject.serialize());
		ECDH1PUX25519Decrypter decrypter = new ECDH1PUX25519Decrypter(bobKey, aliceKey.toPublicJWK(), Collections.singleton(JWTClaimNames.EXPIRATION_TIME));
		jweObject.decrypt(decrypter);

		assertEquals("Hello world!", jweObject.getPayload().toString());
	}


	public void testCritParamReject()
		throws Exception {

		OctetKeyPair aliceKey = generateOKP();
		OctetKeyPair bobKey = generateOKP();

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_1PU, EncryptionMethod.A128CBC_HS256).
			customParam(JWTClaimNames.EXPIRATION_TIME, "2014-04-24").
			criticalParams(Collections.singleton(JWTClaimNames.EXPIRATION_TIME)).
			build();

		JWEObject jweObject = new JWEObject(header, new Payload("Hello world!"));
		ECDH1PUX25519Encrypter encrypter = new ECDH1PUX25519Encrypter(aliceKey, bobKey.toPublicJWK());
		jweObject.encrypt(encrypter);

		jweObject = JWEObject.parse(jweObject.serialize());

		try {
			ECDH1PUX25519Decrypter decrypter = new ECDH1PUX25519Decrypter(bobKey, aliceKey.toPublicJWK());
			jweObject.decrypt(decrypter);
			fail();
		} catch (JOSEException e) {
			// ok
			assertEquals("Unsupported critical header parameter(s)", e.getMessage());
		}
	}
}
