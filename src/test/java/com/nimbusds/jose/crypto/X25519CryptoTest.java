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


import java.util.Collections;

import com.google.crypto.tink.subtle.X25519;
import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimNames;
import junit.framework.TestCase;


/**
 * Tests X25519 ECDH encryption and decryption.
 *
 * @author Tim McLean
 * @version 2018-07-16
 */
public class X25519CryptoTest extends TestCase {


	private static OctetKeyPair generateOKP()
		throws Exception {

		byte[] privateKey = X25519.generatePrivateKey();
		byte[] publicKey = X25519.publicFromPrivate(privateKey);

		return new OctetKeyPair.Builder(Curve.X25519, Base64URL.encode(publicKey)).
			d(Base64URL.encode(privateKey)).
			build();
	}


	public void testCycle_ECDH_ES_X25519()
		throws Exception {

		OctetKeyPair okp = generateOKP();

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A128GCM).
			agreementPartyUInfo(Base64URL.encode("Alice")).
			agreementPartyVInfo(Base64URL.encode("Bob")).
			build();

		JWEObject jweObject = new JWEObject(header, new Payload("Hello world!"));

		X25519Encrypter encrypter = new X25519Encrypter(okp.toPublicJWK());
		jweObject.encrypt(encrypter);

		OctetKeyPair epk = (OctetKeyPair) jweObject.getHeader().getEphemeralPublicKey();
		assertEquals(Curve.X25519, epk.getCurve());
		assertNotNull(epk.getX());
		assertNull(epk.getD());

		assertNull(jweObject.getEncryptedKey());

		String jwe = jweObject.serialize();

		jweObject = JWEObject.parse(jwe);

		X25519Decrypter decrypter = new X25519Decrypter(okp);
		jweObject.decrypt(decrypter);

		assertEquals("Hello world!", jweObject.getPayload().toString());
	}


	public void testCycle_ECDH_ES_Curve_P256_A128KW()
		throws Exception {

		OctetKeyPair okp = generateOKP();

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES_A128KW, EncryptionMethod.A128GCM).
			agreementPartyUInfo(Base64URL.encode("Alice")).
			agreementPartyVInfo(Base64URL.encode("Bob")).
			build();

		JWEObject jweObject = new JWEObject(header, new Payload("Hello world!"));

		X25519Encrypter encrypter = new X25519Encrypter(okp.toPublicJWK());
		jweObject.encrypt(encrypter);

		OctetKeyPair epk = (OctetKeyPair) jweObject.getHeader().getEphemeralPublicKey();
		assertEquals(Curve.X25519, epk.getCurve());
		assertNotNull(epk.getX());
		assertNull(epk.getD());

		assertNotNull(jweObject.getEncryptedKey());

		String jwe = jweObject.serialize();

		jweObject = JWEObject.parse(jwe);

		X25519Decrypter decrypter = new X25519Decrypter(okp);
		jweObject.decrypt(decrypter);

		assertEquals("Hello world!", jweObject.getPayload().toString());
	}


	public void testCritParamDeferral()
		throws Exception {

		OctetKeyPair okp = generateOKP();

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A128CBC_HS256).
			customParam(JWTClaimNames.EXPIRATION_TIME, "2014-04-24").
			criticalParams(Collections.singleton(JWTClaimNames.EXPIRATION_TIME)).
			build();

		JWEObject jweObject = new JWEObject(header, new Payload("Hello world!"));
		jweObject.encrypt(new X25519Encrypter(okp.toPublicJWK()));

		jweObject = JWEObject.parse(jweObject.serialize());

		jweObject.decrypt(new X25519Decrypter(okp, Collections.singleton(JWTClaimNames.EXPIRATION_TIME)));

		assertEquals("Hello world!", jweObject.getPayload().toString());
	}


	public void testCritParamReject()
		throws Exception {

		OctetKeyPair okp = generateOKP();

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A128CBC_HS256).
			customParam(JWTClaimNames.EXPIRATION_TIME, "2014-04-24").
			criticalParams(Collections.singleton(JWTClaimNames.EXPIRATION_TIME)).
			build();

		JWEObject jweObject = new JWEObject(header, new Payload("Hello world!"));
		jweObject.encrypt(new X25519Encrypter(okp.toPublicJWK()));

		jweObject = JWEObject.parse(jweObject.serialize());

		try {
			jweObject.decrypt(new X25519Decrypter(okp));
			fail();
		} catch (JOSEException e) {
			// ok
			assertEquals("Unsupported critical header parameter(s)", e.getMessage());
		}
	}
}
