/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2021, Connect2id Ltd and contributors.
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


import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.impl.ConcatKDF;
import com.nimbusds.jose.crypto.impl.ECDH1PU;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.util.Base64URL;
import junit.framework.TestCase;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;

import static org.junit.Assert.assertArrayEquals;

/**
 * Tests the ECDH-1PU key agreement derivation.
 *
 * @version 2021-08-05
 * @author Alexander Martynov
 */
public class ECDH1PUTest extends TestCase{

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

	private static OctetKeyPair generateOKP(Curve curve)
			throws Exception {

		return new OctetKeyPairGenerator(curve).generate();
	}

	private static class TestVector {
		public JWEAlgorithm algorithm;
		public EncryptionMethod encryptionMethod;
		public byte[] Ze;
		public byte[] Zs;
		public byte[] expectedZ;
		public byte[] expectedSharedKey;
		public Base64URL tag;
		public String apu;
		public String apv;

		public TestVector(
				JWEAlgorithm algorithm,
				EncryptionMethod encryptionMethod,
				byte[] Ze,
				byte[] Zs,
				byte[] expectedZ,
				byte[] expectedSharedKey,
				Base64URL tag,
				String apu,
				String apv) {
			this.algorithm = algorithm;
			this.encryptionMethod = encryptionMethod;
			this.Ze = Ze;
			this.Zs = Zs;
			this.expectedZ = expectedZ;
			this.expectedSharedKey = expectedSharedKey;
			this.tag = tag;
			this.apu = apu;
			this.apv = apv;
		}
	}

	private static final TestVector[] testVectors = new TestVector[] {
			// https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04#appendix-A
			new TestVector(
					JWEAlgorithm.ECDH_1PU,
					EncryptionMethod.A256GCM,
					fromHex("9e56d91d817135d372834283bf84269cfb316ea3da806a48f6daa7798cfe90c4"),
					fromHex("e3ca3474384c9f62b30bfd4c688b3e7d4110a1b4badc3cc54ef7b81241efd50d"),
					fromHex("9e56d91d817135d372834283bf84269cfb316ea3da806a48f6daa7798cfe90c4" +
									"e3ca3474384c9f62b30bfd4c688b3e7d4110a1b4badc3cc54ef7b81241efd50d"),
					fromHex("6caf13723d14850ad4b42cd6dde935bffd2fff00a9ba70de05c203a5e1722ca7"),
					null,
					"Alice",
					"Bob"
			),

			// https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04#appendix-B.9
			new TestVector(
					JWEAlgorithm.ECDH_1PU_A128KW,
					EncryptionMethod.A256CBC_HS512,
					fromHex("32810896e0fe4d570ed1acfcedf67117dc194ed5daac21d8ff7af3244694897f"),
					fromHex("2157612c9048edfae77cb2e4237140605967c05c7f77a48eeaf2cf29a5737c4a"),
					fromHex("32810896e0fe4d570ed1acfcedf67117dc194ed5daac21d8ff7af3244694897f" +
									"2157612c9048edfae77cb2e4237140605967c05c7f77a48eeaf2cf29a5737c4a"),
					fromHex("df4c37a0668306a11e3d6b0074b5d8df"),
					Base64URL.from("HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ"),
					"Alice",
					"Bob and Charlie"
			),

			// https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04#appendix-B.10
			new TestVector(
					JWEAlgorithm.ECDH_1PU_A128KW,
					EncryptionMethod.A256CBC_HS512,
					fromHex("89dcfe4c37c1dc0271f346b5b3b19c3b705ca2a72f9a237785c34406fcb75f10"),
					fromHex("78fe63fc661cf8d18f92a8422a6418e4ed5e20a9168185fdeedca1c3d8e6a61c"),
					fromHex("89dcfe4c37c1dc0271f346b5b3b19c3b705ca2a72f9a237785c34406fcb75f10" +
							"78fe63fc661cf8d18f92a8422a6418e4ed5e20a9168185fdeedca1c3d8e6a61c"),
					fromHex("57d8126f1b7ec4ccb0584dac03cb27cc"),
					Base64URL.from("HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ"),
					"Alice",
					"Bob and Charlie"
			)
	};

	private static byte[] fromHex(String hex) {
		byte[] result = new byte[hex.length() / 2];
		for (int i=0; i<result.length; i++) {
			result[i] = (byte) Integer.parseInt(hex.substring(2*i, 2*i + 2), 16);
		}
		return result;
	}

	public void testSameCurve() throws Exception {
		ECPrivateKey aliceKeyP_256 = generateECJWK(Curve.P_256).toECPrivateKey();
		ECPublicKey bobKeyP_256 = generateECJWK(Curve.P_256).toECPublicKey();
		ECDH1PU.validateSameCurve(aliceKeyP_256, bobKeyP_256);

		ECPrivateKey aliceKeyP_384 = generateECJWK(Curve.P_384).toECPrivateKey();
		ECPublicKey bobKeyP_384 = generateECJWK(Curve.P_384).toECPublicKey();
		ECDH1PU.validateSameCurve(aliceKeyP_384, bobKeyP_384);

		ECPrivateKey aliceKeyP_521 = generateECJWK(Curve.P_521).toECPrivateKey();
		ECPublicKey bobKeyP_521 = generateECJWK(Curve.P_521).toECPublicKey();
		ECDH1PU.validateSameCurve(aliceKeyP_521, bobKeyP_521);

		OctetKeyPair aliceOKPKey = generateOKP(Curve.X25519);
		OctetKeyPair bobOKPKey = generateOKP(Curve.X25519).toPublicJWK();
		ECDH1PU.validateSameCurve(aliceOKPKey, bobOKPKey);
	}

	public void testCurveNotMatch() throws Exception {
		try {
			ECPrivateKey aliceKeyP_256 = generateECJWK(Curve.P_256).toECPrivateKey();
			ECPublicKey bobKeyP_521 = generateECJWK(Curve.P_521).toECPublicKey();
			ECDH1PU.validateSameCurve(aliceKeyP_256, bobKeyP_521);
			fail();
		} catch (JOSEException e) {
			assertEquals("Curve of public key does not match curve of private key", e.getMessage());
		}

		try {
			OctetKeyPair aliceOKPKey = generateOKP(Curve.X25519);
			OctetKeyPair bobOKPKey = generateOKP(Curve.X25519);
			ECDH1PU.validateSameCurve(aliceOKPKey, bobOKPKey);
			fail();
		} catch (JOSEException e) {
			assertEquals("OKP public key should not be a private key", e.getMessage());
		}

		try {
			OctetKeyPair aliceOKPKey = generateOKP(Curve.X25519).toPublicJWK();
			OctetKeyPair bobOKPKey = generateOKP(Curve.X25519);
			ECDH1PU.validateSameCurve(aliceOKPKey, bobOKPKey);
			fail();
		} catch (JOSEException e) {
			assertEquals("OKP private key should be a private key", e.getMessage());
		}

		try {
			OctetKeyPair aliceOKPKey = generateOKP(Curve.Ed25519);
			OctetKeyPair bobOKPKey = generateOKP(Curve.X25519).toPublicJWK();
			ECDH1PU.validateSameCurve(aliceOKPKey, bobOKPKey);
			fail();
		} catch (JOSEException e) {
			assertEquals("Curve of public key does not match curve of private key", e.getMessage());
		}

		try {
			OctetKeyPair aliceOKPKey = generateOKP(Curve.Ed25519);
			OctetKeyPair bobOKPKey = generateOKP(Curve.Ed25519).toPublicJWK();
			ECDH1PU.validateSameCurve(aliceOKPKey, bobOKPKey);
			fail();
		} catch (JOSEException e) {
			assertEquals("Only supports OctetKeyPairs with crv=X25519", e.getMessage());
		}
	}

	public void test_TestVectors() throws Exception {
		for (TestVector vector : testVectors) {
			SecretKey Ze = new SecretKeySpec(vector.Ze, "AES");
			SecretKey Zs = new SecretKeySpec(vector.Zs, "AES");
			SecretKey Z = ECDH1PU.deriveZ(Ze, Zs);

			assertArrayEquals(vector.expectedZ, Z.getEncoded());

			JWEHeader jwe = new JWEHeader.Builder(vector.algorithm, vector.encryptionMethod)
					.agreementPartyUInfo(Base64URL.encode(vector.apu))
					.agreementPartyVInfo(Base64URL.encode(vector.apv))
					.build();

			if (vector.tag == null) {
				SecretKey sharedKey = ECDH1PU.deriveSharedKey(jwe, Z, new ConcatKDF("SHA-256"));
				assertArrayEquals(vector.expectedSharedKey, sharedKey.getEncoded());
			}

			if (vector.tag != null) {
				SecretKey sharedKey = ECDH1PU.deriveSharedKey(jwe, Z, vector.tag, new ConcatKDF("SHA-256"));
				assertArrayEquals(vector.expectedSharedKey, sharedKey.getEncoded());
			}
		}
	}
}
