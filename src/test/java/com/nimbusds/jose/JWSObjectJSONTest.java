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

package com.nimbusds.jose;


import java.text.ParseException;
import java.util.Collections;
import java.util.Map;

import junit.framework.TestCase;

import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;


/**
 * Tests JWS with JSON general and flattened serialisation.
 *
 * @author Alexander Martynov
 * @author Vladimir Dzhuvinov
 * @version 2021-10-08
 */
public class JWSObjectJSONTest extends TestCase {
	
	
	private static final Payload PAYLOAD = new Payload("Hello, world!");
	
	private static final ECKey EC_JWK;
	
	
	static {
		
		try {
			EC_JWK = new ECKeyGenerator(Curve.SECP256K1)
				.keyID("123")
				.generate();
		} catch (JOSEException e) {
			throw new RuntimeException(e);
		}
	}
	
	private static final OctetKeyPair OKP_JWK;
	
	static {
		try {
			OKP_JWK = new OctetKeyPairGenerator(Curve.Ed25519)
				.keyID("456")
				.generate();
		} catch (JOSEException e) {
			throw new RuntimeException(e);
		}
	}
	
	public void testGeneral_singleSignature()
		throws Exception {
		
		JWSObjectJSON jwsObject = new JWSObjectJSON(PAYLOAD);
		
		assertEquals(PAYLOAD, jwsObject.getPayload());
		assertTrue(jwsObject.getSignatures().isEmpty());
		
		JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.ES256K);
		jwsObject.sign(jwsHeader, null, new ECDSASigner(EC_JWK));
		
		JWSObjectJSON.Signature sig = jwsObject.getSignatures().get(0);
		assertEquals(jwsHeader, sig.getHeader());
		assertNull(sig.getUnprotectedHeader());
		assertEquals(JWSObjectJSON.Signature.State.SIGNED, sig.getState());
		assertTrue(sig.verify(new ECDSAVerifier(EC_JWK.toPublicJWK())));
		assertEquals(JWSObjectJSON.Signature.State.VERIFIED, sig.getState());
		
		assertEquals(1, jwsObject.getSignatures().size());
		
		// Verify signature via compact JWS
		assertTrue(new JWSObject(sig.getHeader().toBase64URL(), PAYLOAD.toBase64URL(), sig.getSignature()).verify(new ECDSAVerifier(EC_JWK.toPublicJWK())));
		
		// Verify general JSON syntax
		Map<String, Object> jsonObject = jwsObject.toGeneralJSONObject();
		
		assertEquals(PAYLOAD.toBase64URL(), JSONObjectUtils.getBase64URL(jsonObject, "payload"));
		
		Map<String, Object>[] signatures = JSONObjectUtils.getJSONObjectArray(jsonObject, "signatures");
		
		assertEquals(sig.getHeader().toBase64URL().toString(), signatures[0].get("protected"));
		assertEquals(sig.getSignature().toString(), signatures[0].get("signature"));
		assertEquals(2, signatures[0].size());
		
		assertEquals(1, signatures.length);
		
		// Verify general JSON syntax
		String json = jwsObject.serializeGeneral();
		jsonObject = JSONObjectUtils.parse(json);
		
		assertEquals(PAYLOAD.toBase64URL(), JSONObjectUtils.getBase64URL(jsonObject, "payload"));
		
		signatures = JSONObjectUtils.getJSONObjectArray(jsonObject, "signatures");
		
		assertEquals(sig.getHeader().toBase64URL().toString(), signatures[0].get("protected"));
		assertEquals(sig.getSignature().toString(), signatures[0].get("signature"));
		assertEquals(2, signatures[0].size());
		
		assertEquals(1, signatures.length);
		
		// Parse general JSON syntax
		jwsObject = JWSObjectJSON.parse(json);
		
		assertEquals(PAYLOAD.toString(), jwsObject.getPayload().toString());
		
		sig = jwsObject.getSignatures().get(0);
		assertEquals(jwsHeader.toJSONObject(), sig.getHeader().toJSONObject());
		assertNull(sig.getUnprotectedHeader());
		assertEquals(JWSObjectJSON.Signature.State.SIGNED, sig.getState());
		assertTrue(sig.verify(new ECDSAVerifier(EC_JWK.toPublicJWK())));
		assertEquals(JWSObjectJSON.Signature.State.VERIFIED, sig.getState());
		
		assertEquals(1, jwsObject.getSignatures().size());
	}
	
	
	public void testGeneral_twoSignatures()
		throws Exception {
		
		JWSObjectJSON jwsObject = new JWSObjectJSON(PAYLOAD);
		
		assertEquals(PAYLOAD, jwsObject.getPayload());
		assertTrue(jwsObject.getSignatures().isEmpty());
		
		JWSHeader jwsHeader1 = new JWSHeader(JWSAlgorithm.ES256K);
		jwsObject.sign(jwsHeader1, null, new ECDSASigner(EC_JWK));
		
		JWSHeader jwsHeader2 = new JWSHeader(JWSAlgorithm.EdDSA);
		jwsObject.sign(jwsHeader2, null, new Ed25519Signer(OKP_JWK));
		
		JWSObjectJSON.Signature sig1 = jwsObject.getSignatures().get(0);
		assertEquals(jwsHeader1, sig1.getHeader());
		assertNull(sig1.getUnprotectedHeader());
		assertEquals(JWSObjectJSON.Signature.State.SIGNED, sig1.getState());
		assertTrue(sig1.verify(new ECDSAVerifier(EC_JWK.toPublicJWK())));
		assertEquals(JWSObjectJSON.Signature.State.VERIFIED, sig1.getState());
		
		JWSObjectJSON.Signature sig2 = jwsObject.getSignatures().get(1);
		assertEquals(jwsHeader2, sig2.getHeader());
		assertNull(sig2.getUnprotectedHeader());
		assertEquals(JWSObjectJSON.Signature.State.SIGNED, sig2.getState());
		assertTrue(sig2.verify(new Ed25519Verifier(OKP_JWK.toPublicJWK())));
		assertEquals(JWSObjectJSON.Signature.State.VERIFIED, sig2.getState());
		
		assertEquals(2, jwsObject.getSignatures().size());
		
		// Verify signatures via compact JWS
		assertTrue(new JWSObject(sig1.getHeader().toBase64URL(), PAYLOAD.toBase64URL(), sig1.getSignature()).verify(new ECDSAVerifier(EC_JWK.toPublicJWK())));
		assertTrue(new JWSObject(sig2.getHeader().toBase64URL(), PAYLOAD.toBase64URL(), sig2.getSignature()).verify(new Ed25519Verifier(OKP_JWK.toPublicJWK())));
		
		// Verify general JSON syntax
		Map<String, Object> jsonObject = jwsObject.toGeneralJSONObject();
		
		assertEquals(PAYLOAD.toBase64URL(), JSONObjectUtils.getBase64URL(jsonObject, "payload"));
		
		Map<String, Object>[] signatures = JSONObjectUtils.getJSONObjectArray(jsonObject, "signatures");
		
		assertEquals(sig1.getHeader().toBase64URL().toString(), signatures[0].get("protected"));
		assertEquals(sig1.getSignature().toString(), signatures[0].get("signature"));
		assertEquals(2, signatures[0].size());
		
		assertEquals(sig2.getHeader().toBase64URL().toString(), signatures[1].get("protected"));
		assertEquals(sig2.getSignature().toString(), signatures[1].get("signature"));
		assertEquals(2, signatures[1].size());
		
		assertEquals(2, signatures.length);
		
		// Verify general JSON syntax
		String json = jwsObject.serializeGeneral();
		jsonObject = JSONObjectUtils.parse(json);
		
		assertEquals(PAYLOAD.toBase64URL(), JSONObjectUtils.getBase64URL(jsonObject, "payload"));
		
		signatures = JSONObjectUtils.getJSONObjectArray(jsonObject, "signatures");
		
		assertEquals(sig1.getHeader().toBase64URL().toString(), signatures[0].get("protected"));
		assertEquals(sig1.getSignature().toString(), signatures[0].get("signature"));
		assertEquals(2, signatures[0].size());
		
		assertEquals(sig2.getHeader().toBase64URL().toString(), signatures[1].get("protected"));
		assertEquals(sig2.getSignature().toString(), signatures[1].get("signature"));
		assertEquals(2, signatures[1].size());
		
		assertEquals(2, signatures.length);
		
		// Parse general JSON syntax
		jwsObject = JWSObjectJSON.parse(json);
		
		assertEquals(PAYLOAD.toString(), jwsObject.getPayload().toString());
		
		sig1 = jwsObject.getSignatures().get(0);
		assertEquals(jwsHeader1.toJSONObject(), sig1.getHeader().toJSONObject());
		assertNull(sig1.getUnprotectedHeader());
		assertEquals(JWSObjectJSON.Signature.State.SIGNED, sig1.getState());
		assertTrue(sig1.verify(new ECDSAVerifier(EC_JWK.toPublicJWK())));
		assertEquals(JWSObjectJSON.Signature.State.VERIFIED, sig1.getState());
		
		sig2 = jwsObject.getSignatures().get(1);
		assertEquals(jwsHeader2.toJSONObject(), sig2.getHeader().toJSONObject());
		assertNull(sig2.getUnprotectedHeader());
		assertEquals(JWSObjectJSON.Signature.State.SIGNED, sig2.getState());
		assertTrue(sig2.verify(new Ed25519Verifier(OKP_JWK.toPublicJWK())));
		assertEquals(JWSObjectJSON.Signature.State.VERIFIED, sig2.getState());
		
		assertEquals(2, jwsObject.getSignatures().size());
	}
	
	
	public void testGeneral_twoSignatures_unprotectedHeader()
		throws Exception {
		
		JWSObjectJSON jwsObject = new JWSObjectJSON(PAYLOAD);
		
		assertEquals(PAYLOAD, jwsObject.getPayload());
		assertTrue(jwsObject.getSignatures().isEmpty());
		
		JWSHeader jwsHeader1 = new JWSHeader(JWSAlgorithm.ES256K);
		UnprotectedHeader unprotectedHeader1 = new UnprotectedHeader.Builder()
			.keyID(EC_JWK.getKeyID())
			.build();
		jwsObject.sign(jwsHeader1, unprotectedHeader1, new ECDSASigner(EC_JWK));
		
		JWSHeader jwsHeader2 = new JWSHeader(JWSAlgorithm.EdDSA);
		UnprotectedHeader unprotectedHeader2 = new UnprotectedHeader.Builder()
			.keyID(OKP_JWK.getKeyID())
			.build();
		jwsObject.sign(jwsHeader2, unprotectedHeader2, new Ed25519Signer(OKP_JWK));
		
		JWSObjectJSON.Signature sig1 = jwsObject.getSignatures().get(0);
		assertEquals(jwsHeader1, sig1.getHeader());
		assertEquals(unprotectedHeader1, sig1.getUnprotectedHeader());
		assertEquals(JWSObjectJSON.Signature.State.SIGNED, sig1.getState());
		assertTrue(sig1.verify(new ECDSAVerifier(EC_JWK.toPublicJWK())));
		assertEquals(JWSObjectJSON.Signature.State.VERIFIED, sig1.getState());
		
		JWSObjectJSON.Signature sig2 = jwsObject.getSignatures().get(1);
		assertEquals(jwsHeader2, sig2.getHeader());
		assertEquals(unprotectedHeader2, sig2.getUnprotectedHeader());
		assertEquals(JWSObjectJSON.Signature.State.SIGNED, sig2.getState());
		assertTrue(sig2.verify(new Ed25519Verifier(OKP_JWK.toPublicJWK())));
		assertEquals(JWSObjectJSON.Signature.State.VERIFIED, sig2.getState());
		
		assertEquals(2, jwsObject.getSignatures().size());
		
		// Verify signatures via compact JWS
		assertTrue(new JWSObject(sig1.getHeader().toBase64URL(), PAYLOAD.toBase64URL(), sig1.getSignature()).verify(new ECDSAVerifier(EC_JWK.toPublicJWK())));
		assertTrue(new JWSObject(sig2.getHeader().toBase64URL(), PAYLOAD.toBase64URL(), sig2.getSignature()).verify(new Ed25519Verifier(OKP_JWK.toPublicJWK())));
		
		// Verify general JSON syntax
		Map<String, Object> jsonObject = jwsObject.toGeneralJSONObject();
		
		assertEquals(PAYLOAD.toBase64URL(), JSONObjectUtils.getBase64URL(jsonObject, "payload"));
		
		Map<String, Object>[] signatures = JSONObjectUtils.getJSONObjectArray(jsonObject, "signatures");
		
		assertEquals(sig1.getHeader().toBase64URL().toString(), signatures[0].get("protected"));
		assertEquals(sig1.getUnprotectedHeader().toJSONObject(), signatures[0].get("header"));
		assertEquals(sig1.getSignature().toString(), signatures[0].get("signature"));
		assertEquals(3, signatures[0].size());
		
		assertEquals(sig2.getHeader().toBase64URL().toString(), signatures[1].get("protected"));
		assertEquals(sig2.getUnprotectedHeader().toJSONObject(), signatures[1].get("header"));
		assertEquals(sig2.getSignature().toString(), signatures[1].get("signature"));
		assertEquals(3, signatures[1].size());
		
		assertEquals(2, signatures.length);
		
		// Verify general JSON syntax
		String json = jwsObject.serializeGeneral();
		jsonObject = JSONObjectUtils.parse(json);
		
		assertEquals(PAYLOAD.toBase64URL(), JSONObjectUtils.getBase64URL(jsonObject, "payload"));
		
		signatures = JSONObjectUtils.getJSONObjectArray(jsonObject, "signatures");
		
		assertEquals(sig1.getHeader().toBase64URL().toString(), signatures[0].get("protected"));
		assertEquals(sig1.getUnprotectedHeader().toJSONObject(), signatures[0].get("header"));
		assertEquals(sig1.getSignature().toString(), signatures[0].get("signature"));
		assertEquals(3, signatures[0].size());
		
		assertEquals(sig2.getHeader().toBase64URL().toString(), signatures[1].get("protected"));
		assertEquals(sig2.getUnprotectedHeader().toJSONObject(), signatures[1].get("header"));
		assertEquals(sig2.getSignature().toString(), signatures[1].get("signature"));
		assertEquals(3, signatures[1].size());
		
		assertEquals(2, signatures.length);
		
		// Parse general JSON syntax
		jwsObject = JWSObjectJSON.parse(json);
		
		assertEquals(PAYLOAD.toString(), jwsObject.getPayload().toString());
		
		sig1 = jwsObject.getSignatures().get(0);
		assertEquals(jwsHeader1.toJSONObject(), sig1.getHeader().toJSONObject());
		assertEquals(unprotectedHeader1.toJSONObject(), sig1.getUnprotectedHeader().toJSONObject());
		assertEquals(JWSObjectJSON.Signature.State.SIGNED, sig1.getState());
		assertTrue(sig1.verify(new ECDSAVerifier(EC_JWK.toPublicJWK())));
		assertEquals(JWSObjectJSON.Signature.State.VERIFIED, sig1.getState());
		
		sig2 = jwsObject.getSignatures().get(1);
		assertEquals(jwsHeader2.toJSONObject(), sig2.getHeader().toJSONObject());
		assertEquals(unprotectedHeader2.toJSONObject(), sig2.getUnprotectedHeader().toJSONObject());
		assertEquals(JWSObjectJSON.Signature.State.SIGNED, sig2.getState());
		assertTrue(sig2.verify(new Ed25519Verifier(OKP_JWK.toPublicJWK())));
		assertEquals(JWSObjectJSON.Signature.State.VERIFIED, sig2.getState());
		
		assertEquals(2, jwsObject.getSignatures().size());
	}
	
	
	public void testFlattened()
		throws Exception {
		
		JWSObjectJSON jwsObject = new JWSObjectJSON(PAYLOAD);
		
		assertEquals(PAYLOAD, jwsObject.getPayload());
		assertTrue(jwsObject.getSignatures().isEmpty());
		
		JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.ES256K);
		jwsObject.sign(jwsHeader, null, new ECDSASigner(EC_JWK));
		
		JWSObjectJSON.Signature sig = jwsObject.getSignatures().get(0);
		assertEquals(jwsHeader, sig.getHeader());
		assertNull(sig.getUnprotectedHeader());
		assertEquals(JWSObjectJSON.Signature.State.SIGNED, sig.getState());
		assertTrue(sig.verify(new ECDSAVerifier(EC_JWK.toPublicJWK())));
		assertEquals(JWSObjectJSON.Signature.State.VERIFIED, sig.getState());
		
		assertEquals(1, jwsObject.getSignatures().size());
		
		// Verify signature via compact JWS
		assertTrue(new JWSObject(sig.getHeader().toBase64URL(), PAYLOAD.toBase64URL(), sig.getSignature()).verify(new ECDSAVerifier(EC_JWK.toPublicJWK())));
		
		// Verify flattened JSON syntax
		Map<String, Object> jsonObject = jwsObject.toFlattenedJSONObject();
		
		assertEquals(PAYLOAD.toBase64URL(), JSONObjectUtils.getBase64URL(jsonObject, "payload"));
		assertEquals(sig.getHeader().toBase64URL(), JSONObjectUtils.getBase64URL(jsonObject, "protected"));
		assertEquals(sig.getSignature(), JSONObjectUtils.getBase64URL(jsonObject, "signature"));
		assertEquals(3, jsonObject.size());
		
		// Verify general JSON syntax
		String json = jwsObject.serializeFlattened();
		jsonObject = JSONObjectUtils.parse(json);
		
		assertEquals(PAYLOAD.toBase64URL(), JSONObjectUtils.getBase64URL(jsonObject, "payload"));
		assertEquals(sig.getHeader().toBase64URL(), JSONObjectUtils.getBase64URL(jsonObject, "protected"));
		assertEquals(sig.getSignature(), JSONObjectUtils.getBase64URL(jsonObject, "signature"));
		assertEquals(3, jsonObject.size());
		
		// Parse flattened JSON syntax
		jwsObject = JWSObjectJSON.parse(json);
		
		assertEquals(PAYLOAD.toString(), jwsObject.getPayload().toString());
		
		sig = jwsObject.getSignatures().get(0);
		assertEquals(jwsHeader.toJSONObject(), sig.getHeader().toJSONObject());
		assertNull(sig.getUnprotectedHeader());
		assertEquals(JWSObjectJSON.Signature.State.SIGNED, sig.getState());
		assertTrue(sig.verify(new ECDSAVerifier(EC_JWK.toPublicJWK())));
		assertEquals(JWSObjectJSON.Signature.State.VERIFIED, sig.getState());
		
		assertEquals(1, jwsObject.getSignatures().size());
	}
	
	
	public void testFlattened_unprotectedHeader()
		throws Exception {
		
		JWSObjectJSON jwsObject = new JWSObjectJSON(PAYLOAD);
		
		assertEquals(PAYLOAD, jwsObject.getPayload());
		assertTrue(jwsObject.getSignatures().isEmpty());
		
		JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.ES256K);
		UnprotectedHeader unprotectedHeader = new UnprotectedHeader.Builder()
			.keyID(EC_JWK.getKeyID())
			.build();
		jwsObject.sign(jwsHeader, unprotectedHeader, new ECDSASigner(EC_JWK));
		
		JWSObjectJSON.Signature sig = jwsObject.getSignatures().get(0);
		assertEquals(jwsHeader, sig.getHeader());
		assertEquals(unprotectedHeader, sig.getUnprotectedHeader());
		assertEquals(JWSObjectJSON.Signature.State.SIGNED, sig.getState());
		assertTrue(sig.verify(new ECDSAVerifier(EC_JWK.toPublicJWK())));
		assertEquals(JWSObjectJSON.Signature.State.VERIFIED, sig.getState());
		
		assertEquals(1, jwsObject.getSignatures().size());
		
		// Verify signature via compact JWS
		assertTrue(new JWSObject(sig.getHeader().toBase64URL(), PAYLOAD.toBase64URL(), sig.getSignature()).verify(new ECDSAVerifier(EC_JWK.toPublicJWK())));
		
		// Verify flattened JSON syntax
		Map<String, Object> jsonObject = jwsObject.toFlattenedJSONObject();
		
		assertEquals(PAYLOAD.toBase64URL(), JSONObjectUtils.getBase64URL(jsonObject, "payload"));
		assertEquals(sig.getHeader().toBase64URL(), JSONObjectUtils.getBase64URL(jsonObject, "protected"));
		assertEquals(sig.getUnprotectedHeader().toJSONObject(), JSONObjectUtils.getJSONObject(jsonObject, "header"));
		assertEquals(sig.getSignature(), JSONObjectUtils.getBase64URL(jsonObject, "signature"));
		assertEquals(4, jsonObject.size());
		
		// Verify general JSON syntax
		String json = jwsObject.serializeFlattened();
		jsonObject = JSONObjectUtils.parse(json);

		assertEquals(PAYLOAD.toBase64URL(), JSONObjectUtils.getBase64URL(jsonObject, "payload"));
		assertEquals(sig.getHeader().toBase64URL(), JSONObjectUtils.getBase64URL(jsonObject, "protected"));
		assertEquals(sig.getUnprotectedHeader().toJSONObject(), JSONObjectUtils.getJSONObject(jsonObject, "header"));
		assertEquals(sig.getSignature(), JSONObjectUtils.getBase64URL(jsonObject, "signature"));
		assertEquals(4, jsonObject.size());
		
		// Parse flattened JSON syntax
		jwsObject = JWSObjectJSON.parse(json);
		
		assertEquals(PAYLOAD.toString(), jwsObject.getPayload().toString());
		
		sig = jwsObject.getSignatures().get(0);
		assertEquals(jwsHeader.toJSONObject(), sig.getHeader().toJSONObject());
		assertEquals(unprotectedHeader.toJSONObject(), sig.getUnprotectedHeader().toJSONObject());
		assertEquals(JWSObjectJSON.Signature.State.SIGNED, sig.getState());
		assertTrue(sig.verify(new ECDSAVerifier(EC_JWK.toPublicJWK())));
		assertEquals(JWSObjectJSON.Signature.State.VERIFIED, sig.getState());
		
		assertEquals(1, jwsObject.getSignatures().size());
	}
	
	
	public void testFlattened_moreThanOneSignature()
		throws JOSEException {
		
		JWSObjectJSON jwsObject = new JWSObjectJSON(PAYLOAD);
		
		jwsObject.sign(new JWSHeader(JWSAlgorithm.ES256K), null, new ECDSASigner(EC_JWK));
		jwsObject.sign(new JWSHeader(JWSAlgorithm.EdDSA), null, new Ed25519Signer(OKP_JWK));
		
		assertEquals(2, jwsObject.getSignatures().size());
		
		try {
			jwsObject.toFlattenedJSONObject();
			fail();
		} catch (IllegalStateException e) {
			assertEquals("The flattened JWS JSON serialization requires exactly one signature", e.getMessage());
		}
		
		try {
			jwsObject.serializeFlattened();
			fail();
		} catch (IllegalStateException e) {
			assertEquals("The flattened JWS JSON serialization requires exactly one signature", e.getMessage());
		}
	}
	
	
	// see https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.7
	public void testParseJWSGeneral_RFC_Example_Appendix()
		throws Exception {
		
		RSAKey rsaJWK = RSAKey.parse(
			"{" +
				"\"kty\":\"RSA\"," +
				"\"n\":\"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx" +
				"HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs" +
				"D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH" +
				"SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV" +
				"MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8" +
				"NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ\"," +
				"\"e\":\"AQAB\"," +
				"\"d\":\"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I" +
				"jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0" +
				"BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn" +
				"439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT" +
				"CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh" +
				"BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ\"," +
				"\"p\":\"4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdi" +
				"YrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPG" +
				"BY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc\"," +
				"\"q\":\"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxa" +
				"ewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA" +
				"-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc\"," +
				"\"dp\":\"BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3Q" +
				"CLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb" +
				"34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0\"," +
				"\"dq\":\"h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa" +
				"7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-ky" +
				"NlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU\"," +
				"\"qi\":\"IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2o" +
				"y26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLU" +
				"W0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U\"" +
				"}");
		
		ECKey ecJWK = ECKey.parse(
			"{" +
				"\"kty\":\"EC\"," +
				"\"crv\":\"P-256\"," +
				"\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\"," +
				"\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"," +
				"\"d\":\"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI\"" +
				"}"
		);
		
		JWSObjectJSON jwsObjectJSON = JWSObjectJSON.parse(
			"{" +
				"\"payload\":\"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ\"," +
				"\"signatures\":[" +
				"{\"protected\":\"eyJhbGciOiJSUzI1NiJ9\"," +
				"\"header\":{\"kid\":\"2010-12-29\"}," +
				"\"signature\":\"cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZ" +
				"mh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjb" +
				"KBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHl" +
				"b1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZES" +
				"c6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AX" +
				"LIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw\"}," +
				"{\"protected\":\"eyJhbGciOiJFUzI1NiJ9\"," +
				"\"header\":{\"kid\":\"e9bc097a-ce51-4036-9562-d2ade882db0d\"}," +
				"\"signature\":\"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q\"}" +
				"]" +
				"}"
		);
		
		Map<String, Object> expectedPayload = JSONObjectUtils.parse(
			"{" +
				"\"iss\":\"joe\",\n" +
				"\"exp\":1300819380,\n" +
				"\"http://example.com/is_root\":true" +
				"}"
		);
		
		assertEquals(expectedPayload, jwsObjectJSON.getPayload().toJSONObject());
		
		assertEquals(2, jwsObjectJSON.getSignatures().size());
		
		// First RSA signature
		JWSObjectJSON.Signature sig_1 = jwsObjectJSON.getSignatures().get(0);
		
		assertEquals(JWSAlgorithm.RS256, sig_1.getHeader().getAlgorithm());
		assertEquals(Collections.singleton("alg"), sig_1.getHeader().getIncludedParams());
		
		assertEquals("2010-12-29", sig_1.getUnprotectedHeader().getKeyID());
		assertEquals(Collections.singleton("kid"), sig_1.getUnprotectedHeader().getIncludedParams());
		
		assertEquals(
			new Base64URL(
				"cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZ" +
					"mh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjb" +
					"KBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHl" +
					"b1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZES" +
					"c6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AX" +
					"LIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"),
			sig_1.getSignature()
		);
		
		assertTrue(sig_1.verify(new RSASSAVerifier(rsaJWK.toRSAPublicKey())));
		
		// Second EC signature
		JWSObjectJSON.Signature sig_2 = jwsObjectJSON.getSignatures().get(1);
		
		assertEquals(JWSAlgorithm.ES256, sig_2.getHeader().getAlgorithm());
		assertEquals(Collections.singleton("alg"), sig_2.getHeader().getIncludedParams());
		
		assertEquals("e9bc097a-ce51-4036-9562-d2ade882db0d", sig_2.getUnprotectedHeader().getKeyID());
		assertEquals(Collections.singleton("kid"), sig_2.getUnprotectedHeader().getIncludedParams());
		
		assertEquals(
			new Base64URL("DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"),
			sig_2.getSignature()
		);
		
		assertTrue(sig_2.verify(new ECDSAVerifier(ecJWK.toECPublicKey())));
	}
	
	
	// see https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.7
	public void testParseJWSFlattened_RFC_Example_Appendix()
		throws Exception {
		
		ECKey key = ECKey.parse(
			"{" +
				"\"kty\":\"EC\"," +
				"\"crv\":\"P-256\"," +
				"\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\"," +
				"\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"," +
				"\"d\":\"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI\"" +
				"}"
		);
		
		JWSObjectJSON jwsObjectJSON = JWSObjectJSON.parse(
			"{" +
				"\"payload\":\"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ\"," +
				"\"protected\":\"eyJhbGciOiJFUzI1NiJ9\"," +
				"\"header\":{\"kid\":\"e9bc097a-ce51-4036-9562-d2ade882db0d\"}," +
				"\"signature\":\"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q\"" +
				"}"
		);
		
		Map<String, Object> expectedPayload = JSONObjectUtils.parse(
			"{" +
				"\"iss\":\"joe\",\n" +
				"\"exp\":1300819380,\n" +
				"\"http://example.com/is_root\":true" +
				"}"
		);
		
		assertEquals(expectedPayload, jwsObjectJSON.getPayload().toJSONObject());
		
		assertEquals(1, jwsObjectJSON.getSignatures().size());
		
		JWSObjectJSON.Signature sig = jwsObjectJSON.getSignatures().get(0);
		
		assertEquals(JWSAlgorithm.ES256, sig.getHeader().getAlgorithm());
		assertEquals(Collections.singleton("alg"), sig.getHeader().getIncludedParams());
		
		assertEquals("e9bc097a-ce51-4036-9562-d2ade882db0d", sig.getUnprotectedHeader().getKeyID());
		assertEquals(Collections.singleton("kid"), sig.getUnprotectedHeader().getIncludedParams());
		
		assertEquals(
			new Base64URL("DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"),
			sig.getSignature()
		);
		
		assertTrue(sig.verify(new ECDSAVerifier(key.toECPublicKey())));
	}
	
	
	public void testSignatureStatesEnum() {
		
		assertEquals(2, JWSObjectJSON.Signature.State.values().length);
	}
	
	
	public void testConstructor_null_Payload() {
		
		try {
			new JWSObjectJSON(null);
			fail();
		} catch (NullPointerException e) {
			assertEquals("The payload must not be null", e.getMessage());
		}
	}
	
	
	public void testNoSignature_preventSerialize() {
		
		JWSObjectJSON jwsObject = new JWSObjectJSON(PAYLOAD);
		
		assertTrue(jwsObject.getSignatures().isEmpty());
		
		try {
			jwsObject.toGeneralJSONObject();
			fail();
		} catch (IllegalStateException e) {
			assertEquals("The general JWS JSON serialization requires at least one signature", e.getMessage());
		}
		
		try {
			jwsObject.toFlattenedJSONObject();
			fail();
		} catch (IllegalStateException e) {
			assertEquals("The flattened JWS JSON serialization requires exactly one signature", e.getMessage());
		}
		
		try {
			jwsObject.serializeGeneral();
			fail();
		} catch (IllegalStateException e) {
			assertEquals("The general JWS JSON serialization requires at least one signature", e.getMessage());
		}
		
		try {
			jwsObject.serializeFlattened();
			fail();
		} catch (IllegalStateException e) {
			assertEquals("The flattened JWS JSON serialization requires exactly one signature", e.getMessage());
		}
	}
	
	
	public void testPreventSignWhenHeaderParameterNamesIntersect()
		throws JOSEException {
		
		JWSObjectJSON jwsObject = new JWSObjectJSON(PAYLOAD);
		
		assertEquals(PAYLOAD, jwsObject.getPayload());
		assertTrue(jwsObject.getSignatures().isEmpty());
		
		JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.ES256K)
			.keyID(EC_JWK.getKeyID())
			.build();
		UnprotectedHeader unprotectedHeader = new UnprotectedHeader.Builder()
			.keyID(EC_JWK.getKeyID())
			.build();
		
		try {
			jwsObject.sign(jwsHeader, unprotectedHeader, new ECDSASigner(EC_JWK));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The parameters in the JWS protected header and the unprotected header must be disjoint", e.getMessage());
		}
	}
	
	
	public void testParse_headerParameterNamesIntersect()
		throws JOSEException {
		
		JWSObjectJSON jwsObject = new JWSObjectJSON(PAYLOAD);
		
		assertEquals(PAYLOAD, jwsObject.getPayload());
		assertTrue(jwsObject.getSignatures().isEmpty());
		
		JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.ES256K)
			.keyID(EC_JWK.getKeyID())
			.build();
		
		jwsObject.sign(jwsHeader, null, new ECDSASigner(EC_JWK));
		
		Map<String, Object> jsonObject = jwsObject.toFlattenedJSONObject();
		
		// Add unprotected header
		UnprotectedHeader unprotectedHeader = new UnprotectedHeader.Builder()
			.keyID(EC_JWK.getKeyID())
			.build();
		
		jsonObject.put("header", unprotectedHeader.toJSONObject());
		
		String json = JSONObjectUtils.toJSONString(jsonObject);
		
		try {
			JWSObjectJSON.parse(json);
			fail();
		} catch (ParseException e) {
			assertEquals("The parameters in the JWS protected header and the unprotected header must be disjoint", e.getMessage());
		}
	}
}