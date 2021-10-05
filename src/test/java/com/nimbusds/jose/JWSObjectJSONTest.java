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


import java.util.Collections;
import java.util.Map;

import junit.framework.TestCase;

import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;


/**
 * Tests JWS with JSON general and flattened serialisation.
 *
 * @author Alexander Martynov
 * @author Vladimir Dzhuvinov
 * @version 2021-10-05
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
	public void testParseFlattened_RFC_Example_Appendix()
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
			"  \"payload\":\"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ\"," +
			"  \"protected\":\"eyJhbGciOiJFUzI1NiJ9\"," +
			"  \"header\":{\"kid\":\"e9bc097a-ce51-4036-9562-d2ade882db0d\"}," +
			"  \"signature\":\"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q\"" +
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
		
		assertEquals(JWSAlgorithm.ES256, jwsObjectJSON.getSignatures().get(0).getHeader().getAlgorithm());
		assertEquals(Collections.singleton("alg"), jwsObjectJSON.getSignatures().get(0).getHeader().getIncludedParams());
		
		assertEquals("e9bc097a-ce51-4036-9562-d2ade882db0d", jwsObjectJSON.getSignatures().get(0).getUnprotectedHeader().getKeyID());
		assertEquals(Collections.singleton("kid"), jwsObjectJSON.getSignatures().get(0).getUnprotectedHeader().getIncludedParams());

		assertEquals(
			new Base64URL("DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"),
			jwsObjectJSON.getSignatures().get(0).getSignature()
		);
		
		assertTrue(jwsObjectJSON.getSignatures().get(0).verify(new ECDSAVerifier(key.toECPublicKey())));
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
}