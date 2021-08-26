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


import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.util.JSONObjectUtils;
import junit.framework.TestCase;

import java.security.interfaces.ECPrivateKey;
import java.util.Map;


/**
 * Tests JWS JSON Serialization object methods.
 *
 * @author Alexander Martynov
 * @version 2021-08-17
 */
public class JWSObjectJSONTest extends TestCase {

    public void testJSONObjectSerializationGeneral() throws Exception {
        JWSHeader header = new JWSHeader(JWSAlgorithm.ES256K);
        JWSObjectJSON jwsObject = new JWSObjectJSON(header, new Payload("Hello world!"));

        ECPrivateKey privateKey = new ECKeyGenerator(Curve.SECP256K1).generate().toECPrivateKey();
        jwsObject.sign(new ECDSASigner(privateKey));

        Map<String, Object> json = jwsObject.toGeneralJSONObject();
        Map<String, Object>[] signatures = JSONObjectUtils.getJSONObjectArray(json, "signatures");
        assertNotNull(signatures);

        // support single signature
        assertEquals(1, signatures.length);

        Map<String, Object> signature = signatures[0];
        assertEquals(jwsObject.getHeader().toBase64URL().toString(), signature.get("protected").toString());
        assertEquals(jwsObject.getPayload().toBase64URL().toString(), json.get("payload").toString());
        assertEquals(jwsObject.getSignature().toString(), signature.get("signature").toString());
    }

    public void testJSONObjectSerializationGeneral_UH() throws Exception {
        JWSHeader header = new JWSHeader(JWSAlgorithm.EdDSA);
        JWSObjectJSON jwsObject = new JWSObjectJSON(header, new Payload("Hello world!"));

        UnprotectedHeader uh = new UnprotectedHeader.Builder()
                .keyID("123345")
                .build();

        OctetKeyPair privateKey = new OctetKeyPairGenerator(Curve.Ed25519).generate();
        jwsObject.sign(uh, new Ed25519Signer(privateKey));

        Map<String, Object> json = jwsObject.toGeneralJSONObject();
        Map<String, Object>[] signatures = JSONObjectUtils.getJSONObjectArray(json, "signatures");
        assertNotNull(signatures);

        // support single signature
        assertEquals(1, signatures.length);

        Map<String, Object> signature = signatures[0];
        Map<String, Object> signatureUH = JSONObjectUtils.getJSONObject(signature, "header");
        assertNotNull(signatureUH);

        assertEquals(jwsObject.getHeader().toBase64URL().toString(), signature.get("protected").toString());
        assertEquals(jwsObject.getPayload().toBase64URL().toString(), json.get("payload").toString());
        assertEquals(jwsObject.getSignature().toString(), signature.get("signature").toString());
        assertEquals(jwsObject.getUnprotectedHeader().getKeyID(), signatureUH.get("kid").toString());
    }

    public void testJSONObjectSerializationFlattened() throws Exception {
        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
        JWSObjectJSON jwsObject = new JWSObjectJSON(header, new Payload("Hello world!"));

        jwsObject.sign(new MACSigner("12345678901234567890123456789012"));

        Map<String, Object> json = jwsObject.toFlattenedJSONObject();
        assertEquals(jwsObject.getHeader().toBase64URL().toString(), json.get("protected").toString());
        assertEquals(jwsObject.getPayload().toBase64URL().toString(), json.get("payload").toString());
        assertEquals(jwsObject.getSignature().toString(), json.get("signature").toString());
    }

    public void testJSONSerializationAndParse() throws Exception {
        Map<String, Object> jsonPayload = JSONObjectUtils.parse("{\"iss\":\"joe\",\n" +
                "      \"exp\":1300819380,\n" +
                "      \"http://example.com/is_root\":true}");

        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
        JWSObjectJSON jwsObject = new JWSObjectJSON(header, new Payload(jsonPayload));

        OctetSequenceKey jwk = new OctetSequenceKeyGenerator(256).generate();
        jwsObject.sign(new MACSigner(jwk));

        String json = jwsObject.serialize();
        assertNotNull(json);

        JWSObjectJSON parsed = JWSObjectJSON.parse(json);
        assertTrue(jwsObject.verify(new MACVerifier(jwk)));

        assertEquals(jwsObject.getHeader().toBase64URL(), parsed.getHeader().toBase64URL());
        assertEquals(jwsObject.getPayload().toBase64URL(), parsed.getPayload().toBase64URL());
        assertEquals(jwsObject.getSignature(), parsed.getSignature());
    }

    // see https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.7
    public void test_flattened_appendix() throws Exception {
        ECKey key = ECKey.parse("{\"kty\":\"EC\",\n" +
                "      \"crv\":\"P-256\",\n" +
                "      \"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\n" +
                "      \"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\",\n" +
                "      \"d\":\"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI\"\n" +
                "     }");

        JWSObjectJSON jwsObjectJSON = JWSObjectJSON.parse("{" +
                "      \"payload\":" +
                "       \"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ\"," +
                "      \"protected\":\"eyJhbGciOiJFUzI1NiJ9\"," +
                "      \"header\":" +
                "       {\"kid\":\"e9bc097a-ce51-4036-9562-d2ade882db0d\"}," +
                "      \"signature\":" +
                "       \"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q\"" +
                "     }");

        assertTrue(jwsObjectJSON.verify(new ECDSAVerifier(key.toECPublicKey())));
    }
}