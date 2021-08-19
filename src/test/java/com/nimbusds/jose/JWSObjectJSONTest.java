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


import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.util.JSONObjectUtils;
import junit.framework.TestCase;

import java.security.interfaces.ECPrivateKey;
import java.util.List;
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

        Map<String, Object> json = jwsObject.toJSONObject(false);
        Map<String, Object>[] signatures = JSONObjectUtils.getJSONObjectArray(json, "signatures");
        assertNotNull(signatures);

        // support single signature
        assertEquals(1, signatures.length);

        Map<String, Object> signature = signatures[0];
        assertEquals(jwsObject.getHeader().toBase64URL().toString(), signature.get("protected").toString());
        assertEquals(jwsObject.getPayload().toBase64URL().toString(), json.get("payload").toString());
        assertEquals(jwsObject.getSignature().toString(), signature.get("signature").toString());
    }

    public void testJSONObjectSerializationFlattened() throws Exception {
        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
        JWSObjectJSON jwsObject = new JWSObjectJSON(header, new Payload("Hello world!"));

        jwsObject.sign(new MACSigner("12345678901234567890123456789012"));

        Map<String, Object> json = jwsObject.toJSONObject(true);
        assertEquals(jwsObject.getHeader().toBase64URL().toString(), json.get("protected").toString());
        assertEquals(jwsObject.getPayload().toBase64URL().toString(), json.get("payload").toString());
        assertEquals(jwsObject.getSignature().toString(), json.get("signature").toString());
    }

    public void testJSONSerializationAndParse() throws Exception {
        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
        JWSObjectJSON jwsObject = new JWSObjectJSON(header, new Payload("Hello world!"));

        OctetSequenceKey jwk = new OctetSequenceKeyGenerator(256).generate();
        jwsObject.sign(new MACSigner(jwk));

        String json = jwsObject.toString();
        assertNotNull(json);

        JWSObjectJSON parsed = JWSObjectJSON.parse(json);
        assertTrue(jwsObject.verify(new MACVerifier(jwk)));

        assertEquals(jwsObject.getHeader().toBase64URL(), parsed.getHeader().toBase64URL());
        assertEquals(jwsObject.getPayload().toBase64URL(), parsed.getPayload().toBase64URL());
        assertEquals(jwsObject.getSignature(), parsed.getSignature());
    }
}