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


import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import junit.framework.TestCase;

import java.util.Map;


/**
 * Tests JWS JSON Serialization object methods.
 *
 * @author Alexander Martynov
 * @version 2021-08-17
 */
public class JJWSObjectTest extends TestCase {
    
    public void testJSONObjectSerialization() throws Exception {
        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
        JJWSObject jwsObject = new JJWSObject(header, new Payload("Hello world!"));

        jwsObject.sign(new MACSigner("12345678901234567890123456789012"));

        Map<String, Object> json = jwsObject.toJSONObject();
        assertEquals(jwsObject.getHeader().toBase64URL(), json.get("protected"));
        assertEquals(jwsObject.getPayload().toBase64URL(), json.get("payload"));
        assertEquals(jwsObject.getSignature(), json.get("signature"));
    }

    public void testJSONSerializationAndParse() throws Exception {
        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
        JJWSObject jwsObject = new JJWSObject(header, new Payload("Hello world!"));

        OctetSequenceKey jwk = new OctetSequenceKeyGenerator(256).generate();
        jwsObject.sign(new MACSigner(jwk));

        String json = jwsObject.toJSONString();
        assertNotNull(json);

        JJWSObject parsed = JJWSObject.parse(json);
        assertTrue(jwsObject.verify(new MACVerifier(jwk)));

        assertEquals(jwsObject.getHeader().toBase64URL(), parsed.getHeader().toBase64URL());
        assertEquals(jwsObject.getPayload().toBase64URL(), parsed.getPayload().toBase64URL());
        assertEquals(jwsObject.getSignature(), parsed.getSignature());
    }
}