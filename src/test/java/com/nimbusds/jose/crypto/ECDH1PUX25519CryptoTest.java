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


import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimNames;
import junit.framework.TestCase;

import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.util.Collections;


/**
 * Tests X25519 ECDH-1PU encryption and decryption.
 *
 * @author Alexander Martynov
 * @version 2021-08-04
 */
public class ECDH1PUX25519CryptoTest extends TestCase {


    private static OctetKeyPair generateOKP(Curve curve) {

        try {
            return new OctetKeyPairGenerator(curve).generate();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    private static class CycleTest {
        public Curve curve;
        public JWEAlgorithm algorithm;
        public EncryptionMethod encryptionMethod;

        public CycleTest(JWEAlgorithm algorithm, Curve curve, EncryptionMethod encryptionMethod) {
            this.curve = curve;
            this.algorithm = algorithm;
            this.encryptionMethod = encryptionMethod;
        }
    }

    private static class CurveTest {
        public OctetKeyPair aliceKey;
        public OctetKeyPair bobKey;
        public OctetKeyPair aliceWrongKey;
        public OctetKeyPair bobWrongKey;
        public String expectedMessage;

        public CurveTest(OctetKeyPair aliceKey,
                         OctetKeyPair bobKey,
                         OctetKeyPair aliceWrongKey,
                         OctetKeyPair bobWrongKey,
                         String expectedMessage) {
            this.aliceKey = aliceKey;
            this.bobKey = bobKey;
            this.aliceWrongKey = aliceWrongKey;
            this.bobWrongKey = bobWrongKey;
            this.expectedMessage = expectedMessage;
        }
    }

    private static final CurveTest[] notMatchedCurves = new CurveTest[]{
            new CurveTest(
                    generateOKP(Curve.X25519),
                    generateOKP(Curve.X25519).toPublicJWK(),
                    generateOKP(Curve.X25519),
                    generateOKP(Curve.X25519),
                    "OKP public key should not be a private key"
            ),

            new CurveTest(
                    generateOKP(Curve.X25519),
                    generateOKP(Curve.X25519).toPublicJWK(),
                    generateOKP(Curve.X25519).toPublicJWK(),
                    generateOKP(Curve.X25519).toPublicJWK(),
                    "OKP private key should be a private key"
            )
    };

    private static final CycleTest[] allowedCycles = new CycleTest[]{
            new CycleTest(JWEAlgorithm.ECDH_1PU, Curve.X25519, EncryptionMethod.A128CBC_HS256),
            new CycleTest(JWEAlgorithm.ECDH_1PU, Curve.X25519, EncryptionMethod.A192CBC_HS384),
            new CycleTest(JWEAlgorithm.ECDH_1PU, Curve.X25519, EncryptionMethod.A256CBC_HS512),
            new CycleTest(JWEAlgorithm.ECDH_1PU, Curve.X25519, EncryptionMethod.A128GCM),
            new CycleTest(JWEAlgorithm.ECDH_1PU, Curve.X25519, EncryptionMethod.A192GCM),
            new CycleTest(JWEAlgorithm.ECDH_1PU, Curve.X25519, EncryptionMethod.A256GCM),
            new CycleTest(JWEAlgorithm.ECDH_1PU, Curve.X25519, EncryptionMethod.XC20P),

            new CycleTest(JWEAlgorithm.ECDH_1PU_A128KW, Curve.X25519, EncryptionMethod.A128CBC_HS256),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A128KW, Curve.X25519, EncryptionMethod.A192CBC_HS384),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A128KW, Curve.X25519, EncryptionMethod.A256CBC_HS512),

            new CycleTest(JWEAlgorithm.ECDH_1PU_A192KW, Curve.X25519, EncryptionMethod.A128CBC_HS256),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A192KW, Curve.X25519, EncryptionMethod.A192CBC_HS384),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A192KW, Curve.X25519, EncryptionMethod.A256CBC_HS512),

            new CycleTest(JWEAlgorithm.ECDH_1PU_A256KW, Curve.X25519, EncryptionMethod.A128CBC_HS256),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A256KW, Curve.X25519, EncryptionMethod.A192CBC_HS384),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A256KW, Curve.X25519, EncryptionMethod.A256CBC_HS512)
    };

    private static final CycleTest[] forbiddenCycles = new CycleTest[]{
            new CycleTest(JWEAlgorithm.ECDH_1PU_A128KW, Curve.X25519, EncryptionMethod.A128GCM),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A128KW, Curve.X25519, EncryptionMethod.A192GCM),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A128KW, Curve.X25519, EncryptionMethod.A256GCM),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A128KW, Curve.X25519, EncryptionMethod.XC20P),

            new CycleTest(JWEAlgorithm.ECDH_1PU_A192KW, Curve.X25519, EncryptionMethod.A128GCM),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A192KW, Curve.X25519, EncryptionMethod.A192GCM),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A192KW, Curve.X25519, EncryptionMethod.A256GCM),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A192KW, Curve.X25519, EncryptionMethod.XC20P),

            new CycleTest(JWEAlgorithm.ECDH_1PU_A256KW, Curve.X25519, EncryptionMethod.A128GCM),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A256KW, Curve.X25519, EncryptionMethod.A192GCM),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A256KW, Curve.X25519, EncryptionMethod.A256GCM),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A256KW, Curve.X25519, EncryptionMethod.XC20P),
    };

    public void testCycle() throws Exception {
        Payload payload = new Payload("Hello world!");

        for (CycleTest cycle : allowedCycles) {
            OctetKeyPair aliceKey = generateOKP(cycle.curve);
            OctetKeyPair bobKey = generateOKP(cycle.curve);

            JWEHeader header = new JWEHeader.Builder(cycle.algorithm, cycle.encryptionMethod).
                    agreementPartyUInfo(Base64URL.encode("Alice")).
                    agreementPartyVInfo(Base64URL.encode("Bob")).
                    build();

            JWEObject jweObject = new JWEObject(header, payload);

            ECDH1PUX25519Encrypter encrypter = new ECDH1PUX25519Encrypter(aliceKey, bobKey.toPublicJWK());
            encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
            jweObject.encrypt(encrypter);

            OctetKeyPair epk = (OctetKeyPair) jweObject.getHeader().getEphemeralPublicKey();
            assertEquals(cycle.curve, epk.getCurve());
            assertNotNull(epk.getX());
            assertNull(epk.getD());

            String jwe = jweObject.serialize();
            jweObject = JWEObject.parse(jwe);

            ECDH1PUX25519Decrypter decrypter = new ECDH1PUX25519Decrypter(bobKey, aliceKey.toPublicJWK());
            decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
            jweObject.decrypt(decrypter);

            assertEquals(payload.toString(), jweObject.getPayload().toString());
        }
    }

    public void testCycle_isForbidden() {
        Payload payload = new Payload("Hello world!");

        for (CycleTest cycle : forbiddenCycles) {
            OctetKeyPair aliceKey = generateOKP(cycle.curve);
            OctetKeyPair bobKey = generateOKP(cycle.curve);

            JWEHeader header = new JWEHeader.Builder(cycle.algorithm, cycle.encryptionMethod).
                    agreementPartyUInfo(Base64URL.encode("Alice")).
                    agreementPartyVInfo(Base64URL.encode("Bob")).
                    build();

            JWEObject jweObject = new JWEObject(header, payload);

            try {
                ECDH1PUX25519Encrypter encrypter = new ECDH1PUX25519Encrypter(aliceKey, bobKey.toPublicJWK());
                encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
                jweObject.encrypt(encrypter);
                fail();
            } catch (JOSEException e) {
                String expectedMessage = String.format("Unsupported JWE encryption method %s, " +
                                "must be A128CBC-HS256, A192CBC-HS384 or A256CBC-HS512",
                        cycle.encryptionMethod.getName());
                assertEquals(expectedMessage, e.getMessage());
            }
        }
    }

    public void testCycle_WithCekSpecified() throws Exception {
        Payload payload = new Payload("Hello world!");

        for (CycleTest cycle : allowedCycles) {
            if (cycle.encryptionMethod.cekBitLength() == 0)
                continue;

            SecretKey cek = ContentCryptoProvider.generateCEK(cycle.encryptionMethod, new SecureRandom());

            OctetKeyPair aliceKey = generateOKP(cycle.curve);
            OctetKeyPair bobKey = generateOKP(cycle.curve);

            JWEHeader header = new JWEHeader.Builder(cycle.algorithm, cycle.encryptionMethod).
                    agreementPartyUInfo(Base64URL.encode("Alice")).
                    agreementPartyVInfo(Base64URL.encode("Bob")).
                    build();

            JWEObject jweObject = new JWEObject(header, payload);

            ECDH1PUX25519Encrypter encrypter = new ECDH1PUX25519Encrypter(aliceKey, bobKey.toPublicJWK(), cek);
            encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
            jweObject.encrypt(encrypter);

            OctetKeyPair epk = (OctetKeyPair) jweObject.getHeader().getEphemeralPublicKey();
            assertEquals(cycle.curve, epk.getCurve());
            assertNotNull(epk.getX());
            assertNull(epk.getD());

            String jwe = jweObject.serialize();
            jweObject = JWEObject.parse(jwe);

            ECDH1PUX25519Decrypter decrypter = new ECDH1PUX25519Decrypter(bobKey, aliceKey.toPublicJWK());
            decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
            jweObject.decrypt(decrypter);

            assertEquals(payload.toString(), jweObject.getPayload().toString());
        }
    }

    public void testCritParamDeferral()
            throws Exception {

        OctetKeyPair aliceKey = generateOKP(Curve.X25519);
        OctetKeyPair bobKey = generateOKP(Curve.X25519);

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

        OctetKeyPair aliceKey = generateOKP(Curve.X25519);
        OctetKeyPair bobKey = generateOKP(Curve.X25519);

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

    public void testCurveNotMatch() throws Exception {
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_1PU, EncryptionMethod.A128CBC_HS256).
                customParam(JWTClaimNames.EXPIRATION_TIME, "2014-04-24").
                criticalParams(Collections.singleton(JWTClaimNames.EXPIRATION_TIME)).
                build();

        for (CurveTest curveTest : notMatchedCurves) {
            try {
                OctetKeyPair aliceOKPKey = curveTest.aliceWrongKey;
                OctetKeyPair bobOKPKey = curveTest.bobWrongKey;

                JWEObject jweObject = new JWEObject(header, new Payload("Hello world!"));
                ECDH1PUX25519Encrypter encrypter = new ECDH1PUX25519Encrypter(aliceOKPKey, bobOKPKey);
                jweObject.encrypt(encrypter);

                fail();
            } catch (JOSEException e) {
                assertEquals(curveTest.expectedMessage, e.getMessage());
            }
        }

        for (CurveTest curveTest : notMatchedCurves) {
            OctetKeyPair aliceOKPKey = curveTest.aliceKey;
            OctetKeyPair bobOKPKey = curveTest.bobKey;

            JWEObject jweObject = new JWEObject(header, new Payload("Hello world!"));
            ECDH1PUX25519Encrypter encrypter = new ECDH1PUX25519Encrypter(aliceOKPKey, bobOKPKey);
            jweObject.encrypt(encrypter);

            try {
                ECDH1PUX25519Decrypter decrypter = new ECDH1PUX25519Decrypter(curveTest.aliceWrongKey, curveTest.bobWrongKey);
                decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
                jweObject.decrypt(decrypter);
                fail();
            } catch (JOSEException e) {
                assertEquals(curveTest.expectedMessage, e.getMessage());
            }
        }
    }

    // see https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04#appendix-B
    public void test_ECDH_1PU_decryption() throws Exception {
        String exceptedPlaintext = "Three is a magic number.";
        OctetKeyPair aliceKey = OctetKeyPair.parse(
                "{\"kty\": \"OKP\",\n" +
                        " \"crv\": \"X25519\",\n" +
                        " \"x\": \"Knbm_BcdQr7WIoz-uqit9M0wbcfEr6y-9UfIZ8QnBD4\",\n" +
                        " \"d\": \"i9KuFhSzEBsiv3PKVL5115OCdsqQai5nj_Flzfkw5jU\"}");

        OctetKeyPair bobKey = OctetKeyPair.parse(
                "{\"kty\": \"OKP\",\n" +
                        " \"crv\": \"X25519\",\n" +
                        " \"x\": \"BT7aR0ItXfeDAldeeOlXL_wXqp-j5FltT0vRSG16kRw\",\n" +
                        " \"d\": \"1gDirl_r_Y3-qUa3WXHgEXrrEHngWThU3c9zj9A2uBg\"}");

        OctetKeyPair charlieKey = OctetKeyPair.parse(
                "{\"kty\": \"OKP\",\n" +
                        " \"crv\": \"X25519\",\n" +
                        " \"x\": \"BT7aR0ItXfeDAldeeOlXL_wXqp-j5FltT0vRSG16kRw\",\n" +
                        " \"d\": \"1gDirl_r_Y3-qUa3WXHgEXrrEHngWThU3c9zj9A2uBg\"}");

        JWEObject jweObject = new JWEObject(
                Base64URL.from("eyJhbGciOiJFQ0RILTFQVStBMTI4S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYXB1Ijoi" +
                        "UVd4cFkyVSIsImFwdiI6IlFtOWlJR0Z1WkNCRGFHRnliR2xsIiwiZXBrIjp7Imt0eSI6Ik9L" +
                        "UCIsImNydiI6IlgyNTUxOSIsIngiOiJrOW9mX2NwQWFqeTBwb1c1Z2FpeFhHczluSGt3ZzFB" +
                        "RnFVQUZhMzlkeUJjIn19"),
                Base64URL.from("pOMVA9_PtoRe7xXW1139NzzN1UhiFoio8lGto9cf0t8PyU-sjNXH8-LIRLycq8CHJQbDwvQeU1cSl55cQ0hGezJu2N9IY0QN"),
                Base64URL.from("AAECAwQFBgcICQoLDA0ODw"),
                Base64URL.from("Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw"),
                Base64URL.from("HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ")
        );

        String jwe = jweObject.serialize();

        // Bob can decrypt message
        JWEObject bobMessage = JWEObject.parse(jwe);
        ECDH1PUX25519Decrypter bobDecrypter = new ECDH1PUX25519Decrypter(
                bobKey,
                aliceKey.toPublicJWK()
        );

        bobMessage.decrypt(bobDecrypter);
        assertEquals(exceptedPlaintext, bobMessage.getPayload().toString());

        // Charlie can decrypt message
        JWEObject charlieMessage = JWEObject.parse(jwe);
        ECDH1PUX25519Decrypter charlieDecrypter = new ECDH1PUX25519Decrypter(
                charlieKey,
                aliceKey.toPublicJWK()
        );

        charlieMessage.decrypt(charlieDecrypter);
        assertEquals(exceptedPlaintext, charlieMessage.getPayload().toString());
    }
}
