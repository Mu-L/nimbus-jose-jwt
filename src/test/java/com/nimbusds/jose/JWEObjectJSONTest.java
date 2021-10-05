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
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.Pair;
import junit.framework.TestCase;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class JWEObjectJSONTest extends TestCase {

    private static ECKey generateEC(final Curve curve, String kid)
            throws Exception {
        return new ECKeyGenerator(curve).keyID(kid).generate();
    }

    private static OctetKeyPair generateOKP(final Curve curve, String kid)
            throws Exception {
        return new OctetKeyPairGenerator(curve).keyID(kid).generate();
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

    private static final CycleTest[] allowedECDH_ESCycles = new CycleTest[]{
            new CycleTest(JWEAlgorithm.ECDH_ES_A256KW, Curve.P_521, EncryptionMethod.A128CBC_HS256),
            new CycleTest(JWEAlgorithm.ECDH_ES_A256KW, Curve.P_256, EncryptionMethod.A192CBC_HS384),
            new CycleTest(JWEAlgorithm.ECDH_ES_A256KW, Curve.P_384, EncryptionMethod.A256CBC_HS512),

            new CycleTest(JWEAlgorithm.ECDH_ES_A128KW, Curve.P_521, EncryptionMethod.A128CBC_HS256),
            new CycleTest(JWEAlgorithm.ECDH_ES_A128KW, Curve.P_256, EncryptionMethod.A192CBC_HS384),
            new CycleTest(JWEAlgorithm.ECDH_ES_A128KW, Curve.P_384, EncryptionMethod.A256CBC_HS512),

            new CycleTest(JWEAlgorithm.ECDH_ES_A192KW, Curve.P_521, EncryptionMethod.A128CBC_HS256),
            new CycleTest(JWEAlgorithm.ECDH_ES_A192KW, Curve.P_256, EncryptionMethod.A192CBC_HS384),
            new CycleTest(JWEAlgorithm.ECDH_ES_A192KW, Curve.P_384, EncryptionMethod.A256CBC_HS512),

            new CycleTest(JWEAlgorithm.ECDH_ES_A256KW, Curve.P_521, EncryptionMethod.XC20P),
            new CycleTest(JWEAlgorithm.ECDH_ES_A256KW, Curve.P_256, EncryptionMethod.XC20P),
            new CycleTest(JWEAlgorithm.ECDH_ES_A256KW, Curve.P_384, EncryptionMethod.XC20P),

            new CycleTest(JWEAlgorithm.ECDH_ES_A128KW, Curve.P_521, EncryptionMethod.XC20P),
            new CycleTest(JWEAlgorithm.ECDH_ES_A128KW, Curve.P_256, EncryptionMethod.XC20P),
            new CycleTest(JWEAlgorithm.ECDH_ES_A128KW, Curve.P_384, EncryptionMethod.XC20P),

            new CycleTest(JWEAlgorithm.ECDH_ES_A192KW, Curve.P_521, EncryptionMethod.XC20P),
            new CycleTest(JWEAlgorithm.ECDH_ES_A192KW, Curve.P_256, EncryptionMethod.XC20P),
            new CycleTest(JWEAlgorithm.ECDH_ES_A192KW, Curve.P_384, EncryptionMethod.XC20P),

            new CycleTest(JWEAlgorithm.ECDH_ES_A256KW, Curve.P_521, EncryptionMethod.A256GCM),
            new CycleTest(JWEAlgorithm.ECDH_ES_A256KW, Curve.P_256, EncryptionMethod.A256GCM),
            new CycleTest(JWEAlgorithm.ECDH_ES_A256KW, Curve.P_384, EncryptionMethod.A256GCM),

            new CycleTest(JWEAlgorithm.ECDH_ES_A128KW, Curve.P_521, EncryptionMethod.A256GCM),
            new CycleTest(JWEAlgorithm.ECDH_ES_A128KW, Curve.P_256, EncryptionMethod.A256GCM),
            new CycleTest(JWEAlgorithm.ECDH_ES_A128KW, Curve.P_384, EncryptionMethod.A256GCM),

            new CycleTest(JWEAlgorithm.ECDH_ES_A192KW, Curve.P_521, EncryptionMethod.A256GCM),
            new CycleTest(JWEAlgorithm.ECDH_ES_A192KW, Curve.P_256, EncryptionMethod.A256GCM),
            new CycleTest(JWEAlgorithm.ECDH_ES_A192KW, Curve.P_384, EncryptionMethod.A256GCM)
    };

    private static final CycleTest[] allowedECDH_1PUX25519Cycles = new CycleTest[]{
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

    private static final CycleTest[]  forbiddenECDH_1PUX25519Cycles = new CycleTest[]{
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
    
    public void testECDH_1PU_multi_encrypt_decrypt() throws Exception {
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_1PU_A256KW, EncryptionMethod.A256CBC_HS512)
                .agreementPartyVInfo(Base64URL.encode("Alice"))
                .agreementPartyUInfo(Base64URL.encode("Bob"))
                .build();

        ECKey aliceKey = generateEC(Curve.P_521, "alice");
        ECKey bobKey = generateEC(Curve.P_521, "bob");
        ECKey charlieKey = generateEC(Curve.P_521, "charlie");

        JWEObjectJSON jwe = new JWEObjectJSON(header, new Payload("Hello, world"));

        List<Pair<UnprotectedHeader, ECKey>> recipients = Arrays.asList(
                Pair.of(new UnprotectedHeader.Builder().keyID("bob").build(), bobKey),
                Pair.of(new UnprotectedHeader.Builder().keyID("charlie").build(), charlieKey)
        );

        ECDH1PUEncrypterMulti encrypterMulti = new ECDH1PUEncrypterMulti(aliceKey, recipients);
        jwe.encrypt(encrypterMulti);

        String json = jwe.serialize();

        JWEObjectJSON decrypted = JWEObjectJSON.parse(json);
        ECDH1PUDecrypterMulti decryptor = new ECDH1PUDecrypterMulti(aliceKey, recipients);
        decrypted.decrypt(decryptor);

        assertEquals("Hello, world", decrypted.getPayload().toString());
    }

    public void testECDH_ES_multi_encrypt_decrypt() throws Exception {
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A256CBC_HS512)
                .agreementPartyVInfo(Base64URL.encode("Alice"))
                .agreementPartyUInfo(Base64URL.encode("Bob"))
                .build();

        ECKey bobKey = generateEC(Curve.P_521, "bob");
        ECKey charlieKey = generateEC(Curve.P_521, "charlie");

        List<Pair<UnprotectedHeader, ECKey>> recipients = Arrays.asList(
                Pair.of(new UnprotectedHeader.Builder().keyID("bob").build(), bobKey),
                Pair.of(new UnprotectedHeader.Builder().keyID("charlie").build(), charlieKey)
        );

        JWEObjectJSON jwe = new JWEObjectJSON(header, new Payload("Hello, world"));
        ECDHEncrypterMulti encrypterMulti = new ECDHEncrypterMulti(recipients);
        jwe.encrypt(encrypterMulti);

        String json = jwe.serialize();

        JWEObjectJSON decrypted = JWEObjectJSON.parse(json);
        ECDHDecrypterMulti decryptor = new ECDHDecrypterMulti(recipients);
        decrypted.decrypt(decryptor);

        assertEquals("Hello, world", decrypted.getPayload().toString());
    }

    public void testECDH_1PU_X25519_multi_encrypt_decrypt() throws Exception {
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_1PU_A256KW, EncryptionMethod.A256CBC_HS512)
                .agreementPartyVInfo(Base64URL.encode("Alice"))
                .agreementPartyUInfo(Base64URL.encode("Bob"))
                .build();

        OctetKeyPair aliceKey = generateOKP(Curve.X25519, "alice");
        OctetKeyPair bobKey = generateOKP(Curve.X25519, "bob");
        OctetKeyPair charlieKey = generateOKP(Curve.X25519, "charlie");

        List<Pair<UnprotectedHeader, OctetKeyPair>> recipients = Arrays.asList(
                Pair.of(new UnprotectedHeader.Builder().keyID("bob").build(), bobKey),
                Pair.of(new UnprotectedHeader.Builder().keyID("charlie").build(), charlieKey)
        );

        JWEObjectJSON jwe = new JWEObjectJSON(header, new Payload("Hello, world"));
        ECDH1PUX25519EncrypterMulti encrypterMulti = new ECDH1PUX25519EncrypterMulti(aliceKey, recipients);
        jwe.encrypt(encrypterMulti);

        String json = jwe.serialize();

        JWEObjectJSON decrypted = JWEObjectJSON.parse(json);
        ECDH1PUX25519DecrypterMulti decryptor = new ECDH1PUX25519DecrypterMulti(aliceKey, recipients);
        decrypted.decrypt(decryptor);

        assertEquals("Hello, world", decrypted.getPayload().toString());
    }

    public void testECDH_X25519_multi_encrypt_decrypt() throws Exception {
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A256CBC_HS512)
                .agreementPartyVInfo(Base64URL.encode("Alice"))
                .agreementPartyUInfo(Base64URL.encode("Bob"))
                .build();

        OctetKeyPair aliceKey = generateOKP(Curve.X25519, "alice");
        OctetKeyPair bobKey = generateOKP(Curve.X25519, "bob");
        OctetKeyPair charlieKey = generateOKP(Curve.X25519, "charlie");

        List<Pair<UnprotectedHeader, OctetKeyPair>> recipients = Arrays.asList(
                Pair.of(new UnprotectedHeader.Builder().keyID("alice").build(), aliceKey),
                Pair.of(new UnprotectedHeader.Builder().keyID("bob").build(), bobKey),
                Pair.of(new UnprotectedHeader.Builder().keyID("charlie").build(), charlieKey)
        );

        JWEObjectJSON jwe = new JWEObjectJSON(header, new Payload("Hello, world"));
        X25519EncrypterMulti encrypterMulti = new X25519EncrypterMulti(recipients);
        jwe.encrypt(encrypterMulti);

        String json = jwe.serialize();

        JWEObjectJSON decrypted = JWEObjectJSON.parse(json);
        X25519DecrypterMulti decryptor = new X25519DecrypterMulti(recipients);
        decrypted.decrypt(decryptor);

        assertEquals("Hello, world", decrypted.getPayload().toString());
    }

    public void test_allowedECDH_1PUX25519Cycles() throws Exception {
        Payload payload = new Payload("Hello world!");

        for (CycleTest cycle : allowedECDH_1PUX25519Cycles) {
            OctetKeyPair aliceKey = generateOKP(cycle.curve, "1");
            OctetKeyPair bobKey = generateOKP(cycle.curve, "2");
            OctetKeyPair charlieKey = generateOKP(cycle.curve, "3");

            JWEHeader header = new JWEHeader.Builder(cycle.algorithm, cycle.encryptionMethod).
                    agreementPartyUInfo(Base64URL.encode("Alice")).
                    agreementPartyVInfo(Base64URL.encode("Bob, Charlie")).
                    build();

            JWEObjectJSON jweObject = new JWEObjectJSON(header, payload);

            List<Pair<UnprotectedHeader, OctetKeyPair>> recipients = Arrays.asList(
                    Pair.of(new UnprotectedHeader.Builder().keyID("bob").build(), bobKey),
                    Pair.of(new UnprotectedHeader.Builder().keyID("charlie").build(), charlieKey)
            );

            ECDH1PUX25519EncrypterMulti encrypter = new ECDH1PUX25519EncrypterMulti(aliceKey, recipients);

            encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
            jweObject.encrypt(encrypter);

            OctetKeyPair epk = (OctetKeyPair) jweObject.getHeader().getEphemeralPublicKey();
            assertEquals(cycle.curve, epk.getCurve());
            assertNotNull(epk.getX());
            assertNull(epk.getD());

            String jwe = jweObject.serialize();
            jweObject = JWEObjectJSON.parse(jwe);
            assertNotNull(jweObject.getRecipients());
            assertEquals(2, jweObject.getRecipients().size());

            ECDH1PUX25519DecrypterMulti decrypter = new ECDH1PUX25519DecrypterMulti(aliceKey.toPublicJWK(), recipients);

            decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
            jweObject.decrypt(decrypter);

            assertEquals(payload.toString(), jweObject.getPayload().toString());
        }
    }

    public void test_allowedECDH_ESCycles() throws Exception {
        Payload payload = new Payload("Hello world!");

        for (CycleTest cycle : allowedECDH_ESCycles) {
            ECKey aliceKey = generateEC(cycle.curve, "1");
            ECKey bobKey = generateEC(cycle.curve, "2");
            ECKey charlieKey = generateEC(cycle.curve, "3");

            JWEHeader header = new JWEHeader.Builder(cycle.algorithm, cycle.encryptionMethod).
                    agreementPartyUInfo(Base64URL.encode("Alice")).
                    agreementPartyVInfo(Base64URL.encode("Bob, Charlie")).
                    build();

            JWEObjectJSON jweObject = new JWEObjectJSON(header, payload);

            List<Pair<UnprotectedHeader, ECKey>> recipients = Arrays.asList(
                    Pair.of(new UnprotectedHeader.Builder().keyID("alice").build(), aliceKey),
                    Pair.of(new UnprotectedHeader.Builder().keyID("bob").build(), bobKey),
                    Pair.of(new UnprotectedHeader.Builder().keyID("charlie").build(), charlieKey)
            );

            ECDHEncrypterMulti encrypter = new ECDHEncrypterMulti(recipients);
            encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
            jweObject.encrypt(encrypter);

            ECKey epk = (ECKey) jweObject.getHeader().getEphemeralPublicKey();
            assertEquals(cycle.curve, epk.getCurve());
            assertNotNull(epk.getX());
            assertNull(epk.getD());

            String jwe = jweObject.serialize();
            jweObject = JWEObjectJSON.parse(jwe);
            assertNotNull(jweObject.getRecipients());
            assertEquals(3, jweObject.getRecipients().size());

            ECDHDecrypterMulti decrypter = new ECDHDecrypterMulti(recipients);
            decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
            jweObject.decrypt(decrypter);

            assertEquals(payload.toString(), jweObject.getPayload().toString());
        }
    }

    public void test_forbiddenECDH_1PUX25519Cycles() throws Exception {
        Payload payload = new Payload("Hello world!");

        for (CycleTest cycle : forbiddenECDH_1PUX25519Cycles) {
            OctetKeyPair aliceKey = generateOKP(cycle.curve, "1");
            OctetKeyPair bobKey = generateOKP(cycle.curve, "2");
            OctetKeyPair charlieKey = generateOKP(cycle.curve, "3");

            JWEHeader header = new JWEHeader.Builder(cycle.algorithm, cycle.encryptionMethod).
                    agreementPartyUInfo(Base64URL.encode("Alice")).
                    agreementPartyVInfo(Base64URL.encode("Bob, Charlie")).
                    build();

            JWEObjectJSON jweObject = new JWEObjectJSON(header, payload);

            List<Pair<UnprotectedHeader, OctetKeyPair>> recipients = Arrays.asList(
                    Pair.of(new UnprotectedHeader.Builder().keyID("bob").build(), bobKey),
                    Pair.of(new UnprotectedHeader.Builder().keyID("charlie").build(), charlieKey)
            );

            try {
                ECDH1PUX25519EncrypterMulti encrypter = new ECDH1PUX25519EncrypterMulti(aliceKey, recipients);

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

    /**
     * see https://datatracker.ietf.org/doc/html/rfc7516#appendix-A.4.7
     */
    public void test_ecdh_1pu_a128kw_appendix() throws Exception {
        OctetKeyPair aliceKey = OctetKeyPair.parse("{\"kty\": \"OKP\"," +
                "         \"crv\": \"X25519\"," +
                "         \"x\": \"Knbm_BcdQr7WIoz-uqit9M0wbcfEr6y-9UfIZ8QnBD4\"," +
                "         \"d\": \"i9KuFhSzEBsiv3PKVL5115OCdsqQai5nj_Flzfkw5jU\"}");


        OctetKeyPair bobKey = OctetKeyPair.parse("{\"kid\": \"bob-key-2\"," +
                "         \"kty\": \"OKP\"," +
                "         \"crv\": \"X25519\"," +
                "         \"x\": \"BT7aR0ItXfeDAldeeOlXL_wXqp-j5FltT0vRSG16kRw\"," +
                "         \"d\": \"1gDirl_r_Y3-qUa3WXHgEXrrEHngWThU3c9zj9A2uBg\"}");

        OctetKeyPair charlieKey = OctetKeyPair.parse("{\"kid\": \"2021-05-06\"," +
                "         \"kty\": \"OKP\"," +
                "         \"crv\": \"X25519\"," +
                "         \"x\": \"q-LsvU772uV_2sPJhfAIq-3vnKNVefNoIlvyvg1hrnE\"," +
                "         \"d\": \"Jcv8gklhMjC0b-lsk5onBbppWAx5ncNtbM63Jr9xBQE\"}");

        String json = "{" +
                "     \"protected\":" +
                "      \"eyJhbGciOiJFQ0RILTFQVStBMTI4S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYXB1IjoiUVd4cFkyVSIsImFwdiI6IlFtOWlJR0Z1WkNCRGFHRnliR2xsIiwiZXBrIjp7Imt0eSI6Ik9LUCIsImNydiI6IlgyNTUxOSIsIngiOiJrOW9mX2NwQWFqeTBwb1c1Z2FpeFhHczluSGt3ZzFBRnFVQUZhMzlkeUJjIn19\"," +
                "     \"unprotected\":" +
                "      {\"jku\":\"https://alice.example.com/keys.jwks\"}," +
                "     \"recipients\":[" +
                "      {\"header\":" +
                "        {\"kid\":\"bob-key-2\"}," +
                "       \"encrypted_key\":" +
                "        \"pOMVA9_PtoRe7xXW1139NzzN1UhiFoio8lGto9cf0t8PyU-sjNXH8-LIRLycq8CHJQbDwvQ" +
                "        eU1cSl55cQ0hGezJu2N9IY0QN\"}," +
                "      {\"header\":" +
                "        {\"kid\":\"2021-05-06\"}," +
                "       \"encrypted_key\":" +
                "        \"56GVudgRLIMEElQ7DpXsijJVRSWUSDNdbWkdV3g0GUNq6hcT_GkxwnxlPIWrTXCqRpVKQC8" +
                "         fe4z3PQ2YH2afvjQ28aiCTWFE\"}]," +
                "     \"iv\":" +
                "      \"AAECAwQFBgcICQoLDA0ODw\"," +
                "     \"ciphertext\":" +
                "      \"Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw\"," +
                "     \"tag\":" +
                "      \"HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ\"" +
                "    }";

        // both key decryption
        JWEObjectJSON jwe = JWEObjectJSON.parse(json);
        List<Pair<UnprotectedHeader, OctetKeyPair>> recipients = Arrays.asList(
                Pair.of(new UnprotectedHeader.Builder().keyID("bob-key-2").build(), bobKey),
                Pair.of(new UnprotectedHeader.Builder().keyID("2021-05-06").build(), charlieKey)
        );

        ECDH1PUX25519DecrypterMulti decrypterMulti = new ECDH1PUX25519DecrypterMulti(aliceKey.toPublicJWK(), recipients);
        jwe.decrypt(decrypterMulti);
        assertEquals("Three is a magic number.", jwe.getPayload().toString());

        // bob key decryption
        jwe = JWEObjectJSON.parse(json);
        recipients = Collections.singletonList(Pair.of(new UnprotectedHeader.Builder().keyID("bob-key-2").build(), bobKey));
        decrypterMulti = new ECDH1PUX25519DecrypterMulti(aliceKey.toPublicJWK(), recipients);
        jwe.decrypt(decrypterMulti);
        assertEquals("Three is a magic number.", jwe.getPayload().toString());

        // charlie key decryption
        jwe = JWEObjectJSON.parse(json);
        recipients = Collections.singletonList(Pair.of(new UnprotectedHeader.Builder().keyID("2021-05-06").build(), charlieKey));
        decrypterMulti = new ECDH1PUX25519DecrypterMulti(aliceKey.toPublicJWK(), recipients);
        jwe.decrypt(decrypterMulti);
        assertEquals("Three is a magic number.", jwe.getPayload().toString());
    }

    public void test_customUnprotectedHeader_is_passed() throws Exception {
        ECKey aliceKey = generateEC(Curve.P_521, "1");
        ECKey bobKey = generateEC(Curve.P_521, "2");
        ECKey charlieKey = generateEC(Curve.P_521, "3");

        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.XC20P).
                agreementPartyUInfo(Base64URL.encode("Alice")).
                agreementPartyVInfo(Base64URL.encode("Bob, Charlie")).
                build();

        JWEObjectJSON jweObject = new JWEObjectJSON(header, new Payload("hello"));

        List<Pair<UnprotectedHeader, ECKey>> recipients = Arrays.asList(
                Pair.of(new UnprotectedHeader.Builder().keyID("alice").build(), aliceKey),
                Pair.of(new UnprotectedHeader.Builder().keyID("bob").param("test", "test").build(), bobKey),
                Pair.of(new UnprotectedHeader.Builder().keyID("charlie").param("test1", "test1").build(), charlieKey)
        );

        ECDHEncrypterMulti encrypter = new ECDHEncrypterMulti(recipients);
        jweObject.encrypt(encrypter);

        assertEquals(3, jweObject.getRecipients().size());
        assertEquals("test", jweObject.getRecipients().get(1).getHeader().getParam("test").toString());
        assertEquals("test1", jweObject.getRecipients().get(2).getHeader().getParam("test1").toString());

        JWEObjectJSON decrypted = JWEObjectJSON.parse(jweObject.serialize());
        ECDHDecrypterMulti decryptor = new ECDHDecrypterMulti(recipients);
        decrypted.decrypt(decryptor);
        assertEquals("test", decrypted.getRecipients().get(1).getHeader().getParam("test").toString());
        assertEquals("test1", decrypted.getRecipients().get(2).getHeader().getParam("test1").toString());
    }

    public void test_curves_not_matched() throws Exception {
        JWEObjectJSON jweX25519 = JWEObjectJSON.parse("{" +
                "     \"protected\":" +
                        "      \"eyJhbGciOiJFQ0RILTFQVStBMTI4S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYXB1IjoiUVd4cFkyVSIsImFwdiI6IlFtOWlJR0Z1WkNCRGFHRnliR2xsIiwiZXBrIjp7Imt0eSI6Ik9LUCIsImNydiI6IlgyNTUxOSIsIngiOiJrOW9mX2NwQWFqeTBwb1c1Z2FpeFhHczluSGt3ZzFBRnFVQUZhMzlkeUJjIn19\"," +
                        "     \"ciphertext\":" +
                        "      \"Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw\"" +
                        "    }");

        JWEObjectJSON jweNist = JWEObjectJSON.parse("{" +
                "     \"protected\":" +
                "      \"eyJhbGciOiJFQ0RILUVTIiwKICAgICAgImVuYyI6IkExMjhHQ00iLAogICAgICAiYXB1IjoiUVd4cFkyVSIsCiAgICAgICJhcHYiOiJRbTlpIiwKICAgICAgImVwayI6CiAgICAgICB7Imt0eSI6IkVDIiwKICAgICAgICAiY3J2IjoiUC0yNTYiLAogICAgICAgICJ4IjoiZ0kwR0FJTEJkdTdUNTNha3JGbU15R2NzRjNuNWRPN01td05CSEtXNVNWMCIsCiAgICAgICAgInkiOiJTTFdfeFNmZnpsUFdySEVWSTMwREhNXzRlZ1Z3dDNOUXFlVUQ3bk1GcHBzIgogICAgICAgfQogICAgIH0=\"," +
                "     \"ciphertext\":" +
                "      \"Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw\"" +
                "    }");

        ECKey aliceKey = generateEC(Curve.P_521, "1");
        ECKey bobKey = generateEC(Curve.P_521, "1");

        List<Pair<UnprotectedHeader, ECKey>> recipients = Collections.singletonList(
                Pair.of(new UnprotectedHeader.Builder().keyID("bob").build(), bobKey)
        );

        try {
            ECDHDecrypterMulti ecdhDecrypterMulti = new ECDHDecrypterMulti(recipients);
            jweX25519.decrypt(ecdhDecrypterMulti);
            fail();
        } catch (Exception e) {
            assertEquals("com.nimbusds.jose.jwk.OctetKeyPair cannot be cast to com.nimbusds.jose.jwk.ECKey", e.getMessage());
        }

        try {
            ECDH1PUDecrypterMulti ecdh1puDecrypterMulti = new ECDH1PUDecrypterMulti(aliceKey, recipients);
            jweX25519.decrypt(ecdh1puDecrypterMulti);
            fail();
        } catch (Exception e) {
            assertEquals("com.nimbusds.jose.jwk.OctetKeyPair cannot be cast to com.nimbusds.jose.jwk.ECKey", e.getMessage());
        }

        try {
            ECDHDecrypterMulti ecdhDecrypterMulti = new ECDHDecrypterMulti(recipients);
            jweNist.decrypt(ecdhDecrypterMulti);
            fail();
        } catch (Exception e) {
            assertEquals("Invalid ephemeral public EC key: Point(s) not on the expected curve", e.getMessage());
        }

        try {
            ECDH1PUDecrypterMulti ecdh1puDecrypterMulti = new ECDH1PUDecrypterMulti(aliceKey, recipients);
            jweNist.decrypt(ecdh1puDecrypterMulti);
            fail();
        } catch (Exception e) {
            assertEquals("Curve of public key does not match curve of private key", e.getMessage());
        }
    }

    public void test_invalid_ciphertext_expected() throws Exception {
        OctetKeyPair aliceKey = OctetKeyPair.parse("{\"kty\": \"OKP\"," +
                "         \"crv\": \"X25519\"," +
                "         \"x\": \"Knbm_BcdQr7WIoz-uqit9M0wbcfEr6y-9UfIZ8QnBD4\"," +
                "         \"d\": \"i9KuFhSzEBsiv3PKVL5115OCdsqQai5nj_Flzfkw5jU\"}");


        OctetKeyPair bobKey = OctetKeyPair.parse("{\"kid\": \"bob-key-2\"," +
                "         \"kty\": \"OKP\"," +
                "         \"crv\": \"X25519\"," +
                "         \"x\": \"BT7aR0ItXfeDAldeeOlXL_wXqp-j5FltT0vRSG16kRw\"," +
                "         \"d\": \"1gDirl_r_Y3-qUa3WXHgEXrrEHngWThU3c9zj9A2uBg\"}");

        JWEObjectJSON jwe = JWEObjectJSON.parse("{" +
                "     \"protected\":" +
                "      \"eyJhbGciOiJFQ0RILTFQVStBMTI4S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYXB1IjoiUVd4cFkyVSIsImFwdiI6IlFtOWlJR0Z1WkNCRGFHRnliR2xsIiwiZXBrIjp7Imt0eSI6Ik9LUCIsImNydiI6IlgyNTUxOSIsIngiOiJrOW9mX2NwQWFqeTBwb1c1Z2FpeFhHczluSGt3ZzFBRnFVQUZhMzlkeUJjIn19\"," +
                "     \"recipients\":[" +
                "      {\"header\":" +
                "        {\"kid\":\"bob-key-2\"}," +
                "       \"encrypted_key\":" +
                "        \"pOMVA9_PtoRe7xXW1139NzzN1UhiFoio8lGto9cf0t8PyU-sjNXH8-LIRLycq8CHJQbDwvQ" +
                "        eU1cSl55cQ0hGezJu2N9IY0QN\"}]," +
                "     \"iv\":" +
                "      \"AAECAwQFBgcICQoLDA0ODw\"," +
                "     \"ciphertext\":" +
                "      \"Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw22\"," +
                "     \"tag\":" +
                "      \"HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ\"" +
                "    }");

        List<Pair<UnprotectedHeader, OctetKeyPair>> recipients = Collections.singletonList(
                Pair.of(new UnprotectedHeader.Builder().keyID("bob-key-2").build(), bobKey)
        );

        try {
            ECDH1PUX25519DecrypterMulti decrypterMulti = new ECDH1PUX25519DecrypterMulti(aliceKey.toPublicJWK(), recipients);
            jwe.decrypt(decrypterMulti);
            fail();
        } catch (Exception e) {
            assertEquals("MAC check failed", e.getMessage());
        }
    }

    public void test_recipient_kid_not_found() throws Exception {
        OctetKeyPair aliceKey = generateOKP(Curve.X25519, "1");
        OctetKeyPair bobKey = generateOKP(Curve.X25519, "2");


        List<Pair<UnprotectedHeader, OctetKeyPair>> recipients = Collections.singletonList(
                Pair.of(new UnprotectedHeader.Builder().keyID("bob-key-3").build(), bobKey)
        );

        try {
            JWEObjectJSON jwe = JWEObjectJSON.parse("{" +
                    "     \"protected\":" +
                    "      \"eyJhbGciOiJFQ0RILTFQVStBMTI4S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYXB1IjoiUVd4cFkyVSIsImFwdiI6IlFtOWlJR0Z1WkNCRGFHRnliR2xsIiwiZXBrIjp7Imt0eSI6Ik9LUCIsImNydiI6IlgyNTUxOSIsIngiOiJrOW9mX2NwQWFqeTBwb1c1Z2FpeFhHczluSGt3ZzFBRnFVQUZhMzlkeUJjIn19\"," +
                    "     \"recipients\":[" +
                    "      {\"header\":" +
                    "        {\"kid\":\"bob-key-2\"}," +
                    "       \"encrypted_key\":" +
                    "        \"pOMVA9_PtoRe7xXW1139NzzN1UhiFoio8lGto9cf0t8PyU-sjNXH8-LIRLycq8CHJQbDwvQ" +
                    "        eU1cSl55cQ0hGezJu2N9IY0QN\"}]," +
                    "     \"iv\":" +
                    "      \"AAECAwQFBgcICQoLDA0ODw\"," +
                    "     \"ciphertext\":" +
                    "      \"Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw22\"," +
                    "     \"tag\":" +
                    "      \"HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ\"" +
                    "    }");

            ECDH1PUX25519DecrypterMulti decrypterMulti = new ECDH1PUX25519DecrypterMulti(aliceKey.toPublicJWK(), recipients);
            jwe.decrypt(decrypterMulti);
            fail();
        } catch (Exception e) {
            assertEquals("Missing JWE encrypted key", e.getMessage());
        }

        try {
            JWEObjectJSON jwe = JWEObjectJSON.parse("{" +
                    "     \"protected\":" +
                    "      \"eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJhcHUiOiJRV3hwWTJVIiwiYXB2IjoiUW05aUlHRnVaQ0JEYUdGeWJHbGwiLCJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6Ims5b2ZfY3BBYWp5MHBvVzVnYWl4WEdzOW5Ia3dnMUFGcVVBRmEzOWR5QmMifX0=\"," +
                    "     \"recipients\":[" +
                    "      {\"header\":" +
                    "        {\"kid\":\"bob-key-2\"}," +
                    "       \"encrypted_key\":" +
                    "        \"pOMVA9_PtoRe7xXW1139NzzN1UhiFoio8lGto9cf0t8PyU-sjNXH8-LIRLycq8CHJQbDwvQ" +
                    "        eU1cSl55cQ0hGezJu2N9IY0QN\"}]," +
                    "     \"iv\":" +
                    "      \"AAECAwQFBgcICQoLDA0ODw\"," +
                    "     \"ciphertext\":" +
                    "      \"Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw22\"," +
                    "     \"tag\":" +
                    "      \"HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ\"" +
                    "    }");

            X25519DecrypterMulti decrypterMulti = new X25519DecrypterMulti(recipients);
            jwe.decrypt(decrypterMulti);
            fail();
        } catch (Exception e) {
            assertEquals("Missing JWE encrypted key", e.getMessage());
        }
    }

    public void test_no_epk_provided() throws Exception {
        OctetKeyPair aliceKeyOKP = generateOKP(Curve.X25519, "1");
        OctetKeyPair bobKeyOKP = generateOKP(Curve.X25519, "2");
        ECKey aliceKeyEC = generateEC(Curve.P_521, "1");
        ECKey bobKeyEC = generateEC(Curve.P_521, "2");

        JWEObjectJSON octetJwe = JWEObjectJSON.parse("{" +
                "     \"protected\":" +
                "      \"eyJhbGciOiJFQ0RILTFQVStBMTI4S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYXB1IjoiUVd4cFkyVSIsImFwdiI6IlFtOWlJR0Z1WkNCRGFHRnliR2xsIn0=\"," +
                "     \"recipients\":[" +
                "      {\"header\":" +
                "        {\"kid\":\"bob-key-2\"}," +
                "       \"encrypted_key\":" +
                "        \"pOMVA9_PtoRe7xXW1139NzzN1UhiFoio8lGto9cf0t8PyU-sjNXH8-LIRLycq8CHJQbDwvQ" +
                "        eU1cSl55cQ0hGezJu2N9IY0QN\"}]," +
                "     \"iv\":" +
                "      \"AAECAwQFBgcICQoLDA0ODw\"," +
                "     \"ciphertext\":" +
                "      \"Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw22\"," +
                "     \"tag\":" +
                "      \"HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ\"" +
                "    }");

        List<Pair<UnprotectedHeader, OctetKeyPair>> recipientsOKP = Collections.singletonList(
                Pair.of(new UnprotectedHeader.Builder().keyID("bob-key-3").build(), bobKeyOKP)
        );

        List<Pair<UnprotectedHeader, ECKey>> recipientsEC = Collections.singletonList(
                Pair.of(new UnprotectedHeader.Builder().keyID("bob-key-3").build(), bobKeyEC)
        );

        try {
            ECDH1PUX25519DecrypterMulti decrypterMulti = new ECDH1PUX25519DecrypterMulti(aliceKeyOKP.toPublicJWK(), recipientsOKP);
            octetJwe.decrypt(decrypterMulti);
            fail();
        } catch (Exception e) {
            assertEquals("Missing ephemeral public key epk JWE header parameter", e.getMessage());
        }

        try {
            X25519DecrypterMulti decrypterMulti = new X25519DecrypterMulti(recipientsOKP);
            octetJwe.decrypt(decrypterMulti);
            fail();
        } catch (Exception e) {
            assertEquals("Missing ephemeral public key epk JWE header parameter", e.getMessage());
        }

        try {
            ECDHDecrypterMulti decrypterMulti = new ECDHDecrypterMulti(recipientsEC);
            octetJwe.decrypt(decrypterMulti);
            fail();
        } catch (Exception e) {
            assertEquals("Missing ephemeral public EC key \"epk\" JWE header parameter", e.getMessage());
        }

        try {
            ECDH1PUDecrypterMulti decrypterMulti = new ECDH1PUDecrypterMulti(aliceKeyEC, recipientsEC);
            octetJwe.decrypt(decrypterMulti);
            fail();
        } catch (Exception e) {
            assertEquals("Missing ephemeral public EC key \"epk\" JWE header parameter", e.getMessage());
        }
    }

    public void test_wrong_bob_encrypted_key_passed() throws Exception {
        OctetKeyPair aliceKey = OctetKeyPair.parse("{\"kty\": \"OKP\"," +
                "         \"crv\": \"X25519\"," +
                "         \"x\": \"Knbm_BcdQr7WIoz-uqit9M0wbcfEr6y-9UfIZ8QnBD4\"," +
                "         \"d\": \"i9KuFhSzEBsiv3PKVL5115OCdsqQai5nj_Flzfkw5jU\"}");

        OctetKeyPair bobKey = OctetKeyPair.parse("{\"kid\": \"bob-key-2\"," +
                "         \"kty\": \"OKP\"," +
                "         \"crv\": \"X25519\"," +
                "         \"x\": \"BT7aR0ItXfeDAldeeOlXL_wXqp-j5FltT0vRSG16kRw\"," +
                "         \"d\": \"1gDirl_r_Y3-qUa3WXHgEXrrEHngWThU3c9zj9A2uBg\"}");

        OctetKeyPair charlieKey = OctetKeyPair.parse("{\"kid\": \"2021-05-06\"," +
                "         \"kty\": \"OKP\"," +
                "         \"crv\": \"X25519\"," +
                "         \"x\": \"q-LsvU772uV_2sPJhfAIq-3vnKNVefNoIlvyvg1hrnE\"," +
                "         \"d\": \"Jcv8gklhMjC0b-lsk5onBbppWAx5ncNtbM63Jr9xBQE\"}");

        JWEObjectJSON jwe = JWEObjectJSON.parse("{" +
                "     \"protected\":" +
                "      \"eyJhbGciOiJFQ0RILTFQVStBMTI4S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYXB1IjoiUVd4cFkyVSIsImFwdiI6IlFtOWlJR0Z1WkNCRGFHRnliR2xsIiwiZXBrIjp7Imt0eSI6Ik9LUCIsImNydiI6IlgyNTUxOSIsIngiOiJrOW9mX2NwQWFqeTBwb1c1Z2FpeFhHczluSGt3ZzFBRnFVQUZhMzlkeUJjIn19\"," +
                "     \"recipients\":[" +
                "      {\"header\":" +
                "        {\"kid\":\"bob-key-2\"}," +
                "       \"encrypted_key\":" +
                "        \"pOMVA9_PtoRe7xXW1139NzzN1UhiFoio8lGto9cf0t8PyU-sjNXH8-LIRLycq8CHJQbDwvQ" +
                "        eU1cSl55cQ0hGezJu2N9IY0QN\"}," +
                "      {\"header\":" +
                "        {\"kid\":\"2021-05-06\"}," +
                "       \"encrypted_key\":" +
                "        \"56GVudgRLIMEElQ7DpXsijJVRSWUSDNdbWkdV3g012Nq6hcT_GkxwnxlPIWrTXCqRpVKQC8" +
                "         fe4z3PQ2YH2afvjQ28aiCTWFE\"}]," +
                "     \"iv\":" +
                "      \"AAECAwQFBgcICQoLDA0ODw\"," +
                "     \"ciphertext\":" +
                "      \"Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw\"," +
                "     \"tag\":" +
                "      \"HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ\"" +
                "    }");

        try {
            List<Pair<UnprotectedHeader, OctetKeyPair>> recipients = Arrays.asList(
                    Pair.of(new UnprotectedHeader.Builder().keyID("bob-key-2").build(), bobKey),
                    Pair.of(new UnprotectedHeader.Builder().keyID("2021-05-06").build(), charlieKey)
            );

            ECDH1PUX25519DecrypterMulti decrypterMulti = new ECDH1PUX25519DecrypterMulti(aliceKey.toPublicJWK(), recipients);
            jwe.decrypt(decrypterMulti);
            fail();
        } catch (Exception e) {
            assertEquals("Couldn't unwrap AES key: Integrity check failed", e.getMessage());
        }
    }

    public void test_wrong_bob_encrypted_key_passed_charlie_can_decrypt() throws Exception {
        OctetKeyPair aliceKey = OctetKeyPair.parse("{\"kty\": \"OKP\"," +
                "         \"crv\": \"X25519\"," +
                "         \"x\": \"Knbm_BcdQr7WIoz-uqit9M0wbcfEr6y-9UfIZ8QnBD4\"," +
                "         \"d\": \"i9KuFhSzEBsiv3PKVL5115OCdsqQai5nj_Flzfkw5jU\"}");

        OctetKeyPair bobKey = OctetKeyPair.parse("{\"kid\": \"bob-key-2\"," +
                "         \"kty\": \"OKP\"," +
                "         \"crv\": \"X25519\"," +
                "         \"x\": \"BT7aR0ItXfeDAldeeOlXL_wXqp-j5FltT0vRSG16kRw\"," +
                "         \"d\": \"1gDirl_r_Y3-qUa3WXHgEXrrEHngWThU3c9zj9A2uBg\"}");

        JWEObjectJSON jwe = JWEObjectJSON.parse("{" +
                "     \"protected\":" +
                "      \"eyJhbGciOiJFQ0RILTFQVStBMTI4S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYXB1IjoiUVd4cFkyVSIsImFwdiI6IlFtOWlJR0Z1WkNCRGFHRnliR2xsIiwiZXBrIjp7Imt0eSI6Ik9LUCIsImNydiI6IlgyNTUxOSIsIngiOiJrOW9mX2NwQWFqeTBwb1c1Z2FpeFhHczluSGt3ZzFBRnFVQUZhMzlkeUJjIn19\"," +
                "     \"recipients\":[" +
                "      {\"header\":" +
                "        {\"kid\":\"bob-key-2\"}," +
                "       \"encrypted_key\":" +
                "        \"pOMVA9_PtoRe7xXW1139NzzN1UhiFoio8lGto9cf0t8PyU-sjNXH8-LIRLycq8CHJQbDwvQ" +
                "        eU1cSl55cQ0hGezJu2N9IY0QN\"}," +
                "      {\"header\":" +
                "        {\"kid\":\"2021-05-06\"}," +
                "       \"encrypted_key\":" +
                "        \"56GVudgRLIMEElQ7DpXsijJVRSWUSDNdbWkdV3g012Nq6hcT_GkxwnxlPIWrTXCqRpVKQC8" +
                "         fe4z3PQ2YH2afvjQ28aiCTWFE\"}]," +
                "     \"iv\":" +
                "      \"AAECAwQFBgcICQoLDA0ODw\"," +
                "     \"ciphertext\":" +
                "      \"Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw\"," +
                "     \"tag\":" +
                "      \"HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ\"" +
                "    }");

        List<Pair<UnprotectedHeader, OctetKeyPair>> recipients = Collections.singletonList(
                Pair.of(new UnprotectedHeader.Builder().keyID("bob-key-2").build(), bobKey)
        );

        ECDH1PUX25519DecrypterMulti decrypterMulti = new ECDH1PUX25519DecrypterMulti(aliceKey.toPublicJWK(), recipients);
        jwe.decrypt(decrypterMulti);

        assertEquals("Three is a magic number.", jwe.getPayload().toString());
    }

    public void test_kid_is_not_passed() {
        try {
            new UnprotectedHeader.Builder().keyID(null).build();
            fail();
        } catch (Exception e) {
            assertEquals("The \"kid\" should be specified", e.getMessage());
        }
    }

    public void test_unprotected_header_kid_is_not_found() throws Exception {
        OctetKeyPair bobKeyOKP = generateOKP(Curve.X25519, "2");

        List<Pair<UnprotectedHeader, OctetKeyPair>> recipients = Collections.singletonList(
                Pair.of(new UnprotectedHeader.Builder().keyID("bob-2").build(), bobKeyOKP)
        );

        try {
            JWEObjectJSON jwe = JWEObjectJSON.parse("{" +
                    "     \"protected\":" +
                    "      \"eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJhcHUiOiJRV3hwWTJVIiwiYXB2IjoiUW05aUlHRnVaQ0JEYUdGeWJHbGwiLCJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6Ims5b2ZfY3BBYWp5MHBvVzVnYWl4WEdzOW5Ia3dnMUFGcVVBRmEzOWR5QmMifX0=\"," +
                    "     \"recipients\":[{\"header\":" +
                    "        {\"kid\":\"bob-key-2\"}," +
                    "       \"encrypted_key\":" +
                    "        \"pOMVA9_PtoRe7xXW1139NzzN1UhiFoio8lGto9cf0t8PyU-sjNXH8-LIRLycq8CHJQbDwvQ" +
                    "        eU1cSl55cQ0hGezJu2N9IY0QN\"}]," +
                    "     \"iv\":" +
                    "      \"AAECAwQFBgcICQoLDA0ODw\"," +
                    "     \"ciphertext\":" +
                    "      \"Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw22\"," +
                    "     \"tag\":" +
                    "      \"HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ\"" +
                    "    }");

            X25519DecrypterMulti decrypterMulti = new X25519DecrypterMulti(recipients);
            jwe.decrypt(decrypterMulti);
            fail();
        } catch (Exception e) {
            assertEquals("Missing JWE encrypted key", e.getMessage());
        }
    }

    public void test_unprotected_header_is_not_present() throws Exception {
        OctetKeyPair bobKeyOKP = generateOKP(Curve.X25519, "2");

        List<Pair<UnprotectedHeader, OctetKeyPair>> recipients = Collections.singletonList(
                Pair.of(new UnprotectedHeader.Builder().keyID("bob-2").build(), bobKeyOKP)
        );

        try {
            JWEObjectJSON jwe = JWEObjectJSON.parse("{" +
                    "     \"protected\":" +
                    "      \"eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJhcHUiOiJRV3hwWTJVIiwiYXB2IjoiUW05aUlHRnVaQ0JEYUdGeWJHbGwiLCJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6Ims5b2ZfY3BBYWp5MHBvVzVnYWl4WEdzOW5Ia3dnMUFGcVVBRmEzOWR5QmMifX0=\"," +
                    "     \"recipients\":[{" +
                    "       \"encrypted_key\":" +
                    "        \"pOMVA9_PtoRe7xXW1139NzzN1UhiFoio8lGto9cf0t8PyU-sjNXH8-LIRLycq8CHJQbDwvQ" +
                    "        eU1cSl55cQ0hGezJu2N9IY0QN\"}]," +
                    "     \"iv\":" +
                    "      \"AAECAwQFBgcICQoLDA0ODw\"," +
                    "     \"ciphertext\":" +
                    "      \"Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw22\"," +
                    "     \"tag\":" +
                    "      \"HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ\"" +
                    "    }");

            X25519DecrypterMulti decrypterMulti = new X25519DecrypterMulti(recipients);
            jwe.decrypt(decrypterMulti);
            fail();
        } catch (Exception e) {
            assertEquals("Missing JWE encrypted key", e.getMessage());
        }
    }

    public void test_encryption_decryption_where_kid_is_url() throws Exception {
        String aliceKid = "https://www.crockford.com/blog.html";
        String bobKid = "https://www.crockford.com/books.html";
        String charlieKid = "https://www.json.org/json-en.html";

        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_1PU_A256KW, EncryptionMethod.A256CBC_HS512)
                .agreementPartyVInfo(Base64URL.encode(bobKid + "." + charlieKid))
                .agreementPartyUInfo(Base64URL.encode(aliceKid))
                .senderKeyID(aliceKid)
                .build();

        ECKey aliceKey = generateEC(Curve.P_521, aliceKid);
        ECKey bobKey = generateEC(Curve.P_521, bobKid);
        ECKey charlieKey = generateEC(Curve.P_521, charlieKid);

        JWEObjectJSON jwe = new JWEObjectJSON(header, new Payload("Hello, world"));

        List<Pair<UnprotectedHeader, ECKey>> recipients = Arrays.asList(
                Pair.of(new UnprotectedHeader.Builder().keyID(bobKid).build(), bobKey),
                Pair.of(new UnprotectedHeader.Builder().keyID(charlieKid).build(), charlieKey)
        );

        ECDH1PUEncrypterMulti encrypterMulti = new ECDH1PUEncrypterMulti(aliceKey, recipients);
        jwe.encrypt(encrypterMulti);

        String json = jwe.serialize();

        JWEObjectJSON decrypted = JWEObjectJSON.parse(json);

        assertEquals(aliceKid, decrypted.getHeader().getSenderKeyID());
        assertEquals(2, decrypted.getRecipients().size());

        UnprotectedHeader bobPerRecipientHeader = null;
        for (JWERecipient recipient: decrypted.getRecipients()) {
            if (recipient.getHeader().getKeyID().equals(bobKid))
                bobPerRecipientHeader = recipient.getHeader();
        }
        assertNotNull(bobPerRecipientHeader);

        UnprotectedHeader charliePerRecipientHeader = null;
        for (JWERecipient recipient: decrypted.getRecipients()) {
            if (recipient.getHeader().getKeyID().equals(charlieKid))
                charliePerRecipientHeader = recipient.getHeader();
        }
        assertNotNull(charliePerRecipientHeader);

        ECDH1PUDecrypterMulti decryptor = new ECDH1PUDecrypterMulti(aliceKey, recipients);
        decrypted.decrypt(decryptor);

        assertEquals("Hello, world", decrypted.getPayload().toString());
    }

    public void test_jwe_custom_header_decrypt_success() throws Exception{
        OctetKeyPair aliceKey = OctetKeyPair.parse("{\"kty\": \"OKP\"," +
                "         \"crv\": \"X25519\"," +
                "         \"x\": \"Knbm_BcdQr7WIoz-uqit9M0wbcfEr6y-9UfIZ8QnBD4\"," +
                "         \"d\": \"i9KuFhSzEBsiv3PKVL5115OCdsqQai5nj_Flzfkw5jU\"}");

        OctetKeyPair bobKey = OctetKeyPair.parse("{\"kid\": \"bob-key-2\"," +
                "         \"kty\": \"OKP\"," +
                "         \"crv\": \"X25519\"," +
                "         \"x\": \"BT7aR0ItXfeDAldeeOlXL_wXqp-j5FltT0vRSG16kRw\"," +
                "         \"d\": \"1gDirl_r_Y3-qUa3WXHgEXrrEHngWThU3c9zj9A2uBg\"}");

        JWEObjectJSON jwe = JWEObjectJSON.parse("{" +
                "    \"custom\": \"1223\"," +
                "    \"aad\": \"eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkEyNTZDQ\"," +
                "     \"protected\":" +
                "      \"eyJhbGciOiJFQ0RILTFQVStBMTI4S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYXB1IjoiUVd4cFkyVSIsImFwdiI6IlFtOWlJR0Z1WkNCRGFHRnliR2xsIiwiZXBrIjp7Imt0eSI6Ik9LUCIsImNydiI6IlgyNTUxOSIsIngiOiJrOW9mX2NwQWFqeTBwb1c1Z2FpeFhHczluSGt3ZzFBRnFVQUZhMzlkeUJjIn19\"," +
                "     \"recipients\":[" +
                "      {\"header\":" +
                "        {\"kid\":\"bob-key-2\"}," +
                "       \"encrypted_key\":" +
                "        \"pOMVA9_PtoRe7xXW1139NzzN1UhiFoio8lGto9cf0t8PyU-sjNXH8-LIRLycq8CHJQbDwvQ" +
                "        eU1cSl55cQ0hGezJu2N9IY0QN\"}]," +
                "     \"iv\":" +
                "      \"AAECAwQFBgcICQoLDA0ODw\"," +
                "     \"ciphertext\":" +
                "      \"Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw\"," +
                "     \"tag\":" +
                "      \"HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ\"" +
                "    }");

        assertNotNull(jwe.getRecipients());
        assertNotNull(jwe.getIV());
        assertNotNull(jwe.getAuthTag());
        assertNotNull(jwe.getCipherText());
        assertNotNull(jwe.getHeader());
        assertEquals(1, jwe.getRecipients().size());

        List<Pair<UnprotectedHeader, OctetKeyPair>> recipients = Collections.singletonList(
                Pair.of(new UnprotectedHeader.Builder().keyID("bob-key-2").build(), bobKey)
        );

        ECDH1PUX25519DecrypterMulti decrypterMulti = new ECDH1PUX25519DecrypterMulti(aliceKey, recipients);
        jwe.decrypt(decrypterMulti);

        assertEquals("Three is a magic number.", jwe.getPayload().toString());
    }

    public void test_jwe_parsing_failed() {
        try {
            JWEObjectJSON.parse("");
            fail();
        } catch (Exception e) {
            assertEquals("Invalid JSON: Unexpected token  at position 0.", e.getMessage());
        }

        try {
            JWEObjectJSON.parse("{\"ciphertext\":" +
                    "      \"Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw\"}");
            fail();
        } catch (Exception e) {
            assertEquals("The header must not be null", e.getMessage());
        }

        try {
            JWEObjectJSON.parse("{\"protected\":" +
                    "      \"Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw\"}");
            fail();
        } catch (Exception e) {
            assertEquals("Invalid JWE header:", e.getMessage().substring(0, 19));
        }

        try {
            JWEObjectJSON.parse("{\"protected\":" +
                    "      \"eyJhbGciOiJFQ0RILTFQVStBMTI4S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYXB1IjoiUVd4cFkyVSIsImFwdiI6IlFtOWlJR0Z1WkNCRGFHRnliR2xsIiwiZXBrIjp7Imt0eSI6Ik9LUCIsImNydiI6IlgyNTUxOSIsIngiOiJrOW9mX2NwQWFqeTBwb1c1Z2FpeFhHczluSGt3ZzFBRnFVQUZhMzlkeUJjIn19\"}");
            fail();
        } catch (Exception e) {
            assertEquals("The ciphertext must not be null", e.getMessage());
        }
    }
}