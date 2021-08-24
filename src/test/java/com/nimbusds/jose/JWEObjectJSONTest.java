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

        JWEObjectJSON jwe = JWEObjectJSON.parse("{" +
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
                "    }");

        List<Pair<UnprotectedHeader, OctetKeyPair>> recipients = Arrays.asList(
                Pair.of(new UnprotectedHeader.Builder().keyID("bob-key-2").build(), bobKey),
                Pair.of(new UnprotectedHeader.Builder().keyID("2021-05-06").build(), charlieKey)
        );

        ECDH1PUX25519DecrypterMulti decrypterMulti = new ECDH1PUX25519DecrypterMulti(aliceKey.toPublicJWK(), recipients);
        jwe.decrypt(decrypterMulti);

        assertEquals("Three is a magic number.", jwe.getPayload().toString());
    }
}