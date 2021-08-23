package com.nimbusds.jose;

import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.util.Base64URL;
import junit.framework.TestCase;

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
        ECDH1PUEncrypterMulti encrypterMulti = new ECDH1PUEncrypterMulti(aliceKey, new ECKey[]{ bobKey, charlieKey });
        jwe.encrypt(encrypterMulti);

        String json = jwe.serialize();

        JWEObjectJSON decrypted = JWEObjectJSON.parse(json);
        ECDH1PUDecrypterMulti decryptor = new ECDH1PUDecrypterMulti(aliceKey, new ECKey[]{ bobKey, charlieKey });
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

        JWEObjectJSON jwe = new JWEObjectJSON(header, new Payload("Hello, world"));
        ECDHEncrypterMulti encrypterMulti = new ECDHEncrypterMulti(new ECKey[]{ bobKey, charlieKey });
        jwe.encrypt(encrypterMulti);

        String json = jwe.serialize();

        JWEObjectJSON decrypted = JWEObjectJSON.parse(json);
        ECDHDecrypterMulti decryptor = new ECDHDecrypterMulti(new ECKey[]{ bobKey, charlieKey });
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

        JWEObjectJSON jwe = new JWEObjectJSON(header, new Payload("Hello, world"));
        ECDH1PUX25519EncrypterMulti encrypterMulti = new ECDH1PUX25519EncrypterMulti(aliceKey, new OctetKeyPair[]{ bobKey, charlieKey });
        jwe.encrypt(encrypterMulti);

        String json = jwe.serialize();

        JWEObjectJSON decrypted = JWEObjectJSON.parse(json);
        ECDH1PUX25519DecrypterMulti decryptor = new ECDH1PUX25519DecrypterMulti(aliceKey, new OctetKeyPair[]{ bobKey, charlieKey });
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

        JWEObjectJSON jwe = new JWEObjectJSON(header, new Payload("Hello, world"));
        X25519EncrypterMulti encrypterMulti = new X25519EncrypterMulti(new OctetKeyPair[]{ aliceKey, bobKey, charlieKey });
        jwe.encrypt(encrypterMulti);

        String json = jwe.serialize();

        JWEObjectJSON decrypted = JWEObjectJSON.parse(json);
        X25519DecrypterMulti decryptor = new X25519DecrypterMulti(new OctetKeyPair[]{ aliceKey, bobKey, charlieKey });
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

            ECDH1PUX25519EncrypterMulti encrypter = new ECDH1PUX25519EncrypterMulti(aliceKey,
                    new OctetKeyPair[]{ bobKey.toPublicJWK(), charlieKey.toPublicJWK() });

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

            ECDH1PUX25519DecrypterMulti decrypter = new ECDH1PUX25519DecrypterMulti(aliceKey.toPublicJWK(),
                    new OctetKeyPair[] { bobKey, charlieKey });

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

            ECDHEncrypterMulti encrypter = new ECDHEncrypterMulti(new ECKey[]{ aliceKey, bobKey, charlieKey });
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

            ECDHDecrypterMulti decrypter = new ECDHDecrypterMulti(new ECKey[] { aliceKey, bobKey, charlieKey });
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

            try {
                ECDH1PUX25519EncrypterMulti encrypter = new ECDH1PUX25519EncrypterMulti(aliceKey,
                        new OctetKeyPair[]{ bobKey.toPublicJWK(), charlieKey.toPublicJWK() });

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
}