/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2021, Connect2id Ltd.
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
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import junit.framework.TestCase;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.Collections;
import java.util.HashSet;


/**
 * Tests ECDH-1PU encryption and decryption.
 *
 * @author Alexander Martynov
 * @version 2021-08-04
 */
public class ECDH1PUCryptoTest extends TestCase {

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

    private static final CycleTest[] allowedCycles = new CycleTest[] {
            new CycleTest(JWEAlgorithm.ECDH_1PU, Curve.P_256, EncryptionMethod.A128CBC_HS256),
            new CycleTest(JWEAlgorithm.ECDH_1PU, Curve.P_256, EncryptionMethod.A192CBC_HS384),
            new CycleTest(JWEAlgorithm.ECDH_1PU, Curve.P_256, EncryptionMethod.A256CBC_HS512),
            new CycleTest(JWEAlgorithm.ECDH_1PU, Curve.P_256, EncryptionMethod.A128GCM),
            new CycleTest(JWEAlgorithm.ECDH_1PU, Curve.P_256, EncryptionMethod.A192GCM),
            new CycleTest(JWEAlgorithm.ECDH_1PU, Curve.P_256, EncryptionMethod.A256GCM),

            new CycleTest(JWEAlgorithm.ECDH_1PU, Curve.P_384, EncryptionMethod.A128CBC_HS256),
            new CycleTest(JWEAlgorithm.ECDH_1PU, Curve.P_384, EncryptionMethod.A192CBC_HS384),
            new CycleTest(JWEAlgorithm.ECDH_1PU, Curve.P_384, EncryptionMethod.A256CBC_HS512),
            new CycleTest(JWEAlgorithm.ECDH_1PU, Curve.P_384, EncryptionMethod.A128GCM),
            new CycleTest(JWEAlgorithm.ECDH_1PU, Curve.P_384, EncryptionMethod.A192GCM),
            new CycleTest(JWEAlgorithm.ECDH_1PU, Curve.P_384, EncryptionMethod.A256GCM),

            new CycleTest(JWEAlgorithm.ECDH_1PU, Curve.P_521, EncryptionMethod.A128CBC_HS256),
            new CycleTest(JWEAlgorithm.ECDH_1PU, Curve.P_521, EncryptionMethod.A192CBC_HS384),
            new CycleTest(JWEAlgorithm.ECDH_1PU, Curve.P_521, EncryptionMethod.A256CBC_HS512),
            new CycleTest(JWEAlgorithm.ECDH_1PU, Curve.P_521, EncryptionMethod.A128GCM),
            new CycleTest(JWEAlgorithm.ECDH_1PU, Curve.P_521, EncryptionMethod.A192GCM),
            new CycleTest(JWEAlgorithm.ECDH_1PU, Curve.P_521, EncryptionMethod.A256GCM),

            new CycleTest(JWEAlgorithm.ECDH_1PU_A128KW, Curve.P_256, EncryptionMethod.A128CBC_HS256),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A128KW, Curve.P_256, EncryptionMethod.A192CBC_HS384),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A128KW, Curve.P_256, EncryptionMethod.A256CBC_HS512),

            new CycleTest(JWEAlgorithm.ECDH_1PU_A128KW, Curve.P_384, EncryptionMethod.A128CBC_HS256),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A128KW, Curve.P_384, EncryptionMethod.A192CBC_HS384),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A128KW, Curve.P_384, EncryptionMethod.A256CBC_HS512),

            new CycleTest(JWEAlgorithm.ECDH_1PU_A128KW, Curve.P_521, EncryptionMethod.A128CBC_HS256),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A128KW, Curve.P_521, EncryptionMethod.A192CBC_HS384),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A128KW, Curve.P_521, EncryptionMethod.A256CBC_HS512),

            new CycleTest(JWEAlgorithm.ECDH_1PU_A192KW, Curve.P_256, EncryptionMethod.A128CBC_HS256),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A192KW, Curve.P_256, EncryptionMethod.A192CBC_HS384),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A192KW, Curve.P_256, EncryptionMethod.A256CBC_HS512),

            new CycleTest(JWEAlgorithm.ECDH_1PU_A192KW, Curve.P_384, EncryptionMethod.A128CBC_HS256),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A192KW, Curve.P_384, EncryptionMethod.A192CBC_HS384),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A192KW, Curve.P_384, EncryptionMethod.A256CBC_HS512),

            new CycleTest(JWEAlgorithm.ECDH_1PU_A192KW, Curve.P_521, EncryptionMethod.A128CBC_HS256),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A192KW, Curve.P_521, EncryptionMethod.A192CBC_HS384),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A192KW, Curve.P_521, EncryptionMethod.A256CBC_HS512),

            new CycleTest(JWEAlgorithm.ECDH_1PU_A256KW, Curve.P_256, EncryptionMethod.A128CBC_HS256),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A256KW, Curve.P_256, EncryptionMethod.A192CBC_HS384),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A256KW, Curve.P_256, EncryptionMethod.A256CBC_HS512),

            new CycleTest(JWEAlgorithm.ECDH_1PU_A256KW, Curve.P_384, EncryptionMethod.A128CBC_HS256),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A256KW, Curve.P_384, EncryptionMethod.A192CBC_HS384),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A256KW, Curve.P_384, EncryptionMethod.A256CBC_HS512),

            new CycleTest(JWEAlgorithm.ECDH_1PU_A256KW, Curve.P_521, EncryptionMethod.A128CBC_HS256),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A256KW, Curve.P_521, EncryptionMethod.A192CBC_HS384),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A256KW, Curve.P_521, EncryptionMethod.A256CBC_HS512),
    };

    private static final CycleTest[] forbiddenCycles = new CycleTest[] {
            new CycleTest(JWEAlgorithm.ECDH_1PU_A128KW, Curve.P_256, EncryptionMethod.A128GCM),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A128KW, Curve.P_256, EncryptionMethod.A192GCM),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A128KW, Curve.P_256, EncryptionMethod.A256GCM),

            new CycleTest(JWEAlgorithm.ECDH_1PU_A128KW, Curve.P_384, EncryptionMethod.A128GCM),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A128KW, Curve.P_384, EncryptionMethod.A192GCM),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A128KW, Curve.P_384, EncryptionMethod.A256GCM),

            new CycleTest(JWEAlgorithm.ECDH_1PU_A128KW, Curve.P_521, EncryptionMethod.A128GCM),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A128KW, Curve.P_521, EncryptionMethod.A192GCM),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A128KW, Curve.P_521, EncryptionMethod.A256GCM),

            new CycleTest(JWEAlgorithm.ECDH_1PU_A192KW, Curve.P_256, EncryptionMethod.A128GCM),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A192KW, Curve.P_256, EncryptionMethod.A192GCM),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A192KW, Curve.P_256, EncryptionMethod.A256GCM),

            new CycleTest(JWEAlgorithm.ECDH_1PU_A192KW, Curve.P_384, EncryptionMethod.A128GCM),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A192KW, Curve.P_384, EncryptionMethod.A192GCM),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A192KW, Curve.P_384, EncryptionMethod.A256GCM),

            new CycleTest(JWEAlgorithm.ECDH_1PU_A192KW, Curve.P_521, EncryptionMethod.A128GCM),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A192KW, Curve.P_521, EncryptionMethod.A192GCM),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A192KW, Curve.P_521, EncryptionMethod.A256GCM),

            new CycleTest(JWEAlgorithm.ECDH_1PU_A256KW, Curve.P_256, EncryptionMethod.A128GCM),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A256KW, Curve.P_256, EncryptionMethod.A192GCM),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A256KW, Curve.P_256, EncryptionMethod.A256GCM),

            new CycleTest(JWEAlgorithm.ECDH_1PU_A256KW, Curve.P_384, EncryptionMethod.A128GCM),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A256KW, Curve.P_384, EncryptionMethod.A192GCM),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A256KW, Curve.P_384, EncryptionMethod.A256GCM),

            new CycleTest(JWEAlgorithm.ECDH_1PU_A256KW, Curve.P_521, EncryptionMethod.A128GCM),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A256KW, Curve.P_521, EncryptionMethod.A192GCM),
            new CycleTest(JWEAlgorithm.ECDH_1PU_A256KW, Curve.P_521, EncryptionMethod.A256GCM),
    };

    public void testCycle() throws Exception {
        Payload payload = new Payload("Hello world!");

        for (CycleTest cycle : allowedCycles) {
            ECKey aliceKey = generateECJWK(cycle.curve);
            ECKey bobKey = generateECJWK(cycle.curve);

            JWEHeader header = new JWEHeader.Builder(cycle.algorithm, cycle.encryptionMethod).
                    agreementPartyUInfo(Base64URL.encode("Alice")).
                    agreementPartyVInfo(Base64URL.encode("Bob")).
                    build();

            JWEObject jweObject = new JWEObject(header, payload);

            ECDH1PUEncrypter encrypter = new ECDH1PUEncrypter(aliceKey.toECPrivateKey(), bobKey.toECPublicKey());
            encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
            jweObject.encrypt(encrypter);

            ECKey epk = (ECKey) jweObject.getHeader().getEphemeralPublicKey();
            assertEquals(cycle.curve, epk.getCurve());
            assertNotNull(epk.getX());
            assertNotNull(epk.getY());
            assertNull(epk.getD());

            String jwe = jweObject.serialize();
            jweObject = JWEObject.parse(jwe);

            ECDH1PUDecrypter decrypter = new ECDH1PUDecrypter(bobKey.toECPrivateKey(), aliceKey.toECPublicKey());
            decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
            jweObject.decrypt(decrypter);

            assertEquals(payload.toString(), jweObject.getPayload().toString());
        }
    }

    public void testCycle_isForbidden() throws Exception {
        Payload payload = new Payload("Hello world!");

        for (CycleTest cycle : forbiddenCycles) {
            ECKey aliceKey = generateECJWK(cycle.curve);
            ECKey bobKey = generateECJWK(cycle.curve);

            JWEHeader header = new JWEHeader.Builder(cycle.algorithm, cycle.encryptionMethod).
                    agreementPartyUInfo(Base64URL.encode("Alice")).
                    agreementPartyVInfo(Base64URL.encode("Bob")).
                    build();

            JWEObject jweObject = new JWEObject(header, payload);

            try {
                ECDH1PUEncrypter encrypter = new ECDH1PUEncrypter(aliceKey.toECPrivateKey(), bobKey.toECPublicKey());
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

            ECKey aliceKey = generateECJWK(cycle.curve);
            ECKey bobKey = generateECJWK(cycle.curve);

            JWEHeader header = new JWEHeader.Builder(cycle.algorithm, cycle.encryptionMethod).
                    agreementPartyUInfo(Base64URL.encode("Alice")).
                    agreementPartyVInfo(Base64URL.encode("Bob")).
                    build();

            JWEObject jweObject = new JWEObject(header, payload);

            ECDH1PUEncrypter encrypter = new ECDH1PUEncrypter(aliceKey.toECPrivateKey(), bobKey.toECPublicKey(), cek);
            encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
            jweObject.encrypt(encrypter);

            ECKey epk = (ECKey) jweObject.getHeader().getEphemeralPublicKey();
            assertEquals(cycle.curve, epk.getCurve());
            assertNotNull(epk.getX());
            assertNotNull(epk.getY());
            assertNull(epk.getD());

            String jwe = jweObject.serialize();
            jweObject = JWEObject.parse(jwe);

            ECDH1PUDecrypter decrypter = new ECDH1PUDecrypter(bobKey.toECPrivateKey(), aliceKey.toECPublicKey());
            decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
            jweObject.decrypt(decrypter);

            assertEquals(payload.toString(), jweObject.getPayload().toString());
        }
    }

    public void testCritParamDeferral()
        throws Exception {

        ECKey aliceKey = generateECJWK(Curve.P_256);
        ECKey bobKey = generateECJWK(Curve.P_256);

        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_1PU, EncryptionMethod.A128CBC_HS256).
            customParam("exp", "2014-04-24").
            criticalParams(new HashSet<>(Collections.singletonList("exp"))).
            build();

        JWEObject jweObject = new JWEObject(header, new Payload("Hello world!"));
        jweObject.encrypt(new ECDH1PUEncrypter(aliceKey.toECPrivateKey(), bobKey.toECPublicKey()));

        jweObject = JWEObject.parse(jweObject.serialize());

        jweObject.decrypt(new ECDH1PUDecrypter(
                bobKey.toECPrivateKey(),
                aliceKey.toECPublicKey(),
                new HashSet<>(Collections.singletonList("exp"))));

        assertEquals("Hello world!", jweObject.getPayload().toString());
    }


    public void testCritParamReject()
        throws Exception {

        ECKey aliceKey = generateECJWK(Curve.P_256);
        ECKey bobKey = generateECJWK(Curve.P_256);

        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_1PU, EncryptionMethod.A128CBC_HS256).
            customParam("exp", "2014-04-24").
            criticalParams(new HashSet<>(Collections.singletonList("exp"))).
            build();

        JWEObject jweObject = new JWEObject(header, new Payload("Hello world!"));
        jweObject.encrypt(new ECDH1PUEncrypter(aliceKey.toECPrivateKey(), bobKey.toECPublicKey()));

        jweObject = JWEObject.parse(jweObject.serialize());

        try {
            jweObject.decrypt(new ECDH1PUDecrypter(bobKey.toECPrivateKey(), aliceKey.toECPublicKey()));
            fail();
        } catch (JOSEException e) {
            // ok
            assertEquals("Unsupported critical header parameter(s)", e.getMessage());
        }
    }

    public void testCurveNotMatch() throws Exception {
        ECKey aliceKey = generateECJWK(Curve.P_256);
        ECKey bobKey = generateECJWK(Curve.P_521);
        ECKey correctBobKey = generateECJWK(Curve.P_256);

        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_1PU_A128KW, EncryptionMethod.A256CBC_HS512).
                agreementPartyUInfo(Base64URL.encode("Alice")).
                agreementPartyVInfo(Base64URL.encode("Bob")).
                build();

        JWEObject jweObject = new JWEObject(header, new Payload("Hello, world"));

        try {

            ECDH1PUEncrypter encrypter = new ECDH1PUEncrypter(aliceKey.toECPrivateKey(), bobKey.toECPublicKey());
            encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
            jweObject.encrypt(encrypter);

            fail();
        } catch (JOSEException e) {
            assertEquals("Curve of public key does not match curve of private key", e.getMessage());
        }

        try {
            ECDH1PUEncrypter encrypter = new ECDH1PUEncrypter(aliceKey.toECPrivateKey(), correctBobKey.toECPublicKey());
            encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
            jweObject.encrypt(encrypter);

            ECDH1PUDecrypter decrypter = new ECDH1PUDecrypter(bobKey.toECPrivateKey(), aliceKey.toECPublicKey());
            decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
            jweObject.decrypt(decrypter);

            fail();
        } catch (JOSEException e) {
            assertEquals("Curve of public key does not match curve of private key", e.getMessage());
        }
    }
}
