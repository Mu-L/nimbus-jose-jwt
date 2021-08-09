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


import com.nimbusds.jose.CriticalHeaderParamsAware;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.impl.*;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import net.jcip.annotations.ThreadSafe;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;


/**
 * Elliptic Curve Diffie-Hellman decrypter of
 * {@link com.nimbusds.jose.JWEObject JWE objects} for curves using EC JWK
 * keys. Expects a private EC key (with a P-256, P-384 or P-521 curve).
 *
 * <p>Public Key Authenticated Encryption for JOSE
 * <a href="https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04">ECDH-1PU</a>
 * for more information.
 *
 * <p>For Curve25519/X25519, see {@link ECDH1PUX25519Decrypter} instead.
 *
 * <p>This class is thread-safe.
 *
 * <p>Supports the following key management algorithms:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#ECDH_1PU}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#ECDH_1PU_A128KW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#ECDH_1PU_A192KW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#ECDH_1PU_A256KW}
 * </ul>
 *
 * <p>Supports the following elliptic curves:
 *
 * <ul>
 *     <li>{@link Curve#P_256}
 *     <li>{@link Curve#P_384}
 *     <li>{@link Curve#P_521}
 * </ul>
 *
 * <p>Supports the following content encryption algorithms for Direct key agreement mode:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128CBC_HS256}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A192CBC_HS384}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256CBC_HS512}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128GCM}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A192GCM}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256GCM}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128CBC_HS256_DEPRECATED}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256CBC_HS512_DEPRECATED}
 * </ul>
 *
 * <p>Supports the following content encryption algorithms for Key wrapping mode:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128CBC_HS256}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A192CBC_HS384}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256CBC_HS512}
 * </ul>
 *
 * @author Alexander Martynov
 * @version 2021-08-03
 */
@ThreadSafe
public class ECDH1PUDecrypter extends ECDH1PUCryptoProvider implements JWEDecrypter, CriticalHeaderParamsAware {


    /**
     * The supported EC JWK curves by the ECDH crypto provider class.
     */
    public static final Set<Curve> SUPPORTED_ELLIPTIC_CURVES;


    static {
        Set<Curve> curves = new LinkedHashSet<>();
        curves.add(Curve.P_256);
        curves.add(Curve.P_384);
        curves.add(Curve.P_521);
        SUPPORTED_ELLIPTIC_CURVES = Collections.unmodifiableSet(curves);
    }


    /**
     * The private EC key.
     */
    private final ECPrivateKey privateKey;

    /**
     * The public EC key.
     */
    private final ECPublicKey publicKey;

    /**
     * The critical header policy.
     */
    private final CriticalHeaderParamsDeferral critPolicy = new CriticalHeaderParamsDeferral();


    /**
     * Creates a new Elliptic Curve Diffie-Hellman decrypter.
     *
     * @param privateKey 	The private EC key. Must not be {@code null}.
     * @param publicKey 	The public EC key. Must not be {@code null}.
     *
     * @throws JOSEException If the elliptic curve is not supported.
     */
    public ECDH1PUDecrypter(final ECPrivateKey privateKey,
                            final ECPublicKey publicKey)
        throws JOSEException {

        this(privateKey, publicKey, null);
    }

    /**
     * Creates a new Elliptic Curve Diffie-Hellman decrypter.
     *
     * @param privateKey     The private EC key. Must not be {@code null}.
     * @param publicKey 	 The public EC key. Must not be {@code null}.
     * @param defCritHeaders The names of the critical header parameters
     *                       that are deferred to the application for
     *                       processing, empty set or {@code null} if none.
     *
     * @throws JOSEException If the elliptic curve is not supported.
     */
    public ECDH1PUDecrypter(final ECPrivateKey privateKey,
                            final ECPublicKey publicKey,
                            final Set<String> defCritHeaders)
        throws JOSEException {

        this(privateKey, publicKey, defCritHeaders, Curve.forECParameterSpec(privateKey.getParams()));
    }


    /**
     * Creates a new Elliptic Curve Diffie-Hellman decrypter. This
     * constructor can also accept a private EC key located in a PKCS#11
     * store that doesn't expose the private key parameters (such as a
     * smart card or HSM).
     *
     * @param privateKey     The private EC key. Must not be {@code null}.
     * @param publicKey 	 The public EC key. Must not be {@code null}.
     * @param defCritHeaders The names of the critical header parameters
     *                       that are deferred to the application for
     *                       processing, empty set or {@code null} if none.
     * @param curve          The key curve. Must not be {@code null}.
     *
     * @throws JOSEException If the elliptic curve is not supported.
     */
    public ECDH1PUDecrypter(final ECPrivateKey privateKey,
                            final ECPublicKey publicKey,
                            final Set<String> defCritHeaders,
                            final Curve curve)
        throws JOSEException {

        super(curve);

        critPolicy.setDeferredCriticalHeaderParams(defCritHeaders);

        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    /**
     * Returns the public EC key.
     *
     * @return The public EC key.
     */
    public ECPublicKey getPublicKey() {

        return publicKey;
    }

    /**
     * Returns the private EC key.
     *
     * @return The private EC key. Casting to
     *         {@link ECPrivateKey} may not be
     *         possible if the key is located in a PKCS#11 store that
     *         doesn't expose the private key parameters.
     */
    public PrivateKey getPrivateKey() {

        return privateKey;
    }


    @Override
    public Set<Curve> supportedEllipticCurves() {

        return SUPPORTED_ELLIPTIC_CURVES;
    }


    @Override
    public Set<String> getProcessedCriticalHeaderParams() {

        return critPolicy.getProcessedCriticalHeaderParams();
    }


    @Override
    public Set<String> getDeferredCriticalHeaderParams() {

        return critPolicy.getProcessedCriticalHeaderParams();
    }


    @Override
    public byte[] decrypt(final JWEHeader header,
                  final Base64URL encryptedKey,
                  final Base64URL iv,
                  final Base64URL cipherText,
                  final Base64URL authTag)
        throws JOSEException {

        ECDH1PU.validateSameCurve(privateKey, publicKey);

        critPolicy.ensureHeaderPasses(header);

        // Get ephemeral EC key
        ECKey ephemeralKey = (ECKey) header.getEphemeralPublicKey();

        if (ephemeralKey == null) {
            throw new JOSEException("Missing ephemeral public EC key \"epk\" JWE header parameter");
        }

        ECPublicKey ephemeralPublicKey = ephemeralKey.toECPublicKey();

        ECDH1PU.validateSameCurve(privateKey, ephemeralPublicKey);

        SecretKey Ze = ECDH.deriveSharedSecret(
            ephemeralPublicKey,
            privateKey,
            getJCAContext().getKeyEncryptionProvider());

        SecretKey Zs = ECDH.deriveSharedSecret(
                publicKey,
                privateKey,
                getJCAContext().getKeyEncryptionProvider());

        SecretKey Z = ECDH1PU.deriveZ(Ze, Zs);

        return decryptWithZ(header, Z, encryptedKey, iv, cipherText, authTag);
    }
}
