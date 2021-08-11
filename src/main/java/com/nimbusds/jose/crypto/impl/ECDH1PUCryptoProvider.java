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

package com.nimbusds.jose.crypto.impl;


import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.util.Base64URL;

import javax.crypto.SecretKey;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;


/**
 * The base abstract class for Elliptic Curve Diffie-Hellman One-Pass Unified Model
 * encrypters and decrypters of {@link com.nimbusds.jose.JWEObject JWE objects}.
 *
 * <p>Supports the following key management algorithms:
 *
 * <ul>
 *     <li>{@link JWEAlgorithm#ECDH_1PU}
 *     <li>{@link JWEAlgorithm#ECDH_1PU_A128KW}
 *     <li>{@link JWEAlgorithm#ECDH_1PU_A192KW}
 *     <li>{@link JWEAlgorithm#ECDH_1PU_A256KW}
 * </ul>
 *
 * <p>Supports the following elliptic curves:
 *
 * <ul>
 *     <li>{@link Curve#P_256}
 *     <li>{@link Curve#P_384}
 *     <li>{@link Curve#P_521}
 *     <li>{@link Curve#X25519}
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
public abstract class ECDH1PUCryptoProvider extends BaseJWEProvider {


    /**
     * The supported JWE algorithms by the ECDH crypto provider class.
     */
    public static final Set<JWEAlgorithm> SUPPORTED_ALGORITHMS;


    /**
     * The supported encryption methods by the ECDH crypto provider class.
     */
    public static final Set<EncryptionMethod> SUPPORTED_ENCRYPTION_METHODS = ContentCryptoProvider.SUPPORTED_ENCRYPTION_METHODS;


    static {
        Set<JWEAlgorithm> algs = new LinkedHashSet<>();
        algs.add(JWEAlgorithm.ECDH_1PU);
        algs.add(JWEAlgorithm.ECDH_1PU_A128KW);
        algs.add(JWEAlgorithm.ECDH_1PU_A192KW);
        algs.add(JWEAlgorithm.ECDH_1PU_A256KW);
        SUPPORTED_ALGORITHMS = Collections.unmodifiableSet(algs);
    }


    /**
     * The elliptic curve.
     */
    private final Curve curve;


    /**
     * The Concatenation Key Derivation Function (KDF).
     */
    private final ConcatKDF concatKDF;


    /**
     * Creates a new Elliptic Curve Diffie-Hellman One-Pass Unified Model
     * encryption / decryption provider.
     *
     * @param curve The elliptic curve. Must be supported and not
     *              {@code null}.
     *
     * @throws JOSEException If the elliptic curve is not supported.
     */
    protected ECDH1PUCryptoProvider(final Curve curve)
        throws JOSEException {

        super(SUPPORTED_ALGORITHMS, ContentCryptoProvider.SUPPORTED_ENCRYPTION_METHODS);

        Curve definedCurve = curve != null ? curve : new Curve("unknown");

        if (!supportedEllipticCurves().contains(curve)) {
            throw new JOSEException(AlgorithmSupportMessage.unsupportedEllipticCurve(
                definedCurve, supportedEllipticCurves()));
        }

        this.curve = curve;

        concatKDF = new ConcatKDF("SHA-256");
    }


    /**
     * Returns the Concatenation Key Derivation Function (KDF).
     *
     * @return The concat KDF.
     */
    protected ConcatKDF getConcatKDF() {

        return concatKDF;
    }


    /**
     * Returns the names of the supported elliptic curves. These correspond
     * to the {@code crv} EC JWK parameter.
     *
     * @return The supported elliptic curves.
     */
    public abstract Set<Curve> supportedEllipticCurves();


    /**
     * Returns the elliptic curve of the key (JWK designation).
     *
     * @return The elliptic curve.
     */
    public Curve getCurve() {

        return curve;
    }

    /**
     * Encrypts the specified plaintext using the specified shared secret
     * ("Z").
     *
     * Encrypts the specified plaintext using if provided,
     * the content encryption key (CEK) for {@link ECDH.AlgorithmMode#KW}.
     */
    protected JWECryptoParts encryptWithZ(final JWEHeader header,
                                          final SecretKey Z,
                                          final byte[] clearText,
                                          final SecretKey contentEncryptionKey)
        throws JOSEException {

        final JWEAlgorithm alg = header.getAlgorithm();
        final ECDH.AlgorithmMode algMode = ECDH1PU.resolveAlgorithmMode(alg);
        final EncryptionMethod enc = header.getEncryptionMethod();

        final SecretKey cek;
        final Base64URL encryptedKey; // The CEK encrypted (second JWE part)

        if (algMode.equals(ECDH.AlgorithmMode.DIRECT)) {

            // Derive shared key via concat KDF
            getConcatKDF().getJCAContext().setProvider(getJCAContext().getMACProvider()); // update before concat
            cek = ECDH1PU.deriveSharedKey(header, Z, getConcatKDF());

            return ContentCryptoProvider.encrypt(header, clearText, cek, null, getJCAContext());
        }

        if (algMode.equals(ECDH.AlgorithmMode.KW)) {

            // Key wrapping mode supports only AES_CBC_HMAC_SHA2
            // See https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04#section-2.1
            if (!EncryptionMethod.Family.AES_CBC_HMAC_SHA.contains(enc)) {
                throw new JOSEException(AlgorithmSupportMessage.unsupportedEncryptionMethod(
                        header.getEncryptionMethod(),
                        EncryptionMethod.Family.AES_CBC_HMAC_SHA));
            }

            if (contentEncryptionKey != null) { // Use externally supplied CEK
                cek = contentEncryptionKey;
            } else { // Generate the CEK according to the enc method
                cek = ContentCryptoProvider.generateCEK(enc, getJCAContext().getSecureRandom());
            }

            JWECryptoParts encrypted = ContentCryptoProvider.encrypt(header, clearText, cek, null, getJCAContext());

            SecretKey sharedKey = ECDH1PU.deriveSharedKey(header, Z, encrypted.getAuthenticationTag(), getConcatKDF());
            encryptedKey = Base64URL.encode(AESKW.wrapCEK(cek, sharedKey, getJCAContext().getKeyEncryptionProvider()));

            return new JWECryptoParts(
                    header,
                    encryptedKey,
                    encrypted.getInitializationVector(),
                    encrypted.getCipherText(),
                    encrypted.getAuthenticationTag()
            );
        }

        throw new JOSEException("Unexpected JWE ECDH algorithm mode: " + algMode);
    }

    /**
     * Decrypts the encrypted JWE parts using the specified shared secret ("Z").
     */
    protected byte[] decryptWithZ(final JWEHeader header,
                                  final SecretKey Z,
                                  final Base64URL encryptedKey,
                                  final Base64URL iv,
                                  final Base64URL cipherText,
                                  final Base64URL authTag)
        throws JOSEException {

        final JWEAlgorithm alg = header.getAlgorithm();
        final ECDH.AlgorithmMode algMode = ECDH1PU.resolveAlgorithmMode(alg);

        // Derive shared key via concat KDF
        getConcatKDF().getJCAContext().setProvider(getJCAContext().getMACProvider()); // update before concat

        JWEHeader updatedHeader = new JWEHeader.Builder(header).
                iv(iv).
                authTag(authTag).
                build();

        final SecretKey cek;

        if (algMode.equals(ECDH.AlgorithmMode.DIRECT)) {
            cek = ECDH1PU.deriveSharedKey(updatedHeader, Z, getConcatKDF());
        } else if (algMode.equals(ECDH.AlgorithmMode.KW)) {
            if (encryptedKey == null) {
                throw new JOSEException("Missing JWE encrypted key");
            }

            SecretKey sharedKey = ECDH1PU.deriveSharedKey(updatedHeader, Z, authTag, getConcatKDF());
            cek = AESKW.unwrapCEK(sharedKey, encryptedKey.decode(), getJCAContext().getKeyEncryptionProvider());
        } else {
            throw new JOSEException("Unexpected JWE ECDH algorithm mode: " + algMode);
        }

        return ContentCryptoProvider.decrypt(header, null, iv, cipherText, authTag, cek, getJCAContext());
    }

}
