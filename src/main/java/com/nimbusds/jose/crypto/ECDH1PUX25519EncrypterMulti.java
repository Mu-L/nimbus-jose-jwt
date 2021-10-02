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
import com.nimbusds.jose.crypto.impl.*;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.util.Pair;
import net.jcip.annotations.ThreadSafe;

import javax.crypto.SecretKey;
import java.util.*;


/**
 * Elliptic Curve Diffie-Hellman Multi-recipient encrypter of
 * {@link JWEObjectJSON JWE objects} for curves using EC JWK keys.
 * Expects a public EC key (with a P-256, P-384, or P-521 curve).
 *
 * <p>Public Key Authenticated Encryption for JOSE
 * <a href="https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04">ECDH-1PU</a>
 * for more information.
 *
 * <p>For Curve25519/X25519, see {@link ECDH1PUX25519Encrypter} instead.
 *
 * <p>This class is thread-safe.
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
 *     <li>{@link Curve#X25519}
 * </ul>
 *
 * <p>Supports the following content encryption algorithms for Direct key agreement mode:
 *
 * <ul>
 *     <li>{@link EncryptionMethod#A128CBC_HS256}
 *     <li>{@link EncryptionMethod#A192CBC_HS384}
 *     <li>{@link EncryptionMethod#A256CBC_HS512}
 *     <li>{@link EncryptionMethod#A128GCM}
 *     <li>{@link EncryptionMethod#A192GCM}
 *     <li>{@link EncryptionMethod#A256GCM}
 *     <li>{@link EncryptionMethod#A128CBC_HS256_DEPRECATED}
 *     <li>{@link EncryptionMethod#A256CBC_HS512_DEPRECATED}
 *     <li>{@link EncryptionMethod#XC20P}
 * </ul>
 *
 * <p>Supports the following content encryption algorithms for Key wrapping mode:
 *
 * <ul>
 *     <li>{@link EncryptionMethod#A128CBC_HS256}
 *     <li>{@link EncryptionMethod#A192CBC_HS384}
 *     <li>{@link EncryptionMethod#A256CBC_HS512}
 * </ul>
 *
 * @author Alexander Martynov
 * @version 2021-08-18
 */
@ThreadSafe
public class ECDH1PUX25519EncrypterMulti extends ECDH1PUCryptoProvider implements JWEEncrypterMulti {

    /**
     * The supported EC JWK curves by the ECDH crypto provider class.
     */
    public static final Set<Curve> SUPPORTED_ELLIPTIC_CURVES;


    static {
        Set<Curve> curves = new LinkedHashSet<>();
        curves.add(Curve.X25519);
        SUPPORTED_ELLIPTIC_CURVES = Collections.unmodifiableSet(curves);
    }

    /**
     * The private sender JWK key.
     */
    private final OctetKeyPair sender;

    /**
     * The list of public recipient's keys.
     */
    private final List<Pair<UnprotectedHeader, OctetKeyPair>>recipients;

    /**
     * Creates a curve x25519 Elliptic Curve Diffie-Hellman Multi-recipient encryptor.
     *
     * @param sender     The private sender JWK key.
     * @param recipients The list of public recipient's keys.
     *
     * @throws JOSEException If the key subtype is not supported.
     */
    public ECDH1PUX25519EncrypterMulti(final OctetKeyPair sender, final List<Pair<UnprotectedHeader, OctetKeyPair>>recipients)
        throws JOSEException {

        super(sender.getCurve());

        this.sender = sender;
        this.recipients = recipients;
    }

    @Override
    public Set<Curve> supportedEllipticCurves() {
        return SUPPORTED_ELLIPTIC_CURVES;
    }

    @Override
    public JWECryptoParts encrypt(JWEHeader header, byte[] clearText) throws JOSEException {

        // Generate ephemeral OctetKey key pair on the same curve as the consumer's public key
        OctetKeyPair ephemeralPrivateKey = new OctetKeyPairGenerator(getCurve()).generate();
        OctetKeyPair ephemeralPublicKey = ephemeralPrivateKey.toPublicJWK();

        // Add the ephemeral public OctetKey key to the header
        JWEHeader updatedHeader = new JWEHeader.Builder(header).
                ephemeralPublicKey(ephemeralPublicKey).
                build();

        List<Pair<UnprotectedHeader, SecretKey>> sharedKeys = new ArrayList<>();

        for (Pair<UnprotectedHeader, OctetKeyPair> recipient : recipients) {
            SecretKey Z = ECDH1PU.deriveSenderZ(
                    sender,
                    recipient.getRight().toPublicJWK(),
                    ephemeralPrivateKey
            );

            sharedKeys.add(Pair.of(recipient.getLeft(), Z));
        }

        return encryptMulti(updatedHeader, sharedKeys, clearText);
    }
}
