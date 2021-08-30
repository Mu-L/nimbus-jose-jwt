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
import com.nimbusds.jose.crypto.utils.ECChecks;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.Pair;
import net.jcip.annotations.ThreadSafe;

import javax.crypto.SecretKey;
import java.util.*;


/**
 * Elliptic Curve Diffie-Hellman Multi-recipient decrypter of
 * {@link JWEObjectJSON JWE objects} for curves using EC JWK
 * keys. Expects a private EC key (with a P-256, P-384 or P-521 curve).
 *
 * <p>Public Key Authenticated Encryption for JOSE
 * <a href="https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04">ECDH-1PU</a>
 * for more information.
 *
 * <p>This class is thread-safe.
 *
 * <p>Supports the following key management algorithms:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#ECDH_ES}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#ECDH_ES_A128KW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#ECDH_ES_A192KW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#ECDH_ES_A256KW}
 * </ul>
 *
 * <p>Supports the following elliptic curves:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.jwk.Curve#P_256}
 *     <li>{@link com.nimbusds.jose.jwk.Curve#P_384}
 *     <li>{@link com.nimbusds.jose.jwk.Curve#P_521}
 * </ul>
 *
 * <p>Supports the following content encryption algorithms:
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
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#XC20P}
 * </ul>
 *
 * @author Alexander Martynov
 * @version 2021-08-19
 */
@ThreadSafe
public class ECDHDecrypterMulti extends ECDHCryptoProvider implements JWEDecrypterMulti, CriticalHeaderParamsAware {


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
     * The critical header policy.
     */
    private final CriticalHeaderParamsDeferral critPolicy = new CriticalHeaderParamsDeferral();

    /**
     * The list of private recipient's keys.
     */
    private final List<Pair<UnprotectedHeader, ECKey>>recipients;

    /**
     * Creates Elliptic Curve Diffie-Hellman Multi-recipient decrypter.
     *
     * @param recipients     The list of private recipient's keys.
     *
     * @throws JOSEException If the key subtype is not supported.
     */
    public ECDHDecrypterMulti(final List<Pair<UnprotectedHeader, ECKey>>recipients)
            throws JOSEException {

        this(recipients, null);
    }

    /**
     * Creates Elliptic Curve Diffie-Hellman Multi-recipient decrypter.
     *
     * @param recipients     The list of private recipient's keys.
     * @param defCritHeaders The names of the critical header parameters
     *                       that are deferred to the application for
     *                       processing, empty set or {@code null} if none.
     *
     * @throws JOSEException If the key subtype is not supported.
     */
    public ECDHDecrypterMulti(final List<Pair<UnprotectedHeader, ECKey>>recipients, final Set<String> defCritHeaders)
        throws JOSEException {

        super(recipients.get(0).getRight().getCurve());

        this.recipients = recipients;
        critPolicy.setDeferredCriticalHeaderParams(defCritHeaders);
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
                          final List<Recipient> recipients,
                          final Base64URL iv,
                          final Base64URL cipherText,
                          final Base64URL authTag)
            throws JOSEException {

        critPolicy.ensureHeaderPasses(header);

        // Get ephemeral EC key
        ECKey ephemeralKey = (ECKey) header.getEphemeralPublicKey();

        if (ephemeralKey == null) {
            throw new JOSEException("Missing ephemeral public EC key \"epk\" JWE header parameter");
        }

        List<Pair<UnprotectedHeader, SecretKey>> sharedKeys = new ArrayList<>();

        for (Pair<UnprotectedHeader, ECKey> recipient : this.recipients) {
            if (!ECChecks.isPointOnCurve(ephemeralKey.toECPublicKey(), recipient.getRight().toECPrivateKey())) {
                throw new JOSEException("Invalid ephemeral public EC key: Point(s) not on the expected curve");
            }

            SecretKey Z = ECDH.deriveSharedSecret(
                    ephemeralKey.toECPublicKey(),
                    recipient.getRight().toECPrivateKey(),
                    getJCAContext().getKeyEncryptionProvider()
            );

            sharedKeys.add(Pair.of(recipient.getLeft(), Z));
        }

        return decryptMulti(header, sharedKeys, recipients, iv, cipherText, authTag);
    }
}
