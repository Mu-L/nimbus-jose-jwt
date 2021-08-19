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
import net.jcip.annotations.ThreadSafe;

import javax.crypto.SecretKey;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;


/**
 * Elliptic Curve Diffie-Hellman Multi decrypter of
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

    private final ECKey[] recipients;

    public ECDHDecrypterMulti(final ECKey[] recipients)
            throws JOSEException {

        this(recipients, null);
    }

    public ECDHDecrypterMulti(final ECKey[] recipients, final Set<String> defCritHeaders)
        throws JOSEException {

        super(recipients[0].getCurve());

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

        return decryptMulti(header, recipients, iv, cipherText, authTag);
    }

    private byte[] decryptMulti(
            final JWEHeader header,
            final List<Recipient> recipients,
            final Base64URL iv,
            final Base64URL cipherText,
            final Base64URL authTag
    ) throws JOSEException {
        byte[] result = null;

        for (ECKey recipientKey : this.recipients) {
            Recipient recipient = null;

            String kid = recipientKey.getKeyID();
            if (kid == null)
                throw new JOSEException("\"kid\" header should be specified");

            for (Recipient rec : recipients) {
                if (kid.equals(rec.getHeader().get("kid"))) {
                    recipient = rec;
                }
            }

            if (recipient == null)
                throw new JOSEException("Recipient not found");

            result = decrypt(header, recipientKey, recipient, iv, cipherText, authTag);
        }

        return result;
    }

    private byte[] decrypt(JWEHeader header, ECKey key, Recipient recipient, Base64URL iv, Base64URL cipherText, Base64URL authTag) throws JOSEException {
        // Get ephemeral EC key
        ECKey ephemeralKey = (ECKey) header.getEphemeralPublicKey();

        if (ephemeralKey == null) {
            throw new JOSEException("Missing ephemeral public key epk JWE header parameter");
        }

        ECChecks.isPointOnCurve(ephemeralKey.toECPublicKey(), key.toECPrivateKey());

        SecretKey Z = ECDH.deriveSharedSecret(
                ephemeralKey.toECPublicKey(),
                key.toECPrivateKey(),
                getJCAContext().getKeyEncryptionProvider());

        return decryptWithZ(header, Z, recipient.getEncryptedKey(), iv, cipherText, authTag);
    }
}
