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
import com.nimbusds.jose.util.Base64URL;
import net.jcip.annotations.ThreadSafe;

import javax.crypto.SecretKey;
import java.util.*;


/**
 * Elliptic Curve Diffie-Hellman Multi encrypter of
 * {@link JWEObjectJSON JWE objects} for curves using EC JWK keys.
 * Expects a public EC key (with a P-256, P-384, or P-521 curve).
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
 * <p>Supports the following elliptic curve:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.jwk.Curve#X25519} (Curve25519)
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
 * @version 2021-08-18
 */
@ThreadSafe
public class X25519EncrypterMulti extends ECDHCryptoProvider implements JWEEncryptorMulti {

    /**
     * The supported EC JWK curves by the ECDH crypto provider class.
     */
    public static final Set<Curve> SUPPORTED_ELLIPTIC_CURVES;


    static {
        Set<Curve> curves = new LinkedHashSet<>();
        curves.add(Curve.X25519);
        SUPPORTED_ELLIPTIC_CURVES = Collections.unmodifiableSet(curves);
    }

    private final OctetKeyPair[] recipients;
    private OctetKeyPair ephemeralKeyPair;

    public X25519EncrypterMulti(final OctetKeyPair[] recipients)
        throws JOSEException {

        super(recipients[0].getCurve());

        this.recipients = recipients;
    }

    @Override
    public Set<Curve> supportedEllipticCurves() {
        return SUPPORTED_ELLIPTIC_CURVES;
    }

    @Override
    public JWECryptoMultiParts encrypt(JWEHeader header, byte[] clearText) throws JOSEException {
        this.ephemeralKeyPair = new OctetKeyPairGenerator(getCurve()).generate();

        // Add the ephemeral public EC key to the header
        JWEHeader updatedHeader = new JWEHeader.Builder(header).
                ephemeralPublicKey(this.ephemeralKeyPair.toPublicJWK()).
                build();

       return encryptMulti(updatedHeader, clearText);
    }

    private JWECryptoMultiParts encryptMulti(JWEHeader header, byte[] clearText) throws JOSEException {
        SecretKey cek = ContentCryptoProvider.generateCEK(header.getEncryptionMethod(), getJCAContext().getSecureRandom());
        List<Recipient> recipients = new ArrayList<>();
        boolean encrypted = false;
        JWECryptoParts parts = null;

        for (OctetKeyPair key : this.recipients) {
            Base64URL encryptedKey;
            SecretKey Z = ECDH.deriveSharedSecret(
                    key.toPublicJWK(),
                    ephemeralKeyPair
            );

            if (!encrypted) {
                parts = encryptWithZ(header, Z, clearText, cek);
                encryptedKey = parts.getEncryptedKey();
                encrypted = true;
            } else {
                encryptedKey = deriveEncryptedKey(header, Z, cek);
            }

            if (encryptedKey != null) {
                Recipient recipient = new Recipient
                        .Builder()
                        .encryptedKey(encryptedKey)
                        .kid(key.getKeyID())
                        .build();

                recipients.add(recipient);
            }
        }

        if (parts == null) {
            throw new JOSEException("Content MUST be encrypted");
        }

        return new JWECryptoMultiParts(
                parts.getHeader(),
                Collections.unmodifiableList(recipients),
                parts.getInitializationVector(),
                parts.getCipherText(),
                parts.getAuthenticationTag()
        );
    }

    private Base64URL deriveEncryptedKey(JWEHeader header, SecretKey sharedSecret, SecretKey cek) throws JOSEException {
        final JWEAlgorithm alg = header.getAlgorithm();
        final ECDH.AlgorithmMode algMode = ECDH.resolveAlgorithmMode(alg);

        if (algMode.equals(ECDH.AlgorithmMode.KW)) {
            SecretKey sharedKey = ECDH.deriveSharedKey(header, sharedSecret, getConcatKDF());
            return Base64URL.encode(AESKW.wrapCEK(cek, sharedKey, getJCAContext().getKeyEncryptionProvider()));
        }

        return null;
    }
}
