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

import com.google.crypto.tink.subtle.XChaCha20Poly1305;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.util.ByteUtils;
import com.nimbusds.jose.util.Container;
import net.jcip.annotations.ThreadSafe;

import javax.crypto.*;
import java.security.*;

/**
 * This class defines the XChaCha20 stream cipher as well as the use
 * of the Poly1305 authenticator.
 *
 * The eXtended-nonce ChaCha cipher construction (XChaCha) allows for
 * ChaCha-based ciphersuites to accept a 192-bit nonce with similar
 * guarantees to the original construction, except with a much lower
 * probability of nonce misuse occurring.
 *
 * <p>This class is thread-safe.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/draft-arciszewski-xchacha-03">XChaCha: eXtended-nonce ChaCha and AEAD_XChaCha20_Poly1305</a>
 *
 *
 * @author Alexander Martynov
 * @version 2021-08-04
 */
@ThreadSafe
public class XC20P {

    /**
     * The standard authentication tag length (128 bits).
     */
    public static final int AUTH_TAG_BIT_LENGTH = 128;

    /**
     * The standard Initialisation Vector (IV) length (192 bits).
     */
    public static final int IV_BIT_LENGTH = 192;


    /**
     *
     * Encrypts the specified plain text using XChaCha20_Poly1305.
     *
     * @param secretKey   The AES key. Must not be {@code null}.
     * @param plainText   The plain text. Must not be {@code null}.
     * @param ivContainer The initialisation vector (IV).
     *                    This is output parameter. On output, it carries
     *                    the nonce the cipher actually used.
     * @param authData    The authenticated data. Must not be {@code null}.
     *
     * @return The authenticated cipher text.
     *
     * @throws JOSEException If encryption failed.
     */
    public static AuthenticatedCipherText encryptAuthenticated(final SecretKey secretKey,
                                        final Container<byte[]> ivContainer,
                                        final byte[] plainText,
                                        final byte[] authData)
            throws JOSEException {

        final XChaCha20Poly1305 aead;

        try {
            aead = new XChaCha20Poly1305(secretKey.getEncoded());

        } catch (InvalidKeyException e) {
            throw new JOSEException("Invalid XChaCha20Poly1305 key: " + e.getMessage(), e);
        }

        final byte[] cipherOutput;

        try {
            cipherOutput = aead.encrypt(plainText, authData);

        } catch (GeneralSecurityException e) {
            throw new JOSEException("Couldn't encrypt with XChaCha20Poly1305: " + e.getMessage(), e);
        }

        final int tagPos = cipherOutput.length - ByteUtils.byteLength(AUTH_TAG_BIT_LENGTH);
        final int cipherTextPos = ByteUtils.byteLength(IV_BIT_LENGTH);

        byte[] iv = ByteUtils.subArray(cipherOutput, 0, cipherTextPos);
        byte[] cipherText = ByteUtils.subArray(cipherOutput, cipherTextPos, tagPos - cipherTextPos);
        byte[] authTag = ByteUtils.subArray(cipherOutput, tagPos, ByteUtils.byteLength(AUTH_TAG_BIT_LENGTH));

        // set nonce
        ivContainer.set(iv);

        return new AuthenticatedCipherText(cipherText, authTag);
    }


    /**
     * Decrypts the specified cipher text using XChaCha20_Poly1305.
     *
     * @param secretKey  The AES key. Must not be {@code null}.
     * @param iv         The initialisation vector (IV). Must not be
     *                   {@code null}.
     * @param cipherText The cipher text. Must not be {@code null}.
     * @param authData   The authenticated data. Must not be {@code null}.
     * @param authTag    The authentication tag. Must not be {@code null}.
     *
     * @return The decrypted plain text.
     *
     * @throws JOSEException If decryption failed.
     */
    public static byte[] decryptAuthenticated(final SecretKey secretKey,
                                 final byte[] iv,
                                 final byte[] cipherText,
                                 final byte[] authData,
                                 final byte[] authTag)
            throws JOSEException {

        final XChaCha20Poly1305 aead;

        try {
            aead = new XChaCha20Poly1305(secretKey.getEncoded());

        } catch (InvalidKeyException e) {
            throw new JOSEException("Invalid XChaCha20Poly1305 key: " + e.getMessage(), e);
        }

        final byte[] cipherInput = ByteUtils.concat(iv, cipherText, authTag);

        try {
            return aead.decrypt(cipherInput, authData);

        } catch (GeneralSecurityException e) {

            throw new JOSEException("XChaCha20Poly1305decryption failed: " + e.getMessage(), e);
        }
    }
}
