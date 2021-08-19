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


import com.nimbusds.jose.util.Base64URL;

import java.util.List;

/**
 * JSON Web Encryption (JWE) decrypter for multiple recipients.
 * It should be used only for General JSON Serialization {@link JWEObjectJSON}.
 *
 *
 * @author Alexander Martynov
 * @version 2021-08-19
 */
public interface JWEDecrypterMulti extends JWEProvider {

	/**
	 * Decrypts the specified cipher text of a {@link JWEObjectJSON JWE Object}.
	 *
	 * @param header       The JSON Web Encryption (JWE) header. Must
	 *                     specify a supported JWE algorithm and method.
	 *                     Must not be {@code null}.
	 * @param recipients   The recipients, {@code null} if not required
	 *                     by the JWE algorithm.
	 * @param iv           The initialisation vector, {@code null} if not
	 *                     required by the JWE algorithm.
	 * @param cipherText   The cipher text to decrypt. Must not be
	 *                     {@code null}.
	 * @param authTag      The authentication tag, {@code null} if not
	 *                     required.
	 *
	 * @return The clear text.
	 *
	 * @throws JOSEException If the JWE algorithm or method is not
	 *                       supported, if a critical header parameter is
	 *                       not supported or marked for deferral to the
	 *                       application, or if decryption failed for some
	 *                       other reason.
	 */
	byte[] decrypt(final JWEHeader header,
                   final List<Recipient> recipients,
                   final Base64URL iv,
                   final Base64URL cipherText,
                   final Base64URL authTag)
		throws JOSEException;
}
