/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd.
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
import net.jcip.annotations.Immutable;

import java.util.List;


@Immutable
public final class JWECryptoMultiParts {


	/**
	 * The modified JWE header (optional).
	 */
	private final JWEHeader header;


	/**
	 * The initialisation vector (optional).
	 */
	private final Base64URL iv;


	/**
	 * The cipher text.
	 */
	private final Base64URL cipherText;


	/**
	 * The authentication tag (optional).
	 */
	private final Base64URL authenticationTag;

	private final List<Recipient> recipients;


	public JWECryptoMultiParts(final List<Recipient> recipients,
                               final Base64URL iv,
                               final Base64URL cipherText,
                               final Base64URL authenticationTag) {

		this(null, recipients, iv, cipherText, authenticationTag);
	}

	public JWECryptoMultiParts(final JWEHeader header,
                               final List<Recipient> recipients,
                               final Base64URL iv,
                               final Base64URL cipherText,
                               final Base64URL authenticationTag) {

		this.header = header;

		this.recipients = recipients;

		this.iv = iv;

		if (cipherText == null) {

			throw new IllegalArgumentException("The cipher text must not be null");
		}

		this.cipherText = cipherText;

		this.authenticationTag = authenticationTag;
	}


	/**
	 * Gets the modified JWE header.
	 *
	 * @return The modified JWE header, {@code null} of not.
	 */
	public JWEHeader getHeader() {

		return header;
	}

	public List<Recipient> getRecipients() {
		return recipients;
	}

	/**
	 * Gets the initialisation vector (IV).
	 *
	 * @return The initialisation vector (IV), {@code null} if not required
	 *         by the JWE algorithm.
	 */
	public Base64URL getInitializationVector() {

		return iv;
	}


	/**
	 * Gets the cipher text.
	 *
	 * @return The cipher text.
	 */
	public Base64URL getCipherText() {

		return cipherText;
	}


	/**
	 * Gets the authentication tag.
	 *
	 * @return The authentication tag, {@code null} if the encryption
	 *         algorithm provides built-in integrity checking.
	 */
	public Base64URL getAuthenticationTag() {

		return authenticationTag;
	}
}
