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

package com.nimbusds.jose.jwk;


import java.net.URI;
import java.text.ParseException;
import java.util.List;
import java.util.Set;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jose.util.X509CertChainUtils;


/**
 * JSON Web Key (JWK) metadata.
 *
 * @author Vladimir Dzhuvinov
 * @version 2020-06-03
 */
final class JWKMetadata {


	/**
	 * Parses the JWK type.
	 *
	 * @param o The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The key type.
	 *
	 * @throws ParseException If parsing failed.
	 */
	static KeyType parseKeyType(final JSONObject o)
		throws ParseException {

		try {
			return KeyType.parse(JSONObjectUtils.getString(o, "kty"));
		} catch (IllegalArgumentException e) {
			throw new ParseException(e.getMessage(), 0);
		}
	}


	/**
	 * Parses the optional public key use.
	 *
	 * @param o The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The key use, {@code null} if not specified or if the key is
	 *         intended for signing as well as encryption.
	 *
	 * @throws ParseException If parsing failed.
	 */
	static KeyUse parseKeyUse(final JSONObject o)
		throws ParseException {

		return KeyUse.parse(JSONObjectUtils.getString(o, "use"));
	}


	/**
	 * Parses the optional key operations.
	 *
	 * @param o The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The key operations, {@code null} if not specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	static Set<KeyOperation> parseKeyOperations(final JSONObject o)
		throws ParseException {
		
		return KeyOperation.parse(JSONObjectUtils.getStringList(o, "key_ops"));
	}


	/**
	 * Parses the optional algorithm.
	 *
	 * @param o The JSON object to parse. Must not be {@code null}.
	 *
	 * @return  The intended JOSE algorithm, {@code null} if not specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	static Algorithm parseAlgorithm(final JSONObject o)
		throws ParseException {

		return Algorithm.parse(JSONObjectUtils.getString(o, "alg"));
	}


	/**
	 * Parses the optional key ID.
	 *
	 * @param o The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The key ID, {@code null} if not specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	static String parseKeyID(final JSONObject o)
		throws ParseException {

		return JSONObjectUtils.getString(o, "kid");
	}


	/**
	 * Parses the optional X.509 certificate URL.
	 *
	 * @param o The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The X.509 certificate URL, {@code null} if not specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	static URI parseX509CertURL(final JSONObject o)
		throws ParseException {

		return JSONObjectUtils.getURI(o, "x5u");
	}


	/**
	 * Parses the optional X.509 certificate thumbprint.
	 *
	 * @param o The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The X.509 certificate thumbprint, {@code null} if not
	 *         specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	static Base64URL parseX509CertThumbprint(final JSONObject o)
		throws ParseException {

		return JSONObjectUtils.getBase64URL(o, "x5t");
	}


	/**
	 * Parses the optional X.509 certificate SHA-256 thumbprint.
	 *
	 * @param o The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The X.509 certificate SHA-256 thumbprint, {@code null} if
	 *         not specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	static Base64URL parseX509CertSHA256Thumbprint(final JSONObject o)
		throws ParseException {

		return JSONObjectUtils.getBase64URL(o, "x5t#S256");
	}


	/**
	 * Parses the optional X.509 certificate chain.
	 *
	 * @param o The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The X.509 certificate chain (containing at least one
	 *         certificate) as a unmodifiable list, {@code null} if not
	 *         specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	static List<Base64> parseX509CertChain(final JSONObject o)
		throws ParseException {
		
		// https://tools.ietf.org/html/rfc7517#section-4.7
		List<Base64> chain = X509CertChainUtils.toBase64List(JSONObjectUtils.getJSONArray(o, "x5c"));
		
		if (chain == null || ! chain.isEmpty()) {
			return chain;
		}
		
		return null; // Empty chains not allowed
	}
}
