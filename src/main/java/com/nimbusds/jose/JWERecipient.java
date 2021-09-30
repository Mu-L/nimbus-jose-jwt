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


import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import net.jcip.annotations.Immutable;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;


/**
 * JSON Web Encryption (JWE) recipient specific encrypted key and unprotected
 * header.
 *
 * <p>This class is immutable.
 *
 * <p>See https://datatracker.ietf.org/doc/html/rfc7516#section-7.2
 *
 * @author Alexander Martynov
 * @author Vladimir Dzhuvinov
 * @version 2021-09-30
 */
@Immutable
public class JWERecipient {
	
	
	private final Base64URL encryptedKey;
	
	
	private final UnprotectedHeader header;
	
	
	/**
	 * Creates a new JWE recipient.
	 *
	 * @param header       The unprotected header, {@code null} if not
	 *                     specified.
	 * @param encryptedKey The encrypted key, {@code null} if not
	 *                     specified.
	 */
	public JWERecipient(final UnprotectedHeader header, final Base64URL encryptedKey) {
		this.header = header;
		this.encryptedKey = encryptedKey;
	}
	
	
	/**
	 * Returns the unprotected header for this JWE recipient.
	 *
	 * @return The unprotected header, {@code null} if not specified.
	 */
	public UnprotectedHeader getHeader() {
		return header;
	}
	
	
	/**
	 * Returns the encrypted key for this JWE recipient.
	 *
	 * @return The encrypted key, {@code null} if not specified.
	 */
	public Base64URL getEncryptedKey() {
		return encryptedKey;
	}
	
	
	/**
	 * Returns a JSON object representation.
	 *
	 * @return The JSON object, empty if no header and encrypted key are
	 *         specified.
	 */
	public Map<String, Object> toJSONObject() {
		
		Map<String, Object> json = new HashMap<>();
		
		if (getHeader() != null) {
			json.put("header", getHeader().toJSONObject());
		}
		
		if (getEncryptedKey() != null) {
			json.put("encrypted_key", getEncryptedKey().toString());
		}
		
		return json;
	}
	
	
	/**
	 * Parses a JWE recipient from the specified JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be
	 *                   {@code null}.
	 *
	 * @return The JWE recipient object.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static JWERecipient parse(final Map<String, Object> jsonObject)
		throws ParseException {
		
		UnprotectedHeader header = UnprotectedHeader.parse(JSONObjectUtils.getJSONObject(jsonObject, "header"));
		Base64URL encryptedKey = JSONObjectUtils.getBase64URL(jsonObject, "encrypted_key");
		return new JWERecipient(header, encryptedKey);
	}
	
	
	/**
	 * Parses a JSON array of JWE recipient JSON objects.
	 *
	 * @param jsonArray The JSON array to parse. Must not be {@code null}.
	 *
	 * @return The JWE recipients.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static List<JWERecipient> parse(final Map<String, Object>[] jsonArray)
		throws ParseException {
		
		List<JWERecipient> recipients = new ArrayList<>();
		
		if (jsonArray != null) {
			for (Map<String, Object> json : jsonArray) {
				recipients.add(parse(json));
			}
		}
		
		return recipients;
	}
}
